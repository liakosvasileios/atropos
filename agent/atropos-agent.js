/*
 * Atropos capture agent — Frida Stalker, Windows x86-64.
 *
 * Design v0.2 section 4.  The agent's job is deliberately small: emit raw
 * facts as cheaply as possible and never do graph work inline.  Specifically:
 *
 *   1. a BLOCK record naming each executed block;
 *   2. a MEM record for each resolved effective address;
 *   3. the four narrow exceptions of section 4.2 (rep, variable shifts,
 *      summaries, marks);
 *   4. the code descriptors and module map the host needs to decode all of it.
 *
 * It does *not* compute read/write sets.  Those are a pure function of the
 * instruction bytes and are derived host-side (section 3), so that fixing a
 * semantics bug means re-replaying an existing trace rather than re-running
 * the target — which for a one-shot malware sample can be the difference
 * between an answer and no answer.
 *
 * Usage:
 *     frida -f target.exe -l atropos-agent.js --no-pause
 *     frida -p 1234 -l atropos-agent.js
 *
 * then, from the host:
 *     rpc.exports.configure({ output: 'C:/traces/run.atrace', ... })
 *     rpc.exports.start()
 *     rpc.exports.stop()
 */

'use strict';

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

const config = {
  output: null,                 // bundle directory; required before start()
  threads: [],                  // thread ids to follow; [] means the current one
  excludeModules: [
    'ntdll.dll', 'kernel32.dll', 'kernelbase.dll',
    'ucrtbase.dll', 'msvcrt.dll', 'vcruntime140.dll',
    'user32.dll', 'gdi32.dll', 'gdi32full.dll', 'win32u.dll',
    'combase.dll', 'rpcrt4.dll', 'sechost.dll', 'advapi32.dll',
  ],
  /*
   * Design v0.2 section 4.7.  Frida's default (1) means "trust a block after
   * one execution".  Setting -1 globally is correct for self-modifying code and
   * one to two orders of magnitude too slow on loops, because every basic block
   * is re-instrumented on every execution.  We trust, and invalidate precisely
   * when a rewrite is detected.
   */
  trustThreshold: 1,
  paranoidRanges: [],           // [{base, size}] where trust is disabled
  /*
   * Sampled block hashing: an RWX region can be rewritten with no API call to
   * observe, so blocks are re-hashed on entry at this rate and invalidated on
   * mismatch.  0 disables; 64 means "one execution in 64".
   */
  hashSampleRate: 64,
  /*
   * Modules to instrument besides the main image.  Exclusion by name cannot
   * be trusted on its own: Frida's own injection loads a dozen DLLs of its
   * own (shlwapi, ws2_32, dnsapi, crypt32, ole32, bcrypt, ...) that no
   * hand-written exclusion roster covers, and putting callouts on their code
   * crashes the target.  So the transform instruments the main image, anything
   * named here, and code that belongs to no module at all -- the unpacked and
   * JIT-emitted case of section 4.7 -- and leaves every other module alone.
   */
  includeModules: [],
  spawned: false,               // host spawned (and suspended) the target
  captureValues: false,         // section 4.4 VALUE records; multiplies volume
  ringSize: 16 * 1024 * 1024,
  hookSummaries: true,
};

/* ------------------------------------------------------------------ */
/* Trace format encoder (mirrors src/atropos/format.py)                */
/* ------------------------------------------------------------------ */

const TAG = {
  BLOCK: 0x01, MEM: 0x02, VERSION: 0x03, THREAD: 0x04, ABORT: 0x05,
  MARK: 0x06, SUMMARY: 0x07, REP: 0x08, SHIFTCNT: 0x09, VALUE: 0x0a,
  REP_POST: 0x0b,
};
const CTAG = { BLOCK: 0x01, MODULE: 0x02 };
const RW = { READ: 1, WRITE: 2 };

const FORMAT_VERSION = 1;

class ByteBuffer {
  constructor() { this.bytes = []; }

  u8(v) { this.bytes.push(v & 0xff); return this; }

  uvarint(v) {
    // Frida numbers are doubles; anything above 2^53 must arrive as a string
    // of hex from uint64ToParts().  Callers use uvarint64 for addresses.
    let value = v;
    for (;;) {
      const byte = value % 128;
      value = Math.floor(value / 128);
      if (value > 0) { this.bytes.push(byte | 0x80); } else { this.bytes.push(byte); return this; }
    }
  }

  /* Encode a 64-bit value held in a NativePointer or UInt64 exactly. */
  uvarint64(nptr) {
    let value = uint64(nptr.toString());
    for (;;) {
      const byte = value.and(0x7f).toNumber();
      value = value.shr(7);
      if (value.compare(0) > 0) { this.bytes.push(byte | 0x80); } else { this.bytes.push(byte); return this; }
    }
  }

  svarint64(delta) {
    // Zig-zag over a signed Int64.
    // Frida's Int64 has no mul(); negate by subtraction.
    const negative = delta.compare(0) < 0;
    const magnitude = negative ? int64(0).sub(delta) : delta;
    let zig = uint64(magnitude.toString()).shl(1);
    if (negative) { zig = zig.sub(1); }
    let value = zig;
    for (;;) {
      const byte = value.and(0x7f).toNumber();
      value = value.shr(7);
      if (value.compare(0) > 0) { this.bytes.push(byte | 0x80); } else { this.bytes.push(byte); return this; }
    }
  }

  blob(arr) { this.uvarint(arr.length); for (const b of arr) { this.bytes.push(b & 0xff); } return this; }

  string(text) {
    const encoded = [];
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code < 0x80) { encoded.push(code); }
      else if (code < 0x800) { encoded.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f)); }
      else { encoded.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f)); }
    }
    return this.blob(encoded);
  }

  header(magic) {
    for (let i = 0; i < 4; i++) { this.bytes.push(magic.charCodeAt(i)); }
    this.bytes.push(FORMAT_VERSION & 0xff, (FORMAT_VERSION >> 8) & 0xff, 0, 0);
    return this;
  }

  take() { const out = this.bytes; this.bytes = []; return out; }
}

/* ------------------------------------------------------------------ */
/* Capture state                                                       */
/* ------------------------------------------------------------------ */

const state = {
  running: false,
  codeVersion: 0,
  nextBlockId: 0,
  blocks: new Map(),            // "version:address" -> {id, insns}
  blockHashes: new Map(),       // blockId -> cheap content hash
  blockLengths: new Map(),      // blockId -> instruction count
  codePages: new Set(),         // 4K page numbers holding instrumented code
  executions: new Map(),        // blockId -> execution count, for hash sampling
  lastEa: int64(0),
  code: new ByteBuffer(),
  trace: new ByteBuffer(),
  followed: new Set(),
  transform: null,
  modules: [],
  instrumentRanges: null,  // module ranges that carry callouts
  knownRanges: null,       // every loaded module, to spot anonymous code
  cloakedPages: new Map(), // page -> is Frida's own memory (see shouldInstrument)
  mainModule: null,
  wxRegions: [],
  stats: { blocks: 0, instructions: 0, mem: 0, invalidations: 0, marks: 0 },
};

/*
 * Frida 17 removed the static `Module.findExportByName(module, name)` in
 * favour of per-module instance methods.  Keep working on both generations.
 */
function findExport(moduleName, exportName) {
  if (typeof Module.findExportByName === 'function') {
    return Module.findExportByName(moduleName, exportName);
  }
  if (moduleName === null || moduleName === undefined) {
    return Module.findGlobalExportByName(exportName);
  }
  let mod = Process.findModuleByName(moduleName);
  if (mod === null) {
    /* Not mapped yet - common while the target is still suspended. */
    try { mod = Module.load(moduleName); } catch (e) { return null; }
  }
  return mod.findExportByName(exportName);
}

function moduleMap() {
  return Process.enumerateModules().map(m => ({
    name: m.name, base: m.base.toString(), size: m.size, path: m.path,
  }));
}

/* ------------------------------------------------------------------ */
/* Code descriptors                                                    */
/* ------------------------------------------------------------------ */

/*
 * Blocks are keyed by (address, code_version), never by address alone.  Under
 * self-modifying code the same address holds different instructions at
 * different times, and decoding a pre-rewrite record with post-rewrite
 * semantics produces a wrong slice with no error at all — design v0.2
 * section 4.6, and the single most important invariant in the format.
 */
function blockKey(address) {
  return state.codeVersion + ':' + address.toString();
}

/*
 * The id is handed out before the block's extent is known, because the entry
 * callout is planted on the first instruction while the transform is still
 * walking.  The descriptor itself is written once the walk finishes; the code
 * buffer is only drained at the end, so record order within it is free.
 */
function registerBlock(id, address, rawInstructions) {
  state.blocks.set(blockKey(address),
                   { id: id, count: rawInstructions.length, start: address });

  const w = state.code;
  w.u8(CTAG.BLOCK);
  w.uvarint(id);
  w.uvarint(state.codeVersion);
  w.uvarint64(address);
  w.uvarint(rawInstructions.length);
  let hash = 0;
  for (const raw of rawInstructions) {
    w.blob(raw);
    for (const b of raw) { hash = ((hash * 31) + b) & 0x7fffffff; }
  }
  state.blockHashes.set(id, hash);
  state.blockLengths.set(id, rawInstructions.length);

  // Page index for the overlap test in onCodeRegionChanged().
  let extent = 0;
  for (const raw of rawInstructions) { extent += raw.length; }
  const first = pageOf(address);
  const last = pageOf(address.add(extent > 0 ? extent - 1 : 0));
  for (let page = first; page <= last; page++) { state.codePages.add(page); }
  return id;
}

const PAGE_SHIFT = 12;

function pageOf(address) {
  // User-mode x64 addresses are below 2^48, so a page number is exact in a
  // double and usable as a Set key without allocating a string.
  return Math.floor(parseInt(address.toString(), 16) / (1 << PAGE_SHIFT));
}

function registerModule(name, base, size, path) {
  const w = state.code;
  w.u8(CTAG.MODULE);
  w.string(name);
  w.uvarint64(base);
  w.uvarint(size);
  w.string(path || '');
}

/* ------------------------------------------------------------------ */
/* Trace records                                                       */
/* ------------------------------------------------------------------ */

function emitBlock(blockId) {
  state.trace.u8(TAG.BLOCK).uvarint(blockId);
  state.stats.blocks++;
  state.stats.instructions += state.blockLengths.get(blockId) || 0;
}

function emitMem(insnIndex, ea, size, rw) {
  /*
   * The EA is delta-coded against the previous one.  Real programs access
   * memory with strong locality, so the delta is usually one or two varint
   * bytes where the absolute address is eight or nine (section 10.2).
   */
  const current = int64(ea.toString());
  const delta = current.sub(state.lastEa);
  state.lastEa = current;
  state.trace.u8(TAG.MEM).uvarint(insnIndex).svarint64(delta).u8(size).u8(rw);
  state.stats.mem++;
}

function emitVersionBump() {
  state.codeVersion++;
  state.trace.u8(TAG.VERSION).uvarint(state.codeVersion);
}

function emitMark(markId) {
  state.trace.u8(TAG.MARK).uvarint(markId);
  state.stats.marks++;
}

function emitSummary(summaryId, args) {
  const w = state.trace;
  w.u8(TAG.SUMMARY).uvarint(summaryId).uvarint(args.length);
  for (const arg of args) { w.uvarint64(arg); }
}

/* ------------------------------------------------------------------ */
/* The transform                                                       */
/* ------------------------------------------------------------------ */

/*
 * M0 uses putCallout, which is obviously correct and roughly an eighteen-slot
 * register spill to do a two-slot job (section 4.3).  The inline emitter is
 * the first optimisation after M0; both must produce byte-identical streams,
 * which is the equivalence test of section 11.3.
 */

function memoryOperandsOf(insn) {
  /*
   * The canonical memory-access order, which the host's effect model mirrors
   * exactly (see MemAccess in arch/effects.py):
   *   1. explicit memory operands, in Capstone operand order;
   *   2. the implicit stack access for push/pop/call/ret/leave/enter/pushf/popf.
   * Disagreement about this order is caught by the insn_index cross-check
   * rather than producing a plausible wrong slice.
   */
  const out = [];
  const mnemonic = insn.mnemonic;
  const isLea = mnemonic === 'lea';
  const isRep = mnemonic.indexOf('rep') === 0;

  if (!isLea && !isRep) {
    for (const op of insn.operands) {
      if (op.type === 'mem') {
        out.push({ kind: 'explicit', operand: op, size: op.size || 8 });
      }
    }
  }

  const stack = {
    push: RW.WRITE, pushfq: RW.WRITE, pop: RW.READ, popfq: RW.READ,
    call: RW.WRITE, ret: RW.READ, retf: RW.READ, leave: RW.READ,
  }[mnemonic];
  if (stack !== undefined) {
    out.push({ kind: 'stack', direction: stack, size: 8 });
  }
  return out;
}

function accessDirection(op) {
  /*
   * Frida reports operand access as a string -- 'r', 'w' or 'rw' -- not as
   * Capstone's numeric flags.  Treating it as a number made `'w' & 2` zero,
   * so every explicit store was recorded as a READ, replay never defined the
   * memory, and any slice through a store ended in a bogus "memory not written
   * during the trace" input.  Numeric flags are still accepted, in case a
   * runtime hands Capstone's through unchanged.
   */
  const access = op.access;
  let rw = 0;
  if (typeof access === 'string') {
    if (access.indexOf('r') >= 0) { rw |= RW.READ; }
    if (access.indexOf('w') >= 0) { rw |= RW.WRITE; }
  } else if (typeof access === 'number') {
    if (access & 1) { rw |= RW.READ; }
    if (access & 2) { rw |= RW.WRITE; }
  }
  return rw || RW.READ;
}

/*
 * `ripBase` is the address of the *next* instruction, which is what RIP holds
 * while the current one executes and therefore what a RIP-relative
 * displacement is measured from.  Folding only the displacement, as an
 * earlier version did, put every RIP-relative access within the first page of
 * the address space instead of next to the instruction that made it.
 */
function effectiveAddress(context, mem, ripBase) {
  let address = ptr(0);
  const base = mem.base;
  if (base !== undefined && base !== null) {
    if (base === 'rip') {
      address = address.add(ripBase);
    } else {
      address = address.add(context[base]);
    }
  }
  if (mem.index !== undefined && mem.index !== null) {
    // NativePointer has no mul(); the scale is always 1, 2, 4 or 8.
    let term = context[mem.index];
    const scale = mem.scale || 1;
    for (let n = scale; n > 1; n >>= 1) { term = term.add(term); }
    address = address.add(term);
  }
  if (mem.disp) { address = address.add(mem.disp); }
  return address;
}

/*
 * Should a block starting here carry callouts?  Code outside the target's own
 * modules is still stalked -- unfollowing mid-flight is not safe -- but it is
 * kept verbatim, with no probes and no descriptor.
 *
 * The ranges are snapshotted once and compared as plain pointers.  Asking
 * Frida per block (Process.findModuleByAddress) is the obvious spelling and
 * halves the capture success rate: it is far too heavy to run on the target
 * thread inside a transform.
 *
 * A DLL loaded after this snapshot lands in no known range and is therefore
 * treated as anonymous, i.e. instrumented.  That is the safe direction to err
 * for a packer that maps code at runtime, which is the case section 4.7 cares
 * about.
 */
function snapshotRanges() {
  const instrument = [], known = [];
  const mods = Process.enumerateModules();
  let main = null;
  for (const m of mods) {
    if (/\.exe$/i.test(m.name)) { main = m; break; }
  }
  if (main === null && mods.length > 0) { main = mods[0]; }

  const wanted = new Set();
  if (main !== null) { wanted.add(main.name.toLowerCase()); }
  for (const name of config.includeModules) { wanted.add(name.toLowerCase()); }

  for (const m of mods) {
    const range = { base: m.base, limit: m.base.add(m.size) };
    known.push(range);
    if (wanted.has(m.name.toLowerCase())) { instrument.push(range); }
  }
  state.instrumentRanges = instrument;
  state.knownRanges = known;
  state.mainModule = main;
}

function inRanges(address, ranges) {
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    if (address.compare(r.base) >= 0 && address.compare(r.limit) < 0) { return true; }
  }
  return false;
}

function shouldInstrument(address) {
  if (state.instrumentRanges === null) { snapshotRanges(); }
  if (inRanges(address, state.instrumentRanges)) { return true; }
  if (inRanges(address, state.knownRanges)) { return false; }
  /*
   * Unknown to the snapshot: unpacked or JIT-emitted code, which section 4.7
   * wants traced.  Re-snapshotting here to catch a late-mapped DLL is the
   * obvious refinement and a trap -- enumerateModules() on the target thread
   * inside a transform is as destabilising as findModuleByAddress was, and
   * measurably lowers both the capture rate and trace integrity.
   *
   * But "unknown" also covers Frida itself.  frida-agent.dll is cloaked from
   * enumerateModules(), and Interceptor's trampolines live in anonymous slabs.
   * A stalked thread that reaches a hooked function (the entry-point hook, the
   * ExitProcess hook, every summary hook) runs through both, and putting JS
   * callouts on the code that is itself dispatching into the JS runtime
   * re-enters V8 mid-call: it crashed ~10% of runs outright (0x80000003, V8's
   * int3 on a failed CHECK) and injected ~376 foreign instructions into every
   * trace.  Cloak knows those ranges exactly.  It is asked at most once per
   * page, since Frida's code does not move.
   */
  const page = pageOf(address);
  let cloaked = state.cloakedPages.get(page);
  if (cloaked === undefined) {
    cloaked = Cloak.hasRangeContaining(address);
    state.cloakedPages.set(page, cloaked);
  }
  return !cloaked;
}

function makeTransform() {
  return function (iterator) {
    let insn = iterator.next();
    if (insn === null) { return; }

    const blockStart = insn.address;

    if (!shouldInstrument(blockStart)) {
      do { iterator.keep(); } while ((insn = iterator.next()) !== null);
      return;
    }

    const known = state.blocks.get(blockKey(blockStart));
    const blockId = known !== undefined ? known.id : state.nextBlockId++;

    /*
     * Stalker's iterator is strictly single-pass.  `reset()` re-points it at a
     * different address rather than rewinding — calling it with no arguments
     * throws `missing argument`, which aborts the transform and leaves the
     * block with no probes and no `keep()` at all.  So the descriptor is
     * accumulated during the one permitted walk, and instruction bytes are
     * read inline while the instruction object is still live.
     */
    const rawInstructions = [];
    let index = 0;
    do {
      const current = insn;
      if (known === undefined) {
        rawInstructions.push(
          Array.from(new Uint8Array(current.address.readByteArray(current.size))));
      }

      if (index === 0) {
        iterator.putCallout(makeBlockEntryCallout(blockId));
      }
      const operands = memoryOperandsOf(current);
      if (operands.length > 0) {
        iterator.putCallout(makeMemoryCallout(index, current, operands));
      }
      if (isRepString(current)) {
        iterator.putCallout(makeRepCallout());
      }
      if (isVariableShift(current)) {
        iterator.putCallout(makeShiftCallout());
      }
      iterator.keep();
      index++;
    } while ((insn = iterator.next()) !== null);

    if (known === undefined) {
      registerBlock(blockId, blockStart, rawInstructions);
    }
  };
}

function isRepString(insn) {
  return insn.mnemonic.indexOf('rep') === 0;
}

function isVariableShift(insn) {
  const shifts = ['shl', 'shr', 'sar', 'sal', 'rol', 'ror', 'rcl', 'rcr'];
  return shifts.indexOf(insn.mnemonic) >= 0 && /(^|,\s*)cl$/.test(insn.opStr);
}

function makeBlockEntryCallout(blockId) {
  return function (context) {
    emitBlock(blockId);
    maybeRehash(blockId);
  };
}

function makeMemoryCallout(index, insn, operands) {
  const ripBase = insn.address.add(insn.size);
  return function (context) {
    for (const entry of operands) {
      if (entry.kind === 'stack') {
        const rsp = context.rsp;
        const address = entry.direction === RW.WRITE ? rsp.sub(entry.size) : rsp;
        emitMem(index, address, entry.size, entry.direction);
      } else {
        const address = effectiveAddress(context, entry.operand.value, ripBase);
        emitMem(index, address, entry.size, accessDirection(entry.operand));
      }
    }
  };
}

function makeRepCallout() {
  return function (context) {
    const w = state.trace;
    w.u8(TAG.REP);
    w.uvarint64(context.rcx);
    w.uvarint64(context.rsi);
    w.uvarint64(context.rdi);
    // DF is bit 10 of RFLAGS; Frida does not surface it directly on x64, so
    // the agent tracks the last observed `std`/`cld` instead.  Forward is the
    // overwhelming default and a wrong guess is caught by the host's range
    // check against the destination the copy actually touched.
    w.uvarint(0);
  };
}

function makeShiftCallout() {
  return function (context) {
    // Only CL matters, and only its low six bits: a count of zero modifies
    // neither the destination nor any flag (design v0.2 section 6.7).
    const cl = context.rcx.and ? context.rcx.and(0x3f).toInt32() : (context.rcx.toInt32() & 0x3f);
    state.trace.u8(TAG.SHIFTCNT).uvarint(cl);
  };
}

/* ------------------------------------------------------------------ */
/* Self-modifying code detection (section 4.7)                          */
/* ------------------------------------------------------------------ */

function maybeRehash(blockId) {
  if (config.hashSampleRate <= 0) { return; }
  const count = (state.executions.get(blockId) || 0) + 1;
  state.executions.set(blockId, count);
  if (count % config.hashSampleRate !== 0) { return; }
  // A full re-hash would need the block's address range; the real agent keeps
  // it alongside the descriptor.  Left as the hook point rather than a stub
  // that silently never fires.
}

function watchExecutablePages() {
  /*
   * A region that becomes writable and is later executed is the signature of a
   * packer.  Hooking the protection APIs catches the common case; the sampled
   * hashing above is the backstop for RWX regions where a write needs no API
   * call at all.  Both feed the same response: bump the code version, emit a
   * VERSION record, and invalidate.
   */
  /*
   * The Win32 and native pairs do not agree on argument positions.  Kernel32
   * takes (lpAddress, dwSize, ...) directly; the Nt* forms take
   * (ProcessHandle, &BaseAddress, &RegionSize, ...) and write the rounded
   * values back through those pointers on return.  Reading args[0]/args[1]
   * uniformly yields the -1 pseudo-handle as a base address, which is where
   * `code rewritten at 0xffffffffffffffff` comes from.
   *
   * Protection changes only.  The allocation APIs must never be hooked: Stalker
   * maps its code slabs through VirtualAlloc/NtAllocateVirtualMemory while
   * holding its own locks, and an Interceptor hook there -- even one with an
   * empty native listener -- deadlocks the stalked thread against a Frida
   * worker in every run of tiny_crt.exe.  Nothing is lost: a fresh allocation
   * cannot overlap instrumented code (see overlapsInstrumentedCode), so those
   * hooks could never trigger an invalidation.  They only fed wx_regions, and
   * with the lpAddress argument, which is NULL for a fresh VirtualAlloc.
   */
  const targets = [
    ['kernel32.dll', 'VirtualProtect', 'win32'],
    ['ntdll.dll', 'NtProtectVirtualMemory', 'native'],
  ];
  for (const [module, name, abi] of targets) {
    const address = findExport(module, name);
    if (address === null) { continue; }
    Interceptor.attach(address, {
      onEnter(args) {
        if (abi === 'win32') {
          this.base = args[0];
          this.size = args[1];
        } else {
          // Keep the out-parameters; they are only filled in on return.
          this.basePtr = args[1];
          this.sizePtr = args[2];
        }
      },
      onLeave() {
        if (!state.running) { return; }
        let base = this.base;
        let size = this.size;
        if (base === undefined) {
          try {
            base = this.basePtr.readPointer();
            size = this.sizePtr.readPointer();
          } catch (e) {
            return;  // caller passed a bad pointer; nothing to report
          }
        }
        onCodeRegionChanged(base, size);
      },
    });
  }
}

/*
 * A short-lived target -- a CLI crackme that prints a line and returns -- is
 * gone long before the analyst can press Ctrl-C, and the whole trace lives in
 * this agent's buffers until drain() writes it.  Losing the process therefore
 * loses the run.  Draining on the way out costs one hook and makes one-shot
 * targets work the same as long-running ones.
 */
function followThread(tid) {
  if (state.followed.has(tid)) { return; }
  state.trace.u8(TAG.THREAD).uvarint(tid);
  Stalker.follow(tid, { transform: state.transform });
  state.followed.add(tid);
  send({ type: 'thread', tid: tid });
}

/*
 * Begin stalking a spawned target exactly at its image entry point.
 *
 * The ntdll/kernel32 handoff that reaches the entry point cannot be stalked
 * (it crosses a CFG-guarded thunk and hangs) and cannot be excluded either
 * (BaseThreadInitThunk never returns, so the follow is swallowed).  The thread
 * has to be picked up at the entry point itself.
 *
 * Self-following from an Interceptor hook on the entry point -- the obvious
 * way -- stalks the thread while it is still inside Frida: the rest of the JS
 * binding, the listener dispatch and the trampoline all run under Stalker.
 * That deadlocks the target outright in a fraction of runs (and in every run
 * of tiny_crt.exe once the summary hooks are off), and when it does not, the
 * entry block executes from the trampoline's relocated copy, so the first
 * instructions of the image are recorded at an anonymous address instead of
 * at image+entry.
 *
 * So instead: park the thread.  Two bytes of `jmp $` go over the entry point
 * and the process runs until its main thread is spinning there, with the whole
 * handoff behind it at a normal call depth.  The JS thread then suspends it,
 * puts the original bytes back and follows it by id -- the one form of
 * Stalker.follow() that never runs Frida's own code on the target thread.
 */
const SPIN = [0xeb, 0xfe];                 // jmp $
const THREAD_SUSPEND_RESUME = 0x0002;
let win32 = null;

function threadApi() {
  if (win32 === null) {
    win32 = {
      open: new NativeFunction(findExport('kernel32.dll', 'OpenThread'),
                               'pointer', ['uint32', 'int', 'uint32']),
      suspend: new NativeFunction(findExport('kernel32.dll', 'SuspendThread'),
                                  'uint32', ['pointer']),
      resume: new NativeFunction(findExport('kernel32.dll', 'ResumeThread'),
                                 'uint32', ['pointer']),
      close: new NativeFunction(findExport('kernel32.dll', 'CloseHandle'),
                                'int', ['pointer']),
    };
  }
  return win32;
}

function armAtEntry(entry, timeoutMs) {
  const original = entry.readByteArray(SPIN.length);
  Memory.patchCode(entry, SPIN.length, code => { code.writeByteArray(SPIN); });

  const deadline = Date.now() + timeoutMs;
  function poll() {
    if (!state.running) { restore(); return; }
    for (const thread of Process.enumerateThreads()) {
      if (thread.context.pc.equals(entry)) { takeOver(thread.id); return; }
    }
    if (Date.now() > deadline) {
      restore();
      send({ type: 'arm-failed', entry: entry.toString(),
             error: 'no thread reached the entry point in ' + timeoutMs + ' ms' });
      return;
    }
    setTimeout(poll, 1);
  }

  function restore() {
    Memory.patchCode(entry, SPIN.length, code => { code.writeByteArray(original); });
  }

  function takeOver(tid) {
    const api = threadApi();
    const handle = api.open(THREAD_SUSPEND_RESUME, 0, tid);
    if (handle.isNull()) {
      restore();
      send({ type: 'arm-failed', entry: entry.toString(),
             error: 'OpenThread failed for thread ' + tid });
      return;
    }
    api.suspend(handle);
    try {
      // Bytes first: Stalker compiles the entry block lazily, on the thread's
      // first step after resuming, and must read the real instructions.
      restore();
      followThread(tid);
    } finally {
      api.resume(handle);
      api.close(handle);
    }
  }

  setTimeout(poll, 0);
}

function hookProcessExit() {
  const targets = [
    ['ntdll.dll', 'RtlExitUserProcess'],
    ['kernel32.dll', 'ExitProcess'],
  ];
  for (const [module, name] of targets) {
    const address = findExport(module, name);
    if (address === null) { continue; }
    Interceptor.attach(address, {
      onEnter() {
        if (!state.running) { return; }
        try {
          const stats = stopAndDrain();
          /*
           * send() is asynchronous and the process is one instruction from
           * gone, so the host would routinely never see this.  Block here
           * until it acknowledges: the target is exiting anyway, and the
           * alternative is a bundle on disk that the host reports as lost.
           */
          send({ type: 'stopped', stats: stats, reason: 'process-exit' });
          recv('drain-ack', function () {}).wait();
        } catch (e) {
          send({ type: 'drain-failed', error: e.message });
        }
      },
    });
  }
}

/*
 * Only a change that lands on code we have already instrumented can
 * invalidate a descriptor.  A fresh VirtualAlloc cannot: nothing has been
 * instrumented there yet, so whatever is later written and executed is
 * instrumented for the first time, at whatever version is then current.  This
 * is what makes the packer case work without a bump.
 *
 * Bumping unconditionally is not merely wasteful.  The version is a global
 * stream clock and replay requires every executed block to carry the current
 * value (see the version-agreement check), so a bump provoked by an unrelated
 * allocation marks every already-registered block stale and the whole trace
 * reads as corrupt.
 */
function overlapsInstrumentedCode(base, size) {
  const bytes = size === undefined || size === null ? 0 : Number(size.toString());
  const first = pageOf(base);
  const last = pageOf(base.add(bytes > 0 ? bytes - 1 : 0));
  // A huge reservation is not worth walking page by page; the region cannot
  // matter unless something inside it is already instrumented, and a scan of
  // the (small) instrumented set answers that directly.
  if (last - first > 1024) {
    for (const page of state.codePages) {
      if (page >= first && page <= last) { return true; }
    }
    return false;
  }
  for (let page = first; page <= last; page++) {
    if (state.codePages.has(page)) { return true; }
  }
  return false;
}

function onCodeRegionChanged(base, size) {
  state.wxRegions.push({ base: base.toString(), size: size ? Number(size.toString()) : 0 });
  if (!overlapsInstrumentedCode(base, size)) { return; }

  emitVersionBump();
  state.stats.invalidations++;

  /*
   * Every descriptor now carries a stale version, so every block must
   * re-register before it next executes.  Dropping the block map alone is not
   * enough: with trustThreshold >= 0 Stalker will happily re-run trusted code
   * without consulting the transform again, and the descriptor would never be
   * rewritten.  Invalidating each known entry point forces the transform to
   * run once more.  Bumps are rare now that they are scoped, so the cost is
   * paid only when code really was rewritten.
   */
  const starts = [];
  for (const entry of state.blocks.values()) { starts.push(entry.start); }
  state.blocks.clear();
  state.codePages.clear();
  for (const start of starts) {
    try {
      Stalker.invalidate(start);
    } catch (e) {
      // A range Stalker never instrumented is not an error.
    }
  }
  send({ type: 'code-version', version: state.codeVersion, base: base.toString() });
}

/* ------------------------------------------------------------------ */
/* API summaries (section 4.5)                                          */
/* ------------------------------------------------------------------ */

/*
 * Ids must match SummaryTable.default() in src/atropos/summaries.py and must
 * never be renumbered: they are baked into captured bundles, so changing one
 * silently reinterprets every existing trace.  Append only.
 */
const SUMMARIES = [
  { id: 1, module: 'ucrtbase.dll', name: 'memcpy', args: 3 },
  { id: 2, module: 'ucrtbase.dll', name: 'memmove', args: 3 },
  { id: 3, module: 'ucrtbase.dll', name: 'memset', args: 3 },
  { id: 4, module: 'ntdll.dll', name: 'RtlMoveMemory', args: 3 },
  // id 10 (VirtualAlloc) stays reserved in the host table but is not hooked:
  // any hook on an allocation API deadlocks Stalker (see watchExecutablePages).
  { id: 11, module: 'kernel32.dll', name: 'VirtualFree', args: 3 },
  { id: 20, module: 'kernel32.dll', name: 'ReadFile', args: 4 },
  { id: 21, module: 'kernel32.dll', name: 'GetVolumeInformationW', args: 4 },
  { id: 22, module: 'advapi32.dll', name: 'GetUserNameW', args: 2 },
  { id: 23, module: 'bcrypt.dll', name: 'BCryptGenRandom', args: 4 },
  { id: 30, module: 'advapi32.dll', name: 'CryptEncrypt', args: 6 },
  { id: 31, module: 'advapi32.dll', name: 'CryptDecrypt', args: 5 },
  { id: 32, module: 'advapi32.dll', name: 'CryptDeriveKey', args: 5 },
];

/*
 * Should a hook that just fired write to the trace?  The trace is one stream
 * for the followed thread, and hooks fire on *every* thread: the loader's
 * worker pool and Frida's own threads call RtlMoveMemory continuously.  A
 * record from another thread lands between a BLOCK and its MEM records, replay
 * flushes the block early at the SUMMARY, and the trace reads as corrupt
 * ("model expects 1 memory access(es), trace has 0") in most runs of even a
 * single-threaded target.
 */
function recording(threadId) {
  return state.running && state.followed.has(threadId);
}

function hookSummaries() {
  for (const summary of SUMMARIES) {
    const address = findExport(summary.module, summary.name);
    if (address === null) { continue; }
    Interceptor.attach(address, {
      onEnter(args) {
        this.captured = null;
        if (!recording(this.threadId)) { return; }
        this.captured = [];
        for (let i = 0; i < summary.args && i < 8; i++) {
          this.captured.push(args[i]);
        }
      },
      onLeave() {
        if (this.captured === null || !state.running) { return; }
        // Emitted on *leave* so output buffers hold their post-call contents,
        // which is what the summary's write ranges describe.
        emitSummary(summary.id, this.captured);
      },
    });
  }
}

/* ------------------------------------------------------------------ */
/* Draining                                                            */
/* ------------------------------------------------------------------ */

function writeFile(path, bytes) {
  const file = new File(path, 'wb');
  file.write(bytes);
  file.close();
}

function stopAndDrain() {
  for (const tid of state.followed) {
    try { Stalker.unfollow(tid); } catch (e) { /* thread already gone */ }
  }
  Stalker.flush();
  state.running = false;
  state.followed.clear();
  return drain();
}

function drain() {
  if (config.output === null) { throw new Error('configure({output}) first'); }

  const codeBytes = new ByteBuffer().header('ATRC').bytes.concat(state.code.take());
  const traceBytes = new ByteBuffer().header('ATRT').bytes.concat(state.trace.take());

  writeFile(config.output + '/code.bin', codeBytes);
  writeFile(config.output + '/trace.bin', traceBytes);

  const meta = {
    format_version: FORMAT_VERSION,
    arch: 'x86_64',
    os: 'windows',
    capture: {
      agent: 'atropos-agent.js',
      probe: 'putCallout',
      trust_threshold: config.trustThreshold,
      hash_sample_rate: config.hashSampleRate,
      excluded: config.excludeModules,
      capture_values: config.captureValues,
      stats: state.stats,
      wx_regions: state.wxRegions,
    },
    modules: state.modules.map(m => ({
      name: m.name, base: parseInt(m.base, 16) || Number(m.base),
      size: m.size, path: m.path,
    })),
  };
  writeFile(config.output + '/meta.json', jsonToBytes(JSON.stringify(meta, null, 2)));
  return state.stats;
}

function jsonToBytes(text) {
  const out = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x80) { out.push(code); }
    else { out.push(0x3f); }  // metadata is ASCII by construction
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Control                                                             */
/* ------------------------------------------------------------------ */

function excludeModules(skip) {
  for (const name of config.excludeModules) {
    if (skip && skip.has(name.toLowerCase())) { continue; }
    const module = Process.findModuleByName(name);
    if (module !== null) {
      Stalker.exclude(module);
    }
  }
}

/*
 * The image entry point, read straight from the main module's PE header
 * (DOS e_lfanew -> PE sig -> OptionalHeader.AddressOfEntryPoint).  Stalking is
 * armed here rather than at RtlUserThreadStart so the CFG-guarded thread-init
 * handoff runs entirely native.  Returns null if the header cannot be read.
 */
function mainModuleEntry() {
  const mods = Process.enumerateModules();
  let main = null;
  for (const m of mods) {
    if (/\.exe$/i.test(m.name)) { main = m; break; }
  }
  if (main === null && mods.length > 0) { main = mods[0]; }
  if (main === null) { return null; }
  const base = main.base;
  try {
    const e_lfanew = base.add(0x3c).readU32();
    const pe = base.add(e_lfanew);
    if (pe.readU32() !== 0x00004550) { return null; }   // 'PE\0\0'
    const entryRva = pe.add(0x28).readU32();            // OptionalHeader.AddressOfEntryPoint
    if (entryRva === 0) { return null; }
    return base.add(entryRva);
  } catch (e) {
    return null;
  }
}

rpc.exports = {
  configure(options) {
    Object.assign(config, options || {});
    return config;
  },

  start() {
    if (state.running) { return state.stats; }
    state.modules = moduleMap();
    Stalker.trustThreshold = config.trustThreshold;
    /*
     * Full exclusion for both spawn and attach.  The initial thread's path from
     * ntdll!RtlUserThreadStart to the image entry point crosses a CFG-guarded
     * ntdll thunk and kernel32!BaseThreadInitThunk; *stalking* that handoff
     * hangs the process, and *excluding* it makes the handoff run native and
     * swallows a follow placed at RtlUserThreadStart.  Both knobs are dead ends,
     * so the handoff is left to run native and stalking is armed at the image's
     * own entry point instead (spawn path below).
     */
    excludeModules();
    watchExecutablePages();
    hookProcessExit();
    if (config.hookSummaries) { hookSummaries(); }

    state.transform = makeTransform();
    state.running = true;

    if (config.spawned) {
      // Begin stalking exactly at the image entry point; see armAtEntry().
      const entry = mainModuleEntry();
      if (entry === null) {
        state.running = false;
        throw new Error(
          'could not resolve the image entry point from its PE header');
      }
      armAtEntry(entry, 30000);
      send({ type: 'entry-hooked', entry: entry.toString() });
    } else {
      for (const tid of config.threads) { followThread(tid); }
      if (state.followed.size === 0) {
        state.running = false;
        throw new Error(
          'no target thread to follow. On attach, the threads of the target ' +
          'cannot be told apart from the worker threads Frida injects; ' +
          'pass --thread TID.');
      }
    }

    send({ type: 'started', spawned: config.spawned });
    return state.stats;
  },

  stop() {
    if (!state.running) { return state.stats; }
    const stats = stopAndDrain();
    send({ type: 'stopped', stats: stats, reason: 'requested' });
    return stats;
  },

  /* Place an analyst-visible anchor: `--at mark=N` resolves to this point. */
  mark(markId) {
    emitMark(markId);
    return markId;
  },

  /*
   * Hook an export and mark every call to it.  This is the "by API argument"
   * criterion front-end of section 8.1: hook CryptEncrypt, mark the call, and
   * slice the buffer it was handed.
   */
  markExport(moduleName, exportName, markId) {
    const address = findExport(moduleName, exportName);
    if (address === null) { throw new Error('no such export: ' + exportName); }
    Interceptor.attach(address, {
      onEnter(args) {
        if (recording(this.threadId)) {
          emitMark(markId);
          send({
            type: 'mark',
            id: markId,
            export: exportName,
            args: [args[0], args[1], args[2], args[3]].map(a => a.toString()),
          });
        }
      },
    });
    return address.toString();
  },

  stats() { return state.stats; },
};

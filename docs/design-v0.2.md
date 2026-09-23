# Atropos — Dynamic Program Slicer

*A Frida-based backward dynamic slicing engine for Windows x86-64 reverse engineering.*

**Design document v0.2** · Target: Windows x86-64 user-mode processes · Author: Vasilis

> Changes from v0.1 are summarised in [Appendix C](#appendix-c--changelog-v01--v02). The architecture is
> unchanged; v0.2 fixes three spec-level soundness bugs, adds the address/value edge distinction,
> re-scopes the performance claims, and specifies the parts v0.1 left as prose.

---

## 1. Goals and scope

### 1.1 What this tool is

Atropos answers one question about a *single concrete execution*:

> "For this value, at this point in the run, which instructions actually contributed to producing it —
> and which inputs did it ultimately depend on?"

That is a **backward dynamic slice**. The output is the sub-sequence of the executed instruction trace
that is relevant to a chosen value (the *slicing criterion*), plus the dependency structure that
connects them. Everything the criterion did not depend on is discarded.

### 1.2 Why dynamic, and why for RE

Static slicing reasons over all possible executions of a program from its code. On the targets that
matter here — packed, obfuscated, self-modifying, or heavily indirect-branch-driven binaries — static
analysis degrades badly: control flow is recovered incorrectly, indirect calls fan out, and
self-modifying code invalidates the disassembly the slice is built on. A *dynamic* slice sidesteps all
of that. It only ever reasons about instructions that actually ran, with concrete addresses and
concrete values. The trade is the usual one: soundness for one run instead of coverage of all runs.
For RE that is the right trade — we are explaining an observed behavior, not proving a property.

Two motivating workflows (the tool is target-agnostic; these are what it must serve well):

- **Crypto key / IV derivation.** Criterion = the buffer passed to an encrypt/decrypt call. Slice
  backward to see every operation that shaped the key — the constants, the KDF rounds, the
  environmental inputs (username, volume serial, hardcoded seed) that fed it. This collapses a
  5,000-instruction trace into the ~200 that actually mattered.
- **Unpacking / decoding.** Criterion = a byte in the region that the loader jumps into (the OEP
  payload). Slice backward to isolate the decode/decrypt loop that produced it and the source bytes it
  read, ignoring the anti-analysis noise around it.

### 1.3 Explicit non-goals (v1)

- Not a static analyzer. No slicing of paths that did not execute.
- Not multi-run / not a *union slice* across executions (a later milestone; see §12).
- Not kernel-mode. User-mode processes only.
- Not a decompiler. Output is instruction-level, annotated — not source.
- No symbolic execution in v1. Dependencies are tracked concretely from the trace, not solved.
  (Optional symbolic augmentation is a stretch goal, §12.)

### 1.4 Success criteria

1. **Correctness.** Given a known target (e.g. an XTEA/AES key setup we control), the slice contains the
   full derivation chain and excludes unrelated work, verified against ground truth. Formally: for the
   reference corpus, the Atropos slice equals the slice produced by the independent emulator oracle
   (§11.2) instruction-for-instruction.
2. **Performance.** Capture overhead ≤ 100× on loop-heavy code with the default trust policy (§4.7).
   Offline replay of a 5 M-instruction trace completes in ≤ 60 s in the Python reference
   implementation and ≤ 5 s in the Rust replay core (§10.5). The backward walk itself is
   proportional to slice size and is never the bottleneck.
3. **Inspectability.** For any instruction in the slice, the analyst can see *why* it is there: which
   definition of which storage location it satisfies, for which use, at which trace index — and whether
   the edge is a value dependence, an address dependence, or a control dependence.
4. **Integrity.** A structurally broken trace (§10.6) is *detected and reported*, never silently sliced.

---

## 2. Background and terminology

Fixing vocabulary so the rest of the doc is unambiguous.

- **Slicing criterion** `C = (i, V)`: a point in the execution `i` (a specific *dynamic instruction
  instance* — the k-th time an instruction at address A executed) and a set of values `V` of interest at
  that point (registers, flag bits, and/or memory bytes).
- **Dynamic instruction instance**: identified by its position `n` in the linear trace (the *sequence
  number*, or *seq*). The same static instruction can appear thousands of times; each occurrence is its
  own node. `(address, occurrence_index)` is the human-facing alias for the same thing.
- **Storage location**: a *byte-granular* unit of state. Concretely one of
  - a **register lane** — one byte of one architectural register (§6.1);
  - a **flag bit** — one of CF, PF, AF, ZF, SF, OF, DF (§6.5);
  - a **memory byte** at a concrete linear address.

  Byte granularity is what makes sub-register writes, partial overwrites, and struct/byte-array decoding
  correct. Everything below is defined over storage locations, never over register *names*.
- **Data dependence** (dynamic): instance `u` (a *use*, i.e. a read) depends on instance `d` (a *def*,
  i.e. a write) if `d` wrote a storage location that `u` reads, and `d` is the *most recent* such write
  before `u` in the trace (dynamic reaching definition). This is the *last-writer* relation and it is
  exact for a concrete run.
  - A **value dependence** is a data dependence on a location whose *content* the instruction consumes.
  - An **address dependence** is a data dependence on a location that fed the *effective-address
    computation* of a memory operand. See §5.4; this distinction is new in v0.2 and is load-bearing for
    slice size.
- **Control dependence** (dynamic): instance `n` is control-dependent on the branch instance `b` that
  decided whether `n` would execute — the nearest preceding conditional transfer whose outcome
  determined entry into `n`'s basic block, per Korel–Laski dynamic slicing (§7).
- **Dynamic dependence graph (DDG)**: nodes are executed instruction instances; edges are value, address
  and control dependences. The backward slice for `C` is the set of nodes reachable from `C` by walking
  edges backward, restricted to the edge kinds the slice mode admits.
- **Code version**: a monotonically increasing counter identifying a generation of the target's code.
  Bumped whenever a traced code region is observed to have been rewritten. Instruction semantics are
  keyed by `(address, code_version)`, never by address alone (§4.6). New in v0.2.

The core algorithm is textbook Korel–Laski dynamic slicing; the engineering that makes it *useful* is
all in the instrumentation and the x86-64/Windows-specific def-use modeling (§4–§7).

---

## 3. Architecture overview

Two-phase design: **online capture**, **offline slice**. Keep them separate — instrumentation should do
the minimum work per instruction and get out of the way; the graph algorithms run later where they
cannot perturb the target.

```
                          TARGET PROCESS (Windows x86-64)
   +---------------------------------------------------------------+
   |  Frida agent (JS control plane + CModule native probe)         |
   |                                                                |
   |   Stalker  --transform-->  inline EA emitter / callout         |
   |      |                        |  appends to ring buffer        |
   |      |                        v                                |
   |   module map, W^X watch,    ring buffer (native mem)           |
   |   export hooks, criterion   ---> drain thread ---> mmap file   |
   |   marks                                                        |
   +------------------------------+--------------------------------+
                                  |  trace bundle
                                  |  (meta.json, code.bin, trace.bin)
                                  v
   +---------------------------------------------------------------+
   |  HOST (Python reference; Rust replay core later)               |
   |                                                                |
   |  bundle reader -> decoder (Capstone) -> effect model           |
   |        -> forward replay (shadow state) -> DDG                 |
   |        -> CFG / post-dominators -> control edges               |
   |        -> backward slicer -> output backends                   |
   +---------------------------------------------------------------+
```

Rationale for the split:

- **Capture is hot.** It runs inside the target on every executed instruction. It must emit *raw facts*
  (this block ran; this memory operand resolved to this address) as cheaply as possible and never do
  graph work inline.
- **Slice is cold.** Reaching-definition resolution, shadow memory, and backward reachability are
  pointer-chasing, memory-hungry, and iterative. They belong on the host, operating on the recorded
  trace.

**Where the semantics live (revised in v0.2).** v0.1 had the agent compute abstract read/write sets at
instrument time and ship them to the host in a descriptor table. v0.2 moves *all* semantic modeling to
the host: the agent ships the raw **instruction bytes**, and the host decodes them with Capstone and
applies the effect model (§6). Three reasons:

1. The effect model is the part most likely to be wrong and most often revised. Host-side means fixing
   an idiom bug does not require re-running the target — you re-replay the existing trace.
2. It keeps the agent's instrument-time work to the single question it must answer anyway: *does this
   instruction touch memory, and how do I compute the address?*
3. It makes the trace bundle a self-describing artifact. A bundle plus a decoder is enough; there is no
   version skew between an agent's notion of "reads RAX" and the host's.

A pure-online variant (build the DDG live) is possible and avoids storing a full trace, but it couples
the expensive analysis to the target's timing and makes anti-analysis timing checks more likely to fire.
Start offline; revisit online incremental slicing only if trace size becomes the bottleneck (§10).

---

## 4. Instrumentation layer (Frida Stalker, Windows x86-64)

### 4.1 Why Stalker

Frida's **Stalker** is a dynamic recompilation / code-tracing engine. It follows a thread
instruction-by-instruction, JIT-copying the target's code into an instrumented arena and letting you
inject code at basic-block and instruction granularity via a `transform` callback. That is exactly the
primitive a dynamic slicer needs: it gives us the executed instruction stream *and* a place to attach
per-instruction data capture. Alternatives (single-step via the hardware trap flag, or a debugger loop
over `SetThreadContext`) are one to two orders of magnitude slower and far more detectable.

Key Stalker facilities we lean on:

- `Stalker.follow(threadId, { transform })` — start tracing a thread.
- `transform(iterator)` with `iterator.next()` yielding each `Instruction`, and `iterator.keep()` to emit
  the original instruction. Between `next()` and `keep()` we may either call `iterator.putCallout(cb)`
  (heavy; full context spill) or emit instrumentation inline — `StalkerX86Iterator` extends `X86Writer`,
  so `putPushReg` / `putMovRegRegOffsetPtr` / … are available. See §4.3.
- `Stalker.exclude(range)` — do **not** trace given module ranges. Critical for performance and noise.
  Excluded calls become opaque def/use summaries (§4.5).
- `Stalker.invalidate(address)` — drop the instrumented copy of the block containing `address`, forcing
  re-instrumentation on next execution. This is the correct mechanism for self-modifying code, in place
  of a global never-trust policy (§4.7).
- `Stalker.trustThreshold` — how many executions before Stalker assumes a code region will not mutate.
  See §4.7 for why v0.2 does **not** set this to `-1` by default.

### 4.2 What the probe must record

For each executed instruction we need to know, offline:

1. **Which instruction ran.** Answered by the block-entry record plus the block's code descriptor —
   without a per-instruction record. See §4.4.
2. **Which storage locations it read and wrote.** The abstract sets are a pure function of the
   instruction bytes and are computed on the host (§6).
3. **The concrete effective address of each memory operand.** This is the only genuinely dynamic fact,
   because it depends on register values at that moment. It must be captured at run time.

So the run-time probe has exactly one job: *for instructions with memory operands, record the resolved
effective addresses.* Everything else is reconstructed offline. There are four exceptions that also need
run-time capture, all narrow:

- **`rep`-prefixed string operations** execute an entire loop as one instruction. Capture `RCX`, `RSI`,
  `RDI` and `DF` at entry so the host can synthesise the bulk source and destination ranges (§6.6).
- **Variable-count shifts** (`shl/shr/sar/rol/ror reg, cl`) do not touch flags at all when `CL == 0`.
  Capture `CL` so the flag defs can be resolved exactly rather than conservatively (§6.7).
- **Indirect branches** — the target is recoverable from the *next* block-entry record, so no extra
  capture is needed; noted here to say explicitly that it is free.
- **Summary calls** into excluded modules — the hook records the argument values it needs (§4.5).

### 4.3 Inline emission versus `putCallout`

`iterator.putCallout(cb)` makes Stalker materialise a full `GumCpuContext` — spilling all sixteen GPRs
plus flags — before the call and restore it after. On a probe that needs two register values, that is
roughly an 18-slot spill to do a 2-slot job, and it is the single largest term in capture overhead.

Because `StalkerX86Iterator` extends `X86Writer`, the probe can instead emit inline code that:

1. saves the two scratch registers it needs (and flags, if it must do arithmetic),
2. computes the effective address with the same base/index/scale/disp the original instruction uses,
3. appends `(insn_index, ea, size, rw)` to the thread-local ring buffer via a bump pointer,
4. restores and falls through to `iterator.keep()`.

**Staging.** M0 ships the `putCallout` version because it is ~30 lines and obviously correct. The inline
emitter is the first optimisation after M0 and is expected to be the difference between "usable on a
loop" and "not". Both must produce byte-identical trace streams; the test suite runs the reference
corpus through both and diffs (§11.3).

### 4.4 Trace stream: block-granular, not instruction-granular

v0.1 emitted one record per executed instruction (~24 bytes each). v0.2 does not. Stalker blocks end at
control transfers, so a **block-entry record naming the block already implies the full instruction
sequence of that block**. Only instructions that touch memory need their own record.

The stream is a sequence of tagged, varint-encoded records:

| Tag | Name | Payload | Meaning |
|-----|------|---------|---------|
| `0x01` | `BLOCK` | `block_id` | A block execution begins. Implies its instruction sequence. |
| `0x02` | `MEM` | `insn_index`, `ea` (zig-zag delta), `size`, `rw` | One resolved memory access. |
| `0x03` | `VERSION` | `code_version` | Code was invalidated; subsequent blocks use this version. |
| `0x04` | `THREAD` | `tid` | The following records come from this thread. |
| `0x05` | `ABORT` | `n_executed` | The current block did not run to completion (exception). |
| `0x06` | `MARK` | `mark_id` | An analyst-visible anchor point (from an export hook). |
| `0x07` | `SUMMARY` | `summary_id`, `argv[]` | An un-traced call, to be expanded by a summary (§4.5). |
| `0x08` | `REP` | `rcx`, `rsi`, `rdi`, `df` | Bulk state for a `rep` string op. |
| `0x09` | `SHIFTCNT` | `cl` | Shift count for a variable shift (flag exactness). |
| `0x0a` | `VALUE` | `slot`, `bytes` | Optional value capture (off by default). |

`insn_index` in `MEM` is redundant with the block descriptor — the host knows which instruction it is
up to. It is emitted anyway, as one varint, because it makes desynchronisation *detectable*: if the
index the host expects and the index in the record disagree, the trace is corrupt and we say so instead
of producing a plausible-looking wrong slice (success criterion 4).

Expected savings versus v0.1: on typical compiled x86-64 roughly 30–40 % of instructions touch memory,
and the surviving records lose the 8-byte absolute address (implied by block + index) in favour of a
small index and a delta-coded EA. Combined, 5–10× smaller than v0.1's fixed 24-byte-per-instruction
scheme. The full binary layout is specified in [`trace-format.md`](trace-format.md).

### 4.5 Module boundaries, ASLR, and API summaries

- **ASLR / rebasing.** All addresses are captured absolute. The agent snapshots the module map
  (`Process.enumerateModules()` → base, size, path) at start and on image-load events. Offline, absolute
  addresses are rebased to `module + RVA` so slices are stable across runs and cross-referenced to
  IDA/Ghidra.
- **Excluded modules as summaries.** We do not trace into `ntdll` / CRT / etc. Instead, calls into them
  are modeled as **summary nodes** with a def/use effect: `memcpy`/`RtlMoveMemory` defs `[dst, dst+n)`
  from uses `[src, src+n)` and `n`; `VirtualAlloc` defs a fresh region; `ReadFile` defs the buffer from
  an external input leaf; crypto API calls (`CryptDeriveKey`, `BCryptGenerateSymmetricKey`, …) get
  hand-written summaries mapping input buffers to output buffers. A summary table lets the slicer cross
  an un-traced call without losing the data-flow edge.
- **Unknown external calls** get a conservative default: `RAX` and the pointee of every pointer-looking
  argument are defined, and depend on all pointer arguments and on the integer argument registers.
  Over-approximate but safe, and the resulting nodes are tagged `imprecise` so the output can say so.
- **Syscalls.** Direct syscalls (common in the malware targets) bypass the excluded `ntdll` stubs.
  Detect `syscall` / `int 2e` in the transform; treat as a summary node keyed by the syscall number in
  `EAX`, with a table for the NT syscalls that move data (`NtReadFile`, `NtAllocateVirtualMemory`,
  `NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`).

Summary authoring is documented in [`summaries.md`](summaries.md).

### 4.6 Self-modifying code and the code-version counter

**This is the soundness fix that matters most, because the primary targets are packers.**

v0.1 keyed the descriptor table by address. Under self-modifying code, the same address holds different
instructions at different times, so decoding a pre-rewrite trace record with post-rewrite semantics
yields a wrong def/use set — with no error, no warning, and a plausible-looking slice. Every downstream
guarantee collapses.

v0.2 keys all code by `(address, code_version)`:

- The agent maintains a global `code_version`, starting at 0.
- Whenever a traced code region is observed to have been rewritten (§4.7), the agent increments
  `code_version`, emits a `VERSION` record into the trace stream, and calls `Stalker.invalidate()` on
  the affected range.
- Block descriptors in `code.bin` carry the `code_version` they were instrumented under. A block
  observed at address A under version 3 is a *different block descriptor* from one at A under version 1,
  even if the bytes happen to match.
- The host tracks the current version while replaying and resolves `block_id` accordingly. `block_id` is
  globally unique across versions, so the lookup is a plain array index; the `VERSION` record exists so
  the host can *validate* that a block's recorded version matches the stream's current version, and can
  attribute "this code was rewritten here" in the output.

The offline listing surfaces version transitions explicitly, because "the instruction at
`packer+0x1240` was `xor` in version 0 and `jmp` in version 1" is frequently the answer the analyst
wants, not an implementation detail.

### 4.7 Trust policy for self-modifying code

v0.1 specified `Stalker.trustThreshold = -1` ("never trust"). That is correct and unusably slow: never
trusting means Stalker re-instruments *every basic block on every execution*, so a 4,000-iteration decode
loop pays full re-JIT 4,000 times. Measured against the goal of ≤ 100× overhead, a global never-trust
policy is off by one to two orders of magnitude on exactly the loop-heavy code the unpacking workflow
targets.

The v0.2 default is **trust-with-invalidation**:

- `Stalker.trustThreshold = 1` (Frida's default: trust a block after one execution).
- Detect writes to executable pages and invalidate precisely:
  1. Hook `VirtualProtect` / `NtProtectVirtualMemory` and `VirtualAlloc` / `NtAllocateVirtualMemory`;
     record every region that becomes writable-and-later-executable (W→X transitions) or `RWX`.
     *Implementation note (2026-09-23):* only the protection pair is hooked. Stalker allocates its
     code slabs through the allocation pair, and a hook there deadlocks it. A fresh allocation cannot
     overlap instrumented code, so step 3 never depended on it (reference §16.3, C4).
  2. For `RWX` regions — where a write can happen with no API call to observe — mark the pages
     `PAGE_GUARD` behind the target's back and take the fault, or (cheaper, and the default) hash
     executed blocks on entry at a sampled rate and invalidate on mismatch.
  3. On any detected rewrite: bump `code_version`, emit `VERSION`, `Stalker.invalidate(range)`.
- `--paranoid` sets `trustThreshold = -1` for a *specified address range only*, for targets where the
  detection above is known to miss. Range-scoped rather than global, so the cost is paid only where
  needed.

The trade is explicit: trust-with-invalidation can miss a rewrite that the detector does not see, which
produces a stale-semantics slice — the same failure mode v0.1's `-1` avoided. Mitigations: the sampled
block hashing above, and the trace-integrity check (§10.6) which flags blocks whose recorded bytes
disagree with a re-read of the target's memory at drain time. When integrity checking fires, the tool
reports the bundle as *suspect* rather than slicing it.

---

## 5. The dependence model — data dependences

This is the heart of correctness. A data dependence links a **use** (read) to the **def** (write) that
produced the value it read, for this concrete run.

### 5.1 Shadow storage and last-writer

Offline, we replay the trace maintaining a **shadow map** from storage location → the trace index of the
instruction instance that last wrote it:

- **Shadow registers**: a flat array indexed by *register lane* — one entry per architectural register
  byte (§6.1). ~2 K entries; a dense array, not a dictionary.
- **Shadow flags**: one entry per flag bit (CF, PF, AF, ZF, SF, OF, DF), in the same flat array.
- **Shadow memory**: byte-granular, `byte_address → last_writer_seq`. Sparse: a hashed page table
  (`page → array[4096] of int64`) allocated on demand, freed on `VirtualFree`. Peak memory is
  proportional to the working set of *distinct bytes touched*, not to the address space.

Replaying forward, for each instruction instance `n`:

1. Compute `n`'s effect set from the decoder + effect model (§6), resolving memory operand addresses from
   the trace records.
2. For every location `n` **reads**: look up `last_writer`; emit a dependence edge `n → last_writer`,
   tagged `value` or `address` (§5.4). If the location has no recorded writer, it is a **live-in leaf** —
   initial memory, a value set before tracing began, or an external write — and is recorded as an input.
3. *Then*, for every location `n` **writes**: set `last_writer[loc] = n`.

Order matters: resolve all reads against the *pre-instruction* shadow, then apply all writes.
Instructions that both read and write a location (`add [mem], rax`) are handled correctly by this
ordering and need no special case.

The result is the DDG's data edges, built in a single forward pass, `O(trace length × locations per
instruction)`. No fixpoint is needed — a concrete run has an exact last writer.

### 5.2 Multi-byte reads have multiple defs

**Spec fix (v0.2).** v0.1's algorithm wrote `d = last_writer_at(n, loc)`, singular. That is wrong under
the byte-lane model that the rest of the document correctly insists on. An 8-byte read of `[rbp-0x40]`
may have up to eight distinct last writers — and *does*, in a byte-wise decode loop, which is the
motivating unpacking workflow.

The resolver must, for each read range:

1. Fetch the `last_writer` of every byte in the range.
2. Split the range into **maximal runs of identical writer**.
3. Emit one edge per run, carrying `(space, start, length)` so the output can say "bytes 0–3 of this
   qword came from seq 41 792; bytes 4–7 from seq 12".

The same applies to registers: after `mov eax, X; mov ah, Y`, a read of `RAX` yields three runs
(lane 0 from the first write, lane 1 from the second, lanes 2–7 from the first).

Consequences downstream: the slicer's worklist frontier is keyed by `(seq, space, start, length)`, and
the `visited` set — declared but never used in v0.1's pseudocode — deduplicates on that key. The output
set is still deduplicated per instruction instance.

### 5.3 Memory aliasing is free here

The classic pain of static slicing — "does `[rax]` alias `[rbx]`?" — evaporates. At run time both resolve
to concrete effective addresses. Two accesses alias iff their byte ranges overlap. Byte-granular shadow
memory makes partial overlaps (a 4-byte write later half-read by a 2-byte read) exact, and §5.2's run
splitting reports them faithfully.

### 5.4 Address dependences versus value dependences

**New in v0.2, and the single largest lever on slice readability.**

Consider `mov rax, [rbx+8]`. It reads two quite different things:

- the eight memory bytes at `RBX+8` — the *value* it is fetching;
- the register `RBX` — which only ever influenced *where* it fetched from.

v0.1 made no distinction, so both became plain data edges. The consequence is that `RSP` becomes a
universal attractor: every read of a stack slot pulls in `RSP`, which pulls in the `sub rsp, N` in the
prologue, which pulls in the `call` that pushed the return address, which pulls in the caller's stack
arithmetic, and so on. Slices bloat with pointer plumbing that is almost never the answer to
"what arithmetic made this key".

Every data edge is therefore tagged at build time — for free, since the effect model already knows which
registers fed the addressing expression:

- **`value`** — the instruction consumes the content of this location.
- **`address`** — this location contributed to an effective-address computation.

Note two deliberate consequences:

- `lea rax, [rbx+rcx*4+8]` produces **value** edges on `RBX` and `RCX`, not address edges: `lea` does not
  access memory, so the address *is* the value (§6.4).
- A memory read's edges to the *memory bytes* are always `value`; only the base/index register edges are
  `address`.

Slice modes then become a 2×2 (§7.3). In practice, "value edges only, no control" is the mode that
produces a readable KDF reconstruction, and address edges are switched on when the question is
specifically "who controlled this pointer" — which, for an indirect call target, is the whole question.

### 5.5 Indirect calls and jumps

Resolved concretely: the trace shows exactly where control went. The indirect branch instance has a
data dependence on whatever computed its target register or memory operand — so "who controlled this
indirect call target" falls out of the same backward walk. Because the target register feeds a control
transfer rather than an address computation, its edges are tagged `value`, so this question is
answerable in the default (value-only) mode.

---

## 6. x86-64 register semantics

Getting the architecture's register model wrong silently corrupts every slice. This section is the spec
for the effect model; the implementation-level tables live in
[`semantics-x86-64.md`](semantics-x86-64.md).

### 6.1 Sub-register aliasing → model registers as byte lanes

`RAX / EAX / AX / AL / AH` are views on one 64-bit register. A slicer that treats them as distinct names
is wrong; one that treats a write to `EAX` as a write to all of `RAX` is also wrong — but in a *specific*
way:

- Writing a 32-bit register (`EAX`) **zero-extends** into the full 64-bit register: `RAX[63:32]` becomes
  0. So `mov eax, …` writes all 8 bytes of RAX (the top 4 as a defined zero, dependent on *this*
  instruction).
- Writing a 16-bit (`AX`) or 8-bit (`AL` / `AH`) register **preserves** the upper bytes: `mov al, 1`
  writes only `RAX[7:0]`; `RAX[63:8]` keep their previous last-writers.

Therefore each GPR is modeled as **8 byte lanes**. `mov al, bl` → writes lane `RAX[0]`, reads lane
`RBX[0]`. `mov eax, ebx` → writes lanes `RAX[0..7]` (0–3 the value, 4–7 a defined zero), reads
`RBX[0..3]`. This makes `AH` (`RAX[1]`) correctly independent of `AL` (`RAX[0]`).

The same applies to vector registers, with the legacy-vs-VEX zeroing rule: a legacy SSE write to `xmm0`
preserves `ymm0[255:128]`, while a VEX/EVEX-encoded write zero-extends it. Vector registers are modeled
as byte lanes too, and the zeroing rule is applied per encoding.

The concrete lane allocation used by the implementation:

| Space | Lanes | Contents |
|-------|-------|----------|
| GPR | 0 … 127 | 16 registers × 8 bytes, `RAX`=0, `RCX`=8, `RDX`=16, … |
| FLAG | 128 … 143 | CF, PF, AF, ZF, SF, OF, DF (one lane each; remainder reserved) |
| VEC | 144 … 2191 | 32 registers × 64 bytes (ZMM-width) |
| SEG | 2192 … 2239 | FS/GS base and friends — `gs:[0x30]` TEB access matters on Windows |

`RIP` is deliberately **not** modeled. It is a compile-time constant per instruction instance, so
RIP-relative addressing contributes a constant, not a dependence.

### 6.2 A byte-lane worked example

```asm
mov  eax, 0x10        ; def RAX[0..7]  (0..3 = value, 4..7 = zero)   — no register uses
mov  ah,  0x20        ; def RAX[1]     — no uses (imm); RAX[0], RAX[2..7] unchanged
add  al,  ah          ; use RAX[0], RAX[1]; def RAX[0]; def CF PF AF ZF SF OF
```

A slice on `AL` (`RAX[0]`) after the `add` pulls in: the `add` (writer of `RAX[0]`) → its uses `RAX[0]`
(written by `mov eax`) and `RAX[1]` (written by `mov ah`). `mov ah` is correctly included; the top bytes
of `mov eax` are correctly *excluded*. Get the lane model wrong and you either drop `mov ah` or
spuriously drag in unrelated bytes.

### 6.3 Implicit operands

Many x86 instructions touch registers or flags not named in the operands. These must be in the read/write
sets or dependences vanish:

- `push` / `pop` / `call` / `ret` / `enter` / `leave`: read and write `RSP` (and `RBP` for
  `enter`/`leave`); `call` writes `[RSP-8]`, `ret` reads `[RSP]`.
- One-operand `mul` / `imul`, and `div` / `idiv`: implicit `RAX` / `RDX`.
- String ops `movs` / `stos` / `lods` / `cmps` / `scas`: implicit `RSI` / `RDI` / `RCX` (with `rep`), and
  `DF` controls direction.
- `cdq` / `cqo`: `RAX` → `RDX`.
- Arithmetic and logic: implicit flag writes. `adc` / `sbb` / `rcl` / `rcr`: implicit `CF` read.
- `setcc` / `cmovcc` / `jcc`: implicit flag reads, per condition (§6.5).

Capstone's detail mode reports implicit accesses via `regs_access()`; we take that as the base and apply
an override table for the cases below.

### 6.4 Idiom exceptions (avoiding false uses)

Certain instructions are *idioms* that appear to read a register but semantically do not. Treating them
as reads injects false dependences that pollute every slice:

- `xor r, r` / `sub r, r` / `pxor x, x` / `vpxor x, x, x` / `pcmpeqd x, x` set the register to a constant
  regardless of prior value. Model as **def only, no register use** (they still def flags, where
  applicable).
- `and r, 0` / `imul r, r, 0` → constant 0; `or r, -1` → constant. Handled by the same override table;
  the zeroing `xor` / `sub` case is mandatory because it is ubiquitous in compiler output.
- `lea` performs address arithmetic but does **not** access memory and does **not** touch flags. Its
  base/index registers are `value` uses (§5.4). Treating `lea` as a memory access is the most common
  modeling bug in this class of tool.
- `nop`, multi-byte `nop`, and prefix-only forms have no effect.
- `xchg r, r` with identical operands is a `nop`; `xchg` generally is a two-way def/use pair.

A caution the override table must respect: `sbb r, r` looks like the `sub r, r` idiom and is **not** one
— it genuinely reads `CF`, and is the standard "broadcast the carry" pattern. Idiom matching is by exact
mnemonic, not by operand-identity alone.

### 6.5 Flags at bit granularity

Treating `RFLAGS` as one location over-couples: `cmp` sets CF/OF/SF/ZF/AF/PF, but a following `jz` only
reads ZF and `jc` only CF. Modeled monolithically, a `jz` would depend on any prior flag writer even when
its ZF came from elsewhere. Each flag bit is therefore its own shadow location, and each instruction
carries a per-bit read mask and write mask, derived from Capstone's `eflags` field and refined by the
override table.

Per-condition read masks matter as much as per-instruction ones: `jz` reads ZF; `jl` reads SF and OF;
`ja` reads CF and ZF; `jp` reads PF. Getting these right is what keeps control-dependence chains (§7.2)
from fanning out into every arithmetic instruction that happened to set a flag.

### 6.6 `rep`-prefixed string operations

Under Stalker, a `rep movsb` executes as a *single* instrumented instruction that performs `RCX` memory
accesses. A per-operand EA record cannot express that.

The probe emits a `REP` record with `RCX`, `RSI`, `RDI` and `DF` captured at entry. The host expands this
into a bulk effect:

- `rep movs` with count `n`, element size `s`, forward (`DF=0`): uses `[RSI, RSI + n·s)`, defs
  `[RDI, RDI + n·s)`, uses and defs `RSI`, `RDI`, `RCX`. Backward (`DF=1`) mirrors the ranges.
- `rep stos`: defs `[RDI, RDI + n·s)`, uses `RAX` lanes 0 … s−1.
- `repe cmps` / `repne scas`: the count actually consumed is *not* `RCX` at entry — the loop exits early
  on the comparison. The post-execution `RCX` is required to know how far it got, so these emit a second
  `REP` record after the instruction; the delta gives the true iteration count.

A bulk def is recorded as a single instruction instance defining a range, which is exactly right: every
byte in the destination has the same last writer, and the slice shows one node, not `n`.

Fidelity note: within a single `rep movs`, byte `k` of the destination depends only on byte `k` of the
source. The bulk model conflates them, so slicing one destination byte pulls in the whole source range.
This is an over-approximation, it is flagged in the output as `bulk`, and `--expand-rep` re-expands a
chosen `rep` instance into `n` synthetic per-iteration nodes for the cases where the analyst needs
byte-exact provenance through a `memcpy`.

### 6.7 Value-dependent flag effects

**New in v0.2.** A small number of instructions have effects that depend on a runtime value, which a
purely structural model gets wrong:

- `shl/shr/sar/rol/ror r, cl` **do not modify any flag** when `CL & 0x3F == 0`. Capstone reports an
  unconditional flag write. Modeled naively, a subsequent `jz` is attributed to the shift instead of to
  the real ZF producer — a wrong control-dependence chain, silently.
- Shifts by a count greater than 1 leave `OF` undefined; `AF` is undefined after `and`/`or`/`test` and
  after shifts.

Handling:

- Variable shifts emit a `SHIFTCNT` record capturing `CL`. The host resolves the flag defs exactly:
  count 0 → no flag def at all; count ≥ 1 → def per the ISA.
- Flags an instruction leaves **undefined** are recorded as `may-def`. A `may-def` sets the last writer
  (a later read genuinely gets garbage from here) but the resulting edge is tagged `imprecise` and the
  output annotates it, so an analyst chasing a bizarre-looking chain is told the ISA does not define it.

### 6.8 Where Capstone stops

Capstone provides decode, operand structure, `regs_access()` and `eflags` masks. The override table takes
responsibility for: the idioms of §6.4, the per-condition flag read masks of §6.5, the `rep` expansions
of §6.6, the value-dependent flags of §6.7, the 32-bit zero-extension and VEX zeroing rules of §6.1, and
`lea`. Anything not in the override table falls through to Capstone verbatim. Every override is a unit
test (§11.1).

---

## 7. Control dependence

Data dependence alone gives an *executed* slice that reproduces the value; analysts usually also want
"…and the branch that decided we would be here." That is **control dependence**.

### 7.1 The computation, and where the simple version breaks

An executed instance `n` is control-dependent on the most recent executed conditional transfer `b` whose
outcome determined whether `n`'s block was entered. The standard formulation is: `n` is
control-dependent on `b` if `b` has a successor from which `n` is always reached and another from which
it is not — i.e. `n` post-dominates one successor of `b` and does not post-dominate `b` itself.

v0.1 proposed a branch stack: on a conditional branch push `(branch_seq, ipdom_addr)`; every subsequent
instruction is control-dependent on the top of stack until execution reaches that post-dominator, then
pop. That is the right shape and it is what we implement — but v0.1 understated the failure modes, and
they are exactly the ones the target class exhibits:

1. **Call boundaries.** A branch inside a callee must not guard code after the caller returns. The stack
   entry must record call depth, and `ret` must pop every entry deeper than the frame being left.
   Without this, control dependence leaks across function boundaries and the slice grows without bound.
2. **Exceptions and SEH/VEH unwinding** discard arbitrary amounts of stack. The `ABORT` record (§4.4)
   marks a block that did not complete; on it, the branch stack is truncated to the frame the handler
   resumes in, and the region is tagged.
3. **`ret`-based dispatch and non-returning calls** violate the call/return pairing the depth model
   assumes. Detected by a `ret` whose target does not match the recorded return address; the stack is
   resynchronised by depth and the region is tagged `cd-unreliable`.
4. **Control-flow flattening.** This is the important one, because it is the standard obfuscation on the
   targets of interest. In a flattened function, every block returns to a central dispatcher, so the
   dispatcher is the immediate post-dominator of essentially every conditional branch. The relation is
   then technically correct and *completely uninformative*: every block is control-dependent on the same
   `switch`, and the branch stack never grows. Emitting those edges adds noise, not information.

### 7.2 Two-pass construction

Because replay is offline, the CFG needed for post-dominance is available from the trace itself. Control
dependence is therefore a two-pass computation:

**Pass 1 — structure.** Walk the trace recording, per `code_version`, the set of blocks and the observed
edges between them. Partition into functions by call/return boundaries. For each function, compute
post-dominators by the standard iterative dataflow over the reverse CFG, then the immediate
post-dominator of each block. Blocks with no observed path to the function exit (an infinite loop, a
`noreturn` call) get a synthetic exit edge so post-dominance is well-defined.

**Pass 2 — attribution.** Replay with the branch stack described above, using the pass-1 ipdom map,
maintaining `(branch_seq, ipdom_addr, call_depth)` entries and popping on ipdom arrival, on `ret` past
the recorded depth, and on `ABORT`.

**Flattening detection** runs between the passes: for each function, if a single block is the ipdom of
more than a threshold fraction of the function's conditional branches *and* has in-degree above a
threshold, the function is marked flattened. In a flattened function Atropos does not emit control edges;
it emits a region annotation instead — "control dependence unavailable: dispatcher at `f+0x40`" — and the
output says so rather than presenting a degenerate relation as an answer. `--force-cd` overrides.

The rationale is the fourth success criterion: an honest "cannot answer" beats a confident wrong answer.
The full algorithm, including the post-dominator dataflow and the flattening heuristic's thresholds and
their calibration, is in [`control-dependence.md`](control-dependence.md).

### 7.3 Slice modes

Control edges can dominate a slice: every instruction depends on the loop condition, which depends on
the counter, which depends on every increment. With the address/value split of §5.4, the mode space is a
2×2 plus caps:

| Mode | Edges followed | Question it answers |
|------|----------------|---------------------|
| `value` (default) | value | "What arithmetic made this value?" |
| `value+addr` | value, address | "…and what computed the pointers it came through?" |
| `value+ctrl` | value, control | "…and what decided we would compute it?" |
| `full` | value, address, control | Everything; the most complete and the largest. |

Plus `--max-control-depth N` (follow at most N nested control edges from any node) and
`--max-nodes N` (stop and report truncation), because a readable partial answer beats an unreadable
complete one. Truncation is always reported, never silent.

---

## 8. The slicing algorithm

Given the DDG built by the forward replay and a criterion `C = (seq, locations)`:

```text
frontier ← { (seq, space, start, len) for each location in C }
slice    ← ∅          # instruction instances, keyed by seq
visited  ← ∅          # (seq, space, start, len) — the frontier dedup key
inputs   ← ∅          # live-in leaves

while frontier not empty:
    key ← frontier.pop()
    if key in visited: continue
    visited.add(key)

    for (d, kind, sub_range) in defs_reaching(key):     # ONE EDGE PER WRITER RUN (§5.2)
        if kind not in mode.allowed_kinds: continue
        if d is LIVE_IN:
            inputs.add((key, sub_range)); continue
        slice.add(d)
        for (space, start, len, kind) in uses_of(d):
            if kind in mode.allowed_kinds:
                frontier.push((d, space, start, len))
        if mode.follows_control:
            for b in guarding_branches(d):
                slice.add(b)
                for use of b: frontier.push((b, …))
```

Notes:

- `defs_reaching(key)` is **not** recomputed here. The forward replay already emitted, for each
  `(instance, read-range)` pair, the set of producing defs split by writer run. The backward pass is pure
  graph reachability over precomputed edges: near-linear in the size of the *slice*, not the trace.
- The frontier is keyed per byte range so multi-byte values are followed run-by-run and merged; the
  output set is deduplicated per instruction instance.
- Termination is guaranteed: every edge points to a strictly earlier trace index (a def precedes its
  use), so the walk is a DAG traversal over a finite trace. `visited` bounds it to
  `O(|edges touched|)`.

### 8.1 Choosing the criterion

Several front-ends, all reducing to `(seq, locations)`:

- **By API argument** — "the buffer and length passed to the N-th `CryptEncrypt`." The agent hooks the
  export, emits a `MARK`, and records the concrete pointer and length; the criterion is those memory
  bytes at that mark's seq.
- **By address + expression** — "at `module+0x1A2F`, occurrence 3, register `RDX` and `[RBP-0x40]`,
  16 bytes."
- **By tainted region** — "any byte in the newly-executed OEP page": criterion is that byte range at the
  seq just before its first execution. Pairs with the W→X detection of §4.7 to become fully automatic.
- **By value watch** — "the first time memory holds these 16 bytes." Requires value-capture mode; the
  host scans for the seq at which the shadow region first matches.

---

## 9. Output and presentation

The slice is only useful if the analyst can read it.

1. **Annotated linear listing** — slice instructions in trace order, each showing `module+RVA`,
   disassembly, occurrence index, code version, and *why included*: which def of which byte range for
   which use, and the edge kind. Primary artifact.
2. **DDG export (DOT / JSON)** — nodes = instruction instances, edges labeled with kind and byte range.
   Collapsible by static instruction so loops do not explode visually: group the N occurrences of one
   address into one node, keep the edge multiset.
3. **Disassembler bridge** — JSON of `{module, rva, code_version, occurrences_in_slice, edge_kinds}`
   consumed by an IDA or Ghidra script to colour and comment the slice in the analyst's existing
   database. This is where RE workflows actually live; it is first-class, not an afterthought.
4. **Input / leaf report** — the live-in set: which memory bytes and registers the slice bottomed out on,
   classified as *immediate constant*, *initial memory*, *summary output* (with the API that produced
   it), or *unattributed external write*. For the crypto workflow this **is** the answer:
   "key = f(hardcoded 0x…, volume serial from `GetVolumeInformation`)".
5. **Loop summarisation** — fold a slice that walks a decode loop 4,000 times into "loop body ×4000 over
   `[src, src+N)` → `[dst, dst+N)`", expandable on demand.
6. **Integrity and precision banner** — every report states, up front: trace integrity status, whether
   any region was `cd-unreliable` or flattened, how many edges are `imprecise` or `bulk`, and whether the
   slice was truncated. The analyst is never left to infer the confidence of what they are reading.

---

## 10. Performance and scale

### 10.1 Capture

The dominant costs and their mitigations:

- **Per-instruction probe.** Inline emission rather than `putCallout` (§4.3) is the primary lever —
  roughly an 18-register spill reduced to two.
- **Re-instrumentation.** Trust-with-invalidation rather than global never-trust (§4.7) is the second,
  and on loop-heavy code it is worth one to two orders of magnitude.
- **Scope.** `Stalker.exclude` on `ntdll`, `kernel32`, `kernelbase`, the CRT and UI modules; follow only
  the thread(s) of interest; `follow`/`unfollow` around a hooked trigger so only the decrypt call is
  traced, not process startup.

### 10.2 Trace volume

Block-granular records (§4.4) plus varint and delta encoding. A 5 M-instruction trace with ~35 % memory
density is on the order of 15–30 MB, versus ~120 MB under v0.1's scheme. The ring buffer drains to a
memory-mapped file on a dedicated thread so RPC never touches the hot path.

### 10.3 Shadow memory

Sparse hashed page table; pages freed on `VirtualFree`. Peak memory ≈ the working set of distinct bytes
touched.

### 10.4 The backward walk

Cheap relative to everything else — proportional to the slice, not the trace. It has never been the
bottleneck in practice and is not expected to be.

### 10.5 Replay cost, honestly

v0.1 claimed "a few million instructions sliceable offline in seconds". In pure Python that is not
achievable: byte-lane shadow updates plus edge emission run at roughly 100–300 K instructions/second, so
a 5 M-instruction trace is 20–60 s for the forward pass, and 10 M+ edges as Python objects is several
gigabytes of RSS.

The v0.2 position:

- **Edges are stored as parallel typed arrays** (`use_seq`, `def_seq`, `space`, `start`, `length`,
  `kind`), never as objects. 10 M edges ≈ 300 MB rather than several GB, and the backward walk becomes
  index arithmetic.
- **Shadow memory pages are typed arrays**, not dictionaries.
- The Python implementation is the **reference** — it defines correctness and is the oracle the Rust port
  is validated against. Its target is *tens of seconds* on a 5 M trace, which is fine for interactive RE.
- The **Rust replay core** is a planned milestone, not a hypothetical: the trace format and effect tables
  are specified language-neutrally from day one so the port is mechanical. Target ≤ 5 s on the same
  trace.

Success criterion 2 is restated accordingly.

### 10.6 Trace integrity

Because a corrupt trace yields a plausible wrong slice, integrity is checked rather than assumed:

- **Block continuity.** Every block entry must have a predecessor whose terminator can transfer to it.
  A gap means a block was entered without being traced — the signature of an exception escaping through
  an excluded module, or of Stalker losing the thread.
- **Index agreement.** Each `MEM` record's `insn_index` must match the instruction the host is up to.
- **Byte re-validation.** At drain time the agent re-reads the bytes of a sample of instrumented blocks;
  a mismatch against the recorded descriptor means an undetected rewrite (§4.7).
- **Depth sanity.** Call depth must not go negative; `ret` targets should match recorded return
  addresses.

Any failure marks the bundle *suspect*, names the affected trace range, and the slicer refuses to
present results from that range without `--allow-suspect`.

---

## 11. Validation

### 11.1 Unit level

Every rule in §6 is a test: each idiom, each implicit-operand family, each per-condition flag mask, the
32-bit zero-extension rule, VEX zeroing, `lea`, `rep` expansion, zero-count shifts. Fixtures are
hand-encoded instruction bytes plus a synthetic trace, so the suite runs on any platform with no Frida
and no target process.

### 11.2 Differential oracle

**New in v0.2, and the highest-value item in this section.** A second, independent slicer is built on top
of an emulator (Unicorn or Miasm), where every register and memory access is observable directly and the
last-writer relation can be implemented in a few hundred lines with no instrumentation in the loop.

Then:

- Run the reference corpus through both. Assert the slices are identical, instruction for instruction.
- **Differential fuzzing**: generate random instruction sequences drawn from the idiom and
  implicit-operand tables, slice both ways, assert equality. Every bug class in §6 is exactly the kind
  this catches and that eyeballing hand-written assembly does not.

The oracle is deliberately slow and simple. Its job is to be obviously correct, not fast.

### 11.3 Cross-implementation equivalence

The `putCallout` probe and the inline-emitter probe (§4.3) must produce byte-identical trace streams on
the corpus. Likewise the Python replay and the Rust replay core must produce identical DDGs. Both are CI
assertions, not aspirations.

### 11.4 End to end

A binary we control with a known key-derivation chain (§1.4, criterion 1), plus a UPX-packed and a
custom-packed sample for the unpacking workflow, with ground truth established by manual analysis and
recorded as a regression fixture.

---

## 12. Limitations and future work

**Inherent limitations, stated plainly:**

- **One run only.** The slice explains the observed execution. Different input may derive the key
  differently. Future: **union slicing** across runs to approximate coverage.
- **External writes.** DMA, another thread, or an un-traced module writing our memory appears as a
  live-in leaf ("someone wrote this, not in our trace"). Multi-thread tracing narrows this, but true
  concurrent ordering on x86-64 needs care: without instrumenting synchronisation there is no total
  order, and a global lock-step counter perturbs timing enough to change behaviour on some targets.
- **Kernel and GPU effects** are opaque — summarised, not traced.
- **Exceptions as control flow.** SEH/VEH-driven obfuscation is Stalker's weakest area: exception
  dispatch leaves the instrumented arena through excluded `ntdll` and re-enters traced code at an address
  Stalker did not route to. Atropos detects the resulting discontinuity (§10.6) rather than mis-slicing,
  but detection is not the same as support. Targets that use exceptions as their primary dispatch
  mechanism are currently out of reach.
- **Timing and anti-analysis.** Stalker slows the target substantially; targets with `rdtsc` or
  `QueryPerformanceCounter` checks may alter behaviour. Mitigation: hook and normalise timing sources;
  accept that some targets need it and some will not cooperate.
- **`rep` bulk conflation** (§6.6) over-approximates unless `--expand-rep` is used.
- **Flattened control flow** yields no control edges by design (§7.1). Data slicing is unaffected.

**Future milestones:**

- **Symbolic augmentation** — turn value-capture mode into per-instruction symbolic expressions so the
  slice yields a *formula* for the criterion (reconstruct the KDF as an expression), bridging toward a
  small symbolic executor seeded by the concrete trace.
- **Forward slicing** — "what did this input affect" (impact analysis): same graph, walk edges forward.
- **Chopping** — the slice between a chosen source and sink (intersection of a forward slice from the
  source and a backward slice from the sink): "how does this input reach that buffer."
- **Automatic criterion discovery** — pair with the W→X / OEP heuristics to auto-slice unpackers with no
  analyst input.
- **Union slicing** across multiple runs.
- **Rust replay core** (§10.5).

---

## 13. Milestone plan

Build order that keeps something testable at every step.

| # | Milestone | Contents | Validation gate |
|---|-----------|----------|-----------------|
| **M0** | Trace capture | Stalker follow, `putCallout` probe, ring buffer → mmap bundle; block descriptors; module map; code-version counter | Re-disassemble the trace; confirm it matches a debugger single-step on a toy program. Integrity checks pass. |
| **M1** | Data slicer, registers | Byte lanes, implicit operands, idioms, per-bit flags, value/address edge split, multi-writer run splitting | Unit tests per §6 rule; oracle agreement (§11.2) on register-only corpus |
| **M2** | Memory dependences | Sparse shadow memory, concrete EA aliasing, `rep` expansion | memcpy / decode-loop corpus; oracle agreement |
| **M3** | Control dependence | Two-pass CFG + post-dominators, depth-aware branch stack, flattening detection, slice modes | Branchy corpus incl. a flattened function; correct "unavailable" report |
| **M4** | Summaries and excludes | Summary table, direct-syscall handling, unknown-call default, `imprecise` tagging | Target that reads a file and transforms it |
| **M5** | Output | Annotated listing, DOT/JSON, IDA + Ghidra scripts, input report, loop summarisation, precision banner | Analyst-readability review on M2/M3 outputs |
| **M6** | Real target | End-to-end crypto key derivation against a binary we control, with ground truth | Success criterion 1 |
| **M7** | Performance | Inline EA emitter; typed-array edge store; equivalence tests (§11.3) | Success criterion 2, Python tier |
| **Stretch** | — | Rust replay core, union slicing, symbolic augmentation, forward slicing, chopping | — |

M0–M2 are the critical path to anything useful; M3 is where the target class starts fighting back.

---

## Appendix A — Open design questions

- **Online vs offline DDG.** Offline (§3). Reconsider incremental online slicing only if trace size
  dominates, which block-granular encoding makes less likely.
- **Value capture default.** Off. Structural last-writer suffices for slicing. Required for symbolic work
  and value-watch criteria — measure the trace-size multiplier before committing to a default.
- **Multi-thread ordering.** v1 traces one thread, or multiple threads with per-thread buffers and a
  global atomic sequence counter, accepting both the contention and the ordering caveat of §12. True
  concurrent slicing is deferred.
- **How far the override table goes.** Capstone for decode and the base access sets; the override table
  for §6.4–§6.7. The boundary is drawn per instruction *class*; the differential oracle (§11.2) is what
  tells us where Capstone's answer is insufficient, rather than guessing up front.
- **Flattening thresholds** (§7.2) need calibration against real obfuscated samples; the initial values
  are a guess and are configurable.
- **`--expand-rep` default.** Currently off. If byte-exact `memcpy` provenance turns out to be the common
  case in practice rather than the exception, it should flip.

## Appendix B — Summary of soundness-critical invariants

A checklist for reviewers and for anyone porting the replay core.

1. Instruction semantics are keyed by `(address, code_version)`. Never by address alone.
2. A read range resolves to *a set* of defs, split by maximal runs of identical last writer.
3. All reads of an instruction are resolved against the pre-instruction shadow before any write is
   applied.
4. A 32-bit register write defines all 8 lanes; a 16- or 8-bit write defines only its own lanes.
5. A VEX/EVEX vector write defines the full register width; a legacy SSE write does not.
6. Zeroing idioms define without using.
7. `lea` accesses no memory, touches no flags, and its base/index are `value` uses.
8. Flag bits are independent locations, and each condition code reads only its own bits.
9. A variable shift with count 0 defines no flags.
10. Control-dependence stack entries carry call depth and are popped on return past that depth.
11. Every edge points strictly backward in trace order.
12. Any integrity violation marks the bundle suspect rather than being silently sliced.

## Appendix C — Changelog v0.1 → v0.2

**Soundness fixes**

- §4.6 — Code is keyed by `(address, code_version)`. v0.1's address-keyed descriptor table silently
  mis-decodes self-modifying code, which is the primary target class.
- §5.2 — A multi-byte read resolves to a *set* of defs split by writer run. v0.1's `last_writer_at()`
  returned a single def, which contradicts its own byte-lane model.
- §6.7 — Value-dependent flag effects (zero-count shifts, undefined flags) are modeled explicitly instead
  of trusted from Capstone.

**Design changes**

- §5.4 — Address dependences are distinguished from value dependences; slice modes become 2×2 (§7.3).
  Without this, `RSP` chains dominate every slice.
- §3 — All semantic modeling moved host-side; the agent ships instruction bytes, not effect sets.
- §4.4 — Trace records are block-granular; only memory-touching instructions get their own record.
  5–10× volume reduction.
- §4.7 — Trust-with-invalidation replaces global `trustThreshold = -1`, which was correct but one to two
  orders of magnitude too slow on loops. `--paranoid` is range-scoped.
- §4.3 — Inline EA emission specified as the post-M0 optimisation, with `putCallout` as the M0 fallback
  and an equivalence test between them.
- §6.6 — `rep`-prefixed string operations get an explicit bulk model and an `--expand-rep` escape hatch.

**Robustness**

- §7.1–§7.2 — Control dependence is a documented two-pass computation with call-depth-aware stack
  handling, exception truncation, `ret`-dispatch resynchronisation, and control-flow-flattening
  detection that reports "unavailable" instead of a degenerate relation.
- §10.6 — Trace-integrity checking; suspect bundles are refused rather than sliced.
- §9.6 — Every report carries a precision banner.

**Expectations**

- §1.4 / §10.5 — Performance claims restated: tens of seconds in Python for a 5 M trace, seconds in the
  Rust core; typed-array edge storage specified.
- §11.2 — Differential emulator oracle and differential fuzzing added as the primary correctness
  mechanism.
- §11.3 — Cross-implementation equivalence (probe vs probe, Python vs Rust) added as a CI gate.
- §13 — Milestone table gains explicit validation gates and a performance milestone.

# Atropos — Analytical Usage Guide

**How to use the tool to answer real questions, step by step**

[`reference.md`](reference.md) tells you what every option does. This guide tells you *which* option
to reach for, *why*, and *what to do with what comes back*. It is organised around the questions an
analyst actually asks, and every example uses output the tool really produced (on the built-in
fixtures, so you can reproduce each one with a single command and no target).

---

## Contents

1. [The mental model, in five minutes](#1-the-mental-model-in-five-minutes)
2. [Before you start](#2-before-you-start)
3. [Walkthrough: your first slice, line by line](#3-walkthrough-your-first-slice-line-by-line)
4. [Recording a trace of a real target](#4-recording-a-trace-of-a-real-target)
5. [Finding the criterion — the hard part](#5-finding-the-criterion--the-hard-part)
6. [Choosing a mode](#6-choosing-a-mode)
7. [Workflow A: what is this crypto key derived from?](#7-workflow-a-what-is-this-crypto-key-derived-from)
8. [Workflow B: which loop decoded this byte, and from what?](#8-workflow-b-which-loop-decoded-this-byte-and-from-what)
9. [Workflow C: who controlled this pointer?](#9-workflow-c-who-controlled-this-pointer)
10. [Workflow D: why did this branch go that way?](#10-workflow-d-why-did-this-branch-go-that-way)
11. [Workflow E: where did this input end up?](#11-workflow-e-where-did-this-input-end-up)
12. [Reading the input report](#12-reading-the-input-report)
13. [Reading the precision banner](#13-reading-the-precision-banner)
14. [Taming large slices](#14-taming-large-slices)
15. [Getting the slice into your disassembler](#15-getting-the-slice-into-your-disassembler)
16. [Scripting with the Python API](#16-scripting-with-the-python-api)
17. [When the answer looks wrong](#17-when-the-answer-looks-wrong)
18. [Pitfalls](#18-pitfalls)

---

## 1. The mental model, in five minutes

Atropos answers exactly one shape of question:

> *This value, at this point in the run — which executed instructions made it, and what did they
> start from?*

To ask it you supply three things, and the whole art of using the tool is choosing them well:

| You supply | In words | On the command line |
|---|---|---|
| **a point** | "at this moment in the execution" | `--at mark=1`, `--at addr=target.exe+0x1a2f@3`, `--at seq=41792` |
| **locations** | "the value living here" | `--loc rdx`, `--loc mem=0x7ff6c0001000+16`, `--loc zf` |
| **a mode** | "and I care about these kinds of influence" | `--mode value`, `value+addr`, `value+ctrl`, `full` |

What comes back is three things, in this order of importance:

1. **The precision banner** — how much to trust the rest.
2. **The input report** — the leaves: constants, untraced memory, API sources. Usually *the answer*.
3. **The listing** — the instruction instances in between, each with a one-line reason for being there.

Three facts to hold onto:

- The tool explains **one run**. If the sample would take a different path on a different input, a
  different trace is needed.
- Everything is **byte-granular**. A slice of `al` and a slice of `rax` are different questions;
  `mem=X+1` and `mem=X+16` are different questions. Ask about the smallest thing you actually care
  about — the slice will be smaller and sharper.
- **Nothing runs during slicing.** Capture is the slow, one-shot, in-target part; replay is a few
  seconds to a minute; each slice after that is instant. Record once, ask many times.

---

## 2. Before you start

```bash
pip install -e .[dev]            # analysis + tests; capstone is the only hard dependency
pytest                           # 153 tests, ~1.5 s, no target needed
atropos demo                     # if this prints a slice, the offline pipeline works
```

On Windows consoles set `PYTHONIOENCODING=utf-8` first, or the `—` in the banner renders as `�`.

For **recording** you also need Frida and Python 3.11+ (`pip install -e .[capture]`); see §4.

Persist the demo fixtures somewhere so you can experiment on them while reading this guide:

```bash
atropos demo --workflow xor-decoder    --out fx/xor.atrace   > /dev/null
atropos demo --workflow key-derivation --out fx/kdf.atrace   > /dev/null
atropos demo --workflow self-modifying --out fx/smc.atrace   > /dev/null
```

Every command below that names `fx/…` runs against these.

---

## 3. Walkthrough: your first slice, line by line

Run:

```bash
atropos slice fx/xor.atrace --at mark=1 --loc mem=0x30002+1
```

You get:

```
==============================================================================
ATROPOS backward slice  —  criterion #32 {[0x30002..+1]}  (mark=1)
mode: value   |   4 of 33 instruction instances (87.9% discarded)
------------------------------------------------------------------------------
  trace integrity: OK
  control dependence: 1 function(s) analysed, no flattening detected
==============================================================================

  #3        target.exe+0x1e             mov dl, 0x5a
              <- defines dl used by #19 (value)
  #18       target.exe+0x20             mov al, byte ptr [rsi]              [occ=2]
              <- defines al used by #19 (value)
  #19       target.exe+0x22             xor al, dl                          [occ=2]
              <- defines al used by #20 (value)
  #20       target.exe+0x24             mov byte ptr [rdi], al              [occ=2]
              <- slicing criterion

INPUTS — where this value ultimately came from
------------------------------------------------------------------------------
  immediate constants in the code  (1)
      #3  target.exe+0x1e   mov dl, 0x5a
  memory not written during the trace (initial state or untraced writer)  (1)
      [0x20002..+1] read by #18 (value)
```

Read it top to bottom:

**Header.** `criterion #32 {[0x30002..+1]}` — `mark=1` resolved to instruction instance #32, and you
asked about one byte at `0x30002` *as of that point*. `4 of 33 … 87.9% discarded` — the trace had 33
instruction instances; four mattered.

**Banner.** Integrity OK, no flattening: trust the rest.

**Listing.** Execution order, oldest first. Each row is `#seq  module+RVA  disassembly  [tags]` and
beneath it *why it is here*:

- `#3 mov dl, 0x5a` — "defines `dl` used by #19": the key byte. No `[occ]` tag: this is its first
  (only) execution.
- `#18 mov al, [rsi]` `[occ=2]` — the **third** execution of that address (occurrence is 0-based).
  It loaded the byte that #19 consumed.
- `#19 xor al, dl` — consumed both; produced `al` for #20.
- `#20 mov [rdi], al` — "slicing criterion": this is the instruction whose write reached your byte.

Notice what is **absent**: the other three iterations of the loop (occurrences 0, 1, 3), `inc rsi`,
`inc rdi`, `dec rcx`, `jnz`, and the pointer set-up. None of them influenced the *value* of byte
`0x30002`. That is the whole point of a slice in `value` mode.

**Input report.** The chain bottoms out on two things: a constant baked into the code (`0x5a`) and one
byte of memory, `0x20002`, that nothing in the trace wrote. In a real unpacking case that byte is the
packed payload — the input report has just told you *exactly which source byte* produced *exactly
which output byte*.

Now change one thing at a time and watch what happens (§6 explains the results):

```bash
atropos slice fx/xor.atrace --at mark=1 --loc mem=0x30002+1 --mode value+addr   # 10 nodes
atropos slice fx/xor.atrace --at mark=1 --loc mem=0x30002+1 --mode value+ctrl   # 9 nodes
atropos slice fx/xor.atrace --at mark=1 --loc mem=0x30000+4                     # all 4 bytes
```

---

## 4. Recording a trace of a real target

### 4.1 Decide: spawn or attach

| | Use when | What to know |
|---|---|---|
| `--spawn target.exe` | You can start the sample yourself (the common case) | Stalking is armed at the image entry point; the loader runs native. Nothing before the entry point is traced. |
| `--attach PID` | The process is already running (a service, an injected payload, a GUI you have navigated to a state) | **You must pass `--thread TID`**: Frida's own threads cannot be told apart from the target's. Find the TID in Process Explorer / `tasklist` / a debugger. |

### 4.2 Decide: where to put marks

A **mark** is an anchor in the trace you can name later as `--at mark=N`. Without marks you must find
your point by address and occurrence (§5), which is harder. Put a mark at every API call whose
*arguments* are the thing you want to slice:

```bash
python -m atropos.capture --spawn sample.exe --out run.atrace \
    --mark-export advapi32.dll:CryptEncrypt=1 \
    --mark-export kernel32.dll:WriteFile=2 \
    --mark-export kernel32.dll:VirtualProtect=3
```

Each hook prints, at call time, the first four argument values:

```
[atropos] mark 1 at CryptEncrypt  args: 0x1a2b3c 0x0 0x1 0x0 ...
```

**Write those down.** `CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, …)` — `pbData` is the fifth
argument so it is not in the four printed, but `RSP+0x28` at the call is; more practically, hook a
call where the buffer *is* in `rcx`–`r9` (`CryptHashData`'s `pbData` is `rdx`; `WriteFile`'s buffer is
`rdx`). The buffer address you copy from this line is the literal you pass to `--loc mem=…+N`.

If your API is not exported by name (internal function), you can still mark by hooking any export the
code calls near it, then use `addr=` relative to the mark's sequence number (§5.3).

### 4.3 Decide: what to exclude, and whether to be paranoid

Defaults exclude the OS and CRT DLLs. Add `--exclude somelib.dll` for large third-party libraries
you know are not the answer (a rendering engine, a JSON parser). Fewer traced instructions = faster
capture and replay, at the cost of "live-in" leaves where those DLLs wrote memory.

Use `--paranoid` **only** when you have evidence the target rewrites code without going through
`VirtualProtect`/`NtProtectVirtualMemory` (an RWX section it writes directly). It re-instruments every block on
every execution and is 10–100× slower on loops. Otherwise trust the default: rewrites through the
protection APIs are detected and versioned automatically.

### 4.4 Run it

```bash
python -m atropos.capture --spawn sample.exe --arg input.bin --out run.atrace \
    --mark-export advapi32.dll:CryptEncrypt=1 --duration 60
```

Watch for these lines:

- `[atropos] following thread N` — stalking started. If you never see it on `--spawn`, the entry
  point hook did not fire (packed stub with an unusual entry? check `atropos info`'s module map).
- `[atropos] code rewritten at 0x… -> version N` — self-modifying code detected; the bundle now has
  two code versions. Good.
- `[atropos] target exiting; trace flushed` — the sample exited before your duration; the agent
  drained on its way out. The bundle is complete.
- `[atropos] captured {...}` — stats. `"instructions": 0` means nothing was stalked (see §17).

Then, **always**:

```bash
atropos info run.atrace
```

and read: the instruction count (is it plausible for what the sample did?), the marks list (did every
mark fire, and how many times?), any code-version changes, and the banner.

---

## 5. Finding the criterion — the hard part

The criterion is the one thing the tool cannot choose for you. Four strategies, in order of
preference.

### 5.1 Marks (best)

If you marked the call, `--at mark=N` puts you at the instruction *after* the mark — i.e. at the
moment of the call, with the arguments already in registers and the buffers already filled. Slice the
buffer or the register directly:

```bash
atropos slice run.atrace --at mark=1 --loc mem=0x1a2b3c+32     # the buffer
atropos slice run.atrace --at mark=1 --loc rdx                 # the register holding the pointer
```

If the mark fired several times (`marks: mark=1 at #4102, #9930, …` in `atropos info`), `mark=1`
resolves to the **first** one. For the others, use their `seq` from the `info` output: `--at
seq=9930`.

### 5.2 Address + occurrence

You know from IDA that the interesting instruction is at RVA `0x1a2f`, and you want its 4th
execution:

```bash
atropos slice run.atrace --at addr=sample.exe+0x1a2f@3 --loc rax
```

`module+RVA` is ASLR-safe: it is rebased onto the module map recorded in *this* bundle. The
occurrence is 0-based. If you guess too high the error tells you how many times it ran:

```
error: address sample.exe+0x1a2f executed 4 time(s); occurrence 9 does not exist
```

Which occurrence? Two tricks:

- Slice `--at addr=…@0 --loc rcx` (the loop counter, say) and read the value chain to work out which
  iteration is which; or
- use `--direction forward` from a known earlier point (a mark) and see which occurrences of your
  address appear in it — those are the ones after the mark.

### 5.3 Sequence numbers

`seq=N` is the raw index. You get them from `atropos info` (marks, version changes) and from the
listing of any previous slice. A typical pattern: slice at a mark, notice `#8841 call [rax]` in the
listing with an `imprecise` tag, then `--at seq=8841 --loc rax --mode value+addr` to ask *what
computed that call target*.

### 5.4 The memory address you do not have

You want the key buffer but only know it is "the thing `CryptEncrypt` was given". Options:

- Mark `CryptEncrypt`; slice **the register**, not the memory: `--loc r8` (if the pointer is in `r8`)
  with `--mode value+addr` gives you the code that *built the pointer*, whose listing will contain
  the `lea`/`mov` that reveals the address; then slice the memory.
- Mark an earlier API that *wrote* the buffer (`CryptDeriveKey`, `ReadFile`) — its printed arguments
  include the pointer.
- If you have a debugger attached alongside, read the register there. The tool deliberately stores
  no register values (design §4.4); it only stores *provenance*.

---

## 6. Choosing a mode

Start with `value`. Escalate only when `value` fails to answer the question. The table gives the
decision rule and what each mode did on the decode-loop fixture:

| Question | Mode | Fixture result | What got added |
|---|---|---|---|
| What arithmetic produced this? | `value` | 4 nodes | — |
| …and where did the *pointer* it was loaded/stored through come from? | `value+addr` | 10 nodes | `mov rsi/rdi, …`, and the `inc rsi`/`inc rdi` of iterations 0–1 |
| …and which *decisions* caused it to be computed at all? | `value+ctrl` | 9 nodes | `mov rcx, 4`, `dec rcx`/`jne` of iterations 0–1 |
| Everything | `full` | 15 nodes | both |

Reasoning about the fixture: the third iteration's store depends on the pointer having been advanced
twice (`addr`) and on the loop having decided to continue twice (`ctrl`). Neither affects the *value*
`0x12 ^ 0x5a`.

**Rules of thumb.**

- **Crypto / KDF / checksum questions → `value`.** You want the arithmetic and its leaves.
- **"Who controls this indirect call / this write address" → `value+addr`** with the pointer
  register as the location.
- **"Why was this path taken" / "what is this comparison against" → `value+ctrl`**, often with a
  *flag* as the location (§10).
- **`full`** when you do not yet know what kind of question you have and the trace is small enough
  to read. On a long loop `full` walks every iteration's counter (a 30 000-iteration loop gave a
  120 000-node `full` slice in testing); use `--max-control-depth` or `--fold-loops`.

The modes nest: `value ⊆ value+addr ⊆ full` and `value ⊆ value+ctrl ⊆ full`. If `value` already
contains what you need, a larger mode only adds.

---

## 7. Workflow A: what is this crypto key derived from?

**Setup.** Sample calls `CryptEncrypt`. You want to know how the key was made.

**Record** with a mark on the encrypt call and, ideally, on `CryptDeriveKey`/`CryptHashData` too:

```bash
python -m atropos.capture --spawn sample.exe --out run.atrace \
    --mark-export advapi32.dll:CryptHashData=1 --mark-export advapi32.dll:CryptEncrypt=2
```

`CryptHashData(hHash, pbData, dwDataLen, flags)` — `pbData` is in `rdx`, `dwDataLen` in `r8`, both
printed at mark time. Say the line reads `args: 0x2b0 0x1f3a40 0x10 0x0`.

**Slice** the 16 bytes of key material as of the hash call, in `value` mode:

```bash
atropos slice run.atrace --at mark=1 --loc mem=0x1f3a40+16
```

**Read the input report first.** On the `key-derivation` fixture (`fx/kdf.atrace`,
`--at mark=1 --loc mem=0x40000+8`) it is:

```
INPUTS — where this value ultimately came from
------------------------------------------------------------------------------
  environmental (from outside the process)  (1)
      #3  GetVolumeInformationW  [source]
  immediate constants in the code  (2)
      #2  target.exe+0x14   movabs rcx, 5
      #5  target.exe+0x21   movabs rdx, 0x9e3779b9
```

That *is* the finding: `key = f(volume serial number, 0x9e3779b9, rotate-by-5)`. The `[source]` tag
marks an API whose output originates outside the process; the constants are what a re-implementation
needs. Only now read the listing for the mixing arithmetic:

```
  #4   mov rax, qword ptr [r9]        <- defines rax used by #6 (value)   ; the serial
  #5   movabs rdx, 0x9e3779b9         <- defines rdx used by #6 (value)
  #6   xor rax, rdx                   <- defines rax used by #7 (value)
  #7   mov r8, rax                    <- defines r8 used by #9 (value)
  #8   shl rax, cl                    <- defines rax used by #9 (value)
  #9   add rax, r8                    <- defines rax used by #10 (value)
  #10  mov qword ptr [rbx], rax       <- slicing criterion
```

Nine instructions; you can transcribe them into Python in a minute.

**If the report instead says** `memory not written during the trace … [0x1f3a40..+16]`, the buffer
was filled by something untraced — an API without a summary, or an excluded DLL. Look at what the
sample imports around the call, add a summary for it (reference §15) or move the mark to the API that
filled the buffer.

**If it says** `register live-in (set before tracing began)`: the value predates the trace. Under
`--spawn` that means it was set before the image entry point — the loader, or an environment block.
`gs:[0x60]`-style TEB/PEB reads look like this and are expected.

---

## 8. Workflow B: which loop decoded this byte, and from what?

**Setup.** A packer decodes a region and jumps into it. You want the decode loop and the source
bytes, and you do not want the anti-debug noise around it.

**Record.** `VirtualProtect` and `NtProtectVirtualMemory` are hooked automatically; each rewrite of
instrumented code bumps the version. (The allocation APIs are not hooked: a hook there deadlocks
Stalker, and a fresh allocation cannot hold instrumented code anyway.) Mark `VirtualProtect` so you have an anchor at the moment the region becomes
executable:

```bash
python -m atropos.capture --spawn packed.exe --out run.atrace \
    --mark-export kernel32.dll:VirtualProtect=1
```

**Find the region.** `atropos info` shows `code version changes` and the `wx_regions` list in the
capture metadata (`base`, `size` of every protection change the target made). Pick a byte inside it —
preferably the *first* byte of the new entry point, since that is the one you know was executed.

**Slice one byte, `value` mode:**

```bash
atropos slice run.atrace --at mark=1 --loc mem=0x7ff6c0301000+1
```

The fixture equivalent is §3: four instructions and one source byte. On a real packer expect the same
shape, plus whatever key schedule feeds the XOR/ADD — that key schedule is the interesting part and it
is now isolated.

**Then widen deliberately:**

- Slice the whole region `mem=BASE+SIZE` to get *all* iterations — and use `--fold-loops` so the
  listing collapses each loop instruction to one row with a count:

  ```
    #4   mov al, byte ptr [rsi]   x4
    #5   xor al, dl               x4
    #6   mov byte ptr [rdi], al   x4
  ```

  The input report then lists the source range, merged into contiguous runs.
- Switch to `value+addr` to see how the loop's *pointers* were set up — this is where the packer's
  section table parsing shows up.

**Self-modifying stubs.** If the same address appears with different disassembly under `[v0]` and
`[v1]` tags, that is code versioning working: the listing shows the instruction *as it was at that
time*. `fx/smc.atrace` demonstrates it: `packed.exe+0x0` is `mov rax, 0x1111` at `#0` and
`mov rbx, 0x2222 [v1]` at `#2`. Never assume an address means one instruction in a packed trace.

---

## 9. Workflow C: who controlled this pointer?

**Setup.** You see `call [rax]` or `jmp rax` and want to know what computed the target — a vtable
lookup, an import resolved by hash, a decoded address.

**Find the instance.** From a listing, or `addr=…@k`. Then slice **the register**, in `value+addr`:

```bash
atropos slice run.atrace --at seq=8841 --loc rax --mode value+addr
```

Why `value+addr`: `rax` was probably loaded from memory (`mov rax, [rcx+0x38]`), and you want to
know both what wrote that memory (`value`) *and* how `rcx+0x38` was arrived at (`addr`) — the object
pointer, the hash-walk over the export table, and so on. In `value` alone you would see the write to
`[rcx+0x38]` but not why `rcx` pointed there.

On the real `crack.atrace` bundle in the repository, slicing the argument registers of an
`RtlMoveMemory` summary in `full` mode gave:

```
  #10  ntdll.dll+0xaad44  mov r9, rcx      <- defines r9 used by #16 (value)
  #15  ntdll.dll+0xaad5a  mov r8, rdx      <- defines r8 used by #99 (addr)
  #16  ntdll.dll+0xaad5d  mov rdx, r9      <- defines rdx used by #99 (addr)
  #19  ntdll.dll+0xaad65  xor ecx, ecx     <- defines rcx used by #99 (addr)
  ...
  register live-in (set before tracing began)  (2)
      rcx read by #10 (value)
      rdx read by #15 (value)
```

Read the `(addr)` tags: those rows are in the slice because they *built the arguments*, not because
they computed data. The leaves say the original `rcx`/`rdx` came from before tracing started — i.e.
the caller was untraced. That tells you where to move your mark.

**Expect stack plumbing** in `value+addr` slices that pass through `push`/`pop`/`call`/`ret`: `rsp` is
an address input to every one of them. If it dominates, go back to `value` and ask about the
specific memory slot instead.

---

## 10. Workflow D: why did this branch go that way?

**Setup.** A `jne` at `sample.exe+0x2f` skipped the "success" path. You want the comparison and its
operands.

**Slice the flag, not the branch.** A conditional branch *reads* a flag; the flag was *defined* by
the `cmp`/`test`/`sub` before it. So the criterion is the flag at the branch:

```bash
atropos slice run.atrace --at addr=sample.exe+0x2f@0 --loc zf
```

On the fixture (`fx/xor.atrace`, `--at mark=1 --loc zf`):

```
  #2   movabs rcx, 4     <- defines rcx used by #9 (value)
  #9   dec rcx           <- defines rcx used by #16 (value)
  #16  dec rcx  [occ=1]  <- …
  #23  dec rcx  [occ=2]
  #30  dec rcx  [occ=3]  <- slicing criterion
```

`ZF` at the end of the run was defined by the last `dec rcx`, whose value chain runs back through
every decrement to the constant `4`. Because flags are modelled as **individual bits**, only the
instructions that fed `ZF` appear — not every arithmetic instruction that ever touched `RFLAGS`.

Use `jl`/`jge` → `--loc sf --loc of`; `jb`/`jae` → `--loc cf`; `jbe` → `--loc cf --loc zf`. The
listing's `defines ZF used by …` lines tell you which comparison produced it; then slice *its*
operands (a `cmp rax, rcx` → `--loc rax --loc rcx` at the `cmp`'s seq) to get both sides of the
comparison — for a serial check, the expected value and the derivation of the entered one.

**`value+ctrl` for the decision *history*.** If the question is "which earlier decisions led to this
code running at all", add `ctrl`. Each instance has exactly one guarding branch; following `ctrl`
walks outward through nested conditions. On a loop it revisits each iteration's exit test —
`--max-control-depth 3` keeps it readable.

**When the banner says `control dependence: unavailable`**, the function is control-flow flattened
and the tool has declined to answer the control question because the relation is degenerate
(every block "depends" on the dispatcher). `--force-cd` will make it answer anyway; expect the entire
dispatch history. The value question still works normally in flattened code — flattening does not
touch data flow.

---

## 11. Workflow E: where did this input end up?

**Forward slicing** answers the dual question: given an instance, what later instances consumed its
output, transitively?

```bash
atropos slice fx/xor.atrace --at seq=3 --loc dl --direction forward
```

```
  #3   mov dl, 0x5a
  #5   xor al, dl               #6   mov [rdi], al
  #12  xor al, dl  [occ=1]      #13  mov [rdi], al  [occ=1]
  #19  xor al, dl  [occ=2]      #20  mov [rdi], al  [occ=2]
  #26  xor al, dl  [occ=3]      #27  mov [rdi], al  [occ=3]
```

The key byte reached all four stores. Use this to answer "does the user-supplied string ever reach the
comparison" — forward from the `ReadFile` summary node, look for the `cmp`.

Note two v0.2 limits: the forward seed is the **whole instance** (`--loc` is parsed but not used to
narrow it), and control is not propagated forward. Also, forward slices can be very large from an
early point; cap them with `--max-nodes`.

**Chop** — the intersection of a forward slice from a source and a backward slice from a sink — is
usually the most readable answer to "how does *this* reach *that*":

```bash
atropos slice fx/xor.atrace --at seq=3 --loc mem=0x30002+1 --direction chop --to mark=1
```

```
  #3   mov dl, 0x5a
  #19  xor al, dl  [occ=2]
  #20  mov [rdi], al  [occ=2]
```

Three instructions: the exact path from the key constant to the third output byte. On a real target,
chop from the `ReadFile` that read the licence file to the `cmp` that rejected it, and you get the
transformation pipeline and nothing else.

---

## 12. Reading the input report

Every slice ends with the leaves. Each category means something specific and implies an action:

| Category | Meaning | What to do |
|---|---|---|
| **environmental (from outside the process)** `[source]` | An API summary of kind *source* fed the chain: `ReadFile`, `GetVolumeInformationW`, `BCryptGenRandom`, … | This is usually the answer. Name it in your notes. |
| **environmental** `[alloc]` | A fresh allocation (`VirtualAlloc`, `HeapAlloc`) — the value depends on zero-initialised memory | Usually benign; occasionally reveals an uninitialised-read bug. |
| **environmental** `[unknown]` | An unmodelled external call defined `rax`; its buffer effects are unknown | Write a summary for it (reference §15) and re-slice. The node carries `imprecise`. |
| **immediate constants in the code** | Instructions in the slice with no data inputs at all: `mov reg, imm`, `xor reg, reg`, `lea reg, [rip+…]` | These are your magic numbers, seeds and table addresses. |
| **initial image data (module)** | Unwritten bytes inside a mapped module: `.rdata` tables, string literals, the import table | Look them up in IDA at that RVA. |
| **memory not written during the trace (initial state or untraced writer)** | Bytes nothing traced wrote: stack from before the entry point, heap filled by an excluded DLL, the packed payload | Decide which: if a DLL filled it, add a summary or un-exclude it; if it is the payload, you are done. |
| **register live-in (set before tracing began)** | A register nobody in the trace wrote | Under `--spawn`, set by the loader (`rcx`/`rdx` at entry, `gs` base). Under `--attach`, anything before you attached. |

Leaves are merged into contiguous ranges per consumer and capped at 12 lines per category; `… and N
more` means use `--format json` to get them all (`"inputs": [...]`).

---

## 13. Reading the precision banner

Every line in the banner changes how much of the output you should believe:

| Banner line | Meaning | Action |
|---|---|---|
| `trace integrity: OK` | All structural checks passed. | Proceed. |
| `trace integrity: suspect \| N error(s)` | The trace describes something other than what ran. `slice` refuses without `--allow-suspect`. | `atropos verify` to read the findings. A *discontinuity* means an exception or lost thread; a *memory access count* mismatch means the agent and the model disagree about an instruction — usually an undetected code rewrite. Re-capture, possibly with `--paranoid`. |
| `trace integrity: notes \| N note(s)` | Weaker observations: a size disagreement, a missing `SHIFTCNT`, an unknown summary id. | Read them with `verify`; affected nodes carry `imprecise`. |
| `node annotations: K summary` | K synthetic nodes stand in for hooked API calls. | Normal. |
| `node annotations: K imprecise` | K nodes consumed an ISA-undefined flag or crossed an unmodelled call. | If one is on your critical path (tag `[imprecise]` on the row), treat that hop as unverified. |
| `node annotations: K bulk` | K `rep`-prefixed string ops modelled as one bulk copy. | Slices through them include the *whole* source range; byte-exact provenance is lost inside the copy. |
| `node annotations: K cd-unreliable` | K nodes are in a function where control dependence was withheld. | Only matters in `value+ctrl`/`full`. |
| `control dependence: unavailable in N function(s)` | Flattening detected; dispatcher location follows on the next line. | See §10. |
| `N rep-prefixed instruction(s) modelled in bulk` | As above, counted. | — |
| `N variable shift(s) had a zero count and correctly defined nothing` | Informational: the tool saw `shl r, cl` with `cl=0` and did *not* record a phantom definition. | — |
| `!! SLICE TRUNCATED: …` (after the listing) | A cap fired. | Raise `--max-nodes`/`--max-control-depth`, or accept an incomplete chain knowingly. |

The banner also travels inside `--format json` (`"precision"`) and `--format bridge`, and the loader
scripts print it in the disassembler's console.

---

## 14. Taming large slices

A 5 M-instruction trace can yield a 50 000-node slice. Tools, in the order to try them:

1. **Ask a smaller question.** One byte, not sixteen. `value`, not `full`. The register at the call,
   not the buffer it points to.
2. **`--fold-loops`** — collapses ≥3 executions of one address into one row with `xK`. Turns a
   4 000-iteration loop body into three rows.
3. **`--max-lines N`** — show the first N rows; the slice is still computed in full (the input report
   is complete).
4. **`--max-control-depth N`** — in `ctrl` modes, stop after N nested guards. Depth 1–2 usually
   captures the decision that matters.
5. **`--max-nodes N`** — hard stop on the walk. The report says so; use it for a first look, not a
   final answer.
6. **`--format dot`** (collapsed by default) — a 4 000-copy loop becomes three boxes and a self-loop
   labelled `x4000`. Pipe to `dot -Tsvg`. `--no-collapse` if you need per-instance nodes.
7. **Chop instead of slice** (§11) — the intersection is often an order of magnitude smaller than
   either side.
8. **`--no-why`** — halves the line count when you only want the instruction sequence.

Replay is the expensive step (~60 000 instructions/s in the Python implementation), and it happens on
every invocation. For repeated queries on a large bundle, use the Python API (§16) and analyse once.

---

## 15. Getting the slice into your disassembler

```bash
atropos slice run.atrace --at mark=1 --loc rdx --mode value+addr \
    --format bridge --write-scripts ./bridge > slice.json
```

`slice.json` is a per-static-address rollup: `module`, `rva`, `code_version`, `occurrences`, a sample of
`seqs`, and which `edge_kinds` pulled it in. Summary nodes are listed separately under `"summaries"`.

**IDA:** *File ▸ Script file…* → `bridge/atropos_ida.py` → pick `slice.json`. Every instruction in the
slice is coloured (green = value, blue = address, red = control — strongest kind wins) and gets a
comment `atropos: x4 [value] v1`. RVAs are rebased onto the database's image base, so ASLR is not an
issue. The console prints the criterion, the banner and any summaries the chain passed through.

**Ghidra:** Script Manager → category *Atropos* → `atropos_ghidra.py`. Same behaviour with
pre-comments and background colours.

Practical use: run several slices (the key derivation, the serial check, the pointer provenance) into
separate JSONs and load them one at a time; the colouring tells you at a glance which functions
participate in which computation. `code_version` in the comment warns you when the database's bytes
(one version) differ from what ran (another).

---

## 16. Scripting with the Python API

Analyse once, query many times:

```python
from atropos import analyse_path, build_criterion, backward_slice, forward_slice, chop, MODES
from atropos.output import render_listing, render_inputs, to_json, ListingOptions

a = analyse_path("run.atrace")               # replay + integrity + control flow; the slow step
print(a.integrity.banner(), a.stats)

if a.integrity.n_errors:
    raise SystemExit(a.integrity.render())   # same refusal the CLI applies

crit = build_criterion("mark=1", ["mem=0x1f3a40+16"], a.result)
r = backward_slice(a.result, crit, MODES["value"])
print(render_inputs(a, r))
```

**Recipe: slice every mark occurrence.** `mark=N` resolves to the first; iterate the side table for the
rest:

```python
for mark_id, seq in a.ddg.marks:
    if mark_id != 1: continue
    r = backward_slice(a.result, build_criterion(f"seq={seq}", ["rdx"], a.result), MODES["value"])
    leaves = sorted({leaf.render() for leaf in r.inputs})
    print(f"#{seq}: {len(r)} nodes; leaves: {leaves}")
```

**Recipe: which API sources feed a value?**

```python
sources = [(s, a.ddg.summary_nodes[s]) for s in r.nodes if a.ddg.summary_kinds.get(s) == "source"]
```

**Recipe: the disassembly of the slice as plain text.**

```python
m, b, d = a.result.model, a.bundle, a.ddg
for s in r.nodes:
    blk = b.blocks.get(d.node_block[s])
    if blk is None:
        print(s, "SUMMARY", d.summary_nodes[s]); continue
    text = " ".join(m.disassemble(blk.insns[d.node_index[s]].raw, d.node_addr[s]))
    print(s, b.rebase(d.node_addr[s]), text, r.inclusions[s].render(d))
```

**Recipe: a custom mode.** `SliceMode("addr-only", follow_value=False, follow_addr=True)` is legal:
"only the pointer provenance, not the data".

**Recipe: add an API summary without editing the package.**

```python
from atropos import analyse, TraceBundle
from atropos.summaries import SummaryTable, Summary, Ref
table = SummaryTable.default()
table.add(Summary(200, "MyDecrypt", "transform", reads=[Ref(0, "1")], writes=[Ref(2, "1")]))
a = analyse(TraceBundle("run.atrace"), summaries=table)
```

The agent must emit `SUMMARY 200` for this to have any effect — add the matching hook to `SUMMARIES`
in `agent/atropos-agent.js`. Note the **string** `"1"` for "length is argument 1": in v0.2 an integer
length is a literal byte count (reference §16.2 #1 explains why the built-in table gets this wrong).

**Recipe: batch many criteria into JSON for another tool.**

```python
import json
queries = [("mark=1", ["rdx"]), ("mark=2", ["mem=0x1f3a40+16"])]
out = {}
for point, locs in queries:
    r = backward_slice(a.result, build_criterion(point, locs, a.result), MODES["value"])
    out[f"{point} {' '.join(locs)}"] = json.loads(to_json(a, r))
json.dump(out, open("slices.json", "w"), indent=2)
```

---

## 17. When the answer looks wrong

Work through this list before doubting the algorithm; in practice the fault is almost always in the
question or the trace.

1. **Is the banner clean?** `suspect` → the slice is about a different execution. Stop.
2. **Did you slice the post-state?** `--at seq=N` means *after* N executes. If N is the store you care
   about, its write is included; if you wanted the state *before* it, use `seq=N-1`.
3. **Is the occurrence right?** `@k` is 0-based. `@0` is the first execution.
4. **Is the location the size you meant?** `--loc eax` is four lanes; a byte written via `al` earlier
   and `ah` later gives two producers, both correctly listed. `mem=X+8` is eight questions.
5. **Is the value actually a value dependence?** If the answer "must" include the `lea` that built the
   pointer and does not, you need `value+addr`. If it "must" include the comparison and does not, you
   need `value+ctrl` (or slice the flag).
6. **Did the chain cross an API?** A leaf `memory not written during the trace` in the middle of what
   should be a chain means an untraced writer. `atropos info` → is the module excluded? Is there a
   summary for the call? (v0.2: memory-moving summaries cover fewer bytes than they should — reference
   §16.2 #1 — so a `memcpy`'d buffer beyond its first two bytes shows as unwritten.)
7. **Is it a `rep`?** A `[bulk]` row means one node stands for a whole copy; the source range is
   included wholesale. That is imprecise, not wrong.
8. **Is the code versioned?** `[vN]` tags: the instruction *as it was then*. Compare with the
   database's bytes before assuming a decoder error.
9. **Is the trace actually of the target?** The real bundles shipped in this repository are 12
   instructions of `ntdll`: the old entry-point hook did not reach the image. `atropos info` →
   `instructions` and the module of the first few `seq`s tell you immediately. A current capture
   starts with `THREAD` followed by the image's own entry block (`image+entry`). If the first blocks
   are at anonymous or `0x7ffd…` addresses, or the bundle reports stores recorded as reads, it was made
   by an agent from before 2026-09-23 (reference §16.3). Re-capture it.
10. **Still wrong?** Build a minimal fixture with `atropos.testkit` reproducing the instruction pattern
    and run `oracle.differential_check` on it; if the two implementations disagree, you have found a
    modelling bug and the fixture is the test case.

---

## 18. Pitfalls

- **Slicing the branch instead of the flag.** `--loc` on a `jne` instance asks about nothing (it
  defines no location). Ask about `zf`.
- **`--loc` on `forward`.** Ignored in v0.2; the whole instance is the seed.
- **Absolute addresses across runs.** ASLR moves modules; `module+0xRVA` does not.
- **`mark=N` with several firings.** Resolves to the first; use `seq=` for the rest.
- **`value+addr` through the stack.** `rsp` is an address input to every push/pop/call/ret; the slice
  fills with frame set-up. Narrow the question.
- **`full` on a long loop.** Control walks every iteration's exit test. Cap the depth.
- **Expecting values.** Atropos stores provenance, never register or memory *contents*. The
  `--capture-values` option records `VALUE` records the current replay ignores. Pair with a debugger
  when you need the number.
- **Trusting a slice with `imprecise` on the critical path.** The dependence exists; its value
  content is not architecturally determined (undefined flag) or not modelled (unknown call).
- **Recording without marks.** You will spend the analysis hunting for `seq` numbers. Hook something.
- **Attaching without `--thread`.** Nothing is traced; the tool tells you so at `start()`.

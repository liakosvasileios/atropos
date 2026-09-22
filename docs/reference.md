# Atropos — Reference Manual

**Code, functionality and usage of Atropos v0.2.0**

This document is the complete user- and developer-facing reference for Atropos. It describes every
command, every option, every public Python symbol and every module in the source tree, and it closes
with the findings of an extensive test pass over the tool. It is written to be read alongside the
code; the design rationale lives in [`design-v0.2.md`](design-v0.2.md) and the theory in
[`theory.md`](theory.md).

---

## Contents

1. [What Atropos does](#1-what-atropos-does)
2. [Installation and environment](#2-installation-and-environment)
3. [Quick start](#3-quick-start)
4. [Concepts you need before using it](#4-concepts-you-need-before-using-it)
5. [Command-line reference](#5-command-line-reference)
6. [Criterion syntax](#6-criterion-syntax)
7. [Slice modes and directions](#7-slice-modes-and-directions)
8. [Output formats](#8-output-formats)
9. [Reading a report](#9-reading-a-report)
10. [Recording a trace (capture)](#10-recording-a-trace-capture)
11. [The trace bundle](#11-the-trace-bundle)
12. [Python API](#12-python-api)
13. [Source tree walkthrough](#13-source-tree-walkthrough)
14. [Testing infrastructure](#14-testing-infrastructure)
15. [Extending Atropos](#15-extending-atropos)
16. [Test pass: findings and known issues](#16-test-pass-findings-and-known-issues)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. What Atropos does

Atropos is a **backward dynamic program slicer** for Windows x86-64 binaries. Given a recorded
execution trace and a *slicing criterion* — a point in that execution plus a set of storage locations
(registers, flag bits, or bytes of memory) — it returns:

- the subset of executed instruction *instances* that contributed to the value(s) at that point;
- the dependence edges connecting them (value, address, control);
- the *inputs* the computation bottomed out on: immediate constants, memory never written during the
  trace, registers live at trace start, and environmental values delivered by API calls.

It reasons about **one concrete run**. Every address is concrete, every branch outcome is known, and
aliasing is decided by byte-range overlap. It never speculates about paths that were not taken.

The tool has two phases that share nothing but a file format:

| Phase | Where | What |
|-------|-------|------|
| **Capture** | Inside the target, under Frida Stalker (`agent/atropos-agent.js`, driven by `atropos.capture`) | Emits raw facts: which block ran, which effective addresses were touched, plus a few narrow records. Never computes semantics. |
| **Analysis** | Offline, any platform (`atropos` CLI / Python package) | Decodes instructions, derives read/write sets, replays the trace forward to build a dependence graph, walks it backward. |

Everything except capture runs without Frida and without a target process.

---

## 2. Installation and environment

```bash
pip install -e .            # core: capstone>=5.0 is the only hard dependency
pip install -e .[capture]   # adds frida>=16.0 for recording traces
pip install -e .[dev]       # adds pytest
```

Requirements:

- Python **3.10+** for analysis. (Note: recent `frida` Python bindings import `typing.NotRequired`,
  which exists only in **3.11+**; on 3.10 `import frida` fails and `atropos.capture` reports "capture
  needs the `frida` package" even though it is installed. Use Python 3.11+ for capture.)
- Capture requires a Windows host and an x86-64 target.
- The `atropos` console script is registered by `pip install -e .`; `python -m atropos` is equivalent
  and works from a source checkout without installation (`src/` is on `pythonpath` in
  `pyproject.toml` for pytest only — for ad-hoc use, install or set `PYTHONPATH=src`).

On Windows consoles, set `PYTHONIOENCODING=utf-8` (or use Windows Terminal with a UTF-8 code page):
the listing uses `—` and `←`-style glyphs that otherwise render as `�`.

Verify the installation:

```bash
atropos --version            # atropos 0.2.0
atropos demo                 # builds and slices a fixture; needs no target
pytest                       # 152 tests, ~1.5 s
```

---

## 3. Quick start

```bash
# 1. Record (Windows, needs frida)
python -m atropos.capture --spawn target.exe --out run.atrace \
    --mark-export advapi32.dll:CryptEncrypt=1

# 2. Inspect
atropos info run.atrace
atropos verify run.atrace

# 3. Slice: the 16 bytes at 0x7ff6c0001000, as of the first CryptEncrypt call
atropos slice run.atrace --at mark=1 --loc mem=0x7ff6c0001000+16

# 4. Push it into IDA / Ghidra
atropos slice run.atrace --at mark=1 --loc rdx --format bridge \
    --write-scripts ./bridge > slice.json
```

Without a target, the three built-in workflows exercise the whole offline pipeline:

```bash
atropos demo --workflow xor-decoder      # unpacking: one output byte of a decode loop
atropos demo --workflow key-derivation   # crypto: key = f(API source, constant)
atropos demo --workflow self-modifying   # packer: one address, two code versions
```

---

## 4. Concepts you need before using it

**Instruction instance / `seq`.** Every executed instruction gets a sequence index `#N`, 0-based, in
trace order. Summary nodes (synthesised for hooked API calls) occupy sequence indices too. The same
static address executed four times is four instances, distinguished in listings as `[occ=k]`.

**Storage location.** Atropos never reasons about "RAX"; it reasons about *bytes*. Registers are byte
*lanes* (`rax[0]`…`rax[7]`), flags are single lanes (`ZF`), and memory is byte-addressed. A location is
`(space, start, length)` where `space` is `reg` or `mem`.

**Last writer.** For every byte, the `seq` of the instance that most recently wrote it, or `LIVE_IN`
(-1) if nothing in the trace has. Data dependence *is* the last-writer relation.

**Edge kinds.**

| Kind | Meaning | Example |
|------|---------|---------|
| `value` | the consumer's *result* is a function of this byte | `add rax, rbx` ← rbx |
| `addr` | this byte decided *where* the consumer read/wrote | `mov rax, [rbx+8]` ← rbx |
| `control` | this branch decided *whether* the consumer ran | body of `if` ← the `jne` |

**Criterion.** `(seq, [locations])`. The locations are resolved to their last writers **as of the
post-state of `seq`** — i.e. after instruction `seq` has executed. `--at seq=0 --loc rsi` after
`mov rsi, X` at `#0` yields `#0` itself.

**Precision banner.** Every report leads with the trace-integrity status, node-annotation counts,
control-dependence availability, and any bulk/approximate modelling in effect. Read it first.

---

## 5. Command-line reference

```
atropos [--version] {info,verify,slice,demo} ...
```

Exit codes: `0` success; `2` usage error, unresolvable criterion, missing bundle, or refusal to slice a
suspect trace; `1` from `verify` when the trace has integrity errors (and from uncaught exceptions —
see §16).

### 5.1 Common options (`info`, `verify`, `slice`)

| Option | Effect |
|--------|--------|
| `bundle` | Path to a `.atrace` directory (positional, required). |
| `--expand-rep` | Request byte-exact provenance through `rep`-prefixed string ops. In v0.2 this records a note per expandable `rep` (`ddg.notes`) and bumps `stats["rep_expanded"]`; it does **not** yet synthesise per-iteration nodes. Bulk edges remain. |
| `--allow-suspect` | Proceed even if integrity checks found errors. Without it, `info` and `slice` print the findings and exit 2. |

### 5.2 `atropos info BUNDLE`

Loads and fully analyses the bundle, then prints:

- bundle path, `arch/os`, and the `capture` metadata dict from `meta.json`;
- instruction / block / memory-access counts (`blocks` shows executions and distinct descriptors);
- DDG size (nodes, edges, approximate bytes) and the edge-kind histogram (`value`, `addr`, `control`,
  `live-in`);
- the module map (`name base +size`);
- marks (`mark=ID at #seq`), code-version changes (`#seq: -> vN`);
- per-pass timings (`replay`, `continuity`, `control_flow`);
- the precision banner.

`control` in the edge-kind histogram is always 0: control dependence is stored per node
(`node_ctrl`), not as edges.

### 5.3 `atropos verify BUNDLE [--limit N]`

Runs the same analysis with `--allow-suspect` implied and prints the integrity report: the banner line
followed by up to `N` findings (default 40) in `[severity] #seq: message` form, then the precision
banner. Exit 1 if any finding is an error, else 0.

### 5.4 `atropos slice BUNDLE --at POINT --loc LOC [--loc LOC ...] [options]`

| Option | Default | Effect |
|--------|---------|--------|
| `--at POINT` | required | The point; see §6. |
| `--loc LOC` | required, repeatable | A location at that point; see §6. Ignored for `--direction forward` (see §7). |
| `--mode {value,value+addr,value+ctrl,full}` | `value` | Which edge kinds the walk follows (§7). |
| `--direction {backward,forward,chop}` | `backward` | Walk direction (§7). |
| `--to POINT` | — | Sink for `chop`; required with `--direction chop`. |
| `--format {listing,dot,json,bridge}` | `listing` | Output backend (§8). |
| `--max-nodes N` | unlimited | Stop the walk once `N` nodes are included; the report says `!! SLICE TRUNCATED`. Criterion seeds are always included even if they exceed `N`. |
| `--max-control-depth N` | unlimited | Stop following `control` edges beyond `N` nested guards. |
| `--max-lines N` | unlimited | Truncate the listing after `N` rows (rendering only; the slice itself is complete). |
| `--fold-loops` | off | Collapse ≥3 executions of one static address into one row with `xK`. |
| `--no-why` | off | Omit the `<- defines … used by …` reason under each row. |
| `--no-collapse` | off | DOT only: one node per *instance* instead of per static address. |
| `--force-cd` | off | Emit control edges even in functions detected as control-flow flattened. |
| `--write-scripts DIR` | — | Also write `atropos_ida.py` and `atropos_ghidra.py` into `DIR`. |

The listing format prints the slice listing followed by a blank line and the input report. The other
three formats print a single document to stdout; `--write-scripts` progress goes to stderr, so
`> slice.json` redirection stays clean.

### 5.5 `atropos demo [--workflow W] [--mode M] [--out DIR]`

Builds a fixture bundle with the test kit, analyses it and prints the listing and input report.

| Workflow | Fixture | Criterion |
|----------|---------|-----------|
| `xor-decoder` (default) | 4-iteration XOR decode loop `[0x20000..+4) -> [0x30000..+4)`, key `0x5a` | `mark=1`, `mem=0x30002+1` |
| `key-derivation` | `GetVolumeInformationW` summary writes 8 bytes; mixed with `0x9e3779b9` and a shift | `mark=1`, `mem=0x40000+8` |
| `self-modifying` | `packed.exe+0x0` holds `mov rax, 0x1111` (v0) then `mov rbx, 0x2222` (v1) | `seq=2`, `rbx` |

`--out` persists the bundle (default: a fresh temp directory). An unknown `--workflow` currently
raises a raw `KeyError` (§16).

### 5.6 `python -m atropos.capture`

See §10.

---

## 6. Criterion syntax

### 6.1 Points (`--at`, `--to`)

| Form | Meaning |
|------|---------|
| `seq=N` | Raw sequence index. Must be in `0..n_nodes-1`. |
| `addr=ADDR[@K]` | The `K`-th execution (0-based, default 0) of static address `ADDR`. `ADDR` is `0x…` or `module+0xRVA`; module names match case-insensitively by full name or prefix (`target` matches `target.exe`). |
| `mark=N` | The instance at which the capture agent emitted `MARK N` (see `--mark-export`). Resolves to the sequence index of the *next* instruction after the mark. |

Errors are specific: *"address target.exe+0x24 executed 4 time(s); occurrence 9 does not exist"*,
*"no MARK 2 in this trace (have: [1])"*, *"seq 999 is outside this trace (0..32)"*.

### 6.2 Locations (`--loc`)

| Form | Resolves to |
|------|-------------|
| `rax`, `ecx`, `dx`, `bl`, `ah`, `r8d`, `sil`, … | The register's lanes: 8/4/2/1 bytes; `ah`/`ch`/`dh`/`bh` are lane 1 of their parent. |
| `xmm3`, `ymm3`, `zmm3`, `mm0`, `st(0)`, `fs`, `gs` | Vector (16/32/64 lanes), MMX (8), x87 (10), segment base (8). |
| `REG[lo:hi]` | An explicit inclusive lane range of the *parent* register, e.g. `rbx[0:3]` = `ebx`, `rcx[0:0]` = `cl`. `hi` must be `< parent width`. |
| `cf`, `pf`, `af`, `zf`, `sf`, `of`, `df` | One flag lane. |
| `mem=ADDR+LEN` | `LEN` bytes at absolute address `ADDR`; both accept `0x…` or decimal; `LEN > 0`. |

Names are case-insensitive. `mem=@rsp+64`-style register-relative addresses are **not** supported by
design: the slicer holds no register values. Resolve the address in the agent hook (marks report their
first four arguments) and pass it literally.

Several `--loc` may be given; the slice is the union.

---

## 7. Slice modes and directions

### 7.1 Modes

| `--mode` | Follows | Question answered |
|----------|---------|-------------------|
| `value` | value | What arithmetic produced this value? |
| `value+addr` | value + addr | …and what computed the pointers it travelled through? |
| `value+ctrl` | value + control | …and which branch decisions caused it to be computed? |
| `full` | all three | Everything. Largest. |

Observed on the `xor-decoder` fixture, slicing one output byte of a 4-iteration loop (33 instances):
`value` → 4 nodes; `value+addr` → 10 (adds the pointer set-up and the `inc rsi/rdi` up to that
iteration); `value+ctrl` → 9 (adds `mov rcx, 4`, and `dec rcx`/`jne` of the guarding iterations);
`full` → 15.

Control edges are per node: each instance has at most one guarding branch (`ddg.node_ctrl[seq]`).
Following control from node *n* enqueues its guard, then the guard's own data uses, and so on. On a
long loop the control chain walks back through *every* iteration's counter update — expected, and the
reason `--max-control-depth` exists.

### 7.2 Directions

**`backward`** (default). Seed = last writers of each `--loc` at `--at`; walk def-edges backward. The
result includes the seed instances themselves.

**`forward`.** Seed = the single instance at `--at`; walk use-edges forward ("what did this go on to
affect?"). In v0.2 the seed is the whole node — `--loc` is parsed but **not** used to narrow which of
its definitions to follow. Mode is honoured (address edges are only followed if the mode allows), but
control is not propagated forward. The forward index is built on demand (one pass over the edge
columns).

**`chop`.** `forward(--at) ∩ backward(--to)`: the instances on a path from the source to the sink.
Inclusion reasons and inputs come from the backward half. Both criteria use the same `--loc` list.

---

## 8. Output formats

### 8.1 `listing` (default)

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
  ...
  #20       target.exe+0x24             mov byte ptr [rdi], al              [occ=2]
              <- slicing criterion

INPUTS — where this value ultimately came from
------------------------------------------------------------------------------
  immediate constants in the code  (1)
      #3  target.exe+0x1e   mov dl, 0x5a
  memory not written during the trace (initial state or untraced writer)  (1)
      [0x20002..+1] read by #18 (value)
```

Row anatomy: `#seq`, `module+RVA` (or `[summary]`), disassembly at the real address (so RIP-relative
operands are right), then optional tags `[occ=k vN flags]` where flags ∈ `bulk`, `imprecise`,
`summary`, `suspect`, `cd-unreliable`, `aborted`. With `--fold-loops`, `xK` follows the text.

The **input report** groups leaves as:

- *environmental (from outside the process)* — summary nodes of kind `source`, `alloc` or `unknown`;
- *immediate constants in the code* — nodes in the slice with no incoming edge the mode allows;
- *initial image data (module)* — unwritten memory inside a mapped module;
- *memory not written during the trace (initial state or untraced writer)* — other unwritten memory;
- *register live-in (set before tracing began)*.

Adjacent byte leaves with the same consumer are merged into ranges. Up to 12 items per group are
shown. If there are no leaves at all: `inputs: none — the slice is closed within the traced execution.`

### 8.2 `dot`

Graphviz, `rankdir=BT`. Edges point **from use to def** (`use -> def`), labelled with the kind and,
when collapsed, a multiplicity `xK`. Styles: value = black solid; address = blue dashed; control = red
dotted. Criterion nodes are green-filled; annotated nodes amber. By default instances of one static
address collapse into one node (`(xK)` in the label); `--no-collapse` keeps every instance.

### 8.3 `json`

```json
{
  "atropos": {"format": 1},
  "criterion": {"seq": 32, "description": "mark=1", "locations": ["[0x30002..+1]"]},
  "mode": "value",
  "stats": {"nodes": 4, "inputs": 1, "edges_visited": 6, "trace_nodes": 33, "reduction": 0.878},
  "truncated": false, "truncation_reason": "",
  "precision": ["trace integrity: OK", "..."],
  "nodes": [{"seq": 18, "address": 335548448, "location": "target.exe+0x20", "code_version": 0,
             "occurrence": 2, "thread": 0, "flags": "", "text": "mov al, byte ptr [rsi]",
             "bytes": "8a06", "why": "defines al used by #19 (value)"}],
  "edges": [{"use": 19, "def": 18, "kind": "value", "space": "reg", "loc": 0, "length": 1}],
  "inputs": [{"space": "mem", "loc": 131074, "length": 1, "used_by": 18,
              "render": "[0x20002..+1] read by #18 (value)"}]
}
```

Summary nodes carry `"summary": "<name>"` instead of `text`/`bytes`. Control edges appear as
`{"use","def","kind":"control"}` with no location. Only edges whose *both* ends are in the slice and
whose kind the mode allows are emitted.

### 8.4 `bridge`

A per-static-address rollup keyed by `(module, rva, code_version)`:

```json
{"atropos_bridge": 1, "criterion": "...", "mode": "value", "precision": [...],
 "instructions": [{"module": "target.exe", "rva": 30, "code_version": 0, "occurrences": 1,
                   "seqs": [4], "edge_kinds": ["value"]}],
 "summaries": [{"seq": 3, "name": "GetVolumeInformationW", "kind": "source"}]}
```

`seqs` is capped at 32 per entry. Summary nodes are listed separately so a script never colours a
pseudo-address. The loader scripts (`--write-scripts`) rebase `rva` onto the database's current image
base, colour each instruction by its strongest edge kind (control > addr > value), and add a comment
`atropos: xN [kinds] vK`. IDA: *File ▸ Script file…*, pick the JSON. Ghidra: run from the Script
Manager (category *Atropos*).

---

## 9. Reading a report

1. **Banner first.** `trace integrity: suspect` means the trace describes something other than what
   ran; the slice is untrustworthy. `control dependence: unavailable in N function(s)` means
   `value+ctrl`/`full` deliberately omitted control edges there (nodes carry `cd-unreliable`).
   `N rep-prefixed instruction(s) modelled in bulk` means slices through `memcpy`-like loops pull in
   whole source ranges (`bulk` tag). `node annotations: K imprecise` means K nodes consumed an
   ISA-undefined flag value or crossed an unmodelled call.
2. **Input report second.** For the crypto workflow this is usually the answer: *"environmental:
   GetVolumeInformationW [source]; immediate constants: 0x9e3779b9"*.
3. **Listing third.** Execution order, each line saying which definition it satisfies and for whom.
   `[occ=k]` tells you which iteration; `[vN]` which code version.
4. **Truncation.** `!! SLICE TRUNCATED` means a cap fired; the chain is incomplete.

---

## 10. Recording a trace (capture)

```
python -m atropos.capture (--spawn PROGRAM | --attach PID_OR_NAME) --out DIR
    [--arg A]... [--mark-export MOD:EXPORT=ID]... [--thread TID]...
    [--exclude MODULE]... [--duration SECONDS] [--paranoid] [--capture-values]
```

| Option | Effect |
|--------|--------|
| `--spawn PROGRAM` | Spawn suspended, inject the agent, resume. Stalking is armed at the image entry point (read from the PE header), so the ntdll/kernel32 thread-start handoff runs native. |
| `--attach PID_OR_NAME` | Attach to a running process. **`--thread TID` is required**: Frida's own threads are indistinguishable from the target's. |
| `--arg A` | Command-line argument for the spawned program (repeatable). |
| `--mark-export MOD:EXPORT=ID` | Hook `MOD!EXPORT`; on every call emit `MARK ID` and print the first four arguments. Enables `--at mark=ID`. |
| `--exclude MODULE` | Additional module to exclude from stalking (appended to the default list: ntdll, kernel32, kernelbase, ucrtbase, msvcrt, vcruntime140, user32, gdi32, gdi32full, win32u, combase, rpcrt4, sechost, advapi32). |
| `--duration S` | Stop after `S` seconds; otherwise Ctrl-C. |
| `--paranoid` | `trustThreshold = -1`: re-instrument every block on every execution. Correct for hostile SMC; 10–100× slower on loops. |
| `--capture-values` | Emit `VALUE` records (agent option; not consumed by v0.2 replay). |

Lifecycle: `configure()` → `mark_export()`… → `start()` → wait → `stop()` (drains to disk). If the
target exits first, the agent's `ExitProcess`/`RtlExitUserProcess` hook drains and blocks for a
`drain-ack` from the host, so one-shot CLI targets still leave a bundle. Host-side messages
`[atropos] following thread`, `code rewritten at … -> version N`, `mark N at EXPORT` narrate progress.

What the agent records per executed block: one `BLOCK`; per instruction with memory operands a `MEM`
per access in *canonical order* (explicit operands in Capstone order, then the implicit stack access);
`REP` before a `rep`-prefixed string op (RCX, RSI, RDI, DF); `SHIFTCNT` before a `shl/shr/… r, cl`
(CL & 0x3F); `SUMMARY` on leaving a hooked API; `MARK`; `VERSION` when a `VirtualProtect`/
`VirtualAlloc`/`NtProtectVirtualMemory`/`NtAllocateVirtualMemory` call touches a page holding
already-instrumented code (then every known block is invalidated so it re-registers under the new
version); `THREAD` when a thread starts being followed.

Agent limitations in v0.2: `DF` in `REP` records is always 0 (Frida does not surface it on x64);
sampled block re-hashing (`hashSampleRate`) is a hook point, not implemented; `ABORT` is not emitted.

---

## 11. The trace bundle

```
run.atrace/
    meta.json     {"format_version":1,"arch":"x86_64","os":"windows","capture":{...},"modules":[{name,base,size,path}]}
    code.bin      "ATRC" + u16 version + u16 reserved, then CTAG_BLOCK / CTAG_MODULE records
    trace.bin     "ATRT" + header, then tagged records
```

Primitives: LEB128 `uvarint`, zig-zag `svarint`, length-prefixed `blob`/`string`.

**code.bin.** `CTAG_BLOCK=0x01`: `block_id, code_version, start_address, n, blob×n` (one blob per
instruction, raw bytes). `block_id` is globally unique across code versions — *code is keyed by
`(address, code_version)`, never by address alone.* `CTAG_MODULE=0x02`: `name, base, size, path`.

**trace.bin** tags:

| Tag | Name | Payload | Replay meaning |
|-----|------|---------|----------------|
| 0x01 | `BLOCK` | `block_id` | Flush the pending block; start accumulating this one. |
| 0x02 | `MEM` | `insn_index, Δea (svarint), size (u8), rw (u8: 1 read, 2 write, 3 both)` | One resolved access of the pending block's instruction `insn_index`. EA is delta-coded against the previous MEM. |
| 0x03 | `VERSION` | `version` | The stream's code version from here on. |
| 0x04 | `THREAD` | `tid` | Subsequent nodes carry this tid. |
| 0x05 | `ABORT` | `n` | The pending block executed only its first `n` instructions. |
| 0x06 | `MARK` | `id` | Anchor: `mark=id` resolves to the next node. |
| 0x07 | `SUMMARY` | `id, n, arg×n` | Apply summary `id` with those argument values now. |
| 0x08 | `REP` | `rcx, rsi, rdi, df` | Pre-state of the next `rep` string op. |
| 0x0B | `REP_POST` | same | Post-state (for `repe/repne`, to learn the iteration count). |
| 0x09 | `SHIFTCNT` | `count` | CL&0x3F for the next variable shift in the block. |
| 0x0A | `VALUE` | `slot, blob` | Captured value; ignored by structural replay. |

Full normative detail: [`trace-format.md`](trace-format.md).

---

## 12. Python API

Everything below is importable from `atropos` unless a module path is given.

### 12.1 Pipeline

```python
from atropos import analyse_path, analyse, Analysis, TraceBundle, ReplayOptions

analysis = analyse_path("run.atrace")                         # TraceBundle + analyse()
analysis = analyse(TraceBundle("run.atrace"),
                   options=ReplayOptions(expand_rep=False, max_rep_expansion=65536,
                                         track_values=False, strict=False),
                   summaries=None,          # SummaryTable; default table if None
                   skip_control=False,      # True: no CFG pass (fuzz loop)
                   force_control=False)     # emit control edges in flattened functions
```

`Analysis` fields: `result: ReplayResult`, `control: ControlFlowAnalysis | None`,
`timings: dict[str, float]`. Properties: `.ddg`, `.bundle`, `.integrity`, `.stats`. Method:
`.precision_banner() -> list[str]`.

`ReplayResult` fields: `ddg: DDG`, `shadow: ShadowState`, `integrity: IntegrityReport`,
`block_runs: list[BlockRun]`, `bundle`, `model: EffectModel`, `stats: dict` with keys
`instructions, blocks, mem_accesses, rep_bulk, rep_expanded, summaries, shift_zero_count`.

### 12.2 Criteria

```python
from atropos import build_criterion, Criterion, Location, CriterionError
from atropos.criterion import parse_location, parse_point, resolve_point, resolve_address

crit = build_criterion("mark=1", ["mem=0x40000+8", "rax"], analysis.result)  # -> Criterion
crit = Criterion(seq=10, locations=[Location(SPACE_MEM, 0x40000, 8)], description="manual")
```

`Location(space, loc, length)`; `SPACE_REG=0`, `SPACE_MEM=1` from `atropos.ddg`. Register lanes come
from `atropos.arch.lanes.lookup(name).lane`.

### 12.3 Slicing

```python
from atropos import backward_slice, forward_slice, chop, MODES, SliceMode, SliceResult, InputLeaf

r = backward_slice(analysis.result, crit, MODES["value+addr"],
                   max_nodes=None, max_control_depth=None)
r = forward_slice(analysis.result, crit, MODES["value"], max_nodes=None)
r = chop(analysis.result, source_crit, sink_crit, MODES["value"])
```

`SliceMode(name, follow_value=True, follow_addr=False, follow_control=False)`; custom modes are
allowed. `SliceResult`: `nodes: list[int]` (sorted), `inclusions: dict[int, Inclusion]`,
`inputs: list[InputLeaf]`, `truncated`, `truncation_reason`, `stats`; `len(r)`, `r.contains(seq)`.
`Inclusion(seq, via_seq, kind, space, loc, length, control_depth).render(ddg)` gives the "why".
`InputLeaf(space, loc, length, used_by, kind).render()`.

`atropos.slicer.resolve_criterion_defs(result, seq, location)` → `[(def_seq, space, start, length)]`
runs, `def_seq == LIVE_IN` for unwritten bytes.

### 12.4 The graph

`DDG` (from `atropos.ddg`) is a column store. Node columns indexed by `seq`: `node_addr`,
`node_block` (−1 for summaries), `node_index`, `node_version`, `node_tid`, `node_flags`,
`node_ctrl` (guard seq or `LIVE_IN`), `node_edge_start`, `node_def_start`. Edge columns:
`edge_def`, `edge_space`, `edge_loc`, `edge_len`, `edge_kind`, `edge_flags`. Def columns:
`def_space`, `def_loc`, `def_len`. Side tables: `marks: [(id, seq)]`, `version_changes: [(seq, v)]`,
`summary_nodes: {seq: name}`, `summary_kinds: {seq: kind}`, `notes`.

Accessors: `n_nodes`, `n_edges`, `edge_range(seq)`, `def_range(seq)`, `edges_of(seq) -> [Edge]`,
`defs_of(seq)`, `edge_at(i, use_seq)`, `guarding_branch(seq)`, `occurrence_index()` (cached
`array`), `edge_kind_histogram()`, `flag_histogram()`, `approx_bytes()`.

Constants: `KIND_VALUE=0, KIND_ADDR=1, KIND_CONTROL=2`; edge flags `EF_IMPRECISE=1, EF_BULK=2,
EF_SUMMARY=4`; node flags `NF_BULK=1, NF_IMPRECISE=2, NF_SUMMARY=4, NF_SUSPECT=8,
NF_CD_UNRELIABLE=16, NF_ABORTED=32`; `format_node_flags(flags)`.

### 12.5 Output

```python
from atropos.output import (ListingOptions, render_listing, render_inputs,
                            to_dot, to_json, to_bridge_json, write_scripts, IDA_SCRIPT, GHIDRA_SCRIPT)
text = render_listing(analysis, r, ListingOptions(show_why=True, show_flags=True, fold_loops=False,
                                                  fold_threshold=3, max_lines=None))
text = render_inputs(analysis, r)
dot  = to_dot(analysis, r, collapse=True, show_control=True)
js   = to_json(analysis, r)
br   = to_bridge_json(analysis, r)
paths = write_scripts("bridge/")
```

### 12.6 Lower layers

- `atropos.arch.lanes`: `lookup(name) -> RegSlot(name, lane, size, parent_lane, parent_size, kind)`,
  `lane_name(lane)`, `render_range(lane, len)`, `flag_lane(bit)`, `flag_mask_to_lanes(mask)`,
  constants `FLAG_ZF` etc., `N_LANES = 2640`.
- `atropos.arch.effects`: `EffectModel(strict=False).effects_for(raw) -> Effects`,
  `.disassemble(raw, address) -> (mnemonic, op_str)`, `DEFAULT_MODEL`. `Effects` fields:
  `reg_value_uses`, `reg_addr_uses`, `reg_defs` (tuples of `(lane, length)`), `flag_uses/defs/maydefs`
  (bit masks), `mem: (MemAccess,…)`, classification booleans, `element_size`, `branch_target`,
  `notes`; `.describe()`.
- `atropos.shadow`: `ShadowState().regs/.mem` with `read_runs(loc, len) -> [(writer, start, run)]`,
  `write(loc, len, seq)`, `writer_of(loc)`; `ShadowMemory.release(addr, len)`; `LIVE_IN = -1`.
- `atropos.replay`: `Replay(bundle, model, options, summaries).run()`, `replay(bundle, …)`.
- `atropos.cfg`: `analyse_control_flow(result, force)`, `build_control_flow`,
  `attribute_control_dependence`, `compute_ipdom(FunctionCFG)`, `ControlFlowAnalysis` (with the four
  tunable flattening thresholds), `FunctionCFG`.
- `atropos.integrity`: `IntegrityReport` (`error()`, `note()`, `n_errors`, `n_notes`, `status`,
  `banner()`, `render(limit)`, `findings`, `max_findings=200`), `check_continuity(result)`.
- `atropos.summaries`: `Summary(id, name, kind, reads, writes, defines_rax, n_args, max_bytes)`,
  `Ref(ptr, length, scale)`, `UnknownCall`, `SummaryTable` (`default()`, `add`, `get`, `by_name`,
  `ids`), `ARG_REGS`, `SUMMARY_ADDRESS_BASE`.
- `atropos.bundle`: `TraceBundle(path)` (`meta`, `blocks: {id: BlockDescriptor}`, `modules`,
  `records()`, `module_for(addr)`, `rebase(addr)`), `BundleWriter(path, meta)` (`add_block`,
  `add_module`, `emit_block`, `emit_mem`, `emit(tag, *uvarints)`, `emit_bytes`, `close()`; context
  manager), `BlockDescriptor`, `InsnDescriptor`, `Module`, `Record`.
- `atropos.format`: tags, `ByteWriter`, `ByteReader`, `encode_uvarint`, `zigzag_*`, `read_header`,
  `write_header`, `TraceFormatError`.
- `atropos.testkit`, `atropos.oracle`, `atropos.examples`: §14.

---

## 13. Source tree walkthrough

```
agent/atropos-agent.js       Frida capture agent (JS, runs in the target)
src/atropos/
    __init__.py              public API re-exports, __version__
    __main__.py              python -m atropos
    cli.py                   argparse verbs: info / verify / slice / demo
    analysis.py              the pipeline: replay -> continuity -> control flow
    format.py                varint / tag encoding
    bundle.py                on-disk bundle reader/writer
    arch/lanes.py            storage model (byte lanes, flag bits)
    arch/effects.py          the x86-64 effect model (Capstone + overrides)
    shadow.py                last-writer maps (dense regs, sparse paged memory)
    ddg.py                   column-store dependence graph
    replay.py                forward pass: records -> DDG
    cfg.py                   CFG recovery, post-dominance, control attribution, flattening
    slicer.py                backward / forward / chop
    criterion.py             --at / --loc parsing and resolution
    summaries.py             API effect summaries
    integrity.py             integrity report + continuity check
    output/listing.py        listing + input report
    output/graph.py          DOT + JSON
    output/bridge.py         IDA/Ghidra bridge JSON + loader scripts
    capture.py               host driver for the agent (only importer of frida)
    testkit.py               assembler + MiniVM + bundle builder
    oracle.py                independent second slicer + fuzzer
    examples.py              the three demo workflows
tests/                       152 pytest tests
docs/                        design, review, format, semantics, control, summaries, this file, theory
```

### 13.1 `format.py`

Pure encoding. `encode_uvarint` (LEB128; rejects negatives), `zigzag_encode/decode`,
`ByteWriter` (chainable `u8/uvarint/svarint/blob/string/raw`), `ByteReader` (index-based, raises
`TraceFormatError` on truncation, on varints longer than 10 bytes, and on blobs past the end),
8-byte section header `<4sHH` with magic `ATRT`/`ATRC` and `FORMAT_VERSION = 1`.

### 13.2 `bundle.py`

`BundleWriter` is deliberately unvalidating; `TraceBundle` reads `code.bin` eagerly into
`blocks` (rejecting duplicate `block_id`s and unknown tags) and merges module entries from both
`meta.json` and `CTAG_MODULE` records. `records()` yields a *single reused* `Record` object — callers
must copy what they keep. Memory EAs are reconstructed from deltas during iteration.

### 13.3 `arch/lanes.py`

Lane space (2 640 lanes): GPR 0–127 (16×8), FLAG 128–143, VEC 144–2191 (32×64, ZMM width), SEG
2192–2239, MMX 2240–2303, X87 2304–2383, EXTRA 2384–2639. `RIP` is intentionally absent.
`REGISTRY` maps every name to a `RegSlot`; unknown names get deterministic EXTRA slots (first-seen
order; after 32 distinct names, folded onto the last slot and recorded in `EXTRA.overflowed`).
`render_range` collapses `(lane,len)` back to `rax`/`eax`/`ax`/`al`/`ah`/`rbx[2:5]`/`ZF|CF`.

### 13.4 `arch/effects.py`

`EffectModel._compute(raw)` decodes at a synthetic address (0x1000) with Capstone detail on, then:

1. Explicit operands: register reads → `reg_value_uses`; register writes → `reg_defs` widened by
   `_def_range` (32-bit GPR write → all 8 lanes; VEX/EVEX vector write → full 64 lanes; everything
   else → own lanes only). Memory operands: base/index → `reg_addr_uses` (or `reg_value_uses` for
   `lea`), segment → `reg_addr_uses`, and one `MemAccess(index, size, reads, writes)` unless `lea`.
2. Implicit registers from `regs_read`/`regs_write` (skipping `rflags`/`rip`).
3. Flags: Capstone's `eflags` mask → `flag_uses` (TEST/PRIOR), `flag_defs` (MODIFY/SET/RESET),
   `flag_maydefs` (UNDEFINED; wins over defs).
4. Classification: call/ret/jump groups, conditional iff it reads a flag or is `jrcxz/jecxz/loop*`,
   indirect iff any operand is non-immediate, syscall (`syscall/sysenter/int`), `branch_target` for
   immediate targets.
5. Implicit stack access appended for `push/pop/call/ret/retf/leave/pushf(q)/popf(q)`, with `rsp`
   as an address use.
6. String ops: `is_string_op`, `element_size`, `is_rep` (prefix in mnemonic or `insn.prefix`); a
   `rep` drops its explicit `MemAccess`es (bulk model) and notes `rep:bulk`.
7. Overrides (`_apply_overrides`): `nop/endbr64/pause` → no effect; zeroing idioms (`xor/sub/pxor/
   vpxor/xorps/…/pcmpeq*/psub*` with identical sources) → drop the value uses of those registers;
   `and r, 0` / `imul …, 0` / `or r, -1` → drop all value uses; `cmovcc` → add the destination as a
   value use; `xchg r, r` → note only. `sbb r, r` is deliberately *not* an idiom.
8. `is_shift_by_cl` for `shl/shr/sar/sal/rol/ror/rcl/rcr/shld/shrd` reading `cl`.

Effects are cached by raw bytes. Undecodable bytes yield `(bad)` with note `undecodable` (or raise
`UnsupportedInstruction` if `strict`).

### 13.5 `shadow.py`

`ShadowRegisters.lanes` is one `array('q')` of 2 640 entries. `ShadowMemory.pages` is
`{page_no: array('q')[4096]}`, allocated on first touch, released by `release()` only for pages fully
inside a freed range. Both expose `read_runs`, which splits a byte range into maximal runs of equal
writer — the mechanism behind "a multi-byte read has multiple definitions".

### 13.6 `replay.py`

`Replay.run()` streams records, accumulating `MEM`/`REP`/`SHIFTCNT`/`ABORT` for the pending block and
flushing on the next `BLOCK`/`VERSION`/`THREAD`/`MARK`/`SUMMARY`. `_execute_block` groups MEM records
by `insn_index`, checks the count against `eff.mem` (error on mismatch), honours `ABORT`, and calls
`_execute_insn` or `_execute_rep` per instruction, appending a `BlockRun(block_id, first_seq,
n_executed, aborted)`.

`_execute_insn`: for a variable shift, no `SHIFTCNT` → `NF_IMPRECISE` + note; count&0x3F == 0 →
suppress all defs and flag effects. Then **reads first** (register value uses, address uses, flag
uses, memory reads — each split into runs → edges, with `EF_IMPRECISE` if any lane read is currently
undefined), **then writes** (register defs clear the undefined bit; `flag_maydefs` set it; memory
writes). This ordering makes read-modify-write correct with no special case.

`_execute_rep`: count = RCX (or RCX − RCX_post for `repe/repne`); computes `[src, src+count×size)` and
`[dst, …)` honouring DF; emits `EF_BULK` reads and a single bulk def per the mnemonic family
(`movs`: read src, write dst; `stos`: write; `lods/scas`: read; `cmps`: read both); count 0 → no
defs at all (registers untouched).

`_apply_summary`: looks up the id (note + ignore if unknown) and calls `Summary.apply`.

### 13.7 `cfg.py`

**Pass 1 `build_control_flow`.** Walks `block_runs`, opening a new `FunctionCFG` after a `call`
terminator (reusing an existing one if the entry block is known) and popping the function stack after
a `ret`. Intra-function successor edges are added between consecutive runs. Each function then gets
`ipdom` via `compute_ipdom` — Cooper–Harvey–Kennedy on the reversed graph with a virtual exit joined
to every block without observed successors (or, in a closed loop, to the most-predecessor block) —
and is run through `_detect_flattening`.

**Flattening heuristic** (all required; function ≥5 blocks, ≥4 branching blocks): one block is the
ipdom of ≥60 % of branching blocks (conditional *and* unconditional), has in-degree ≥4, and is a
successor of ≥50 % of other blocks. Then `cfg.flattened = True`, a note is recorded, and unless
`--force-cd` no control edges are attributed in that function (nodes get `NF_CD_UNRELIABLE`).

**Pass 2 `attribute_control_dependence`.** A stack of `(branch_seq, ipdom_block, depth)`. On entering
a run: pop entries from deeper frames, pop entries whose ipdom is this block at this depth; the top
(if any) guards every instruction of the run. On leaving: `call` → depth+1; `ret` → depth−1 and pop
deeper entries; conditional branch (not suppressed) → push with its ipdom. Aborted runs drop entries
at or above the current depth.

### 13.8 `slicer.py`

Frontier keyed by `seq`. Seeding uses `resolve_criterion_defs`, a forward scan over the def columns up
to and including `seq`, producing per-byte writers split into runs. The walk pops a node, scans its
edge range, follows allowed kinds, records `Inclusion`s and `InputLeaf`s, and (if the mode allows)
enqueues the node's guard with `control_depth + 1`. Caps set `truncated`. Termination is structural
(every edge points strictly backward). `forward_slice` builds a def→users index on demand. `chop`
intersects.

### 13.9 `criterion.py`

Regex-based parsing (`_MEM_RE`, `_RANGE_RE`, `_ADDR_RE`); `resolve_address` matches module names by
equality or prefix; `resolve_point` scans `node_addr` linearly for `addr=` points.

### 13.10 `summaries.py`

`Summary.apply(replay, args)` adds a node at pseudo-address `0x7FFF_0000_0000_0000 + id`, block −1,
flagged `NF_SUMMARY`; emits `KIND_ADDR|EF_SUMMARY` edges from the argument registers (`rcx, rdx, r8,
r9`); emits `KIND_VALUE|EF_SUMMARY` read edges for each `reads` ref; for `free`, releases shadow
pages; otherwise defines each `writes` ref and (if `defines_rax`) `rax`. Sizes are capped at
`max_bytes` (64 MiB) with a note. `UnknownCall` defines only `rax`, marks `NF_IMPRECISE`, and notes
"crossed unmodelled external call". The default table has 24 entries with **stable, append-only ids**
(see §16 for a defect in how `Ref` lengths resolve).

### 13.11 `integrity.py`

`IntegrityReport` caps retained findings at 200 but counts all. `check_continuity` rejects a
transition from a *fully executed* block whose terminator is not a call/ret/indirect/syscall and whose
next block starts at neither the fall-through nor the (re-decoded at the real address) direct target.

### 13.12 `output/`

Described in §8. `listing._fold` collapses addresses with ≥ `fold_threshold` instances;
`_classify_input` uses the module map; `_merge_adjacent` coalesces byte leaves.

### 13.13 `capture.py` and the agent

`Capture` wraps a Frida session: `spawn`/`attach` → `_inject` → `configure` → `mark_export` →
`start` → `stop` (tolerating a target that already exited and drained). See §10 for the agent's
behaviour; the agent mirrors `format.py` in `ByteBuffer` and `SummaryTable.default()` ids in
`SUMMARIES` (13 hooks in the agent vs 24 host-side entries; the host ignores nothing, the agent simply
hooks a subset).

---

## 14. Testing infrastructure

```bash
pytest            # 152 tests in ~1.5 s, no Frida, no target
pytest -k oracle  # the differential layer only
```

| File | Covers |
|------|--------|
| `test_format.py` | varint/zig-zag round trips, truncation and overlong rejection |
| `test_effects.py` | every override rule, asserting on lane ranges directly |
| `test_replay.py` | byte-lane worked example, multi-def reads, partial overwrite, decode-loop isolation, address/value separation, idioms, `lea`, zero-count shifts, `rep` bulk/zero, RMW |
| `test_control.py` | ipdom on diamond/chain/closed loop, loop-body guards, no leak across `ret`, flattening detection and `--force-cd` |
| `test_integrity.py` | clean trace, discontinuity, MEM-count mismatch, version disagreement, unknown block, abort, finding cap |
| `test_oracle.py` | differential agreement on chain/idiom/sub-register/zero-shift/`lea` and a seeded fuzz loop |
| `test_slicer.py` | criterion parsing, address points, module rebasing, backward/forward/chop, DAG property, all four output formats, the three workflows, bridge summary exclusion |

### 14.1 `testkit.py`

- `Assembler` / `assemble(text)`: a hand-written encoder for the fixture subset (`mov` in all
  reg/imm/mem forms, the 8 ALU ops, `inc/dec/test/lea/shl/shr` (by `cl`), `push/pop/ret/call/jmp/
  jz/jnz`, `rep_movsb`/`rep_stosb`, `nop/cqo`). Raises `AssemblyError` on anything else. Branch
  operands `@label` are patched by `Program.link()`.
- `MiniVM`: a concrete interpreter for the same subset, producing *real* effective addresses and its
  own `writes` log.
- `Program`: `block(name, [lines])` lays out blocks contiguously from `base_address` (default
  `0x14001000`, module `target.exe`); `run(order, vm)` executes the named blocks in the given order
  (control flow is *supplied*, not inferred) and records `ExecutedBlock`s.
- `build_bundle(path, program, order, vm, marks={pos: id}, summaries=[(pos, id, args)],
  code_version)` → `(TraceBundle, MiniVM)`: writes a bundle the host cannot tell from a real capture.

### 14.2 `oracle.py`

`run_oracle(program, order, vm)` computes per-step read/write sets *longhand* (`_effects_of`, with
no shared logic with the effect model), `oracle_slice(trace, step, location)` slices by direct
simulation, and `differential_check(program, order, location, tmp_path, memory)` returns
`(expected, actual)` node sets — compared in `value+addr` mode because the oracle does not distinguish
address uses. `random_program(rng, length)` generates straight-line fixtures. A 300-seed run with
`length=40` produced zero mismatches in the test pass behind this document.

---

## 15. Extending Atropos

**Add an effect-model override.** Edit `_apply_overrides` in `arch/effects.py`; add a unit test in
`tests/test_effects.py` asserting on lane ranges; if the fixture subset can express it, add a
differential test.

**Add an API summary.** Append a `Summary` with a *new* id to `SummaryTable.default()`; add the hook
to `SUMMARIES` in the agent with the same id and argument count; add a fixture. Never renumber.

**Add a fixture instruction.** Extend `Assembler` (`_asm_<mnem>`), `MiniVM._step`, and — if it should
be fuzzed — `oracle._effects_of` and `random_program`.

**Add an output backend.** Consume `SliceResult` + `Analysis`; use `ddg.occurrence_index()`,
`bundle.rebase()`, `model.disassemble(raw, address)` for text, and always include
`analysis.precision_banner()`.

**Another architecture.** The seam is `arch/`: replay, DDG, slicer and outputs are defined over
abstract lanes and never name an x86 register.

---

## 16. Test pass: findings and known issues

The following were established by an extensive test pass (test suite, 300-seed differential fuzz, all
CLI verbs/options/formats/directions/modes, every criterion syntax and error path, four hand-corrupted
bundles, 46 instruction encodings through the effect model, the Python API, the real bundles in the
repository, and a 210 000-node synthetic scale run).

### 16.1 Verified working

- 152/152 tests pass; 300 additional fuzz seeds agree with the oracle.
- All four modes give the expected, distinct node sets on the decode-loop fixture (4 / 10 / 9 / 15).
- Backward, forward and chop; `seq=`, `addr=…@k`, `addr=module+rva`, `mark=`; register, sub-register,
  `ah`, lane range, flag and memory locations; multiple `--loc`.
- `listing` (with `--fold-loops`, `--max-lines`, `--no-why`), `dot` (collapsed and not), `json`,
  `bridge` + `--write-scripts` (both scripts parse as Python).
- `--max-nodes` / `--max-control-depth` truncate and say so.
- Integrity: discontinuity and MEM-count mismatch are detected, `slice`/`info` refuse (exit 2),
  `--allow-suspect` overrides, `verify` exits 1. Truncated and wrong-magic files are rejected.
- Flattening: the dispatcher fixture is reported "unavailable", nodes carry `cd-unreliable`, and
  `--force-cd` restores attribution.
- `rep movsb` bulk node with `bulk` edge, zero-count `shl` defined nothing, `memcpy` and
  `GetVolumeInformationW` summaries appear as nodes/leaves.
- Effect model: 32-bit zero-extension, 8/16-bit partial writes, `ah`, VEX vs legacy SSE widening,
  zeroing idioms (`xor/sub/pxor/vpxor`; `sbb` correctly not), `and …,0`, `or …,-1`, `imul …,0`,
  `lea`, `cmovcc`, per-condition flag masks (`jz`→ZF, `jl`→SF|OF), stack implicit accesses in
  canonical order, `call [rax]` two accesses, `gs:` segment as address use, `syscall`, `cpuid`,
  `rdtsc`, `popfq`, undecodable bytes.
- Performance: ~63 000 instructions/s replay (Python 3.10, this machine); 210 005 nodes / 300 003
  edges in 3.35 s total; DDG ≈ 135 bytes/node; backward `value` slice 0.08 s, `full` slice of a
  30 000-iteration loop (120 003 nodes) 0.32 s.

### 16.2 Defects found

| # | Severity | Where | Finding |
|---|----------|-------|---------|
| 1 | **High** | `summaries.py` `Ref.resolve` + `SummaryTable.default()` | `Ref.length` is treated as a *literal byte count* whenever it is an `int`, and as an *argument index* only when it is a `str`. The default table (and `docs/summaries.md`'s `Ref(3, 4)` example) uses ints as argument indices. Consequently `memcpy`/`memmove`/`memset`/`RtlMoveMemory`/`strcpy` read/write **2 or 1 bytes**, `ReadFile`/`BCryptGenRandom`/`NtReadFile` write 2, `VirtualAlloc`/`HeapAlloc` define 1–2, `CryptEncrypt`/`CryptDecrypt` touch 4, etc. Only summaries whose length really is a literal (`GetVolumeInformationW` = 8) behave as intended. Observed on the real `crack.atrace` (`RtlMoveMemory` reading `+2`) and on a synthetic `memcpy(dst, src, 16)` which covered `+2`. Fix: make the table use `"2"`-style indices (or add an explicit `arg=`/`bytes=` distinction to `Ref`) and update the doc. |
| 2 | Low | `cli.py` `cmd_demo` | `--workflow` has no `choices=`; an unknown name raises a raw `KeyError` (exit 1). |
| 3 | Low | `cli.py` `main` | Only `FileNotFoundError` is caught; a corrupt `code.bin`/`trace.bin` surfaces `TraceFormatError` as a traceback (exit 1) instead of `error: …` (exit 2). |
| 4 | Cosmetic | `slicer.py` `forward_slice`/`chop` | `stats` lack `reduction`, so the listing header prints `0.0% discarded`. |
| 5 | Design gap | `slicer.py` `forward_slice` | `--loc` is accepted but ignored; the forward seed is the whole node at `--at`. |
| 6 | Cosmetic | `slicer.py` `backward_slice` | `--max-nodes` is enforced during the walk only; criterion seeds always enter (e.g. 4 seeds with `--max-nodes 2`). |
| 7 | Cosmetic | `integrity.py` `check_continuity` | The message uses `prev_block.end_address`, which can equal `next.start_address`, giving "target.exe+0xc does not reach target.exe+0xc" for an unconditional jump that fell through. Reporting the terminator's address would be clearer. |
| 8 | Low | `output/bridge.py` `IDA_SCRIPT` | Calls `idaapi.get_imagebase()` without `import idaapi`; works only because IDAPython pre-imports `idaapi` into the script namespace. |
| 9 | Env | `capture.py` | On Python 3.10 with current Frida, `import frida` fails on `typing.NotRequired`; the wrapped message says "pip install frida", which misleads. Requires 3.11+ (or an older Frida). |
| 10 | Doc drift | `README.md` | Says 151 tests; there are 152. |
| 11 | Status | real bundles in repo | `run/crack/crack2/crack3.atrace` contain 12 instructions in `ntdll.dll` plus 88 `RtlMoveMemory` summaries — the excluded-module and entry-point hooking path did not yet trace the target image (milestone M6 is marked as next in the README). `pwdtoytest2.atrace` has zero blocks and 1 011 summary nodes. Both load and slice without error. |
| 12 | Agent gap | `atropos-agent.js` | `REP.df` is always 0; `maybeRehash` is a stub; no `ABORT` emission; agent hooks 13 of the 24 host summaries. All are commented in the source. |

Items 1–3 are the ones worth fixing before the next real-target capture; item 1 changes slice results
through any hooked memory-moving or I/O API.

---

## 17. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `�` in listings on Windows | Console code page. `set PYTHONIOENCODING=utf-8` or `chcp 65001`. |
| `Refusing to slice a suspect trace` | Integrity errors. Run `atropos verify` to see them; re-capture; or `--allow-suspect` if you understand the finding. |
| `control dependence: unavailable in N function(s)` | Flattening detected; `value+ctrl`/`full` omit control edges there. `--force-cd` overrides (results will be noisy). |
| Slice bottoms out in "memory not written during the trace" inside a buffer an API filled | No summary for that API (or, in v0.2, defect §16.2 #1). Add/fix a summary. |
| Slice through `memcpy`-like loop is huge | `rep` bulk model. `--expand-rep` currently only annotates; slice one destination byte in `value` mode and accept the bulk range, or avoid `value+addr`. |
| `capture needs the frida package` although it is installed | Python 3.10 + new Frida (§2). |
| `no target thread to follow` on `--attach` | Pass `--thread TID`. |
| `code rewritten at 0xffffffffffffffff` | Old agent bug with Nt* argument positions; fixed in the current agent (reads out-parameters on return). |
| `addr=` point "never executed" | Wrong module base (ASLR): use `module+0xRVA`, not an absolute address from a different run. |

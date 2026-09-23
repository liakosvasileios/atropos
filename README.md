# Atropos

**Backward dynamic program slicing for Windows x86-64 reverse engineering.**

> *Atropos — the Moira who cuts the thread. A slicer cuts one thread of computation out of a whole
> execution.*

Atropos answers one question about a single concrete execution:

> For this value, at this point in the run, which instructions actually contributed to producing it —
> and which inputs did it ultimately depend on?

Give it a trace and a value. It gives you back the sub-sequence of the executed instructions that
mattered, the dependence structure connecting them, and — usually the part you actually wanted — the
list of inputs the chain bottomed out on.

```
$ atropos slice run.atrace --at mark=1 --loc mem=0x30002+1

ATROPOS backward slice  —  criterion #32 {[0x30002..+1]}  (mark=1)
mode: value   |   4 of 33 instruction instances (87.9% discarded)
------------------------------------------------------------------------------
  trace integrity: OK
  control dependence: 1 function(s) analysed, no flattening detected
==============================================================================

  #3    target.exe+0x1e    mov dl, 0x5a
          <- defines dl used by #19 (value)
  #18   target.exe+0x20    mov al, byte ptr [rsi]        [occ=2]
          <- defines al used by #19 (value)
  #19   target.exe+0x22    xor al, dl                    [occ=2]
          <- defines al used by #20 (value)
  #20   target.exe+0x24    mov byte ptr [rdi], al        [occ=2]
          <- slicing criterion

INPUTS — where this value ultimately came from
------------------------------------------------------------------------------
  immediate constants in the code  (1)
      #3  target.exe+0x1e   mov dl, 0x5a
  memory not written during the trace (initial state or untraced writer)  (1)
      [0x20002..+1] read by #18 (value)
```

Four instructions out of thirty-three. The other three iterations of the decode loop, all the pointer
arithmetic and all the loop control are gone, because none of them contributed to *that byte*.

---

## Why dynamic

Static slicing reasons over every possible execution, from the code. On packed, obfuscated,
self-modifying or indirect-branch-driven binaries that degrades badly: control flow is recovered
incorrectly, indirect calls fan out to everything, and self-modifying code invalidates the disassembly
the whole analysis rests on.

A dynamic slice sidesteps all of it. It only ever reasons about instructions that actually ran, with
concrete addresses and concrete values. The classic hard problem of static slicing — *does `[rax]` alias
`[rbx]`?* — simply evaporates: at run time both resolved to a number, and two accesses alias if and only
if their byte ranges overlap.

The trade is the usual one: soundness for one run instead of coverage of all runs. For reverse
engineering that is the right trade, because you are explaining an observed behaviour, not proving a
property.

---

## Install

```bash
pip install -e .          # capstone is the only hard dependency
pip install -e .[capture] # add frida, if you want to record your own traces
pip install -e .[dev]     # add pytest
```

Everything offline — replay, slicing, output, the entire test suite — runs on any platform. Only
recording a new trace needs Frida and a Windows target.

Try it with no target at all:

```bash
atropos demo --workflow xor-decoder
atropos demo --workflow key-derivation
atropos demo --workflow self-modifying
```

---

## Use

### 1. Record

```bash
python -m atropos.capture --spawn target.exe --out run.atrace \
    --mark-export advapi32.dll:CryptEncrypt=1
```

`--mark-export` hooks an export and drops an anchor at every call, so you can name the criterion as
`--at mark=1` without having to find a sequence number by hand.

### 2. Look

```bash
atropos info run.atrace       # what's in it, and how much to trust it
atropos verify run.atrace     # integrity checks only
```

### 3. Slice

```bash
atropos slice run.atrace \
    --at mark=1 \
    --loc mem=0x7ff6c0001000+16 \
    --mode value
```

**Points** (`--at`): `seq=41792`, `addr=target.exe+0x1a2f@3` (the 4th execution), `mark=7`.

**Locations** (`--loc`, repeatable): `rdx`, `eax`, `ah`, `rbx[0:3]`, `zf`,
`mem=0x7ff6c0001000+16`.

**Modes** (`--mode`):

| Mode | Follows | The question it answers |
|------|---------|-------------------------|
| `value` *(default)* | value edges | What arithmetic made this value? |
| `value+addr` | + address edges | …and what computed the pointers it came through? |
| `value+ctrl` | + control edges | …and what decided we would compute it? |
| `full` | everything | The complete picture, and the largest. |

Start with `value`. Reach for `value+addr` when the question is specifically about a pointer — *who
controlled this indirect call target* — and for `ctrl` when it is about a decision, like a comparison
against a derived key.

### 4. Get it into your disassembler

```bash
atropos slice run.atrace --at mark=1 --loc rdx \
    --format bridge --write-scripts ./bridge > slice.json
```

Then run `bridge/atropos_ida.py` or `bridge/atropos_ghidra.py` and pick `slice.json`. The slice arrives
as colour and comments in the database you already have, with your names and your structs, rebased onto
whatever address the image loaded at this time.

Other formats: `--format listing` (default), `--format dot` (Graphviz; loops collapse to one node with a
repeat count), `--format json`.

---

## Two workflows

### Crypto key derivation

The criterion is the buffer handed to an encrypt call. The slice walks back through the KDF and the
input report names what fed it:

```
INPUTS — where this value ultimately came from
  environmental (from outside the process)  (1)
      #3  GetVolumeInformationW  [source]
  immediate constants in the code  (2)
      #2  target.exe+0x14   mov rcx, 5
      #5  target.exe+0x21   mov rdx, 0x9e3779b9
```

`key = f(volume serial, hardcoded 0x9e3779b9)`. That report is the deliverable; the instruction listing
above it is supporting detail.

### Unpacking

The criterion is a byte in the region the loader is about to jump into. The slice isolates the
decode loop that produced it and the source bytes it read, discarding the anti-analysis noise around it.
Capture watches for pages that become writable and are later executed, and marks them automatically.

---

## How it works

Two phases, deliberately separated.

```
  TARGET PROCESS                         HOST
  ┌────────────────────┐                 ┌──────────────────────────────┐
  │ Frida Stalker      │   trace bundle  │ decode (Capstone)            │
  │  transform         │ ──────────────► │ effect model                 │
  │  per-insn probe    │  meta / code /  │ forward replay + shadow state│
  │  W^X watch         │  trace          │ CFG + post-dominators        │
  │  export hooks      │                 │ backward walk                │
  └────────────────────┘                 └──────────────────────────────┘
```

**Capture is hot.** It runs on every executed instruction inside the target, so it emits raw facts only
— this block ran, this operand resolved to this address — and never does graph work inline. It does not
even compute read/write sets: those are a pure function of the instruction bytes, so they are derived
host-side. That means fixing a semantics bug means re-replaying an existing trace instead of re-running
a target you may only get one shot at.

**Slicing is cold.** One forward pass builds the whole dependence graph by maintaining a *last-writer*
map over byte-granular storage. For each instruction, resolve every location it reads against the
pre-instruction state, then apply everything it writes. That is the entire data-dependence analysis: no
fixpoint, no may/must distinction, no aliasing question — a concrete run has exactly one last writer per
byte. The backward walk is then pure graph reachability, proportional to the size of the *slice* rather
than the trace.

### Things it gets right that are easy to get wrong

**Registers are modelled as byte lanes.** `RAX / EAX / AX / AL / AH` are views on one register, and the
rules differ: writing `EAX` zero-extends and therefore defines all eight bytes, while writing `AL`
defines exactly one and leaves the rest with their previous writers. `AH` is lane 1 and is independent
of `AL`. Get this wrong and slices are quietly missing contributors or full of invented ones.

**A multi-byte read has multiple definitions.** An 8-byte load from a buffer built one byte at a time has
up to eight distinct last writers. Each read range is split into maximal runs of identical writer and
reported per run, so the listing can say *bytes 0–3 came from here, bytes 4–7 from there*.

**Flags are individual bits.** A `jz` reads ZF, a `jl` reads SF and OF. Modelled as one monolithic
`RFLAGS`, every branch would depend on every arithmetic instruction that ran before it, and control
chains would be noise.

**Zeroing idioms do not read their operand.** `xor rax, rax` sets a constant. Modelled as a read, it
injects a false edge into essentially every slice — the idiom is everywhere in compiler output.
`sbb rax, rax` looks identical and *is* a real read of CF; matching is by mnemonic, not shape.

**Address dependences are separated from value dependences.** `mov rax, [rbx+8]` value-depends on the
memory and address-depends on `RBX`. Without the split, `RSP` becomes a universal attractor and every
slice fills with stack plumbing.

**Code is keyed by `(address, code_version)`.** Under a packer the same address holds different
instructions at different times. Keyed by address alone, pre-rewrite records get decoded with
post-rewrite semantics — no error, no warning, a completely plausible wrong slice.

**Control-flow flattening is reported, not answered.** In a flattened function every block returns to one
dispatcher, so the dispatcher post-dominates every branch and the control-dependence relation, while
technically correct, carries no information. Atropos says *control dependence unavailable* rather than
presenting a degenerate relation as an answer.

**A broken trace is refused.** This matters more here than in most tools: a slicer fed a corrupt trace
does not crash, it produces a slice — real addresses, real instructions, a sensible-looking chain, about
a different execution than the one that happened. Continuity, memory-access counts, code versions and
call depth are all checked, and `atropos slice` refuses a suspect bundle unless you pass
`--allow-suspect`.

Every report leads with a precision banner: integrity status, how many edges are imprecise or bulk,
which regions have no control dependence, and whether the slice was truncated. You should never have to
guess how much of the answer to believe.

---

## Correctness

```bash
pytest          # 153 tests, no target process required
```

Three layers:

1. **Unit tests per rule.** Every rule in the effect model has a test asserting on lane ranges directly
   — the sub-register rules, the idioms, `lea`, per-condition flag masks, `rep` expansion, zero-count
   shifts.

2. **A second, independent slicer.** [`oracle.py`](src/atropos/oracle.py) implements the same analysis
   from the fixture's own source text, with the read/write sets written out longhand. It shares nothing
   with the effect model but the fixture. It is deliberately slow and stupid; its job is to be *obviously*
   correct by inspection.

3. **Differential fuzzing.** Randomly generated instruction sequences, sliced both ways, asserted equal.
   This is the layer that matters, because every bug in the effect model produces a *plausible* slice
   rather than an error — hand-written fixtures catch the bugs you thought of, and those are not the
   problem.

That loop has already earned its keep: it caught the oracle reading the source operand of a zeroing
`xor` before applying the idiom check. A slice one instruction wrong, invisible to inspection. That is
the shape of every bug in this part of the system.

---

## Limitations

Stated plainly, because a silent gap is worse than a documented one.

- **One run only.** The slice explains the execution you recorded. A different input may derive the key
  differently. Union slicing across runs is future work.
- **Exceptions as control flow.** SEH/VEH-driven obfuscation is Stalker's weakest area. Atropos *detects*
  the resulting discontinuity rather than mis-slicing, but detection is not support. Targets that
  dispatch primarily through exceptions are out of reach.
- **`rep` is modelled in bulk.** Slicing one destination byte of a `memcpy` pulls in the whole source
  range. Edges are tagged `bulk`; `--expand-rep` is the escape hatch.
- **Kernel and GPU effects** are summarised, not traced.
- **Single-threaded.** Multi-thread traces are recordable but the control-dependence stack is global, and
  true concurrent ordering on x86-64 needs care the tool does not currently take.
- **Timing.** Stalker slows the target substantially. Targets with `rdtsc` checks may behave differently
  under observation.
- **Python replay is tens of seconds** on a 5 M-instruction trace, not seconds. The storage layout is
  typed-array columns specifically so the planned Rust replay core is a mechanical port.

---

## Documentation

| Document | What it covers |
|----------|----------------|
| [`docs/design-v0.2.md`](docs/design-v0.2.md) | The full design: goals, architecture, dependence model, milestones. Start here. |
| [`docs/architecture-review.md`](docs/architecture-review.md) | A paper-style analysis of the architecture — the decisions, their trade-offs, and where the design is exposed. |
| [`docs/trace-format.md`](docs/trace-format.md) | Normative binary format specification. |
| [`docs/semantics-x86-64.md`](docs/semantics-x86-64.md) | The effect model: every override, and what it defends against. |
| [`docs/control-dependence.md`](docs/control-dependence.md) | Post-dominance, call depth, flattening detection. |
| [`docs/summaries.md`](docs/summaries.md) | Writing API and syscall summaries. |
| [`docs/reference.md`](docs/reference.md) | Complete reference: every command, option, API symbol and module; test-pass findings and known issues. |
| [`docs/usage-guide.md`](docs/usage-guide.md) | Analytical usage guide: walkthroughs, choosing a criterion and mode, the five workflows, reading reports, scripting recipes. |
| [`docs/theory.md`](docs/theory.md) | The theoretical foundations: slicing definitions, the byte-lane model, last-writer dependence, control dependence, soundness and complexity. |

## Layout

```
agent/atropos-agent.js     Frida capture agent
src/atropos/
    format.py              varint / tag encoding — the wire format
    bundle.py              the on-disk artifact
    arch/lanes.py          storage model: registers as byte lanes
    arch/effects.py        the effect model  ← the risky part
    shadow.py              last-writer state
    replay.py              forward pass: trace -> dependence graph
    ddg.py                 column-store graph
    cfg.py                 post-dominance and control dependence
    slicer.py              backward walk, forward slice, chop
    criterion.py           turning a question into (seq, locations)
    summaries.py           API models
    integrity.py           trace validation
    oracle.py              the independent second implementation
    testkit.py             assembler + interpreter + bundle writer
    output/                listing, DOT/JSON, IDA/Ghidra bridge
    capture.py             host-side driver for the agent
    cli.py                 the `atropos` command
```

## Status

Design v0.2, milestones M0–M5 implemented and tested; M6 (a real target end to end) and M7 (the inline
EA emitter) are next. See §13 of the design document for the plan and the validation gate on each step.

Capture now works end to end on the two minimal targets in `examples/tiny/`: every run is clean,
deterministic and slices the same in both. `examples/tiny/README.md` lists the expected results, and
`docs/reference.md` §16.3 describes the capture defects fixed to get there. A real crackme end to end is
still open.

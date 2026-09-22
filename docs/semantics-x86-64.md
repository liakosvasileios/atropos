# The x86-64 effect model

Implementation-level companion to design v0.2 §6. Where the design document states the rules, this one
states how they are implemented, which cases Capstone gets right, which it does not, and what each
override is defending against.

Code: [`src/atropos/arch/lanes.py`](../src/atropos/arch/lanes.py) (what storage exists) and
[`src/atropos/arch/effects.py`](../src/atropos/arch/effects.py) (what instructions do to it).
Every rule below has a test in [`tests/test_effects.py`](../tests/test_effects.py).

---

## 1. Why this file is the risky part

Every other component of Atropos fails loudly. A malformed trace raises; a bad criterion is rejected
with an explanation; a broken graph walk would crash.

The effect model fails **silently**. If `xor rax, rax` is modelled as reading RAX, the slicer does not
error — it produces a slice containing an extra chain of instructions that never contributed anything.
If a 32-bit write is modelled as touching four lanes instead of eight, the slicer produces a slice
*missing* a contributor. Both look completely normal. An analyst has no way to tell.

That asymmetry is why this module is host-side (so a fix does not require re-running the target), why
every rule has a unit test, and why there is a second independent implementation to diff against
([`oracle.py`](../src/atropos/oracle.py)).

---

## 2. The lane space

Registers are not locations; register *bytes* are.

| Space | Lanes | Contents |
|-------|-------|----------|
| GPR | 0 … 127 | 16 registers × 8 bytes. `RAX` = 0, `RCX` = 8, `RDX` = 16, `RBX` = 24, … |
| FLAG | 128 … 143 | CF, PF, AF, ZF, SF, OF, DF — one lane each; the rest reserved |
| VEC | 144 … 2191 | 32 registers × 64 bytes (ZMM width) |
| SEG | 2192 … 2239 | segment bases; `gs:[0x30]` is the TEB access on Windows |
| MMX | 2240 … 2303 | 8 × 8 |
| X87 | 2304 … 2383 | 8 × 10 |
| EXTRA | 2384 … 2639 | catch-all, allocated on demand |

`RIP` is deliberately absent. It is a constant per instruction instance, so RIP-relative addressing
contributes a constant rather than a dependence, and modelling it would make every instruction in a
block appear to depend on the one before it.

**Unmodelled registers** get their own eight lanes in EXTRA, allocated in first-seen order. The two
alternatives are both worse: raising loses the entire slice over one exotic instruction, and folding
everything onto a shared lane *invents* dependences between unrelated registers. If EXTRA is exhausted
the allocator folds and records that it did, so the precision banner can say so.

---

## 3. Rules Capstone gets right

Taken verbatim, with no override:

- Operand structure — which operands are registers, memory, immediates; base, index, scale,
  displacement, segment.
- `op.access` per explicit operand: read, write, or both.
- `insn.regs_read` / `insn.regs_write` — the *implicit* register accesses. These cover the cases that
  design v0.2 §6.3 lists and that a naive model drops entirely: `RSP` for push/pop/call/ret, `RAX`/`RDX`
  for one-operand `mul` and `div`, `RSI`/`RDI`/`RCX` for string operations, `RAX`→`RDX` for `cdq`/`cqo`.
- `insn.eflags` — per-flag masks, including per-condition read masks for `jcc`/`setcc`/`cmovcc`, and the
  `UNDEFINED_*` bits that tell us where the ISA promises nothing.

Capstone's answer is the base; the override table below is the delta.

---

## 4. The override table

### 4.1 Sub-register widening — `_def_range`

Capstone reports *which* register is written, not what that write does to the rest of the parent
register. Three rules:

| Written | Defines | Why |
|---------|---------|-----|
| 32-bit GPR (`eax`) | all 8 lanes of the parent | A 32-bit write zero-extends. The top four bytes get a *defined* zero whose writer is this instruction. Model only four lanes and a later 64-bit read picks up a stale dependence the hardware erased. |
| 16- or 8-bit GPR (`ax`, `al`, `ah`) | only its own lanes | The upper bytes are preserved and keep their previous writers. |
| VEX/EVEX vector write | the full register width | AVX encodings zero the bits above the destination. |
| Legacy SSE vector write | only its own lanes | `movups xmm0, …` preserves `ymm0[255:128]`. |

The VEX test is the mnemonic's leading `v`. That is a heuristic rather than a decode of the prefix
bytes, and it is accurate for the AVX instruction set as encoded; a mis-classification would over-define
lanes that were already zero, which is conservative rather than wrong.

### 4.2 Zeroing idioms

`xor r, r`, `sub r, r`, `pxor`, `vpxor`, `pcmpeq*`, `xorps/xorpd`, `psub*` with identical sources set
the destination to a constant regardless of the prior value. Modelled as **def only, no register use**;
they still define flags where applicable.

This is not a micro-optimisation. The zeroing `xor` is ubiquitous in compiler output, so a model that
treats it as a read injects a false edge into essentially every slice through essentially every
function.

Two subtleties the implementation gets right and a naive version does not:

- **`sbb r, r` is not an idiom.** It looks identical to `sub r, r` under operand-identity matching, and
  it genuinely reads CF — it is the standard carry-broadcast pattern. Matching is by exact mnemonic.
- **The VEX three-operand form** `vpxor xmm0, xmm1, xmm2` zeroes only when the two *sources* match,
  regardless of the destination. `vpxor xmm0, xmm0, xmm1` is a real operation.

Also handled: `and r, 0` and `imul r, r, 0` produce zero; `or r, -1` produces all-ones.

### 4.3 `lea`

Capstone models `lea` with a memory operand it never accesses. Three corrections:

- no memory access is enumerated, so no `MEM` record is expected;
- no flags are touched;
- the base and index registers are **value** uses, not address uses — for `lea`, the address *is* the
  value (design v0.2 §5.4).

Treating `lea` as a load is the most common modelling bug in this class of tool, and here it would also
break the agent/host contract on memory-access counts, so the integrity checker catches it too.

### 4.4 `cmovcc` reads its destination

Capstone marks the destination write-only. When the condition is false the destination keeps its
previous value, so it is genuinely read. The 32-bit zero-extension still applies unconditionally, so the
*def* stays widened while the *use* is added.

### 4.5 `rep`-prefixed string operations

Under Stalker a `rep movsb` executes as a single instruction performing `RCX` accesses, which no
per-operand record can express. The model marks these `is_rep`, enumerates **no** memory accesses, and
defers to the `REP` trace record; replay synthesises the bulk ranges.

Direction matters: `DF = 1` runs the ranges downwards, so the start is `RSI − (n−1)·s` rather than
`RSI`.

`RCX = 0` executes zero iterations and leaves `RSI`, `RDI` and `RCX` untouched. Emitting defs for them
would make the instruction their last writer and break every chain running through them — this is
tested (`test_rep_with_zero_count_does_nothing`).

**Known over-approximation.** Within one `rep movs`, destination byte *k* depends only on source byte
*k*. The bulk model conflates them, so slicing one destination byte pulls in the whole source range.
Edges are tagged `bulk`, the banner reports the count, and `--expand-rep` is the escape hatch.

### 4.6 Value-dependent flags

`shl/shr/sar/rol/ror r, cl` with `CL & 0x3F == 0` modify **nothing** — not the destination, not any
flag. Capstone reports an unconditional flag write.

Modelled naively, a following `jz` is attributed to the shift rather than to the real ZF producer: a
wrong control-dependence chain, arrived at silently. The `SHIFTCNT` record resolves it exactly. With no
such record the model falls back to the conservative answer and the node is marked imprecise.

Suppressing the *destination* def matters as much as the flags. Recording one would make the shift the
last writer of a register it did not touch, inserting a phantom hop into every slice passing through.

### 4.7 Undefined flags are may-defs

A flag the ISA leaves undefined (AF after `and`/`or`/`test`, OF after a multi-bit shift) is recorded as
a **may-def**: it takes the last-writer slot, because a later read genuinely does get its garbage from
here, but the resulting *edge* is tagged imprecise.

Imprecision is tracked **per lane**, not per node. Marking every `xor` imprecise because it scrambles an
AF that nobody reads makes the annotation useless; only the reads that actually consume an undefined
value are tagged. Replay keeps a `_undefined` bytearray over the lane space for exactly this.

### 4.8 No-effect forms

`nop`, multi-byte `nop`, `endbr64`, `pause`, and `xchg r, r` with identical operands.

---

## 5. Address versus value uses

For every memory operand the base, index and segment registers become **address** uses; the memory
bytes themselves become **value** uses. `lea` is the documented exception (§4.3).

The split costs nothing — the operand walk already knows which registers fed the addressing expression
— and it is the largest single lever on slice readability. Without it, `RSP` is a universal attractor:
every stack-slot read pulls in the prologue's `sub rsp`, which pulls in the `call` that pushed the
return address, which pulls in the caller's stack arithmetic. See design v0.2 §5.4.

---

## 6. Caching

`Effects` are a pure function of the instruction **bytes** — not the address, because RIP is not a
modelled dependence. The cache key is therefore just the bytes, and a decode-loop body is decoded once
no matter how many million times it runs.

`disassemble()` is separate and takes an address, because the *text* of a RIP-relative instruction
depends on where it lives even though its effects do not.

---

## 7. Where the model is knowingly incomplete

Stated plainly, because a silent gap is worse than a documented one:

- **x87 and MMX** have lanes but no override rules. The x87 stack is modelled as eight fixed registers
  rather than a rotating stack, so `fld`/`fstp` sequences will mis-attribute. Floating-point-heavy
  targets are not the intended workload; if that changes, this is where the work goes.
- **Masked AVX-512 writes** (`{k1}{z}`) are modelled as full-width writes. Over-approximate for merging
  masks, correct for zeroing masks.
- **Segment bases** are modelled as opaque 8-lane values. `gs:[0x30]` gets the right address dependence;
  a program that manipulates the base through `wrgsbase` gets a use of a lane nothing wrote.
- **Undecodable bytes** produce an `Effects` marked `undecodable` with no uses and no defs rather than
  raising, so a packer's garbage byte does not abort the whole replay. `strict=True` raises instead.

---

## 8. Testing

- [`tests/test_effects.py`](../tests/test_effects.py) — one test per rule above, asserting on lane
  ranges directly rather than on slice output.
- [`tests/test_replay.py`](../tests/test_replay.py) — the same rules observed through a full replay,
  including the worked example of design v0.2 §6.2.
- [`tests/test_oracle.py`](../tests/test_oracle.py) — differential agreement with the independent
  implementation, plus a fuzzing loop over randomly generated instruction sequences.

The differential loop has already earned its place: it caught a bug where the oracle read the source
operand of a zeroing `xor` before applying the idiom check. That is the shape of every bug in this
file — a plausible slice, off by one instruction, invisible to inspection.

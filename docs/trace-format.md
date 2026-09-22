# The Atropos trace bundle format, version 1

Normative specification of the on-disk artifact produced by capture and consumed by the host.
Reference implementation: [`src/atropos/format.py`](../src/atropos/format.py) and
[`src/atropos/bundle.py`](../src/atropos/bundle.py); producer:
[`agent/atropos-agent.js`](../agent/atropos-agent.js).

This document exists because the format is a contract between two programs written in different
languages, and because design v0.2 §10.5 commits to a Rust replay core. Everything below is specified
so that port is mechanical: no host endianness, no pointer-size assumption, no language-specific
encoding anywhere in the byte stream.

---

## 1. Layout

A bundle is a **directory**, not a single file:

```
run.atrace/
    meta.json     run metadata, capture configuration, initial module map
    code.bin      block descriptors, keyed by (address, code_version)
    trace.bin     the execution record stream
```

The split is not cosmetic. `code.bin` is appended once per newly *instrumented* block — bounded by the
target's code size — while `trace.bin` is appended once per *executed* block, bounded by the run
length. Separating them lets the agent drain the hot stream to a memory-mapped file without ever
rewriting the cold one, and lets a reader load all descriptors up front and then stream the trace.

## 2. Primitives

### 2.1 `uvarint`

LEB128, little-endian groups of seven bits, high bit set on all but the last byte. Values up to 2⁶⁴−1.
A reader must reject an encoding longer than ten bytes (`format.py` raises `TraceFormatError`).

### 2.2 `svarint`

Zig-zag mapped, then `uvarint`: `zigzag(n) = (n << 1) ^ (n >> 63)`.

Zig-zag rather than two's complement matters here. Effective addresses are delta-coded, and a loop
walking a buffer downwards produces small *negative* deltas. Two's complement would encode −8 as
`0xFFFF_FFFF_FFFF_FFF8` and pay ten bytes for it; zig-zag pays one.

### 2.3 `blob` and `string`

`blob` is a `uvarint` length followed by that many raw bytes. `string` is a `blob` holding UTF-8.

### 2.4 Section header

Every binary section starts with an 8-byte header:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | magic — `ATRC` for `code.bin`, `ATRT` for `trace.bin` |
| 4 | 2 | format version, little-endian u16 (currently `1`) |
| 6 | 2 | reserved, must be zero |

A reader must reject a mismatched magic or an unknown version rather than attempting a best-effort
parse. Guessing at a version it does not understand is precisely the behaviour §10.6 exists to forbid.

---

## 3. `meta.json`

UTF-8 JSON. Fields:

| Field | Type | Meaning |
|-------|------|---------|
| `format_version` | int | Must match the binary sections. |
| `arch` | string | `"x86_64"`. |
| `os` | string | `"windows"`. |
| `capture` | object | Free-form record of how the trace was made — agent name, probe kind, trust threshold, excluded modules, whether value capture was on, and the agent's own counters. Not interpreted by the host, but it is what makes a bundle reproducible and it appears in `atropos info`. |
| `modules` | array | Initial module map: `{name, base, size, path}`. Images loaded later appear as `MODULE` records in `code.bin`. |

`base` and `size` are JSON numbers. Addresses above 2⁵³ would lose precision, which no user-mode
Windows image base reaches; a producer that cannot guarantee that must emit the module as a `MODULE`
record instead, where the field is a `uvarint`.

---

## 4. `code.bin`

A sequence of tagged records after the header.

### 4.1 `CTAG_BLOCK = 0x01`

```
uvarint  block_id          globally unique, across code versions
uvarint  code_version
uvarint  start_address     absolute
uvarint  n_insns
n_insns x blob             the raw bytes of each instruction, in order
```

Instruction addresses are implied: the first is `start_address`, and each subsequent one follows the
previous by its own length. A producer must not emit a block with a gap.

**`block_id` is unique across code versions.** Two blocks at the same address under different versions
are two descriptors with two ids. This is design v0.2 §4.6 and it is the single most important rule in
the format: keyed by address alone, a trace of self-modifying code decodes pre-rewrite records with
post-rewrite semantics and produces a wrong slice with no error at all.

### 4.2 `CTAG_MODULE = 0x02`

```
string   name
uvarint  base
uvarint  size
string   path
```

For images loaded after capture began.

---

## 5. `trace.bin`

A sequence of tagged records after the header. The stream is **block-granular**: a `BLOCK` record
implies the execution of every instruction in that block's descriptor, in order, and only
memory-touching instructions get a record of their own (design v0.2 §4.4).

| Tag | Name | Payload |
|-----|------|---------|
| `0x01` | `BLOCK` | `uvarint block_id` |
| `0x02` | `MEM` | `uvarint insn_index`, `svarint ea_delta`, `u8 size`, `u8 rw` |
| `0x03` | `VERSION` | `uvarint code_version` |
| `0x04` | `THREAD` | `uvarint thread_id` |
| `0x05` | `ABORT` | `uvarint n_executed` |
| `0x06` | `MARK` | `uvarint mark_id` |
| `0x07` | `SUMMARY` | `uvarint summary_id`, `uvarint argc`, `argc × uvarint` |
| `0x08` | `REP` | `uvarint rcx`, `uvarint rsi`, `uvarint rdi`, `uvarint df` |
| `0x09` | `SHIFTCNT` | `uvarint cl` |
| `0x0a` | `VALUE` | `uvarint slot`, `blob bytes` |
| `0x0b` | `REP_POST` | as `REP`, captured *after* the instruction |

### 5.1 `MEM`

`ea_delta` is the signed difference from the previously emitted effective address in the stream; the
running value starts at 0. `rw` is a bitmask: `1` read, `2` write, `3` both (a read-modify-write
operand such as `add [mem], rax` is **one** record with `rw = 3`, not two records).

`insn_index` is the instruction's position within the current block. It is redundant — the reader
already knows which instruction it is up to — and it is emitted anyway, as one varint, because it makes
desynchronisation *detectable*. Without it a dropped record silently reattributes every subsequent
access in the block to the wrong instruction, and the resulting slice looks entirely plausible.

Multiple accesses for one instruction appear as consecutive `MEM` records with the same `insn_index`,
in **canonical order**:

1. explicit memory operands, in Capstone operand order;
2. the implicit stack access, for `push` / `pop` / `call` / `ret` / `leave` / `enter` / `pushf` /
   `popf`.

This order is normative. The host derives the same list from the instruction bytes
(`MemAccess` in [`arch/effects.py`](../src/atropos/arch/effects.py)) and compares counts; a mismatch is
an integrity error.

### 5.2 `VERSION`

Declares that code has been rewritten and that subsequent `BLOCK` records refer to descriptors
captured under the new version. A reader must check each block's recorded `code_version` against the
stream's current one and report a mismatch.

### 5.3 `ABORT`

The current block did not run to completion — the signature of an exception. `n_executed` is how many
instructions actually ran. A reader must execute only that prefix.

### 5.4 `REP` and `REP_POST`

A `rep`-prefixed string operation runs a whole loop as one instrumented instruction, so it emits **no**
`MEM` records. `REP` carries `RCX`, `RSI`, `RDI` and `DF` captured at entry, from which the host
synthesises the bulk source and destination ranges (design v0.2 §6.6).

`repe cmps` and `repne scas` exit early on the comparison, so `RCX` at entry is an upper bound, not the
count. Those emit a second `REP_POST` after the instruction; the difference is the true iteration
count.

### 5.5 `SHIFTCNT`

Emitted immediately before a variable-count shift, carrying `CL`. A count of zero modifies neither the
destination nor any flag (design v0.2 §6.7), and without this record the host must fall back to the
conservative model and say so.

### 5.6 `SUMMARY`

An untraced call, expanded host-side by the summary table. `summary_id` values are **stable**: they are
baked into captured bundles, so renumbering one silently reinterprets every existing trace. The table
is append-only. See [`summaries.md`](summaries.md).

### 5.7 `VALUE`

Optional post-write value capture, off by default. Not consumed by structural slicing; present for the
symbolic-augmentation milestone and for value-watch criteria (design v0.2 §8.1).

---

## 6. Reader obligations

A conforming reader must:

1. Reject a bad magic or unknown version.
2. Reject a varint longer than ten bytes, and a `blob` whose length runs past the end of the section.
3. Report — not repair, and not ignore — a `BLOCK` naming an unknown `block_id`.
4. Report a `code_version` disagreement between a block descriptor and the stream.
5. Report a `MEM` record whose `insn_index` does not match the instruction being executed.
6. Report a count mismatch between the `MEM` records for an instruction and the memory accesses its
   bytes imply.
7. Execute only the prefix of a block named by a preceding `ABORT`.

Every one of these is a case where a lenient reader produces a plausible slice about the wrong
execution. The rule throughout is that the tool says what it cannot answer rather than answering
confidently and wrongly.

---

## 7. Versioning policy

- **Adding a tag** is a minor change; readers must skip unknown tags only if the format version has
  been incremented and they have chosen to be lenient. Version 1 readers reject them.
- **Changing a tag's payload** requires a format-version bump. There is no in-band length prefix on
  records, so a reader cannot skip a record whose shape it does not know.
- **Renumbering a `summary_id`** is forbidden regardless of version — see §5.6.

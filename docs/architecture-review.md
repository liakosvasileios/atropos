# Atropos: An Architectural Analysis of a Backward Dynamic Slicer for Hostile Binaries

**A review of the design of Atropos v0.2**

Author: Vasilis · Status: **open draft — §9 reserved, see the note there**

---

## Abstract

Backward dynamic program slicing is a well-understood technique with a thirty-five-year literature, yet
it is almost absent from practical reverse-engineering toolchains. This paper argues that the gap is not
algorithmic but architectural. The Korel–Laski relation is a page of pseudocode; what makes a slicer
usable on a packed, obfuscated Windows binary is a set of engineering decisions that the slicing
literature treats as implementation detail and that the reverse-engineering literature does not treat at
all.

We analyse the architecture of Atropos, a backward dynamic slicer for Windows x86-64 built on Frida's
Stalker, along four axes: **where the analysis runs** (in-process versus offline), **where instruction
semantics are decided** (capture-time versus replay-time), **what a storage location is** (byte lanes,
flag bits, concrete addresses), and **how the system behaves when it cannot answer** (refusal versus
approximation).

We identify ten load-bearing decisions, state the alternative each was chosen against, and characterise
the exposure each creates. Three of them — keying code by `(address, code_version)`, resolving a
multi-byte read to a *set* of definitions, and distinguishing address dependences from value
dependences — are shown to be soundness- or usability-critical in a specific way: getting them wrong
produces not an error but a *plausible slice about a different computation*. We argue that this failure
mode, silent plausibility, is the defining hazard of the problem domain, and that it justifies design
choices that would otherwise look like over-engineering: an independent second implementation used as a
differential oracle, mandatory trace-integrity checking, and a policy of reporting "unavailable" in
preference to reporting a degenerate relation.

---

## 1. Introduction

### 1.1 The question

A backward dynamic slice answers: *for this value, at this point in this run, which executed
instructions contributed to producing it, and which inputs did it ultimately depend on?*

For a reverse engineer this is frequently the whole task. "Which of these five thousand instructions
built the AES key?" and "which bytes did this decode loop read?" are slicing queries wearing different
clothes. The analyst's usual substitute — set a breakpoint, step backwards mentally, keep a register
diagram on paper — is a manual execution of exactly this algorithm.

### 1.2 Why dynamic, stated as a claim about the domain

Static slicing reasons over all executions from the code. Its accuracy is bounded by the accuracy of the
recovered control-flow graph and the points-to analysis. On the targets that motivate this work, both
degrade to the point of uselessness:

- **Self-modifying code** invalidates the disassembly the analysis is defined over. The bytes at an
  address at analysis time are not the bytes that will execute there.
- **Indirect dispatch** — jump tables, `ret`-based dispatch, hash-resolved imports — makes the CFG's
  edge set either wildly over-approximate or simply wrong.
- **Pointer arithmetic through obfuscation** defeats points-to analysis, so memory dependence collapses
  to "everything may alias everything".

Each of these is a *precision* failure, and precision failures compound: an over-approximate slice that
contains 80 % of the program is not a slice.

A dynamic slice is immune to all three by construction, because it never reasons about anything that did
not happen. The famous hard problem — *does `[rax]` alias `[rbx]`?* — does not arise: at run time both
resolved to numbers, and two accesses alias if and only if their byte ranges overlap. The cost is
generalisation: the slice explains one execution. We claim this is the correct trade for reverse
engineering, where the object of study is an *observed behaviour*, not a program property.

### 1.3 Contribution of this analysis

We do not claim novelty in the slicing algorithm; §2 shows it is textbook. The contributions are:

1. An articulation of **silent plausibility** as the governing hazard of dynamic slicing on binaries,
   and of the architectural consequences that follow from taking it seriously (§4, §6).
2. A decision-by-decision analysis of an implemented system, with each decision's alternative and
   exposure stated (§5).
3. An analytic cost model separating the four cost centres, and an argument about which of them the
   implementation language actually constrains (§6).
4. A validation architecture built around a deliberately independent second implementation, with an
   account of what it can and cannot establish (§7).

---

## 2. Background

### 2.1 Slicing

Weiser introduced program slicing as a model of how programmers debug: the slice of a program with
respect to a *criterion* — a program point and a set of variables — is the subprogram that preserves the
behaviour of the program at that point with respect to those variables [1]. Weiser's slices are static.

Korel and Laski adapted the definition to a single execution history [2]. Agrawal and Horgan formalised
the *dynamic dependence graph* (DDG), whose nodes are executed instruction instances and whose edges are
data and control dependences; the backward slice is the reachable set from the criterion [3]. Tip's
survey remains the standard map of the space [4]. Zhang, Gupta and colleagues addressed the practical
scaling problem — DDG size grows with execution length, not program size — through limited
preprocessing, compaction, and demand-driven construction [5, 6], and later addressed online control
dependence specifically [7]. Control dependence itself rests on the post-dominance formulation of
Ferrante, Ottenstein and Warren [8], computed here by the Cooper–Harvey–Kennedy iterative algorithm
[9].

Atropos's slicing core is [2] and [3] with no modification. That is deliberate and it is the point of
this paper: everything difficult lies elsewhere.

### 2.2 Dynamic binary instrumentation

Pin [10], DynamoRIO [11] and Valgrind [12] are the canonical DBI frameworks; each JIT-copies target code
into an instrumented arena and offers callbacks at instruction or block granularity. Frida's Stalker
belongs to the same family, with a smaller API surface, first-class scriptability, and — decisively for
this domain — the ability to attach to an already-running process on Windows without a custom loader.

Atropos uses Stalker for a specific reason beyond convenience: `Stalker.invalidate()` and
`trustThreshold` expose the *code-cache coherence policy* directly, which is precisely the control
surface a self-modifying target requires (§5.7).

### 2.3 Adjacent techniques

**Dynamic taint analysis** [13] propagates a label forward through execution. It answers "what did this
input reach", the dual of our question, and is cheaper because it needs no dependence graph — but it
cannot answer "what produced this", which is the analyst's question far more often. The two are the
forward and backward walks of the same graph, and Atropos supports both plus their intersection (§5.9).

**Concolic and symbolic execution** — Triton [14], angr [15], and the broader binary-analysis platforms
[15] — produce *formulas*, which is strictly more information than a slice. They also cost far more per
instruction and face path-explosion and solver-timeout failure modes that a purely structural analysis
does not have. Atropos treats symbolic augmentation as a later milestone seeded by the concrete trace,
not as a foundation.

**Record-and-replay platforms** such as PANDA [16] provide whole-system determinism and are the right
substrate for analyses needing repeated re-execution. Atropos records once and analyses offline, which
is weaker but avoids the deployment cost of a full-system emulator — a real consideration when the
analyst's constraint is often "this sample runs once".

**Packer analysis** [17] and control-flow flattening [18] define the adversarial context. §5.6 and §5.8
are direct responses to each.

---

## 3. Architecture

### 3.1 Phase separation

```
        TARGET PROCESS                              HOST (offline)
  ┌───────────────────────────┐             ┌────────────────────────────────┐
  │ Stalker transform         │  bundle     │ decode → effect model          │
  │  · block descriptors      │ ──────────► │ forward replay + shadow state  │
  │  · resolved EAs           │  meta/      │ CFG + post-dominators          │
  │  · W^X / version tracking │  code/      │ backward reachability          │
  │  · export hooks           │  trace      │ output backends                │
  └───────────────────────────┘             └────────────────────────────────┘
       hot: raw facts only                       cold: all the analysis
```

The invariant is that **capture emits facts and never computes**. Two justifications:

*Perturbation.* Analysis inside the target competes with the target for time. Anti-analysis timing
checks are common in this domain, and a phase that does pointer-chasing graph work per instruction makes
them more likely to fire.

*Iteration.* The analysis is where the bugs are. Keeping it offline means a fix is re-run against an
existing trace. For a sample that runs once — a dropper that deletes itself, a licence check that burns
a token — this is not a convenience, it is the difference between an answer and no answer.

### 3.2 The bundle as an interface

Capture and analysis communicate only through a documented, language-neutral artifact: varint-encoded,
tagged records with no host-endianness or pointer-size assumptions. This is a stronger boundary than an
API and buys three things: a third-party capture agent is checked on exactly the same terms as ours; the
planned Rust replay core is a mechanical port rather than a rewrite; and a trace is an archivable
artifact independent of the tool version that produced it.

---

## 4. The governing hazard: silent plausibility

Most components of a system like this fail loudly. A malformed file raises. A bad query is rejected. A
broken graph walk crashes.

**The dependence model does not.** Consider four independent mistakes:

| Mistake | Consequence |
|---------|-------------|
| Model `xor rax, rax` as reading RAX | Slice gains a chain that contributed nothing |
| Model a 32-bit write as touching four lanes | Slice *loses* a real contributor |
| Key code by address alone, under a packer | Slice describes instructions that never ran |
| Resolve a multi-byte read to one definition | Slice silently drops up to seven contributors |

Every one produces a slice. Real addresses, real instructions, a coherent dependence chain, no warning.
The analyst has no independent handle on the answer — that is *why* they are using the tool — so the
error is not merely undetected but undetectable from the output.

We take this as the organising constraint of the architecture, and three otherwise-questionable
decisions follow directly from it:

- **An independent second implementation** (§7.2) is justified because inspection cannot distinguish a
  correct slice from a subtly wrong one, so correctness must be established by disagreement rather than
  by review.
- **Mandatory integrity checking** (§5.8) is justified because a corrupt *input* has the same signature
  as a correct answer, so the input must be validated even though validation catches nothing on a
  well-formed trace.
- **Refusing to answer** (§5.8) is justified because a degenerate relation presented as an answer is
  worse than an admission, and the analyst cannot tell the difference unaided.

A useful test for any proposed change to this system is: *if this were wrong, would anything visibly
break?* If the answer is no, the change needs a test that makes the answer yes.

---

## 5. The load-bearing decisions

Each is stated as a decision, the alternative it was chosen against, and the exposure it creates.

### 5.1 Offline dependence-graph construction

**Decision.** Record a trace; build the DDG afterwards.
**Alternative.** Build the graph online, as Zhang and Gupta's demand-driven approaches do [5, 6],
avoiding trace storage entirely.
**Rationale.** §3.1: perturbation and iteration cost.
**Exposure.** Trace volume becomes a first-order constraint, addressed by §5.3. On a very long-running
target the bundle can exceed what is comfortable to store, and the mitigation — scoping capture to a
time window around a hooked trigger — is manual. If trace size ever dominates in practice, this decision
is the one to revisit; the block-granular encoding is what makes that unlikely.

### 5.2 Semantics decided at replay time, not capture time

**Decision.** The agent ships instruction *bytes*; the host decodes them and derives read/write sets.
**Alternative.** Compute abstract effect sets at instrument time and ship those. This is the natural
design and it is what v0.1 specified.
**Rationale.** Three: the effect model is the component most likely to be wrong and most often revised,
so making a fix require re-running the target is a serious cost; it keeps the agent's instrument-time
work to the one question it must answer anyway (*does this touch memory, and how do I compute the
address?*); and it makes the bundle self-describing, eliminating version skew between the agent's notion
of "reads RAX" and the host's.
**Exposure.** The host must maintain a decoder that agrees with the one the target actually executed.
The `insn_index` cross-check and the memory-access count check (§5.8) exist to make any disagreement
detectable rather than silent.

### 5.3 Block-granular trace encoding

**Decision.** A `BLOCK` record implies the execution of every instruction in that block's descriptor.
Only memory-touching instructions get their own record.
**Alternative.** One fixed-size record per executed instruction — simpler, and what v0.1 specified at
roughly 24 bytes each.
**Rationale.** DBI blocks terminate at control transfers, so block identity already determines the
instruction sequence. On typical compiled x86-64 roughly 30–40 % of instructions touch memory, and the
surviving records shed the absolute address in favour of an index plus a delta-coded EA. The combined
factor is 5–10×.
**Exposure.** The stream is now *stateful*: a dropped or reordered record desynchronises everything after
it within the block. This is why the redundant `insn_index` field is carried despite adding a byte to
every memory record — it converts a silent misattribution into a detected error, which is exactly the
trade §4 argues for.

### 5.4 Storage locations are bytes, not registers

**Decision.** A GPR is eight independent lanes; a vector register is sixty-four; each flag is its own
location; memory is byte-addressed.
**Alternative.** Register-granular storage with a width annotation, which is what most trace-analysis
tools do.
**Rationale.** x86-64's sub-register rules are not uniform, and the non-uniformity is semantically
load-bearing:

```asm
mov  eax, 0x10   ; defines RAX[0..7] — the top four bytes are a *defined* zero
mov  ah,  0x20   ; defines RAX[1] only; RAX[0] and RAX[2..7] keep their writers
add  al,  ah     ; uses RAX[0] and RAX[1]
```

A register-granular model must choose between treating `mov ah` as clobbering RAX (losing `mov eax` as a
contributor) and treating it as not writing RAX at all (losing `mov ah`). Both are wrong, silently, in
opposite directions. Byte lanes make the question not arise.

The same argument applies to flags. Modelled as one `RFLAGS` location, a `jz` depends on every prior
instruction that set any flag; per-bit, it depends on the ZF producer. Since branches are the consumers
that control dependence hangs off, monolithic flags would make control chains uninformative — a
precision failure that propagates into an entirely different subsystem.

**Exposure.** Constant-factor cost in shadow-state updates and edge counts. Measured against the
alternative of being wrong, this is not a close call.

### 5.5 A read resolves to a *set* of definitions

**Decision.** Each read range is split into maximal runs of identical last writer, with one edge per run
carrying its byte range.
**Alternative.** `last_writer(location)` returning a single definition — which is what the pseudocode in
every treatment of the subject implies, and what v0.1 specified.
**Rationale.** It is forced by §5.4 and it is not a corner case. A byte-wise decode loop is the
*motivating* workflow, and an 8-byte read of its output has up to eight distinct producers.
**Exposure.** Edge count grows with fragmentation. A pathological pattern — a qword read over eight
individually-written bytes, repeatedly — produces eight times the edges of the naive model. This is the
correct answer, but it is a real cost and it is why the output backends coalesce adjacent runs for
display.

### 5.6 Code is keyed by `(address, code_version)`

**Decision.** A monotonically increasing version counter, bumped on detected rewrite, forms part of every
code descriptor's identity.
**Alternative.** Key descriptors by address, refreshing on invalidation.
**Rationale.** Under self-modifying code the same address holds different instructions at different
times. Address-keyed, a trace record from before a rewrite is decoded with the semantics of the
instruction that replaced it. There is no error condition: the decode succeeds, the effect sets are
well-formed, the slice is coherent and describes a computation that did not occur.

Since packers are the primary target class, this is not a hardening measure but a correctness
precondition for the intended use.

**Exposure.** Detection of rewrites is not complete (§5.7). A missed rewrite reproduces exactly the
failure this decision exists to prevent. The residual risk is bounded, not eliminated, by sampled block
hashing and byte re-validation at drain time.

### 5.7 Trust-with-invalidation, not global never-trust

**Decision.** `trustThreshold = 1` plus targeted `Stalker.invalidate()` driven by W→X detection and
sampled block hashing. `--paranoid` is range-scoped.
**Alternative.** `trustThreshold = -1` globally: never trust the code cache, re-instrument every block on
every execution. This is what v0.1 specified, and it is *correct*.
**Rationale.** Never-trust is one to two orders of magnitude too slow on loop-heavy code, and loop-heavy
code is precisely the unpacking workflow: a 4 000-iteration decode loop pays full re-instrumentation
4 000 times. A correct analysis that cannot be run is not a correct analysis.
**Exposure.** This is the clearest correctness-for-performance trade in the system, and it is a real
one. An undetected rewrite yields stale-semantics decoding. It is mitigated three ways — protection-API
hooks, sampled hashing of executed blocks, and byte re-validation at drain — and none is complete. The
honest characterisation is that Atropos is sound against packers that change protection through the
documented APIs and probabilistically sound against those that do not.

### 5.8 Honest failure as a first-class output

**Decision.** Three mechanisms: mandatory trace-integrity checking with refusal; suppression of
control-dependence edges in functions detected as flattened; and a precision banner on every report.
**Alternative.** Best-effort analysis with warnings in a log.
**Rationale.** §4. Two cases are worth separating.

*Integrity.* Continuity, memory-access counts, code-version agreement and call-depth sanity are all
checked. None fires on a well-formed trace, which is exactly why they must be automatic: a check the
analyst has to remember to run is a check that catches nothing.

*Flattening.* In a control-flow-flattened function every block returns to a dispatcher, so the
dispatcher immediately post-dominates essentially every branch. The relation is technically correct and
carries no information — every instruction is control-dependent on the same switch. Emitting those edges
would fill the slice with noise *and* imply the question had been answered. Atropos reports "control
dependence unavailable" and annotates the region.

**Exposure.** Both mechanisms are heuristic and both can be wrong in the direction of over-refusal. The
integrity checks are deliberately weak — they reject only impossible transitions, not merely unusual
ones — because a checker that cries wolf gets switched off, which would be worse than not having it. The
flattening thresholds are frankly uncalibrated; they are configurable for that reason, and `--force-cd`
exists as the escape hatch.

### 5.9 Address dependences distinguished from value dependences

**Decision.** Every data edge is tagged `value` or `address` at construction; slice modes select which to
follow.
**Alternative.** A single data-dependence relation, as in the classical formulation.
**Rationale.** `mov rax, [rbx+8]` reads two categorically different things: the memory bytes, which are
the value, and `RBX`, which only determined *where* it looked. Conflated, `RSP` becomes a universal
attractor — every stack-slot read reaches the prologue's `sub rsp`, which reaches the `call` that pushed
the return address, which reaches the caller's stack arithmetic. Slices fill with pointer plumbing that
is essentially never the answer to "what arithmetic made this key".

The distinction is free: the effect model already knows which registers fed the addressing expression.
Its value is that "who controlled this pointer" and "what arithmetic made this value" become *separately
askable*, and for an indirect call target the first is the entire question.

**Exposure.** It is a heuristic classification, not a semantic one. `lea` is the documented exception —
its base and index are value uses, because for `lea` the address *is* the value. A more subtle case is a
computed jump table index, which is genuinely both; Atropos classifies by syntactic role and the analyst
selects the mode.

### 5.10 Column-store graph representation

**Decision.** Nodes and edges as parallel typed arrays; edge ranges implied by construction order rather
than indexed.
**Alternative.** Objects, or an adjacency-list graph library.
**Rationale.** Two effects. First, memory: ten million edges as Python objects is several gigabytes and
as six `array` columns a few hundred megabytes — the difference between analysing a real trace and
swapping. Second, and more elegantly: the forward pass emits every edge of instruction *n* before any
edge of *n+1*, so an instruction's edges are *contiguous*. `node_edge_start[seq]` to
`node_edge_start[seq+1]` is a complete use-set with no auxiliary index at all.
**Exposure.** The representation is append-only and assumes monotonic construction. Any future
incremental or online variant (§5.1) would need a different one.

---

## 6. Cost model

Four cost centres, which behave differently and are worth separating because the implementation language
constrains only one of them.

| Centre | Complexity | Dominant factor | Language-sensitive? |
|--------|-----------|-----------------|---------------------|
| Capture probe | O(executed instructions) | Register spill per probe | No — it is C / emitted code |
| Trace volume | O(executed blocks + memory accesses) | Encoding density | No |
| Forward replay | O(Σ locations touched per instruction) | Shadow updates, edge emission | **Yes** |
| Backward walk | O(edges reachable from criterion) | Slice size, not trace size | Marginally |

**Capture.** The largest term is the probe's register traffic. A generic callout forces the framework to
materialise a full CPU context — sixteen GPRs plus flags — to serve a probe that needs two values.
Emitting the address computation inline reduces an eighteen-slot spill to two. The v0.2 implementation
ships the callout version because it is obviously correct, with the inline emitter staged as the first
optimisation and an equivalence test between them (§7.3). The second-largest term is code-cache
coherence policy, discussed at §5.7.

**Replay.** This is the term the reference implementation's language actually constrains: byte-lane
shadow updates plus edge emission run at roughly 10⁵–10⁶ instructions per second in Python. A 5 M-
instruction trace is therefore tens of seconds, not seconds. We regard restating this honestly as part
of the analysis — v0.1 claimed "seconds", which was not achievable and would have set an expectation the
system could not meet. The column-store representation (§5.10) and the language-neutral format (§3.2)
are the concrete preparation for the Rust port that closes the gap.

**The backward walk** is proportional to the slice. This is the payoff of doing the work once in the
forward pass: a 5 000-node slice out of a 5 M-instruction trace costs 5 000 steps. In practice it has
never been the bottleneck, and the caps that exist (`--max-nodes`, `--max-control-depth`) are there for
*readability*, not for time.

**A structural observation.** Costs one and two scale with execution length; cost four scales with the
answer. The scaling problem in dynamic slicing is therefore entirely a *recording* problem, not an
*analysis* problem — which is why compaction work in the literature [6] targets the trace, and why the
encoding decision of §5.3 is more consequential than any algorithmic choice in the slicer.

---

## 7. Validation architecture

### 7.1 Why review is insufficient

§4 established that a wrong effect model produces a plausible slice. It follows that inspecting slices —
the natural way to gain confidence — cannot establish correctness, and neither can hand-written fixtures
alone: a fixture tests the case its author thought of, and the dangerous cases are the ones nobody
thought of.

### 7.2 The differential oracle

Atropos contains a second, independent implementation of the same analysis. It works from the fixture's
own source text, with read and write sets written out longhand from the architecture manual, and shares
nothing with the effect model except the fixture. It is deliberately slow and simple; its sole
qualification is being *obviously* correct by inspection.

The two are run on the same fixtures and their slices compared instruction for instruction. Randomly
generated instruction sequences extend this into a fuzzing loop.

**What this establishes and what it does not.** It establishes agreement on the modelled subset, which
is a strong statement precisely because the implementations are independent — a shared misconception is
the only way both can be wrong together, and a shared misconception is much less likely when one is
derived from Capstone's access sets and the other transcribed from the manual. It does *not* establish
that either matches the hardware. Both could misread the same manual paragraph. Closing that gap
requires a third oracle at a different level of abstraction — executing the fixture on real silicon and
comparing observed state — which is future work.

The loop has already justified itself: it caught the oracle reading the source operand of a zeroing
`xor` before applying the idiom check, a slice wrong by one instruction and invisible to inspection.
That the *oracle* was the faulty side is itself informative about the method's value.

### 7.3 Layered validation

1. **Per-rule unit tests** asserting on lane ranges directly, not on slice output. A test that goes
   through the slicer can pass for the wrong reason.
2. **Replay-level tests** for the same rules observed end to end, including the byte-lane worked example.
3. **Differential agreement and fuzzing** (§7.2).
4. **Cross-implementation equivalence** — the callout probe and the inline emitter must produce
   byte-identical streams, and the Python and Rust replays identical graphs. Stated as a CI gate rather
   than an aspiration.
5. **Integrity self-tests**: each way a trace can be corrupt has a fixture that constructs it and asserts
   the failure is caught and named.

---

## 8. Threats to validity

Stated as an author would state them about their own system.

**T1 — The oracle shares an interpreter with the system under test.** Both run on the same `MiniVM` for
concrete values, so a VM bug affecting effective addresses would affect both identically. The effect
*model* is independent; the value substrate is not. Mitigating this fully means executing fixtures on
real hardware.

**T2 — The modelled instruction subset is narrow.** Fuzzing covers what the fixture assembler can encode.
x87, MMX, most of AVX-512, and the string operations beyond `movs`/`stos` are outside it. Confidence in
the model is confidence about the covered subset and should not be reported as more.

**T3 — Rewrite detection is incomplete (§5.7).** A packer that writes to an RWX page without a protection
call may evade both the API hooks and the sampled hashing. The residual failure is exactly the one §5.6
was designed to eliminate.

**T4 — Flattening thresholds are uncalibrated.** They were set by reasoning about the shape of a dispatch
loop and validated against a synthetic fixture. Their false-positive and false-negative rates on real
obfuscated samples are unknown. The first version of the heuristic keyed on conditional branches only and
never fired at all, which is a useful reminder of how easy it is for a heuristic to be silently inert.

**T5 — No evaluation on real malware.** Every result in the current implementation is on synthetic
fixtures. Fixtures establish that specific rules hold; they establish nothing about behaviour under
adversarial code, trace volume on a real run, or whether the analyst-facing output is usable. Milestone
M6 exists for this and it has not been done.

**T6 — Single-run generality.** Inherent to dynamic slicing and not a defect of the implementation, but
it bounds every claim: a slice describes one execution. Union slicing across runs would extend, not fix,
this.

**T7 — The precision banner assumes it is read.** The system's honesty guarantees are delivered as text.
An analyst who skips the banner receives an answer with its caveats detached — and the caveats are
sometimes the most important part of the answer.

---

## 9. [ RESERVED — section in preparation ]

> **Note.** This section is intentionally left open at the author's request and will be supplied
> separately. The surrounding numbering is stable: §10 (Conclusion) and the references follow, so
> inserting this section requires no renumbering elsewhere.
>
> Suggested placement in the argument, offered only as scaffolding and to be replaced entirely by the
> author's own material: §§5–6 establish *what* was decided and *what it costs*; §§7–8 establish *how
> much of it is verified* and *what remains uncertain*. A section here can therefore take any of several
> natural roles without disturbing the structure —
>
> - **empirical results** on real targets, which would discharge T5 and turn several claims in §5 from
>   arguments into measurements;
> - **a comparative evaluation** against an adjacent tool or technique from §2.3;
> - **an extended case study** carrying one sample from capture to answer;
> - **a treatment of a dimension the present analysis omits** — concurrency, symbolic augmentation, or
>   union slicing across runs.
>
> Whichever it is, §10 is written to be compatible with it: the conclusion refers to §9 only as
> "the evaluation that follows the architectural analysis" and makes no assumption about its content.

---

## 10. Conclusion

Backward dynamic slicing has been well understood since the late 1980s, and the core of Atropos is
[2] and [3] implemented without modification. That is the finding, not a disclaimer. The difficulty in
building a usable slicer for hostile Windows binaries lies almost entirely outside the algorithm: in
what a storage location is, in when instruction semantics are decided, in how code identity survives
self-modification, and in what the system does when it cannot answer.

The analysis in §5 identifies three decisions whose failure mode is *silent plausibility* — code
versioning, multi-definition reads, and the address/value distinction — and we argue in §4 that this
failure mode is the defining hazard of the domain. It is what justifies an architecture that would
otherwise look defensive: an independent second implementation used as a differential oracle, integrity
checking that catches nothing on a healthy trace, and a system that reports "unavailable" in preference
to reporting a relation it knows to be degenerate.

The cost analysis in §6 makes a second structural point. Capture and trace volume scale with execution
length; the backward walk scales with the answer. Scaling in dynamic slicing is therefore a recording
problem rather than an analysis problem, which is why the trace-encoding decision of §5.3 outweighs any
algorithmic choice in the slicer itself.

What the present work does not have is evidence. Every claim in §5 is an argument, and every result is a
synthetic fixture. The threats in §8 — chiefly T3 (incomplete rewrite detection), T4 (uncalibrated
flattening thresholds) and T5 (no real-target evaluation) — are the honest boundary of the contribution,
and the evaluation that follows the architectural analysis is what will move them.

---

## References

*Given by author, title and venue so that each can be located and checked; page numbers are omitted
deliberately rather than reproduced from memory.*

[1] M. Weiser. "Program Slicing." *IEEE Transactions on Software Engineering*, SE-10(4), 1984. (Earlier
form: ICSE 1981.)

[2] B. Korel and J. Laski. "Dynamic Program Slicing." *Information Processing Letters*, 29(3), 1988.

[3] H. Agrawal and J. R. Horgan. "Dynamic Program Slicing." *PLDI*, 1990.

[4] F. Tip. "A Survey of Program Slicing Techniques." *Journal of Programming Languages*, 3(3), 1995.

[5] X. Zhang, R. Gupta and Y. Zhang. "Precise Dynamic Slicing Algorithms." *ICSE*, 2003.

[6] X. Zhang and R. Gupta. "Cost Effective Dynamic Program Slicing." *PLDI*, 2004.

[7] B. Xin and X. Zhang. "Efficient Online Detection of Dynamic Control Dependence." *ISSTA*, 2007.

[8] J. Ferrante, K. J. Ottenstein and J. D. Warren. "The Program Dependence Graph and Its Use in
Optimization." *ACM TOPLAS*, 9(3), 1987.

[9] K. D. Cooper, T. J. Harvey and K. Kennedy. "A Simple, Fast Dominance Algorithm." Rice University
technical report, 2001.

[10] C.-K. Luk et al. "Pin: Building Customized Program Analysis Tools with Dynamic Instrumentation."
*PLDI*, 2005.

[11] D. Bruening. "Efficient, Transparent, and Comprehensive Runtime Code Manipulation." PhD thesis,
MIT, 2004.

[12] N. Nethercote and J. Seward. "Valgrind: A Framework for Heavyweight Dynamic Binary Instrumentation."
*PLDI*, 2007.

[13] J. Newsome and D. Song. "Dynamic Taint Analysis for Automatic Detection, Analysis, and Signature
Generation of Exploits on Commodity Software." *NDSS*, 2005.

[14] F. Saudel and J. Salwan. "Triton: A Dynamic Symbolic Execution Framework." *SSTIC*, 2015.

[15] Y. Shoshitaishvili et al. "SOK: (State of) The Art of War: Offensive Techniques in Binary
Analysis." *IEEE Symposium on Security and Privacy*, 2016.

[16] B. Dolan-Gavitt et al. "Repeatable Reverse Engineering with PANDA." *Program Protection and Reverse
Engineering Workshop (PPREW)*, 2015.

[17] X. Ugarte-Pedrero et al. "SoK: Deep Packer Inspection — A Longitudinal Study of the Complexity of
Run-Time Packers." *IEEE Symposium on Security and Privacy*, 2015.

[18] C. Wang, J. Hill, J. Knight and J. Davidson. "Software Tamper Resistance: Obstructing Static
Analysis of Programs." University of Virginia technical report, 2000. (The origin of control-flow
flattening; see also T. László and Á. Kiss, "Obfuscating C++ Programs via Control Flow Flattening,"
*Annales Universitatis Scientiarum Budapestinensis*, 2009.)

---

## Appendix — Decision summary

| # | Decision | Chosen against | Primary exposure |
|---|----------|----------------|------------------|
| 5.1 | Offline DDG construction | Online / demand-driven | Trace volume |
| 5.2 | Semantics at replay time | Effect sets at capture time | Decoder agreement (checked) |
| 5.3 | Block-granular encoding | Per-instruction records | Stream desync (checked) |
| 5.4 | Byte-lane storage | Register-granular | Constant-factor cost |
| 5.5 | Multi-definition reads | Single last writer | Edge fragmentation |
| 5.6 | `(address, code_version)` keying | Address-only | Depends on 5.7's detection |
| 5.7 | Trust-with-invalidation | Global never-trust | **Undetected rewrite** |
| 5.8 | Honest failure / refusal | Best-effort with warnings | Over-refusal; T4 |
| 5.9 | Address vs value edges | Single data relation | Syntactic classification |
| 5.10 | Column-store graph | Object graph | Append-only structure |

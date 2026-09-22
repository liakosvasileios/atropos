# The Theory Behind Atropos

Of the three sisters who preside over every mortal thread, Atropos is the one who does not linger. Clotho spins the raw wool of a life into being, Lachesis walks its length and measures out how far it will run, but Atropos comes last, shears in hand, and hers is the only gesture that cannot be undone — a single cut, and the thread simply stops being a thread. The Greeks called her ἄτροπος, "the unturning," because unlike her sisters she does not deliberate or relent; where they shape possibility, she closes it. It is fitting, then, that a tool built to walk backward through a program's execution should borrow her name. Every crash, every exploited check, every silent branch a reverse engineer stares at is itself a kind of cut thread — a moment already decided, already severed from the countless paths that might have led there instead. To understand it, you cannot spin forward with the program as it runs; you must stand at the place where the thread was cut and follow it backward through everything that was woven before it, instruction by instruction, until the shape of the ending explains itself. In that sense the tool does not choose fate as Atropos does — it does the opposite, and unspools what she has already decided, tracing the pattern of a life already finished to learn how it came to end exactly where it did.

**Program slicing, dynamic dependence, and the formal model implemented in v0.2**

This document gives the theoretical foundations of Atropos: the definitions the tool computes, the
algorithms that compute them, the properties those algorithms have (and provably do not have), and the
assumptions on which every result rests. Where the implementation departs from the textbook
formulation, the departure is stated and justified. Section references into the code are given so each
claim can be checked against `src/atropos/`.

The companion documents are [`reference.md`](reference.md) (how to use and read the code),
[`design-v0.2.md`](design-v0.2.md) (engineering rationale) and
[`architecture-review.md`](architecture-review.md) (a critical analysis of the design decisions).

---

## Contents

1. [The problem](#1-the-problem)
2. [Program slicing: static and dynamic](#2-program-slicing-static-and-dynamic)
3. [The execution model](#3-the-execution-model)
4. [Storage locations as bytes](#4-storage-locations-as-bytes)
5. [Instruction semantics as an effect function](#5-instruction-semantics-as-an-effect-function)
6. [Data dependence and the last-writer relation](#6-data-dependence-and-the-last-writer-relation)
7. [Typed dependences: value, address, control](#7-typed-dependences-value-address-control)
8. [Control dependence](#8-control-dependence)
9. [The dynamic dependence graph](#9-the-dynamic-dependence-graph)
10. [The slicing algorithms](#10-the-slicing-algorithms)
11. [Soundness, completeness and precision](#11-soundness-completeness-and-precision)
12. [Code identity under self-modification](#12-code-identity-under-self-modification)
13. [Summaries: dependence across untraced code](#13-summaries-dependence-across-untraced-code)
14. [Trace integrity as invariant enforcement](#14-trace-integrity-as-invariant-enforcement)
15. [Control-flow flattening and honest refusal](#15-control-flow-flattening-and-honest-refusal)
16. [Complexity](#16-complexity)
17. [Validation theory: the differential oracle](#17-validation-theory-the-differential-oracle)
18. [Limitations and open problems](#18-limitations-and-open-problems)
19. [Notation summary](#19-notation-summary)
20. [References](#20-references)

---

## 1. The problem

A reverse engineer looking at a concrete execution of a binary asks a recurring question:

> For this value, at this point in the run, which instructions actually contributed to producing it —
> and which inputs did it ultimately depend on?

Two canonical instances: *the buffer handed to `CryptEncrypt` — how was the key derived, and from
what?* and *the byte at the address a packer is about to jump to — which loop decoded it, from which
source bytes?*

The answer is a **backward dynamic slice**. Atropos computes it for Windows x86-64 executions
recorded under Frida's Stalker. The theory below is, at its core, thirty-five years old (Korel–Laski
1988, Agrawal–Horgan 1990). What is specific to Atropos is the *model* on which that theory is
instantiated — what a "variable" is on x86-64, what an "instruction" does to it, how code identity
survives self-modification, and what the tool says when it cannot answer. Those choices determine
whether the slice is right, and they are where this document spends most of its effort.

---

## 2. Program slicing: static and dynamic

### 2.1 Weiser's static slice

Weiser [1] defined a slice of a program *P* with respect to a criterion *C = (p, V)* — a program point
*p* and a set of variables *V* — as any executable subprogram *P′* of *P* whose behaviour at *p* with
respect to *V* is the same as *P*'s for every input. Static slices reason over all possible executions
from the program text. Computing the minimal one is undecidable; practical algorithms compute a
conservative superset by dataflow over the control-flow graph, or by reachability in the program
dependence graph of Ferrante, Ottenstein and Warren [8].

For binaries the static formulation degrades badly: indirect branches fan out, aliasing of memory
operands is undecidable in general, and self-modifying code invalidates the disassembly the analysis
rests on.

### 2.2 Korel and Laski's dynamic slice

Korel and Laski [2] fixed a single execution: given an input *x*, the *execution history* is the
sequence of statement *instances* executed, and the dynamic slice with respect to *(x, p^k, V)* —
input, the *k*-th occurrence of point *p*, and variables *V* — is the set of instances that
contributed to the values of *V* at that occurrence. Aliasing disappears because every address is
concrete; branch outcomes are known; and only instructions that actually ran participate.

The trade is explicit: a dynamic slice is a statement about **one** execution, not about the program.

### 2.3 Agrawal and Horgan's dynamic dependence graph

Agrawal and Horgan [3] made the computation graph-theoretic. The **dynamic dependence graph (DDG)** has
one node per executed instance and one edge per dynamic data or control dependence; the backward
dynamic slice is the set of nodes from which the criterion is reachable. The DDG is exact for the
execution, and its size is proportional to execution length rather than program size. Zhang, Gupta and
colleagues [5, 6] studied the resulting scaling problem; Xin and Zhang [7] the online detection of
dynamic control dependence.

Atropos implements [2] and [3] directly. Everything that follows specifies precisely what "instance",
"variable", "data dependence" and "control dependence" mean in its model.

---

## 3. The execution model

### 3.1 The trace

An execution is recorded as a trace and replayed offline. After replay, the execution is a finite
sequence of **instruction instances**

$$\tau = \langle i_0, i_1, \ldots, i_{n-1} \rangle,$$

indexed by the **sequence number** $\text{seq}(i_k) = k$. Each instance carries a static address $a$,
a **code version** $v$ (§12), the raw instruction bytes $b$, a thread id, and — from the trace — the
concrete effective address and size of each memory operand it touched.

Two further kinds of instance appear in $\tau$: **summary nodes** synthesised for hooked API calls
(§13), and nothing else. Untraced code (excluded modules, the kernel) contributes no instances; its
effects are either summarised or absent.

### 3.2 Static instruction versus instance

A *static instruction* is the pair $(a, v)$. An *instance* is one execution of it; the *occurrence
index* of $i_k$ is the number of earlier instances with the same $(a, v)$. Everything Atropos computes
is over instances; static instructions appear only when rendering ("this address, executed 4 000
times, collapsed to one row").

### 3.3 Threads

The model is single-threaded: $\tau$ is a total order. Multi-threaded traces are recordable (each
node carries a tid) but the interleaving recorded is the one the agent observed, and the
control-dependence stack (§8) is global. Concurrency-correct slicing is future work (§18).

---

## 4. Storage locations as bytes

### 4.1 The location space

The set of storage locations is

$$\mathcal{L} = \mathcal{L}_{\text{reg}} \;\uplus\; \mathcal{L}_{\text{mem}}, \qquad
\mathcal{L}_{\text{reg}} = \{0, \ldots, 2639\}, \qquad \mathcal{L}_{\text{mem}} = \{0, \ldots, 2^{64}-1\}.$$

Every element is **one byte** (for registers, one *lane*; for flags, one bit modelled as a lane). A
*range* is $(s, \ell, w) \in \{\text{reg},\text{mem}\} \times \mathbb{N} \times \mathbb{N}^{+}$ meaning
the bytes $\ell, \ell+1, \ldots, \ell+w-1$ of space $s$.

The register lane space is laid out as: GPR (16 × 8), FLAG (16 slots, 7 used: CF PF AF ZF SF OF DF),
VEC (32 × 64, ZMM width), SEG (6 × 8), MMX (8 × 8), X87 (8 × 10), EXTRA (32 × 8, allocated on demand
to unmodelled register names). `RIP` has no lane.

### 4.2 Why bytes

x86-64 registers alias at sub-register granularity. `RAX ⊃ EAX ⊃ AX ⊃ AL`, and `AH` is byte 1 of
`RAX`. A model in which "RAX" is one variable makes `mov al, 1` kill the definition of all of RAX
(false kill → missing contributors) or makes a read of `AL` depend on a write to `AH` (false use →
invented contributors). Both errors produce a *plausible* slice with no error. Bytes are the coarsest
granularity at which the aliasing structure of the register file is exactly expressible.

The same holds for memory: a 4-byte store followed by a 2-byte load of its upper half is exactly
described only at byte granularity, and at byte granularity it needs no special case.

### 4.3 The widening rule

Let $\rho(\cdot)$ map a register name to its lane range and $\pi(\cdot)$ to its architectural parent's
range. The **definition footprint** of a write to register $r$ is

$$\text{def}(r) = \begin{cases}
\pi(r) & \text{if } r \text{ is a 32-bit GPR view (zero-extension), or a VEX/EVEX-encoded vector write} \\
\rho(r) & \text{otherwise (8-, 16-, 64-bit GPR; legacy-SSE vector; flags; segment)}
\end{cases}$$

The **use footprint** of a read of $r$ is always $\rho(r)$. Zero-extension is a *definition* of the
upper lanes (their value becomes a known zero attributable to this instruction), not a non-effect —
so `mov eax, x` has eight last-writer entries pointing at it, and a later `mov rbx, rax` correctly
depends on it for all eight bytes, while `mov al, x` leaves lanes 1–7 with their previous writers.
(`arch/effects.py::_def_range`, `arch/lanes.py`.)

### 4.4 Flags as bits

Each of CF, PF, AF, ZF, SF, OF, DF is its own location. A conditional branch reads only the flags its
condition consults ($\text{jz} \to \{\text{ZF}\}$, $\text{jl} \to \{\text{SF}, \text{OF}\}$,
$\text{jbe} \to \{\text{CF}, \text{ZF}\}$). With a monolithic `RFLAGS` location every branch would be
data-dependent on every flag-writing instruction that preceded it — nearly every arithmetic
instruction — and control chains would be noise.

---

## 5. Instruction semantics as an effect function

### 5.1 The effect function

Semantics are decided **at replay time** from the instruction bytes, not at capture time. The
**effect function**

$$E : \text{bytes} \to \big(U_{\text{val}},\; U_{\text{addr}},\; D,\; F_{\text{use}},\; F_{\text{def}},\; F_{\text{may}},\; M,\; \kappa\big)$$

maps raw bytes to: register ranges read for their *value*; register ranges read to form an
*address*; register ranges defined; flag bits read, defined, and possibly-defined (architecturally
undefined afterwards); an ordered list $M$ of memory access *slots* (size, direction, canonical
position); and a classification $\kappa$ (conditional/unconditional branch, call, return, indirect,
syscall, `rep`, variable shift). Memory operand *addresses* are not part of $E$ — they come from the
trace and are matched to the slots of $M$ by position.

$E$ is a pure function of the bytes (not of the address: RIP-relative addressing yields a constant,
not a dependence), so it is memoised by bytes. It is realised as Capstone's decoder plus an explicit
override table (`arch/effects.py`).

### 5.2 Disassembly semantics versus dataflow semantics

A decoder describes operands; a dataflow model needs *information flow*. The two differ in a small
number of high-frequency cases, and each such case, if mishandled, injects a spurious edge into a large
fraction of all slices:

| Instruction | Decoder says | Dataflow truth | Override |
|---|---|---|---|
| `xor r, r`, `sub r, r`, `pxor x, x`, `vpxor x, y, y`, `pcmpeq* x, x`, … | reads *r* | result is a constant; reads nothing | drop the value use of *r* |
| `and r, 0`, `imul r, s, 0`, `or r, -1` | reads *r* (and *s*) | constant | drop all value uses |
| `sbb r, r` | reads *r*, CF | **genuinely** reads CF (carry broadcast) | *no* override — matched by mnemonic, not shape |
| `lea r, [b + i*s + d]` | memory operand | pure arithmetic; no access, no flags | base/index become *value* uses; no slot in $M$ |
| `cmovcc r, s` | writes *r* | if condition false, *r* keeps its value: *r* is read | add *r* as a value use |
| `nop`, `endbr64`, `pause` | various | nothing | no effect |
| `shl r, cl` etc. | writes flags | count 0 ⇒ nothing changes, not even flags | count-dependent (§5.4) |
| `rep movsb` etc. | one access each side | a whole loop | bulk model (§5.5) |

The zeroing idiom is the most consequential: `xor eax, eax` occurs in almost every compiled function,
and modelling it as a read links every slice through that function to whatever last wrote `eax`.

### 5.3 Undefined flags: may-definitions

Where the ISA leaves a flag *undefined* after an instruction (AF after logical ops, OF after
multi-bit shifts, most flags after `mul`), the instruction is recorded as the flag's last writer
(a subsequent read genuinely obtains its garbage from here) but the lane is marked *undefined*. A read
of an undefined lane produces an edge annotated `imprecise`. The dependence *exists*; its value
content is not architecturally determined. Tracking this per lane rather than per node means only
reads that actually consume undefined values are annotated.

### 5.4 Value-dependent effects

Two families of instruction have effects that depend on runtime values the decoder cannot see. The
trace records the needed value in a narrow side record:

- **Variable shifts** (`shl r, cl`): a count of zero (mod 64) modifies neither the destination nor
  any flag. Recording a definition would make the shift the phantom last writer of a register it did
  not touch. With `SHIFTCNT = 0`, all definitions are suppressed. Without a `SHIFTCNT` record the
  conservative (always-defines) model is used and the node is marked `imprecise`.
- **`rep`-prefixed string operations**: the loop is one instruction whose footprint is
  $\text{count} \times \text{element}$ bytes at RSI/RDI, direction by DF, with `repe/repne` needing
  the post-state RCX to learn how far the loop ran. Modelled as a single **bulk** node: one read edge
  per run of the whole source range, one definition of the whole destination range, edges annotated
  `bulk`. Byte-exact provenance ($\text{dst}[j] \leftarrow \text{src}[j]$) is lost inside the bulk
  node; this is the trade documented in §11.3.

---

## 6. Data dependence and the last-writer relation

### 6.1 Definition

For a location $\ell \in \mathcal{L}$ and a sequence index $k$, define the **last writer**

$$\text{LW}_k(\ell) = \max\{\, j < k \;:\; \ell \in D(i_j) \,\} \quad \text{or } \bot \text{ if the set is empty},$$

where $D(i_j)$ is the set of locations instance $i_j$ defines (register defs widened per §4.3, flag
defs and may-defs, memory writes at their concrete addresses). $\bot$ (`LIVE_IN`) means no traced
instance wrote $\ell$ before $k$.

Instance $i_k$ is **data-dependent** on instance $i_j$ through $\ell$ iff

$$\ell \in U(i_k) \;\wedge\; \text{LW}_k(\ell) = j,$$

where $U(i_k)$ is the set of locations $i_k$ uses (value, address and flag reads, memory reads).

**Proposition 6.1 (uniqueness).** *For every $k$ and $\ell$, $\text{LW}_k(\ell)$ is a single element of
$\{0, \ldots, k-1\} \cup \{\bot\}$.*

*Proof.* $\tau$ is a total order and the set is finite; the maximum of a finite totally ordered set is
unique when it exists. $\square$

This is the entire reason dynamic data-dependence analysis is trivial where static analysis is hard:
there is no may/must distinction, no fixpoint, no alias question. Two accesses alias iff their concrete
byte ranges intersect.

### 6.2 The forward pass

The last-writer relation for all $k$ simultaneously is computed by a single forward pass maintaining
**shadow state** $S : \mathcal{L} \to \{0,\ldots,n-1\} \cup \{\bot\}$, initially $\bot$ everywhere:

```
for k in 0 .. n-1:
    for each range (s, ℓ, w) in U(i_k):            # reads, against the PRE-state
        for each maximal run [ℓ', ℓ'+w') ⊆ [ℓ, ℓ+w) with S constant = j on it:
            emit edge  i_k ←(kind, s, ℓ', w')— j     # j may be ⊥
    for each range (s, ℓ, w) in D(i_k):            # then writes
        S[ℓ .. ℓ+w) := k
```

**Invariant (read-before-write).** All uses of $i_k$ are resolved against $S$ *before* any definition
of $i_k$ is applied. This makes read-modify-write instructions (`add [rbx], rax`) correct with no
special case: the read resolves to the previous writer of `[rbx]`, then the write installs $k$.

The pass is $O\!\left(\sum_k (|U(i_k)| + |D(i_k)|)\right)$ — linear in trace length times the mean
footprint per instruction (a small constant: a few register bytes and a memory operand).
(`replay.py::_execute_insn`, `shadow.py`.)

### 6.3 Multi-definition reads

A single read of $w$ bytes has up to $w$ distinct last writers. Consider

```
mov eax, X        ; defines rax[0..7]   (zero-extension)
mov ah, Y         ; defines rax[1]
mov rbx, rax      ; reads  rax[0..7]
```

$\text{LW}$ over `rax[0..7]` is $\langle 1, 2, 1, 1, 1, 1, 1, 1\rangle$ — *two* producers. Run-splitting
(§6.2, `read_runs`) yields edges $(\text{rax}[0], 1)$, $(\text{rax}[1], 2)$, $(\text{rax}[2{:}7], 1)$.
Reporting a single writer per read would silently drop a contributor. The same mechanism gives exact
answers for a buffer assembled one byte at a time and read as a qword.

### 6.4 Live-in leaves

An edge with target $\bot$ is a **live-in leaf**: the value came from initial memory, from a register
set before tracing began, or from an untraced writer. Leaves are classified at output time by
consulting the module map (initial image data vs other memory vs register). Together with *immediate
constants* (instances in the slice with no incoming edge of an allowed kind) and *environmental
sources* (§13), they constitute the **input report** — the set of things the sliced value ultimately
depended on.

---

## 7. Typed dependences: value, address, control

### 7.1 Three kinds

Every edge carries a kind $\kappa \in \{\text{value}, \text{addr}, \text{control}\}$:

- **value** — the consumer's result is a function of this byte (arithmetic and data-movement
  operands, flag reads, memory reads);
- **address** — this byte determined *where* the consumer read or wrote (base/index/segment registers
  of a memory operand, `RSP` for implicit stack accesses, argument registers of a summary);
- **control** — this branch determined *whether* the consumer executed (§8).

### 7.2 Why the address/value split is necessary

`mov rax, [rbx+8]` value-depends on the eight bytes of memory and address-depends on `RBX`. Without
the distinction, every load through the stack pointer would drag in every instruction that adjusted
`RSP` — every `push`, `pop`, `call`, `ret`, prologue and epilogue — and `RSP` becomes a universal
attractor. The pointer provenance is a real dependence and sometimes exactly the question ("who
controlled this indirect call target"); it is just a *different* question from "what arithmetic made
this value", and conflating them makes both unanswerable.

The classification is *syntactic*: a register is an address use iff it appears in a memory operand's
addressing expression. Pointer arithmetic performed with `add`/`lea` before the load is a value
dependence of the pointer register and only becomes an address dependence at the dereference. This
boundary is where the split can be argued with; it is stated so the reader knows what "address
provenance" means precisely.

### 7.3 Modes as filters

A **slice mode** is a set of allowed kinds $K \subseteq \{\text{value}, \text{addr}, \text{control}\}$
with $\text{value} \in K$. The four exposed modes are $\{v\}$, $\{v, a\}$, $\{v, c\}$, $\{v, a, c\}$.
The backward slice in mode $K$ is reachability over edges whose kind lies in $K$. Since adding kinds
adds edges and reachability is monotone in the edge set, the modes form a lattice under inclusion:
$\text{slice}_{\{v\}} \subseteq \text{slice}_{\{v,a\}} \subseteq \text{slice}_{\{v,a,c\}}$ and
likewise for $\{v, c\}$.

---

## 8. Control dependence

### 8.1 Static definition

In the Ferrante–Ottenstein–Warren formulation [8], over a CFG with a unique exit, node $Y$ is
control-dependent on node $X$ iff (i) there is a path from $X$ to $Y$ on which every node other than
$X$ is post-dominated by $Y$, and (ii) $X$ is not post-dominated by $Y$. Equivalently: $X$ is a branch,
one of whose successors leads to $Y$ on all paths and another of which may avoid $Y$. The
**immediate post-dominator** $\text{ipdom}(X)$ is the first node that every path from $X$ to exit
passes through; control dependence of the region "between $X$ and $\text{ipdom}(X)$" is on $X$.

### 8.2 Dynamic definition

In an execution history, instance $i_k$ is **dynamically control-dependent** on the most recent
conditional-branch instance $i_j$ ($j < k$) whose immediate post-dominator block has *not yet* been
reached between $j$ and $k$ in the same activation. Korel–Laski's formulation gives each instance
exactly **one** guarding branch (the innermost pending one), which is why Atropos stores control
dependence as one entry per node (`node_ctrl`) rather than as edges.

### 8.3 The CFG is recovered from the trace

There is no static CFG for a hostile binary. Atropos recovers the *observed* CFG per code version from
the block-run log: nodes are Stalker basic blocks, an edge $B_1 \to B_2$ is added whenever $B_2$
executed immediately after $B_1$ within the same function activation. Functions are delimited at
`call`/`ret` terminators. This CFG contains only edges that were taken; a conditional branch whose
other arm never ran has out-degree one. Post-dominance is computed over this observed graph, so
"post-dominates" means "on every *observed* path".

### 8.4 Post-dominators

Post-dominance is dominance on the reversed graph with a virtual exit joined to every block without
observed successors (or, if the function never exited during the run — a closed loop — to the block
of maximum in-degree, an arbitrary but deterministic choice). Immediate post-dominators are computed
with the Cooper–Harvey–Kennedy iterative algorithm [9]: reverse-postorder traversal, `intersect` on the
dominator tree, iterate to a fixpoint (bounded at 100 rounds as a guard). (`cfg.py::compute_ipdom`.)

### 8.5 Attribution with a call-depth stack

Attribution walks the block-run log with a stack of pending guards $\langle \text{branch\_seq},
\text{ipdom\_block}, \text{depth} \rangle$:

```
on entering block B at call depth d:
    pop while top.depth > d                       # frames we have left
    pop while top.ipdom == B and top.depth == d   # post-dominator reached
    guard(every instance of B) := top.branch_seq or ⊥
on leaving B via its terminator t:
    call            → d += 1
    ret             → d -= 1; pop while top.depth > d
    cond. branch    → push ⟨seq(t), ipdom(B), d⟩   (unless the function is flattened, §15)
    aborted block   → drop entries with depth ≥ d
```

**Why depth is not optional.** A branch taken inside a callee is waiting for a post-dominator that
lives in the callee. Without depth, after the callee returns that entry never pops; every subsequent
instruction in the caller inherits an unrelated guard, the stack grows monotonically, and control
slices grow without bound. With depth, a `ret` discards every entry pushed in the frame being left.

**Proposition 8.1.** *Under the attribution above, if $\text{guard}(i_k) = j$ then $j < k$, $i_j$ is a
conditional branch, and $i_j$ and $i_k$ executed in the same activation with no intervening execution
of $\text{ipdom}(\text{block}(i_j))$ at that depth.* This is the dynamic control-dependence condition
of §8.2 restricted to observed post-dominance. (Sketch: an entry is pushed only by a conditional
terminator, popped exactly when its ipdom is entered at its depth or its frame is left; the top entry at
the time of $i_k$ is the innermost such.)

What is *not* handled: exceptions unwinding frames without a `ret` (detected as discontinuities, §14;
entries are dropped conservatively), and `ret`-based dispatch (a `ret` that is really a jump decrements
the depth and drops guards early — degrading toward "no control dependence" rather than inventing
one).

---

## 9. The dynamic dependence graph

The DDG is $G = (N, E_{\text{data}}, \text{guard})$ with $N = \{0, \ldots, n-1\}$,
$E_{\text{data}} \subseteq N \times (N \cup \{\bot\}) \times \{\text{reg},\text{mem}\} \times \mathbb{N}
\times \mathbb{N}^+ \times \{\text{value}, \text{addr}\} \times \text{Flags}$ (use, def, space, start,
length, kind, annotations) and $\text{guard} : N \to N \cup \{\bot\}$.

**Proposition 9.1 (acyclicity).** *Every data edge and every guard points strictly backward:
$(k, j, \ldots) \in E_{\text{data}} \Rightarrow j < k$, and $\text{guard}(k) = j \Rightarrow j < k$.
Hence $G$ is a DAG and trace order is a topological order.* (By construction: §6.1 gives $j < k$ for
data; §8.5 gives it for guards.)

The graph is stored as parallel typed-array columns. Because the forward pass emits all edges of node
$k$ before any edge of node $k+1$, a node's edges are contiguous and
$[\text{node\_edge\_start}[k], \text{node\_edge\_start}[k+1])$ indexes them with no auxiliary
structure. A parallel *definition* column records what each node wrote, which is what lets a
criterion — a *location at a point*, not an edge — be resolved (§10.1). Measured cost: ≈135 bytes per
node including edges, on the fixture traces.

---

## 10. The slicing algorithms

### 10.1 Criterion resolution

A criterion is $C = (k, \{(s_i, \ell_i, w_i)\})$: a sequence index and a set of ranges. It is
interpreted in the **post-state** of $i_k$: the seed set is

$$\text{seed}(C) = \bigcup_i \{\, \text{LW}_{k+1}(\ell) : \ell \in [\ell_i, \ell_i + w_i) \,\} \setminus \{\bot\},$$

with the $\bot$ entries reported as live-in inputs. This is computed by a forward scan over the
definition columns of nodes $0..k$ (not a second replay), split into runs. A criterion "at the mark"
therefore means "as of the instruction after the mark", and `--at seq=N --loc r` where $i_N$ writes
$r$ seeds with $N$ itself.

### 10.2 Backward slice

$$\text{BS}_K(C) = \{\, j \in N : j \rightsquigarrow_K s \text{ for some } s \in \text{seed}(C) \,\} \cup \text{seed}(C),$$

where $j \rightsquigarrow_K s$ means $s$ reaches $j$ backward along edges of kind in $K$ (data edges
of the allowed kinds, and $\text{guard}$ edges iff $\text{control} \in K$). Computed by depth-first
reachability with a visited set keyed by node:

```
frontier := seed(C); included := seed(C)
while frontier:
    x := frontier.pop()
    for each data edge (x, j, …, kind) with kind ∈ K:
        if j = ⊥: record input leaf; continue
        if j ∉ included: included += j; frontier.push(j); record why(j) = (x, kind, range)
    if control ∈ K and guard(x) = g ≠ ⊥ and g ∉ included:
        included += g; frontier.push(g); why(g) = (x, control); depth(g) = depth(x)+1
```

Keying the frontier by node alone (rather than by node × byte-range as in the design document's
pseudocode) is equivalent and cheaper: once a node is in the slice, *all* its uses are followed, so a
finer key can add nothing. The byte-range frontier is needed only at seeding.

**Termination and cost.** By Proposition 9.1 the reachable set is finite and each node is expanded at
most once; the cost is $O(|\text{BS}| + |\text{edges out of BS}|)$ — proportional to the **answer**,
not to the trace. Caps (`max_nodes`, `max_control_depth`) exist for readability and mark the result
*truncated*.

### 10.3 Forward slice and chop

The forward slice $\text{FS}_K(k)$ is reachability in the reversed direction from a single node,
using an on-demand def→users index; it answers "what did this value go on to affect" (the
taint-analysis question, without a taint engine). The **chop** from $k_1$ to $C_2$ is
$\text{FS}(k_1) \cap \text{BS}(C_2)$: the instances on some dependence path from source to sink —
usually the most readable answer to "how does this input reach that buffer". (v0.2 forwards from the
whole node, not from a location within it, and does not propagate control forward.)

---

## 11. Soundness, completeness and precision

All statements are relative to the model: the trace $\tau$ as recorded, the effect function $E$, and
the summaries in force.

### 11.1 What "sound" means here

**Claim (relative soundness).** *If $E$ is correct for every instruction in $\tau$ and the trace is
faithful (§14), then every instance that influenced the criterion's value through a chain of traced
data/control dependences is in $\text{BS}_{\{v,a,c\}}(C)$.*

Sketch: influence propagates only through reads of locations written earlier (data) or through branch
outcomes (control). By Proposition 6.1 every read is attributed to its actual last writer; by §8.5
every instance is attributed to its innermost pending branch. Reachability closes the chain. $\square$

The claim is about the **model**, not the hardware. It is falsified by any of: a wrong entry in $E$
(§5), a summary that under-approximates an API's footprint (§13), a bulk `rep` node (which is
sound — it over-approximates — but imprecise), an untraced writer (a live-in leaf that is really a
dependence on excluded code), or an unfaithful trace.

### 11.2 One run only

$\text{BS}(C)$ is a statement about $\tau$. A different input may derive the key by a different path;
nothing in the slice says otherwise. This is the defining limitation of dynamic slicing and it is the
right trade for reverse engineering, where the task is to explain an observed behaviour, not to prove a
property of all behaviours.

### 11.3 Sources of imprecision, and how they are surfaced

| Source | Effect on the slice | Annotation |
|---|---|---|
| `rep` bulk model | over-inclusion of the whole source range of a copy | `bulk` (edge and node) |
| ISA-undefined flag values | dependence exists, value content unspecified | `imprecise` (edge and node) |
| Unmodelled external call | defines RAX only; pointer-argument effects unknown | `imprecise`, `summary`, banner count |
| Variable shift without count record | conservative always-defines | `imprecise` |
| Control dependence in flattened function | withheld entirely (§15) | `cd-unreliable`, banner |
| Excluded modules | no instances; effects appear as live-in leaves or via summaries | leaf classification |
| Suspect trace region | anything | `suspect`, refusal |

The design principle is that every departure from exactness is *visible in the output*, in the
precision banner and on the affected rows — so that the analyst can tell an exact answer from an
approximate one without re-deriving it.

---

## 12. Code identity under self-modification

### 12.1 The problem

A packer writes decoded code over the stub that decoded it; a polymorphic loader rewrites its own
loop. The same address holds different instructions at different times. If code is keyed by address
alone, a record emitted before the rewrite is decoded with post-rewrite bytes: a wrong $E$, hence
wrong read/write sets, hence a plausible slice about a computation that never happened. **No error is
raised**, because the replay has no way to know.

### 12.2 The version clock

The agent maintains a global **code version** $v \in \mathbb{N}$, incremented whenever a memory
protection or allocation call touches a page containing already-instrumented code. A block descriptor
is identified by $(a, v)$ and has a globally unique id; the trace carries `VERSION` records at each
bump; replay checks that every executed block's recorded version equals the stream's current version
and reports an error otherwise.

The invariant, stated in the format specification and enforced at the reader: *nothing downstream may
key code by address alone.* The version is part of the node identity, appears in listings as `vN`, and
distinguishes occurrences: the first execution of `(a, 1)` is occurrence 0 even if `(a, 0)` ran a
thousand times.

### 12.3 Trust and its limit

Frida's `trustThreshold` controls when Stalker stops re-examining a block. Never trusting is correct
for hostile code and 10–100× slower on loops. Atropos trusts by default and invalidates every known
block on a version bump, so re-instrumentation runs only when a rewrite was *detected*. The exposure is
an *undetected* rewrite: a write to RWX memory needs no API call. The agent has a hook point for
sampled block re-hashing to catch this; in v0.2 it is not implemented. A rewrite that escapes detection
is the one way the version invariant can be violated without an integrity error — and it is the
principal known threat to soundness (architecture review, T3).

---

## 13. Summaries: dependence across untraced code

### 13.1 The hole

Excluded modules (`ntdll`, `kernel32`, the CRT, …) contribute no instances. A `memcpy` inside the CRT
therefore leaves the destination bytes with no last writer, and a slice through them bottoms out in a
spurious "unwritten memory" leaf: the analyst is told the data came from nowhere.

### 13.2 A summary as a declarative effect

A **summary** is a hand-written element of $E$ for an API: read ranges and write ranges expressed as
(pointer argument, length) pairs, plus whether RAX is defined. The agent hooks the export, captures the
concrete argument values on entry, and emits a `SUMMARY` record on *return* (so write ranges describe
post-call contents). Replay expands it into a synthetic node with real edges: address edges from the
argument registers, value edges from the read ranges, definitions of the write ranges.

Summaries are classified, and the classification is what the input report keys on:

- **transform** — output is a function of input (`memcpy`, `CryptEncrypt`): the edge *crosses* the
  call;
- **source** — output originates outside the process (`ReadFile`, `GetVolumeInformationW`,
  `BCryptGenRandom`): the node is a *leaf*, and the interesting kind — "the key depends on the volume
  serial" is exactly the crypto workflow's answer;
- **alloc / free** — region lifecycle; `free` releases shadow pages so peak memory tracks the live
  working set;
- **unknown** — the conservative default: defines RAX, marks the node imprecise, says so in the banner.

### 13.3 Why "unknown" is weak on purpose

For an unrecognised call the honest options are: guess byte ranges for pointer arguments (too small →
missed dependences; too large → invented ones; both invisible), or admit ignorance. Atropos admits
ignorance and *counts* it, so the banner can say "N edges in this chain crossed an unmodelled call".

### 13.4 Known defect in v0.2

The reference implementation's `Ref` resolves an integer length as a *literal byte count* while the
default table (and its documentation) intends integers as *argument indices*. Most memory-moving and
I/O summaries therefore cover 1–8 bytes rather than the argument-specified length. This is a table
convention bug, not a modelling-theory issue; it is recorded in `reference.md` §16 and affects any
slice that crosses those APIs until fixed.

---

## 14. Trace integrity as invariant enforcement

### 14.1 Silent plausibility

The governing hazard of the domain is this: *a slicer fed a wrong trace does not crash; it produces a
slice.* The slice has real addresses, real instructions and a sensible-looking chain, about a different
execution than the one that happened. The analyst cannot tell from the output. The only defence is to
check the trace's internal consistency and **refuse** to slice when it fails.

### 14.2 The invariants and their checks

| Invariant | Check | What a violation indicates |
|---|---|---|
| Consecutive block executions are connected | continuity: a fully executed block's terminator must be able to reach the next block's start (fall-through, direct target, or an unpredictable transfer: call/ret/indirect/syscall/conditional) | an exception, a lost thread, an untraced transfer |
| The agent and the model agree on what an instruction *is* | $|M(E(b))| = $ number of `MEM` records for that instruction | undetected code rewrite, decoder disagreement |
| Every executed block carries the stream's current version | recorded version = current version | a stale descriptor after a bump |
| Block ids resolve | `BLOCK` names a known descriptor | corrupt or truncated code stream |
| Records are well formed | varint/blob/magic/version checks | truncation, corruption, wrong format version |

A violation is an **error**; the tool refuses to slice unless `--allow-suspect` is given, and then
marks the output. Weaker observations (a size disagreement between decoded and recorded operand, a
missing side record, an unknown summary id) are **notes** and annotate rather than refuse. The checker
is deliberately weak — it rejects only *impossible* transitions, not unusual ones — because obfuscated
code legitimately does strange things and a checker that cries wolf gets disabled.

---

## 15. Control-flow flattening and honest refusal

### 15.1 Why post-dominance degenerates

Control-flow flattening [18] rewrites a function so that every basic block returns to a central
dispatcher that selects the next block from a state variable. In the resulting CFG the dispatcher
post-dominates every other block. The Ferrante–Ottenstein–Warren relation is then *technically
correct*: every instruction is control-dependent on the dispatcher's branch, which is control-dependent
on the previous case block's assignment to the state variable, and so on. The relation carries no
information about the original program's decisions. A `value+ctrl` slice would include the entire
dispatch history and present it as an answer.

### 15.2 Detection

A function is deemed flattened when, jointly: it has ≥5 blocks and ≥4 branching blocks (conditional
*and* unconditional terminators — case blocks end in `jmp dispatcher`, and keying only on conditional
branches finds one branch and never fires); one block is the immediate post-dominator of ≥60 % of the
branching blocks (post-dominance degeneracy); that block has in-degree ≥4 and is a successor of
≥50 % of the other blocks (structural hub — the shape of a dispatch loop that an ordinary
single-exit function does not have). The thresholds are stated as uncalibrated guesses and are
configurable.

### 15.3 The policy

In a flattened function no control edges are attributed; every instance is annotated
`cd-unreliable`; the banner says *control dependence: unavailable*. `--force-cd` overrides. The
principle: **an honest "cannot answer" is strictly better than a confident degenerate answer**,
because the analyst can act on the first and is misled by the second.

---

## 16. Complexity

Let $n$ be trace length (instances), $m$ the number of memory accesses, $f$ the mean footprint (bytes
read + written) per instance, $|B|$ the number of distinct blocks and $|\text{BS}|$ the slice size.

| Stage | Time | Space | Scales with |
|---|---|---|---|
| Capture (in-target) | $O(n)$ probe invocations; dominated by per-probe register spill | ring buffer | execution length |
| Trace volume | $O(n_{\text{blocks}} + m)$ records, delta-coded EAs | disk | execution length |
| Decode | $O(|B| \cdot \text{insns})$, memoised by bytes | cache | *code* size |
| Forward replay | $O(n \cdot f)$ | shadow: $O(\text{lanes} + \text{pages touched})$; DDG: $O(n \cdot f)$ | execution length |
| Post-dominance | CHK: near-linear per function in practice | $O(|B|)$ | code size |
| Attribution | $O(n_{\text{blocks}})$ with amortised stack ops | stack depth | execution length |
| Criterion seeding | $O(\text{defs before } k)$ | $O(w)$ | prefix length |
| Backward walk | $O(|\text{BS}| + \text{edges out of BS})$ | visited set | **the answer** |

The structural observation: every stage that scales with execution length happens *once*, at record
or replay time, and the query scales with the answer. Dynamic slicing's scaling problem is therefore a
*recording* problem, which is why the trace encoding matters more than any algorithmic choice in the
slicer, and why the compaction literature [6] targets the trace.

Measured (reference Python implementation, one machine): ≈$6 \times 10^4$ instances/s replay
end-to-end, ≈135 bytes/node in the DDG, a 4-node value slice in 0.08 s and a 120 000-node full slice
in 0.32 s from a 210 000-node trace. A 5 M-instance trace is thus on the order of a minute to replay
and milliseconds to seconds to query.

---

## 17. Validation theory: the differential oracle

### 17.1 Why review cannot establish correctness

Every bug in $E$ produces a plausible slice, not an error (§14.1). Inspecting slices therefore cannot
establish correctness; neither can hand-written fixtures alone, which test the cases their author
thought of.

### 17.2 Two independent implementations

Atropos contains a second slicer (`oracle.py`) that shares nothing with the effect model but the
fixture: it walks the fixture's *source text*, with read and write sets transcribed longhand from the
architecture manual, and slices by direct simulation of the last-writer relation over
$(\text{space}, \text{byte})$ pairs. It is slow and simple by design; its qualification is being
obviously correct by inspection.

The assertion is $\text{BS}^{\text{oracle}}(C) = \text{BS}^{\text{atropos}}_{\{v,a\}}(C)$ on the same
fixture (in `value+addr` mode, because the oracle does not type its edges). Random straight-line
programs over the modelled subset extend this into a fuzzing loop.

### 17.3 What it proves

Agreement establishes that two independently derived models of the subset agree — a strong statement
because a shared misconception is the only way both can be wrong together, and one is derived from a
decoder's access sets while the other is transcribed from the manual. It does **not** establish that
either matches silicon; both could misread the same paragraph. Closing that gap needs a third oracle
at a different level — executing fixtures on hardware and comparing observed state — which is future
work. The loop has already found a bug (in the oracle: it read the source of a zeroing `xor` before
applying the idiom check), which is itself evidence for the method.

### 17.4 The layered suite

1. per-rule unit tests asserting on lane ranges, not slice output (a test through the slicer can pass
   for the wrong reason);
2. replay-level tests of the same rules end to end;
3. differential agreement and fuzzing;
4. integrity self-tests: each way a trace can be corrupt has a fixture that constructs it and asserts
   the failure is caught *and named*;
5. (planned) cross-implementation equivalence: callout probe vs inline emitter byte-identical streams,
   Python vs Rust replay identical graphs.

---

## 18. Limitations and open problems

- **Single execution.** Union slicing across runs, and the relationship of the union to a static
  slice, are open for this tool.
- **Concurrency.** A total order is assumed. Correct multi-thread slicing on x86-64 needs
  happens-before from synchronisation and the memory model's ordering guarantees; the global control
  stack is also wrong under interleaving.
- **Exceptions as control flow.** SEH/VEH unwinding is detected as a discontinuity, not modelled.
  Targets that dispatch through exceptions are out of reach.
- **Undetected code rewrite.** The version clock is only as good as rewrite detection (§12.3).
- **Bulk `rep`.** Byte-exact expansion is specified (`--expand-rep`) but v0.2 only annotates.
- **Summary completeness.** Every untraced API without a summary is a hole. The table is small and
  the `Ref` convention is currently mis-implemented (§13.4).
- **Flattening thresholds** are uncalibrated against real obfuscated samples.
- **Address-use classification** is syntactic (§7.2).
- **Kernel and DMA effects** are invisible except through summaries.
- **Symbolic augmentation.** A slice is a set of instructions; a formula for the value would be
  strictly more. The concrete trace is the right seed for a symbolic pass, which is future work.
- **No real-target evaluation** in v0.2: every result is on synthetic fixtures. This is the honest
  boundary of the present claims.

---

## 19. Notation summary

| Symbol | Meaning |
|---|---|
| $\tau = \langle i_0 \ldots i_{n-1}\rangle$ | the execution, as instruction instances |
| $\text{seq}(i_k) = k$ | sequence number |
| $(a, v)$ | static instruction: address, code version |
| $\mathcal{L} = \mathcal{L}_{\text{reg}} \uplus \mathcal{L}_{\text{mem}}$ | byte-granular storage locations |
| $\rho(r), \pi(r)$ | lane range of register $r$; of its architectural parent |
| $E(b)$ | effect function of instruction bytes $b$ |
| $U(i), D(i)$ | locations used / defined by instance $i$ |
| $\text{LW}_k(\ell)$ | last writer of $\ell$ before $k$; $\bot$ = live-in |
| $S$ | shadow state, the running last-writer map |
| $\kappa \in \{\text{value}, \text{addr}, \text{control}\}$ | edge kind |
| $K$ | slice mode (set of allowed kinds) |
| $\text{guard}(k)$ | the branch instance $k$ is control-dependent on |
| $\text{ipdom}(B)$ | immediate post-dominator block |
| $C = (k, \{\text{ranges}\})$ | slicing criterion (post-state of $k$) |
| $\text{BS}_K(C), \text{FS}_K(k)$ | backward / forward slice in mode $K$ |

---

## 20. References

[1] M. Weiser. "Program Slicing." *IEEE Transactions on Software Engineering*, SE-10(4), 1984.

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

[11] N. Nethercote and J. Seward. "Valgrind: A Framework for Heavyweight Dynamic Binary
Instrumentation." *PLDI*, 2007.

[12] J. Newsome and D. Song. "Dynamic Taint Analysis for Automatic Detection, Analysis, and Signature
Generation of Exploits on Commodity Software." *NDSS*, 2005.

[13] X. Ugarte-Pedrero et al. "SoK: Deep Packer Inspection — A Longitudinal Study of the Complexity of
Run-Time Packers." *IEEE Symposium on Security and Privacy*, 2015.

[14] W. M. McKeeman. "Differential Testing for Software." *Digital Technical Journal*, 10(1), 1998.

[15] Intel Corporation. *Intel® 64 and IA-32 Architectures Software Developer's Manual*, Volume 2
(instruction set reference) — the source of the longhand read/write sets in the oracle and of the
"undefined flag" rules.

[16] Frida project. *Stalker* documentation — `Stalker.follow`, `transform`, `trustThreshold`,
`Stalker.invalidate`.

[17] Capstone Engine. *Capstone disassembly framework* — instruction detail, operand access sets,
`eflags` masks.

[18] C. Wang, J. Hill, J. Knight and J. Davidson. "Software Tamper Resistance: Obstructing Static
Analysis of Programs." University of Virginia technical report, 2000; T. László and Á. Kiss,
"Obfuscating C++ Programs via Control Flow Flattening," *Annales Univ. Sci. Budapest.*, 2009.

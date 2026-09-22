# Control dependence

Implementation-level companion to design v0.2 §7. Code:
[`src/atropos/cfg.py`](../src/atropos/cfg.py); tests:
[`tests/test_control.py`](../tests/test_control.py).

---

## 1. The question it answers

Data dependence answers *"what arithmetic produced this value?"*. Control dependence answers
*"and what decided we would compute it at all?"*.

For the crypto workflow that second question is often the real one. A key check that compares a derived
value against a magic constant contributes nothing to the value's *data* chain — but the branch it
drives is the whole logic of the sample. Following control edges from the comparison reaches the
constant, and from there the input that had to match it.

The cost is that control edges are voracious. Every instruction in a loop body is control-dependent on
the loop's branch, which is data-dependent on the counter, which is written by every increment. This is
why the mode is opt-in (§4) and why the caps exist.

---

## 2. Definition

An executed instance *n* is control-dependent on the most recent executed conditional transfer *b*
whose outcome determined whether *n*'s block was entered.

The static formulation: *n* is control-dependent on *b* if *n* post-dominates one successor of *b* and
does not post-dominate *b* itself. The dynamic version attributes each executed instance to the specific
dynamic instance of *b* that guarded it.

Atropos stores **one guard per node** rather than a general edge set, because the Korel–Laski relation
used here gives each instance exactly one immediately enclosing branch. Transitive guards are recovered
by following the chain.

---

## 3. Two passes

Replay is offline, so the CFG needed for post-dominance is recoverable from the trace itself. No static
analysis of the binary is involved at any point — which is the entire reason this works on obfuscated
code.

### Pass 1 — structure (`build_control_flow`)

Walk the block-run log:

1. **Recover edges.** Consecutive block executions within one function give an edge.
2. **Partition into functions.** A `call` terminator opens a new function at the callee's entry block;
   a `ret` closes the current one. Blocks are assigned to the function they were first seen in.
3. **Compute post-dominators** per function.

Cross-function transitions do not become CFG edges. A callee's blocks are not part of the caller's
post-dominance relation, and conflating them is how control dependence starts leaking across frames.

### Pass 2 — attribution (`attribute_control_dependence`)

Walk the log again with a stack of `(branch_seq, ipdom_block, call_depth)`:

- On entering a block, pop entries whose frame we have left (`depth` above the current), then entries
  whose post-dominator is this block.
- Every instruction in the block is control-dependent on the top of stack.
- If the block ends in a conditional branch, push an entry for it.
- `call` increments depth; `ret` decrements and pops everything deeper.
- `ABORT` truncates the stack to the frames still accounted for.

---

## 4. Post-dominance

`compute_ipdom` is Cooper–Harvey–Kennedy run on the **reverse** CFG: post-dominance is dominance with
successors and predecessors swapped.

A virtual exit node (`VIRTUAL_EXIT = -1`) is joined to every block with no observed successor. Those
blocks exist in real traces — an infinite loop, a call that never returned, the end of the capture
window — and without the synthetic exit, post-dominance is undefined for them. Undefined here means
"no control dependence at all in that region", which is a silent hole rather than an answer.

If *every* block has a successor (the function is a closed loop in this run), the block with the most
predecessors is chosen as a pseudo-exit. Any choice is arbitrary; this one keeps the resulting tree
shallow.

The iteration is capped at 100 rounds. Convergence on a well-formed reverse CFG takes a handful, and the
cap means a pathological graph degrades to an incomplete relation rather than hanging.

---

## 5. The four failure modes, and what is done about each

Design v0.2 §7.1 lists these. This is the implementation side.

### 5.1 Call boundaries — **handled**

A branch inside a callee must not guard code after the caller resumes. Its post-dominator is in a
function that is no longer executing, so without depth tracking the stack entry *never pops*: the stack
grows monotonically, every later instruction inherits an unrelated guard, and the slice grows without
bound.

Every stack entry carries the call depth it was pushed at, and `ret` pops everything deeper. Tested by
`test_control_dependence_does_not_leak_across_a_return`.

### 5.2 Exceptions — **detected, partially handled**

An SEH/VEH unwind discards an arbitrary amount of stack. The `ABORT` record marks the truncated block;
the branch stack is trimmed to the frames still accounted for.

This is mitigation, not support. The same event usually shows up as a *continuity* error too
(design v0.2 §10.6), and a trace full of them is reported suspect. Targets that use exceptions as their
primary dispatch mechanism are out of reach — stated as such in §12 of the design.

### 5.3 `ret`-based dispatch — **degraded gracefully**

A `ret` whose target is not the recorded return address breaks the call/return pairing the depth model
assumes. Depth is clamped at zero and the stack resynchronised, so the relation degrades locally rather
than corrupting globally.

### 5.4 Control-flow flattening — **detected, and deliberately not answered**

This is the important one, because it is the standard obfuscation on the targets of interest.

In a flattened function every block returns to a central dispatcher, so the dispatcher is the immediate
post-dominator of essentially every branch. The relation is then **technically correct and completely
uninformative**: everything is control-dependent on the same switch. Emitting those edges would fill the
slice with noise while implying the question had been answered.

Atropos reports "control dependence unavailable" instead, annotates the region `cd-unreliable`, and
emits no control edges there. `--force-cd` overrides for anyone who wants to see the degenerate relation
anyway.

#### The heuristic

Two independent signals, both required, plus two size floors:

| Signal | Default | Meaning |
|--------|---------|---------|
| `flatten_ipdom_fraction` | 0.60 | One block is the ipdom of at least this fraction of the function's *branching* blocks. |
| `flatten_min_indegree` | 4 | That block has at least this many distinct predecessors. |
| `flatten_hub_fraction` | 0.50 | It is a successor of at least this fraction of the function's other blocks. |
| `flatten_min_branches` | 4 | Below this, the fraction test is meaningless. |
| (block count) | 5 | Functions smaller than this are never flagged. |

Post-dominance degeneracy alone is not conclusive — a function with one exit and several early returns
looks similar. The structural hub test is what distinguishes a dispatch loop from an ordinary function.

**A note on the branch set.** It includes *unconditional* jumps, not only conditional ones. In a
flattened function the case blocks end with `jmp dispatcher`; the first version of this heuristic keyed
on conditional branches only, found exactly one branch (the dispatcher's own), and never fired. That is
worth recording because it is the kind of mistake that produces no error — just a feature that quietly
never works.

The thresholds are guesses pending calibration against real obfuscated samples (design v0.2 Appendix A)
and are attributes of `ControlFlowAnalysis` so they can be tuned without editing code.

---

## 6. Slice modes and caps

| Mode | Follows | Question |
|------|---------|----------|
| `value` (default) | value | What arithmetic made this value? |
| `value+addr` | value, address | …and what computed the pointers it came through? |
| `value+ctrl` | value, control | …and what decided we would compute it? |
| `full` | all three | Everything. Largest. |

`--max-control-depth N` bounds how many nested control edges are followed from any node.
`--max-nodes N` bounds the slice outright. **Both report truncation explicitly** — a partial answer
presented as a complete one is the failure this whole design is organised against.

---

## 7. What is not implemented

- **Multi-threaded attribution.** The branch stack is global rather than per-thread. Single-thread
  traces are unaffected; interleaved traces would attribute across threads. Design v0.2 Appendix A
  defers concurrent slicing generally, and this is one of the places that decision shows up.
- **Loop-carried control dependence** in the Korel–Laski "second form" is not distinguished from the
  ordinary kind. In practice the branch-stack relation is what analysts read; the distinction matters
  for termination-sensitivity arguments the tool does not make.
- **Switch-table recovery.** An indirect jump through a jump table is resolved concretely (the trace
  says where it went) but no table structure is inferred, so the successors of a switch block are only
  those observed in this run. That is correct for a dynamic slice and would be wrong for a static one.

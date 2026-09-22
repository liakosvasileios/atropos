"""Control dependence: CFG recovery, post-dominance, and attribution.

Design v0.2 section 7.  Two passes, because replay is offline and the control
flow graph we need for post-dominance is recoverable from the trace itself:

**Pass 1 — structure.**  Walk the block-run log, recover the observed CFG per
code version, partition it into functions at call/return boundaries, and
compute the immediate post-dominator of each block.

**Pass 2 — attribution.**  Walk the log again with a stack of pending branches,
each entry carrying ``(branch_seq, ipdom_block, call_depth)``.  Every executed
instruction is control-dependent on the top of the stack.  Entries are popped
when execution reaches the post-dominator, when a ``ret`` leaves the frame the
entry was pushed in, and when a block aborts.

Why the call depth is not optional
----------------------------------

Without it, a branch taken inside a callee keeps guarding instructions after
the caller returns — the post-dominator it is waiting for is in a function that
is no longer executing, so the entry never pops.  The stack grows monotonically,
every subsequent instruction inherits a guard from an unrelated function, and
the slice grows without bound.  This is failure mode 1 of section 7.1 and it is
the one that shows up immediately on any real binary.

Why flattened functions get no control edges at all
---------------------------------------------------

In a control-flow-flattened function every block returns to a central
dispatcher, so the dispatcher post-dominates essentially every conditional
branch.  The control-dependence relation is then *technically correct and
completely uninformative*: everything is control-dependent on the same switch.
Emitting those edges would fill the slice with noise while implying that
Atropos had answered the question.  Instead the function is annotated
"control dependence unavailable" and the edges are omitted, per success
criterion 4 — an honest "cannot answer" beats a confident wrong one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ddg import NF_CD_UNRELIABLE
from .shadow import LIVE_IN

VIRTUAL_EXIT = -1


@dataclass
class FunctionCFG:
    """The observed control flow of one function, under one code version."""

    func_id: int
    entry: int  # block_id
    blocks: set[int] = field(default_factory=set)
    succ: dict[int, set[int]] = field(default_factory=dict)
    pred: dict[int, set[int]] = field(default_factory=dict)
    ipdom: dict[int, int] = field(default_factory=dict)
    flattened: bool = False
    dispatcher: int | None = None

    def add_edge(self, src: int, dst: int) -> None:
        self.blocks.add(src)
        self.blocks.add(dst)
        self.succ.setdefault(src, set()).add(dst)
        self.pred.setdefault(dst, set()).add(src)
        self.succ.setdefault(dst, set())
        self.pred.setdefault(src, set())

    def add_block(self, block_id: int) -> None:
        self.blocks.add(block_id)
        self.succ.setdefault(block_id, set())
        self.pred.setdefault(block_id, set())


@dataclass
class ControlFlowAnalysis:
    functions: dict[int, FunctionCFG] = field(default_factory=dict)
    block_function: dict[int, int] = field(default_factory=dict)
    flattened_functions: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    n_control_edges: int = 0
    n_unreliable: int = 0

    #: A block is treated as a flattening dispatcher when it post-dominates at
    #: least this fraction of the function's conditional branches ...
    flatten_ipdom_fraction: float = 0.6
    #: ... and has at least this many distinct predecessors.  Both thresholds
    #: are guesses pending calibration against real obfuscated samples
    #: (design v0.2 Appendix A) and are configurable for that reason.
    flatten_min_indegree: int = 4
    #: ... and is a successor of at least this fraction of the function's other
    #: blocks, which is the structural signature of a dispatch loop.
    flatten_hub_fraction: float = 0.5
    #: Below this many branching blocks a function is too small for the
    #: fraction test to mean anything.
    flatten_min_branches: int = 4


# --------------------------------------------------------------------------
# Post-dominators
# --------------------------------------------------------------------------


def compute_ipdom(cfg: FunctionCFG) -> dict[int, int]:
    """Immediate post-dominators, by Cooper-Harvey-Kennedy on the reverse CFG.

    Post-dominance is dominance in the reversed graph, so this is the standard
    iterative dominator algorithm with successors and predecessors swapped and
    a virtual exit joined to every observed exit block.  Blocks with no
    observed successor — an infinite loop, a call that never returned, the end
    of the trace — are attached to the virtual exit so post-dominance is
    well-defined for them rather than undefined.
    """
    if not cfg.blocks:
        return {}

    exits = [b for b in cfg.blocks if not cfg.succ.get(b)]
    if not exits:
        # Every block has a successor: the function is a closed loop in this
        # run.  Pick the block with the most predecessors as the pseudo-exit;
        # any choice is arbitrary, and this one keeps the tree shallow.
        exits = [max(cfg.blocks, key=lambda b: len(cfg.pred.get(b, ())))]

    succ = {b: set(cfg.succ.get(b, ())) for b in cfg.blocks}
    for b in exits:
        succ[b] = succ[b] | {VIRTUAL_EXIT}
    succ[VIRTUAL_EXIT] = set()

    # Reverse postorder of the reverse graph == postorder of the forward graph,
    # computed from the virtual exit backwards.
    rpred: dict[int, set[int]] = {VIRTUAL_EXIT: set()}
    for b in cfg.blocks:
        rpred.setdefault(b, set())
    for b, targets in succ.items():
        for t in targets:
            rpred.setdefault(t, set()).add(b)

    order = _postorder(VIRTUAL_EXIT, rpred)
    rpo = list(reversed(order))
    position = {b: i for i, b in enumerate(rpo)}

    idom: dict[int, int] = {VIRTUAL_EXIT: VIRTUAL_EXIT}

    def intersect(a: int, b: int) -> int:
        while a != b:
            while position.get(a, 1 << 30) > position.get(b, 1 << 30):
                nxt = idom.get(a)
                if nxt is None or nxt == a:
                    return b
                a = nxt
            while position.get(b, 1 << 30) > position.get(a, 1 << 30):
                nxt = idom.get(b)
                if nxt is None or nxt == b:
                    return a
                b = nxt
        return a

    changed = True
    guard = 0
    while changed and guard < 100:
        changed = False
        guard += 1
        for block in rpo:
            if block == VIRTUAL_EXIT:
                continue
            new_idom: int | None = None
            for candidate in succ.get(block, ()):  # predecessors in reverse CFG
                if candidate not in idom:
                    continue
                new_idom = candidate if new_idom is None else intersect(candidate, new_idom)
            if new_idom is not None and idom.get(block) != new_idom:
                idom[block] = new_idom
                changed = True

    idom.pop(VIRTUAL_EXIT, None)
    return {b: d for b, d in idom.items() if d != b}


def _postorder(root: int, edges: dict[int, set[int]]) -> list[int]:
    """Iterative postorder, to survive deeply nested traces without recursion."""
    seen: set[int] = set()
    order: list[int] = []
    stack: list[tuple[int, object]] = [(root, iter(sorted(edges.get(root, ()))))]
    seen.add(root)
    while stack:
        node, it = stack[-1]
        advanced = False
        for child in it:  # type: ignore[union-attr]
            if child not in seen:
                seen.add(child)
                stack.append((child, iter(sorted(edges.get(child, ())))))
                advanced = True
                break
        if not advanced:
            stack.pop()
            order.append(node)
    return order


# --------------------------------------------------------------------------
# Pass 1: recover structure
# --------------------------------------------------------------------------


def build_control_flow(result, analysis: ControlFlowAnalysis | None = None) -> ControlFlowAnalysis:
    bundle = result.bundle
    model = result.model
    analysis = analysis or ControlFlowAnalysis()

    next_func_id = 0
    func_stack: list[int] = []
    current: FunctionCFG | None = None
    previous_block: int | None = None
    previous_terminator = None

    for run in result.block_runs:
        block = bundle.blocks.get(run.block_id)
        if block is None:
            continue

        if current is None:
            current = FunctionCFG(next_func_id, run.block_id)
            analysis.functions[next_func_id] = current
            func_stack.append(next_func_id)
            next_func_id += 1

        entering_new_function = False
        if previous_terminator is not None:
            if previous_terminator.is_call:
                entering_new_function = True
            elif previous_terminator.is_ret:
                if len(func_stack) > 1:
                    func_stack.pop()
                current = analysis.functions[func_stack[-1]]
                previous_block = None

        if entering_new_function:
            existing = analysis.block_function.get(run.block_id)
            if existing is not None:
                current = analysis.functions[existing]
            else:
                current = FunctionCFG(next_func_id, run.block_id)
                analysis.functions[next_func_id] = current
                next_func_id += 1
            func_stack.append(current.func_id)
            previous_block = None

        current.add_block(run.block_id)
        analysis.block_function.setdefault(run.block_id, current.func_id)

        if previous_block is not None and analysis.block_function.get(previous_block) == current.func_id:
            current.add_edge(previous_block, run.block_id)

        if run.aborted or not block.insns or run.n_executed < len(block.insns):
            previous_terminator = None
            previous_block = None
        else:
            previous_terminator = model.effects_for(block.insns[-1].raw)
            previous_block = run.block_id

    for cfg in analysis.functions.values():
        cfg.ipdom = compute_ipdom(cfg)
        _detect_flattening(cfg, bundle, model, analysis)

    return analysis


def _detect_flattening(
    cfg: FunctionCFG, bundle, model, analysis: ControlFlowAnalysis
) -> None:
    """Two independent signals, both required.

    **Post-dominance degeneracy** — one block is the immediate post-dominator
    of nearly every branching block in the function.  On its own this is not
    conclusive: a function with a single exit and a lot of early returns looks
    similar.

    **Structural hub** — that same block is a successor of a large fraction of
    the function's blocks.  That is the shape a dispatch loop has and an
    ordinary function does not.

    Note that the branch set includes *unconditional* jumps, not only
    conditional ones.  In a flattened function the case blocks end with
    ``jmp dispatcher``; keying only on conditional branches (which was the
    first attempt) finds one branch — the dispatcher's own — and never fires.
    """
    if len(cfg.blocks) < 5:
        return

    branch_blocks = []
    for block_id in cfg.blocks:
        block = bundle.blocks.get(block_id)
        if block is None or not block.insns:
            continue
        eff = model.effects_for(block.insns[-1].raw)
        if eff.is_cond_branch or eff.is_uncond_branch:
            branch_blocks.append(block_id)

    if len(branch_blocks) < analysis.flatten_min_branches:
        return

    counts: dict[int, int] = {}
    for block_id in branch_blocks:
        target = cfg.ipdom.get(block_id)
        if target is not None and target != VIRTUAL_EXIT:
            counts[target] = counts.get(target, 0) + 1
    if not counts:
        return

    dispatcher, hits = max(counts.items(), key=lambda kv: kv[1])
    fraction = hits / len(branch_blocks)
    indegree = len(cfg.pred.get(dispatcher, ()))
    hub_fraction = indegree / max(1, len(cfg.blocks) - 1)

    if (
        fraction >= analysis.flatten_ipdom_fraction
        and indegree >= analysis.flatten_min_indegree
        and hub_fraction >= analysis.flatten_hub_fraction
    ):
        cfg.flattened = True
        cfg.dispatcher = dispatcher
        analysis.flattened_functions.append(cfg.func_id)
        block = bundle.blocks.get(dispatcher)
        where = bundle.rebase(block.start_address) if block else f"block {dispatcher}"
        analysis.notes.append(
            f"function #{cfg.func_id}: control dependence unavailable — "
            f"looks control-flow flattened (dispatcher at {where}, "
            f"post-dominates {hits}/{len(branch_blocks)} branching blocks, "
            f"in-degree {indegree}/{len(cfg.blocks) - 1})"
        )


# --------------------------------------------------------------------------
# Pass 2: attribute each instance to its guarding branch
# --------------------------------------------------------------------------


@dataclass
class _StackEntry:
    branch_seq: int
    ipdom_block: int
    depth: int


def attribute_control_dependence(
    result, analysis: ControlFlowAnalysis, force: bool = False
) -> ControlFlowAnalysis:
    """Fill ``ddg.node_ctrl`` with each instance's guarding branch."""
    ddg = result.ddg
    bundle = result.bundle
    model = result.model

    stack: list[_StackEntry] = []
    depth = 0

    for run in result.block_runs:
        block = bundle.blocks.get(run.block_id)
        if block is None:
            continue
        func_id = analysis.block_function.get(run.block_id)
        cfg = analysis.functions.get(func_id) if func_id is not None else None
        suppressed = bool(cfg and cfg.flattened and not force)

        # Pop entries whose frame we have left, then entries whose
        # post-dominator we have just reached.
        while stack and stack[-1].depth > depth:
            stack.pop()
        while stack and stack[-1].ipdom_block == run.block_id and stack[-1].depth == depth:
            stack.pop()

        guard = stack[-1].branch_seq if stack else LIVE_IN
        for offset in range(run.n_executed):
            seq = run.first_seq + offset
            if seq >= ddg.n_nodes:
                break
            ddg.node_ctrl[seq] = guard
            if suppressed:
                ddg.node_flags[seq] |= NF_CD_UNRELIABLE
        if guard != LIVE_IN:
            analysis.n_control_edges += run.n_executed
        if suppressed:
            analysis.n_unreliable += run.n_executed

        if run.aborted:
            # An exception discarded an unknown amount of stack; keep only the
            # entries at or below the frame we can still account for.
            stack = [e for e in stack if e.depth < depth]
            continue
        if run.n_executed < len(block.insns) or not block.insns:
            continue

        terminator = model.effects_for(block.insns[-1].raw)
        last_seq = run.first_seq + run.n_executed - 1

        if terminator.is_call:
            depth += 1
        elif terminator.is_ret:
            depth = max(0, depth - 1)
            while stack and stack[-1].depth > depth:
                stack.pop()
        elif terminator.is_cond_branch and not suppressed and cfg is not None:
            ipdom_block = cfg.ipdom.get(run.block_id)
            if ipdom_block is not None and ipdom_block != VIRTUAL_EXIT:
                stack.append(_StackEntry(last_seq, ipdom_block, depth))

    return analysis


def analyse_control_flow(result, force: bool = False) -> ControlFlowAnalysis:
    """Run both passes.  This is what the pipeline calls."""
    analysis = build_control_flow(result)
    attribute_control_dependence(result, analysis, force=force)
    return analysis

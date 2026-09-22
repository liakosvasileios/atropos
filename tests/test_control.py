"""Control-dependence tests: post-dominance, call depth, and flattening.

Design v0.2 section 7.  The three assertions that matter are that a guard is
attributed to the right branch, that the attribution does not leak across a
`ret`, and that a flattened function reports "unavailable" instead of a
degenerate relation.
"""

from __future__ import annotations

import pytest

from atropos import analyse, backward_slice, build_criterion, MODES
from atropos.cfg import ControlFlowAnalysis, FunctionCFG, compute_ipdom
from atropos.ddg import NF_CD_UNRELIABLE
from atropos.shadow import LIVE_IN
from atropos.testkit import MiniVM, Program, build_bundle


# --------------------------------------------------------------------------
# Post-dominance
# --------------------------------------------------------------------------


def test_ipdom_of_a_diamond():
    """In `if/else/join`, both arms post-dominate to the join block."""
    cfg = FunctionCFG(0, entry=1)
    cfg.add_edge(1, 2)  # condition -> then
    cfg.add_edge(1, 3)  # condition -> else
    cfg.add_edge(2, 4)  # then -> join
    cfg.add_edge(3, 4)  # else -> join
    ipdom = compute_ipdom(cfg)
    assert ipdom[1] == 4
    assert ipdom[2] == 4
    assert ipdom[3] == 4


def test_ipdom_of_a_chain():
    cfg = FunctionCFG(0, entry=1)
    cfg.add_edge(1, 2)
    cfg.add_edge(2, 3)
    ipdom = compute_ipdom(cfg)
    assert ipdom[1] == 2
    assert ipdom[2] == 3


def test_ipdom_survives_a_closed_loop():
    """A function with no observed exit must still get a defined relation.

    An infinite loop or a `noreturn` call leaves post-dominance undefined
    unless a synthetic exit is supplied; the alternative is a crash or a
    silently empty control-dependence map.
    """
    cfg = FunctionCFG(0, entry=1)
    cfg.add_edge(1, 2)
    cfg.add_edge(2, 1)
    ipdom = compute_ipdom(cfg)
    assert ipdom  # a relation exists rather than an exception or {}


# --------------------------------------------------------------------------
# Attribution
# --------------------------------------------------------------------------


def _loop_fixture(tmp_path, iterations=3):
    program = Program()
    program.block("setup", ["mov rcx, 3", "mov rax, 0"])
    program.block("body", ["add rax, 1", "dec rcx", "jnz @body"])
    program.block("done", ["ret"])
    bundle, vm = build_bundle(
        tmp_path / "run.atrace", program,
        ["setup"] + ["body"] * iterations + ["done"], vm=MiniVM(),
    )
    return analyse(bundle), vm


def test_loop_body_is_control_dependent_on_the_loop_branch(tmp_path):
    analysis, vm = _loop_fixture(tmp_path)
    ddg = analysis.ddg
    # The first body instruction of the *second* iteration is guarded by the
    # `jnz` that ended the first.
    second_iteration_start = 5
    guard = ddg.node_ctrl[second_iteration_start]
    assert guard != LIVE_IN
    block = analysis.bundle.blocks[ddg.node_block[guard]]
    mnemonic, _ = analysis.result.model.disassemble(
        block.insns[ddg.node_index[guard]].raw, ddg.node_addr[guard]
    )
    assert mnemonic == "jne"


def test_control_mode_pulls_in_the_loop_condition(tmp_path):
    """Value mode explains the arithmetic; control mode explains the schedule."""
    analysis, _ = _loop_fixture(tmp_path)
    last = analysis.ddg.n_nodes - 1
    criterion = build_criterion(f"seq={last}", ["rax"], analysis.result)

    value_only = backward_slice(analysis.result, criterion, MODES["value"])
    with_control = backward_slice(analysis.result, criterion, MODES["value+ctrl"])
    assert len(with_control.nodes) > len(value_only.nodes)


def test_control_dependence_does_not_leak_across_a_return(tmp_path):
    """A branch inside a callee must not guard code after the caller resumes.

    This is failure mode 1 of section 7.1: without call-depth tracking the
    stack entry never pops (its post-dominator is in a function that is no
    longer running), so every later instruction inherits an unrelated guard and
    the slice grows without bound.
    """
    program = Program()
    program.block("caller_pre", ["mov rax, 1", "call @callee"])
    program.block("callee", ["mov rbx, 2", "test rbx, rbx", "jnz @callee_tail"])
    program.block("callee_tail", ["mov rdx, 3", "ret"])
    program.block("caller_post", ["mov r8, 4", "ret"])

    bundle, _ = build_bundle(
        tmp_path / "run.atrace", program,
        ["caller_pre", "callee", "callee_tail", "caller_post"], vm=MiniVM(),
    )
    analysis = analyse(bundle)
    ddg = analysis.ddg

    # `mov r8, 4` runs after the callee returned; no guard from inside it may
    # still be in force.
    caller_post_first = None
    for seq in range(ddg.n_nodes):
        block = analysis.bundle.blocks[ddg.node_block[seq]]
        if block.block_id == program.by_name("caller_post").block_id:
            caller_post_first = seq
            break
    assert caller_post_first is not None

    guard = ddg.node_ctrl[caller_post_first]
    if guard != LIVE_IN:
        callee_block = program.by_name("callee").block_id
        assert ddg.node_block[guard] != callee_block, (
            "a branch inside the callee is still guarding code in the caller"
        )


# --------------------------------------------------------------------------
# Flattening (section 7.1, failure mode 4)
# --------------------------------------------------------------------------


def _flattened_program() -> Program:
    """A dispatch loop: six case blocks, all jumping back to one dispatcher.

    The dispatcher ends in an *indirect* jump, as a real flattened function
    does — the state variable selects the next block at run time.  That also
    keeps the trace structurally honest: an indirect terminator may legitimately
    land anywhere, so the continuity checker has nothing to complain about.
    """
    program = Program()
    program.block("dispatch", ["mov rax, [rsi]", "test rax, rax", "jmp rax"])
    for i in range(6):
        program.block(f"case{i}", [f"mov rbx, {i}", "jmp @dispatch"])
    program.block("exit", ["ret"])
    return program


def test_flattening_is_detected_and_reported_not_answered(tmp_path):
    """A flattened function must report "unavailable", not a degenerate relation.

    Every block returning to one dispatcher makes that dispatcher the immediate
    post-dominator of every branch.  The relation is technically correct and
    carries no information; presenting it as an answer would be worse than
    saying nothing (success criterion 4).
    """
    program = _flattened_program()
    order = ["dispatch"]
    for i in range(6):
        order += [f"case{i}", "dispatch"]
    order.append("exit")

    vm = MiniVM({0x20000 + i: 1 for i in range(8)})
    vm.regs["rsi"] = 0x20000
    bundle, _ = build_bundle(tmp_path / "run.atrace", program, order, vm=vm)
    analysis = analyse(bundle)

    assert analysis.integrity.n_errors == 0, "the fixture itself must be well formed"
    assert analysis.control.flattened_functions
    assert any("flatten" in note for note in analysis.control.notes)

    banner = "\n".join(analysis.precision_banner())
    assert "unavailable" in banner

    # Every instruction in the affected function is annotated, and none of them
    # carries a control edge: the relation is withheld, not guessed at.
    marked = [
        seq for seq in range(analysis.ddg.n_nodes)
        if analysis.ddg.node_flags[seq] & NF_CD_UNRELIABLE
    ]
    assert marked
    assert all(analysis.ddg.node_ctrl[seq] == LIVE_IN for seq in marked)


def test_force_cd_overrides_the_suppression(tmp_path):
    program = _flattened_program()
    order = ["dispatch"]
    for i in range(6):
        order += [f"case{i}", "dispatch"]
    order.append("exit")

    vm = MiniVM({0x20000 + i: 1 for i in range(8)})
    vm.regs["rsi"] = 0x20000
    bundle, _ = build_bundle(tmp_path / "run.atrace", program, order, vm=vm)

    forced = analyse(bundle, force_control=True)
    assert forced.control is not None

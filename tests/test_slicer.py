"""Slicer, criterion parsing, output backends, and the worked examples."""

from __future__ import annotations

import json

import pytest

from atropos import analyse, backward_slice, build_criterion, chop, forward_slice, MODES
from atropos.arch import lanes as L
from atropos.criterion import CriterionError, parse_location, parse_point
from atropos.ddg import SPACE_MEM, SPACE_REG
from atropos.examples import WORKFLOWS
from atropos.output import render_inputs, render_listing, to_bridge_json, to_dot, to_json
from atropos.testkit import MiniVM, Program, build_bundle


# --------------------------------------------------------------------------
# Criterion parsing
# --------------------------------------------------------------------------


def _as_tuple(location):
    return (location.space, location.loc, location.length)


def test_parse_register_locations():
    assert _as_tuple(parse_location("rax")) == (SPACE_REG, L.lookup("rax").lane, 8)
    assert _as_tuple(parse_location("eax")) == (SPACE_REG, L.lookup("rax").lane, 4)
    assert _as_tuple(parse_location("ah")) == (SPACE_REG, L.lookup("rax").lane + 1, 1)


def test_parse_lane_range():
    location = parse_location("rbx[2:5]")
    assert location.loc == L.lookup("rbx").parent_lane + 2
    assert location.length == 4


def test_parse_flag():
    assert parse_location("zf").loc == L.flag_lane(L.FLAG_ZF)


def test_parse_memory():
    location = parse_location("mem=0x7ff6c0001000+16")
    assert _as_tuple(location) == (SPACE_MEM, 0x7FF6C0001000, 16)


@pytest.mark.parametrize(
    "text", ["nonsense", "mem=0x1000", "rbx[9:12]", "rbx[5:2]", "mem=0x1000+0"]
)
def test_bad_locations_raise_with_an_explanation(text):
    with pytest.raises(CriterionError):
        parse_location(text)


def test_bad_point_raises():
    with pytest.raises(CriterionError):
        parse_point("somewhere")


def test_addr_point_reports_how_many_times_it_ran(tmp_path):
    program = Program()
    program.block("main", ["mov rax, 1", "ret"])
    bundle, _ = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=MiniVM())
    analysis = analyse(bundle)
    with pytest.raises(CriterionError, match="occurrence 5 does not exist"):
        build_criterion("addr=target.exe+0x0@5", ["rax"], analysis.result)


def test_module_relative_addresses_resolve(tmp_path):
    program = Program()
    program.block("main", ["mov rax, 1", "ret"])
    bundle, _ = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=MiniVM())
    analysis = analyse(bundle)
    criterion = build_criterion("addr=target.exe+0x0", ["rax"], analysis.result)
    assert criterion.seq == 0


# --------------------------------------------------------------------------
# Modes and caps
# --------------------------------------------------------------------------


def _chain(tmp_path):
    program = Program()
    program.block("main", [
        "mov rax, 1", "mov rbx, rax", "mov rdx, rbx", "mov r8, rdx", "ret",
    ])
    bundle, _ = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=MiniVM())
    return analyse(bundle)


def test_backward_slice_follows_a_chain(tmp_path):
    analysis = _chain(tmp_path)
    criterion = build_criterion("seq=3", ["r8"], analysis.result)
    result = backward_slice(analysis.result, criterion, MODES["value"])
    assert result.nodes == [0, 1, 2, 3]


def test_node_cap_truncates_and_says_so(tmp_path):
    """A truncated slice is reported, never silently short (section 7.3)."""
    analysis = _chain(tmp_path)
    criterion = build_criterion("seq=3", ["r8"], analysis.result)
    result = backward_slice(analysis.result, criterion, MODES["value"], max_nodes=2)
    assert result.truncated
    assert "node cap" in result.truncation_reason
    assert len(result.nodes) <= 3


def test_forward_slice_finds_what_a_value_affected(tmp_path):
    """Impact analysis: the same graph walked the other way (section 12)."""
    analysis = _chain(tmp_path)
    criterion = build_criterion("seq=0", ["rax"], analysis.result)
    result = forward_slice(analysis.result, criterion, MODES["value"])
    assert {0, 1, 2, 3}.issubset(result.nodes)


def test_chop_is_the_intersection(tmp_path):
    analysis = _chain(tmp_path)
    source = build_criterion("seq=1", ["rbx"], analysis.result)
    sink = build_criterion("seq=3", ["r8"], analysis.result)
    result = chop(analysis.result, source, sink, MODES["value"])
    assert set(result.nodes) == {1, 2, 3}
    assert 0 not in result.nodes


def test_slice_is_a_dag_pointing_backwards(tmp_path):
    """Invariant 11: every edge points to a strictly earlier trace index.

    This is what makes termination structural rather than a matter of the
    visited set catching a cycle.
    """
    analysis = _chain(tmp_path)
    ddg = analysis.ddg
    for seq in range(ddg.n_nodes):
        for i in ddg.edge_range(seq):
            assert ddg.edge_def[i] < seq


# --------------------------------------------------------------------------
# Output backends
# --------------------------------------------------------------------------


@pytest.fixture
def sliced(tmp_path):
    bundle, spec, _note = WORKFLOWS["xor-decoder"](tmp_path / "demo.atrace")
    analysis = analyse(bundle)
    criterion = build_criterion(spec[0], spec[1], analysis.result)
    return analysis, backward_slice(analysis.result, criterion, MODES["value"])


def test_listing_says_why_each_line_is_included(sliced):
    analysis, result = sliced
    text = render_listing(analysis, result)
    assert "ATROPOS backward slice" in text
    assert "trace integrity: OK" in text
    assert text.count("<-") >= len(result.nodes) - 1


def test_input_report_names_the_source_byte(sliced):
    analysis, result = sliced
    text = render_inputs(analysis, result)
    assert "0x20002" in text


def test_dot_is_wellformed(sliced):
    analysis, result = sliced
    dot = to_dot(analysis, result)
    assert dot.startswith("digraph atropos_slice {")
    assert dot.rstrip().endswith("}")
    assert dot.count("->") >= 1


def test_json_round_trips(sliced):
    analysis, result = sliced
    data = json.loads(to_json(analysis, result))
    assert data["mode"] == "value"
    assert len(data["nodes"]) == len(result.nodes)
    assert all("why" in node for node in data["nodes"])
    assert data["precision"]


def test_bridge_json_rolls_up_by_static_address(sliced):
    analysis, result = sliced
    data = json.loads(to_bridge_json(analysis, result))
    assert data["atropos_bridge"] == 1
    for entry in data["instructions"]:
        assert entry["module"] == "target.exe"
        assert entry["occurrences"] >= 1


# --------------------------------------------------------------------------
# The worked examples (design v0.2 section 1.2)
# --------------------------------------------------------------------------


def test_xor_decoder_workflow(tmp_path):
    bundle, spec, _ = WORKFLOWS["xor-decoder"](tmp_path / "a.atrace")
    analysis = analyse(bundle)
    criterion = build_criterion(spec[0], spec[1], analysis.result)
    result = backward_slice(analysis.result, criterion, MODES["value"])
    assert len(result.nodes) == 4
    assert result.stats["reduction"] > 0.85


def test_key_derivation_workflow_names_its_inputs(tmp_path):
    """The deliverable is the input report, not the instruction listing.

    "key = f(volume serial from GetVolumeInformationW, hardcoded 0x9e3779b9)"
    is the answer; the arithmetic in between is supporting detail.
    """
    bundle, spec, _ = WORKFLOWS["key-derivation"](tmp_path / "b.atrace")
    analysis = analyse(bundle)
    criterion = build_criterion(spec[0], spec[1], analysis.result)
    result = backward_slice(analysis.result, criterion, MODES["value"])
    report = render_inputs(analysis, result)
    assert "GetVolumeInformationW" in report
    assert "0x9e3779b9" in report


def test_self_modifying_workflow_keeps_versions_apart(tmp_path):
    """The same address, two code versions, two different decodings.

    Keyed by address alone, the second execution would decode as the first —
    with no error and a perfectly plausible slice (design v0.2 section 4.6).
    """
    bundle, spec, _ = WORKFLOWS["self-modifying"](tmp_path / "c.atrace")
    analysis = analyse(bundle)
    assert analysis.ddg.version_changes == [(2, 1)]
    assert analysis.ddg.node_version[0] == 0
    assert analysis.ddg.node_version[2] == 1

    model = analysis.result.model
    texts = []
    for seq in (0, 2):
        block = analysis.bundle.blocks[analysis.ddg.node_block[seq]]
        texts.append(
            model.disassemble(
                block.insns[analysis.ddg.node_index[seq]].raw,
                analysis.ddg.node_addr[seq],
            )[1]
        )
    assert texts[0] != texts[1]
    assert analysis.ddg.node_addr[0] == analysis.ddg.node_addr[2]


def test_bridge_excludes_summary_pseudo_addresses(tmp_path):
    """Summary nodes must not reach the disassembler as locations.

    A summary stands for an untraced call and carries a pseudo-address, not a
    real one.  Rolled up with the rest it would hand the IDA/Ghidra script a
    nonsense RVA to colour — and the script would dutifully try.
    """
    from atropos.summaries import SUMMARY_ADDRESS_BASE

    bundle, spec, _ = WORKFLOWS["key-derivation"](tmp_path / "kd.atrace")
    analysis = analyse(bundle)
    criterion = build_criterion(spec[0], spec[1], analysis.result)
    result = backward_slice(analysis.result, criterion, MODES["value"])

    data = json.loads(to_bridge_json(analysis, result))
    assert all(entry["module"] != "?" for entry in data["instructions"])
    assert all(entry["rva"] < SUMMARY_ADDRESS_BASE for entry in data["instructions"])
    assert [s["name"] for s in data["summaries"]] == ["GetVolumeInformationW"]

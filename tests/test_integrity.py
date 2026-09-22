"""Integrity tests: a broken trace must be detected, not sliced.

Success criterion 4.  A dynamic slicer fed a corrupt trace does not crash — it
produces a slice that looks entirely reasonable and is about a different
execution than the one that happened.  These tests assert that each way a trace
can be wrong is caught and named.
"""

from __future__ import annotations

import pytest

from atropos import analyse
from atropos.bundle import BundleWriter, TraceBundle
from atropos.format import TAG_ABORT, TAG_VERSION
from atropos.integrity import Status
from atropos.testkit import MiniVM, Program, assemble, build_bundle


def _writer(tmp_path, name="run.atrace"):
    return BundleWriter(
        tmp_path / name,
        meta={"modules": [
            {"name": "t.exe", "base": 0x1400_1000, "size": 0x1000, "path": ""}
        ]},
    )


def test_a_clean_trace_is_clean(tmp_path):
    program = Program()
    program.block("main", ["mov rax, 1", "mov rbx, rax", "ret"])
    bundle, _ = build_bundle(tmp_path / "run.atrace", program, ["main"], vm=MiniVM())
    assert analyse(bundle).integrity.status is Status.OK


def test_discontinuity_is_detected(tmp_path):
    """Two blocks that cannot be adjacent must be reported.

    This is the signature of an exception escaping through an excluded module,
    or of Stalker losing the thread — the failure mode design v0.2 section 12
    lists as currently out of reach.  Detecting it is what keeps it from being
    silently mis-sliced.
    """
    writer = _writer(tmp_path)
    a = writer.add_block(0, 0x1400_1000, [assemble("mov rax, 1"), assemble("nop")])
    # A block at an address the first cannot fall through to.
    b = writer.add_block(0, 0x1400_2000, [assemble("mov rbx, 2"), assemble("ret")])
    writer.emit_block(a)
    writer.emit_block(b)
    writer.emit_mem(1, 0x7FFF_0000, 8, 1)
    writer.close()

    analysis = analyse(TraceBundle(writer.path))
    assert analysis.integrity.status is Status.SUSPECT
    assert any("discontinuity" in f.message for f in analysis.integrity.findings)


def test_memory_access_count_mismatch_is_detected(tmp_path):
    """The agent and the model must agree on how many accesses an instruction has.

    Disagreement is the observable symptom of an undetected code rewrite: the
    bytes the host decodes are not the bytes that ran.
    """
    writer = _writer(tmp_path)
    block = writer.add_block(
        0, 0x1400_1000, [assemble("mov rax, [rbx]"), assemble("ret")]
    )
    writer.emit_block(block)
    # The load's MEM record is simply missing.
    writer.emit_mem(1, 0x7FFF_0000, 8, 1)
    writer.close()

    analysis = analyse(TraceBundle(writer.path))
    assert analysis.integrity.status is Status.SUSPECT
    assert any("memory access" in f.message for f in analysis.integrity.findings)


def test_code_version_disagreement_is_detected(tmp_path):
    """A block captured under v0 replayed while the stream says v1 is an error.

    Under self-modifying code this is the difference between decoding the
    instruction that ran and the one that replaced it (design v0.2 section 4.6).
    """
    writer = _writer(tmp_path)
    block = writer.add_block(0, 0x1400_1000, [assemble("ret")])
    writer.emit(TAG_VERSION, 1)
    writer.emit_block(block)  # still a v0 descriptor
    writer.emit_mem(0, 0x7FFF_0000, 8, 1)
    writer.close()

    analysis = analyse(TraceBundle(writer.path))
    assert analysis.integrity.status is Status.SUSPECT
    assert any("code version" in f.message for f in analysis.integrity.findings)


def test_unknown_block_id_is_detected(tmp_path):
    writer = _writer(tmp_path)
    writer.add_block(0, 0x1400_1000, [assemble("ret")])
    writer.emit_block(99)
    writer.close()

    analysis = analyse(TraceBundle(writer.path))
    assert any("unknown block_id" in f.message for f in analysis.integrity.findings)


def test_aborted_block_executes_only_its_prefix(tmp_path):
    """An ABORT record truncates a block; the rest never became nodes."""
    writer = _writer(tmp_path)
    block = writer.add_block(
        0, 0x1400_1000,
        [assemble("mov rax, 1"), assemble("mov rbx, 2"), assemble("mov rdx, 3")],
    )
    writer.emit_block(block)
    writer.emit(TAG_ABORT, 1)
    writer.close()

    analysis = analyse(TraceBundle(writer.path))
    assert analysis.ddg.n_nodes == 1
    assert any("aborted" in f.message for f in analysis.integrity.findings)


def test_findings_are_capped(tmp_path):
    """A systematically broken trace must not exhaust memory in diagnostics."""
    from atropos.integrity import IntegrityReport

    report = IntegrityReport(max_findings=5)
    for i in range(1000):
        report.error(i, "boom")
    assert len(report.findings) == 5
    assert report.n_errors == 1000
    assert report.truncated
    assert "showing first 5" in report.banner()

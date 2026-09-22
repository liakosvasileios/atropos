"""Trace integrity checking.

Design v0.2 section 10.6, and success criterion 4: *a structurally broken trace
is detected and reported, never silently sliced.*

This matters more here than in most tools.  A dynamic slicer that is fed a
corrupt trace does not crash — it produces a slice.  The slice looks entirely
plausible: real addresses, real instructions, a sensible-looking dependence
chain.  It is simply about a different execution than the one that happened.
An analyst has no way to tell from the output that anything went wrong, so the
only defence is to check the trace's internal consistency and refuse.

The checks, and the failure each one catches:

``block continuity``
    Every block execution must be reachable from the previous block's
    terminator.  A gap means a block was entered without being traced — the
    signature of an exception escaping through an excluded module, or of
    Stalker losing the thread (section 12, "Exceptions as control flow").

``memory access agreement``
    The number of memory accesses the effect model derives from an
    instruction's bytes must equal the number the capture agent recorded.
    Disagreement means the agent and the host disagree about what the
    instruction *is* — most often an undetected code rewrite (section 4.6).

``version agreement``
    A block's recorded code version must match the stream's current version.

``depth sanity``
    Call depth must not go negative, and ``ret`` targets should match the
    recorded return address.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(Enum):
    OK = "ok"
    NOTES = "notes"
    SUSPECT = "suspect"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Finding:
    seq: int
    message: str
    severity: str  # "error" | "note"

    def __str__(self) -> str:  # pragma: no cover - human output
        return f"[{self.severity}] #{self.seq}: {self.message}"


@dataclass
class IntegrityReport:
    """Accumulates findings during replay and downstream analysis."""

    findings: list[Finding] = field(default_factory=list)
    suspect_ranges: list[tuple[int, int]] = field(default_factory=list)
    n_nodes: int = 0
    n_edges: int = 0

    #: Cap on how many findings of each severity we retain.  A systematically
    #: broken trace produces millions of identical findings; keeping them all
    #: turns a diagnostic into a memory-exhaustion bug.
    max_findings: int = 200

    _errors: int = 0
    _notes: int = 0

    # -- recording --------------------------------------------------------

    def error(self, seq: int, message: str) -> None:
        self._errors += 1
        if len(self.findings) < self.max_findings:
            self.findings.append(Finding(seq, message, "error"))

    def note(self, seq: int, message: str) -> None:
        self._notes += 1
        if len(self.findings) < self.max_findings:
            self.findings.append(Finding(seq, message, "note"))

    def mark_suspect(self, start: int, end: int) -> None:
        self.suspect_ranges.append((start, end))

    # -- querying ---------------------------------------------------------

    @property
    def n_errors(self) -> int:
        return self._errors

    @property
    def n_notes(self) -> int:
        return self._notes

    @property
    def status(self) -> Status:
        if self._errors:
            return Status.SUSPECT
        if self._notes:
            return Status.NOTES
        return Status.OK

    @property
    def truncated(self) -> bool:
        return self._errors + self._notes > len(self.findings)

    def is_suspect(self, seq: int) -> bool:
        return any(start <= seq < end for start, end in self.suspect_ranges)

    def finalise(self, ddg, bundle) -> None:
        self.n_nodes = ddg.n_nodes
        self.n_edges = ddg.n_edges

    # -- reporting --------------------------------------------------------

    def banner(self) -> str:
        """The one-line status the precision banner leads with (section 9.6)."""
        if self.status is Status.OK:
            return "trace integrity: OK"
        parts = [f"trace integrity: {self.status}"]
        if self._errors:
            parts.append(f"{self._errors} error(s)")
        if self._notes:
            parts.append(f"{self._notes} note(s)")
        if self.truncated:
            parts.append(f"showing first {len(self.findings)}")
        return " | ".join(parts)

    def render(self, limit: int = 20) -> str:  # pragma: no cover - human output
        lines = [self.banner()]
        for finding in self.findings[:limit]:
            lines.append(f"  {finding}")
        if len(self.findings) > limit:
            lines.append(f"  ... and {len(self.findings) - limit} more")
        return "\n".join(lines)


def check_continuity(result, model=None) -> None:
    """Verify that consecutive block executions are actually connected.

    Called after replay, when the block-run log is available.  The test is
    deliberately weak — we only reject transitions that are impossible, not
    merely unusual — because obfuscated code legitimately does strange things
    and a checker that cries wolf gets switched off.

    A transition is accepted if the previous block's terminator is a call, a
    return, an indirect branch, a syscall, or a conditional branch (any of
    which may land anywhere we cannot predict), or if the next block starts at
    the previous block's fall-through address or its direct branch target.
    """
    bundle = result.bundle
    model = model or result.model
    previous = None
    for run in result.block_runs:
        block = bundle.blocks.get(run.block_id)
        if block is None:
            continue
        if previous is not None and not previous.aborted:
            prev_block = bundle.blocks.get(previous.block_id)
            if prev_block is not None and prev_block.insns:
                if not _may_transfer(prev_block, block, model, previous):
                    result.integrity.error(
                        run.first_seq,
                        f"discontinuity: {bundle.rebase(prev_block.end_address)} "
                        f"does not reach {bundle.rebase(block.start_address)} "
                        "(untraced control transfer — exception or lost thread?)",
                    )
        previous = run


def _may_transfer(prev_block, next_block, model, previous_run) -> bool:
    if previous_run.n_executed < len(prev_block.insns):
        return True  # partially executed: we do not know where it went
    terminator = prev_block.insns[-1]
    eff = model.effects_for(terminator.raw)
    if eff.is_call or eff.is_ret or eff.is_indirect or eff.is_syscall:
        return True
    if not eff.is_branch:
        return next_block.start_address == prev_block.end_address
    if eff.branch_target is not None:
        # A relative target decoded at a synthetic address needs re-decoding at
        # the real one before it means anything.
        _, _ = model.disassemble(terminator.raw, terminator.address)
        real_target = _relative_target(model, terminator)
        if real_target is not None and next_block.start_address == real_target:
            return True
    if eff.is_cond_branch and next_block.start_address == prev_block.end_address:
        return True
    return eff.is_uncond_branch and eff.branch_target is None


def _relative_target(model, insn) -> int | None:
    """Re-decode a direct branch at its true address to get its real target."""
    md = model._md
    for decoded in md.disasm(insn.raw, insn.address, count=1):
        for op in decoded.operands:
            if op.type == 2:  # X86_OP_IMM
                return op.imm
    return None

"""Forward replay: turn a trace into a dynamic dependence graph.

This is the single pass described in design v0.2 section 5.1.  For every
executed instruction instance, in order:

1. resolve every location it **reads** against the *pre-instruction* shadow,
   splitting each read range into maximal runs of identical last writer
   (section 5.2) and emitting one edge per run;
2. *then* apply every location it **writes** to the shadow.

The read-then-write ordering is what makes read-modify-write instructions like
``add [mem], rax`` correct without a special case, and it is invariant 3 of
Appendix B.

The pass is linear in trace length and needs no fixpoint: a concrete execution
has exactly one last writer per byte.  Everything expensive about static
slicing — aliasing, may-vs-must, path sensitivity — simply does not arise.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .arch import lanes as L
from .arch.effects import (
    DEFAULT_MODEL,
    EF_BULK,
    EF_IMPRECISE,
    Effects,
    EffectModel,
    KIND_ADDR,
    KIND_VALUE,
)
from .bundle import BlockDescriptor, TraceBundle
from .ddg import (
    DDG,
    NF_ABORTED,
    NF_BULK,
    NF_IMPRECISE,
    NF_SUSPECT,
    SPACE_MEM,
    SPACE_REG,
)
from .format import (
    RW_READ,
    RW_WRITE,
    TAG_ABORT,
    TAG_BLOCK,
    TAG_MARK,
    TAG_MEM,
    TAG_REP,
    TAG_REP_POST,
    TAG_SHIFTCNT,
    TAG_SUMMARY,
    TAG_THREAD,
    TAG_VALUE,
    TAG_VERSION,
)
from .integrity import IntegrityReport
from .shadow import LIVE_IN, ShadowState
from .summaries import SummaryTable


@dataclass
class BlockRun:
    """One execution of one block, recorded for the control-dependence pass."""

    block_id: int
    first_seq: int
    n_executed: int
    aborted: bool = False


@dataclass
class ReplayOptions:
    expand_rep: bool = False
    #: Cap on how many synthetic nodes a single ``rep`` may expand into, so a
    #: `rep movsb` with RCX=2^30 cannot exhaust memory.
    max_rep_expansion: int = 65536
    track_values: bool = False
    strict: bool = False


@dataclass
class ReplayResult:
    ddg: DDG
    shadow: ShadowState
    integrity: IntegrityReport
    block_runs: list[BlockRun]
    bundle: TraceBundle
    model: EffectModel
    stats: dict = field(default_factory=dict)


class Replay:
    """Drives the forward pass."""

    def __init__(
        self,
        bundle: TraceBundle,
        model: EffectModel | None = None,
        options: ReplayOptions | None = None,
        summaries: SummaryTable | None = None,
    ) -> None:
        self.bundle = bundle
        self.model = model or DEFAULT_MODEL
        self.options = options or ReplayOptions()
        self.summaries = summaries or SummaryTable.default()

        self.ddg = DDG()
        self.shadow = ShadowState()
        self.integrity = IntegrityReport()
        self.block_runs: list[BlockRun] = []

        self._version = 0
        self._tid = 0
        self._suspect = False
        # Which lanes currently hold a value the ISA leaves *undefined* (the
        # AF after an `and`, the OF after a multi-bit shift, ...).  Tracking it
        # per lane rather than per node means only the reads that actually
        # consume garbage get tagged imprecise -- flagging every `xor` because
        # it scrambles AF that nobody reads would make the annotation useless.
        self._undefined = bytearray(L.N_LANES)
        self._stats = {
            "instructions": 0,
            "blocks": 0,
            "mem_accesses": 0,
            "rep_bulk": 0,
            "rep_expanded": 0,
            "summaries": 0,
            "shift_zero_count": 0,
        }

    # ------------------------------------------------------------------
    # Driver
    # ------------------------------------------------------------------

    def run(self) -> ReplayResult:
        pending_block: BlockDescriptor | None = None
        mem: list[tuple[int, int, int, int]] = []  # (insn_index, ea, size, rw)
        reps: list[tuple[int, int, int, int, int]] = []  # (rcx,rsi,rdi,df,post)
        shifts: dict[int, int] = {}
        abort_at: int | None = None

        def flush() -> None:
            nonlocal pending_block, mem, reps, shifts, abort_at
            if pending_block is not None:
                self._execute_block(pending_block, mem, reps, shifts, abort_at)
            pending_block = None
            mem = []
            reps = []
            shifts = {}
            abort_at = None

        for rec in self.bundle.records():
            tag = rec.tag
            if tag == TAG_MEM:
                if pending_block is None:
                    self.integrity.error(
                        self.ddg.n_nodes, "MEM record outside any block"
                    )
                    continue
                mem.append((rec.a, rec.b, rec.c, rec.d))
            elif tag == TAG_REP:
                reps.append((rec.a, rec.b, rec.c, rec.d, 0))
            elif tag == TAG_REP_POST:
                reps.append((rec.a, rec.b, rec.c, rec.d, 1))
            elif tag == TAG_SHIFTCNT:
                # Attributed to the instruction currently being accumulated;
                # there is at most one variable shift pending per block flush
                # because the agent emits the record immediately before the
                # instruction it belongs to.
                shifts[len(mem)] = rec.a
                shifts[-1] = rec.a
            elif tag == TAG_ABORT:
                abort_at = rec.a
            elif tag == TAG_BLOCK:
                flush()
                block = self.bundle.blocks.get(rec.a)
                if block is None:
                    self.integrity.error(
                        self.ddg.n_nodes, f"BLOCK record names unknown block_id {rec.a}"
                    )
                    continue
                if block.code_version != self._version:
                    self.integrity.error(
                        self.ddg.n_nodes,
                        f"block {rec.a} was captured under code version "
                        f"{block.code_version} but the stream is at version "
                        f"{self._version}",
                    )
                pending_block = block
            elif tag == TAG_VERSION:
                flush()
                self._version = rec.a
                self.ddg.version_changes.append((self.ddg.n_nodes, rec.a))
            elif tag == TAG_THREAD:
                flush()
                self._tid = rec.a
            elif tag == TAG_MARK:
                flush()
                self.ddg.marks.append((rec.a, self.ddg.n_nodes))
            elif tag == TAG_SUMMARY:
                flush()
                self._apply_summary(rec.a, list(rec.args))
            elif tag == TAG_VALUE:
                pass  # value capture is not consumed by structural slicing

        flush()
        self.ddg.finish()
        self.integrity.finalise(self.ddg, self.bundle)

        return ReplayResult(
            ddg=self.ddg,
            shadow=self.shadow,
            integrity=self.integrity,
            block_runs=self.block_runs,
            bundle=self.bundle,
            model=self.model,
            stats=dict(self._stats),
        )

    # ------------------------------------------------------------------
    # Block execution
    # ------------------------------------------------------------------

    def _execute_block(
        self,
        block: BlockDescriptor,
        mem: list[tuple[int, int, int, int]],
        reps: list[tuple[int, int, int, int, int]],
        shifts: dict[int, int],
        abort_at: int | None,
    ) -> None:
        n = len(block.insns)
        aborted = abort_at is not None and abort_at < n
        if aborted:
            n = abort_at
            self.integrity.note(
                self.ddg.n_nodes,
                f"block {block.block_id} aborted after {n} instruction(s)",
            )

        # Group memory records by instruction index, preserving canonical order
        # within an instruction (design v0.2, MemAccess docstring).
        by_insn: dict[int, list[tuple[int, int, int]]] = {}
        for insn_index, ea, size, rw in mem:
            by_insn.setdefault(insn_index, []).append((ea, size, rw))

        first_seq = self.ddg.n_nodes
        rep_iter = iter(reps)

        for index in range(n):
            insn = block.insns[index]
            eff = self.model.effects_for(insn.raw)
            accesses = by_insn.get(index, ())

            if len(accesses) != len(eff.mem):
                self.integrity.error(
                    self.ddg.n_nodes,
                    f"{self.bundle.rebase(insn.address)}: model expects "
                    f"{len(eff.mem)} memory access(es), trace has {len(accesses)}",
                )

            if eff.is_rep:
                rep = next(rep_iter, None)
                post = next(rep_iter, None) if eff.mnemonic.startswith("repe") or eff.mnemonic.startswith("repne") else None
                self._execute_rep(block, index, insn, eff, rep, post)
            else:
                self._execute_insn(
                    block, index, insn, eff, accesses, shifts.get(-1)
                )
            self._stats["instructions"] += 1

        self._stats["blocks"] += 1
        self.block_runs.append(BlockRun(block.block_id, first_seq, n, aborted))

    # ------------------------------------------------------------------
    # Instruction execution
    # ------------------------------------------------------------------

    def _execute_insn(
        self,
        block: BlockDescriptor,
        index: int,
        insn,
        eff: Effects,
        accesses,
        shift_count: int | None,
    ) -> None:
        flags = NF_SUSPECT if self._suspect else 0

        # A variable shift with a zero count modifies neither the destination
        # nor any flag (design v0.2 section 6.7).  Suppressing the def matters:
        # recording one would make this instruction the last writer of a
        # register it did not touch, inserting a phantom hop into every slice
        # that passes through.
        suppress_defs = False
        flag_defs = eff.flag_defs
        flag_maydefs = eff.flag_maydefs
        if eff.is_shift_by_cl:
            if shift_count is None:
                # No SHIFTCNT record: fall back to the conservative model and
                # say so, rather than guessing.
                flags |= NF_IMPRECISE
                self.integrity.note(
                    self.ddg.n_nodes,
                    f"{self.bundle.rebase(insn.address)}: variable shift with no "
                    "SHIFTCNT record; flag effects are approximate",
                )
            elif (shift_count & 0x3F) == 0:
                suppress_defs = True
                flag_defs = 0
                flag_maydefs = 0
                self._stats["shift_zero_count"] += 1

        seq = self.ddg.add_node(
            insn.address, block.block_id, index, block.code_version, self._tid, flags
        )

        # ---- reads, against the pre-instruction shadow -------------------
        for lane, length in eff.reg_value_uses:
            self._emit_reg_reads(lane, length, KIND_VALUE)
        for lane, length in eff.reg_addr_uses:
            self._emit_reg_reads(lane, length, KIND_ADDR)
        for lane in L.flag_mask_to_lanes(eff.flag_uses):
            self._emit_reg_reads(lane, 1, KIND_VALUE)

        for slot, access in zip(eff.mem, accesses):
            ea, size, rw = access
            self._stats["mem_accesses"] += 1
            if size != slot.size:
                self.integrity.note(
                    seq,
                    f"{self.bundle.rebase(insn.address)}: memory access size "
                    f"{size} differs from decoded operand size {slot.size}",
                )
            if rw & RW_READ:
                self._emit_mem_reads(ea, size, KIND_VALUE)

        # ---- writes ------------------------------------------------------
        if not suppress_defs:
            for lane, length in eff.reg_defs:
                self._def_reg(lane, length, seq)
                for i in range(lane, lane + length):
                    self._undefined[i] = 0
        for lane in L.flag_mask_to_lanes(flag_defs):
            self._def_reg(lane, 1, seq)
            self._undefined[lane] = 0
        for lane in L.flag_mask_to_lanes(flag_maydefs):
            # A may-def still sets the last writer: a later read genuinely does
            # get its garbage from here.  It is the *edge* that is imprecise,
            # not the fact of the dependence.
            self._def_reg(lane, 1, seq)
            self._undefined[lane] = 1

        for slot, access in zip(eff.mem, accesses):
            ea, size, rw = access
            if rw & RW_WRITE:
                self._def_mem(ea, size, seq)

    def _execute_rep(
        self,
        block: BlockDescriptor,
        index: int,
        insn,
        eff: Effects,
        rep: tuple[int, int, int, int, int] | None,
        post: tuple[int, int, int, int, int] | None,
    ) -> None:
        """Model a whole ``rep`` loop as one bulk effect (section 6.6)."""
        if rep is None:
            self.integrity.error(
                self.ddg.n_nodes,
                f"{self.bundle.rebase(insn.address)}: rep-prefixed instruction "
                "with no REP record; cannot model its memory effect",
            )
            self.ddg.add_node(
                insn.address, block.block_id, index, block.code_version,
                self._tid, NF_IMPRECISE,
            )
            return

        rcx, rsi, rdi, df, _ = rep
        count = rcx
        if post is not None:
            # repe/repne exit early on the comparison; the post-execution RCX
            # is the only way to learn how far the loop actually got.
            count = max(0, rcx - post[0])

        size = eff.element_size or 1
        total = count * size

        seq = self.ddg.add_node(
            insn.address, block.block_id, index, block.code_version,
            self._tid, NF_BULK if total else 0,
        )
        self._stats["rep_bulk"] += 1

        # Register and flag reads happen regardless of the count.
        for lane, length in eff.reg_value_uses:
            self._emit_reg_reads(lane, length, KIND_VALUE)
        for lane, length in eff.reg_addr_uses:
            self._emit_reg_reads(lane, length, KIND_ADDR)
        for lane in L.flag_mask_to_lanes(eff.flag_uses):
            self._emit_reg_reads(lane, 1, KIND_VALUE)

        if count == 0:
            # A `rep` with RCX = 0 executes zero iterations and leaves RSI,
            # RDI and RCX untouched.  Emitting defs here would be a phantom.
            return

        src_start = rsi if not df else rsi - total + size
        dst_start = rdi if not df else rdi - total + size

        mnem = eff.mnemonic.split()[-1]
        if mnem.startswith("movs"):
            self._emit_mem_reads(src_start, total, KIND_VALUE, EF_BULK)
            self._def_mem(dst_start, total, seq)
        elif mnem.startswith("stos"):
            self._def_mem(dst_start, total, seq)
        elif mnem.startswith("lods"):
            self._emit_mem_reads(src_start, total, KIND_VALUE, EF_BULK)
        elif mnem.startswith("cmps"):
            self._emit_mem_reads(src_start, total, KIND_VALUE, EF_BULK)
            self._emit_mem_reads(dst_start, total, KIND_VALUE, EF_BULK)
        elif mnem.startswith("scas"):
            self._emit_mem_reads(dst_start, total, KIND_VALUE, EF_BULK)

        for lane, length in eff.reg_defs:
            self._def_reg(lane, length, seq)
        for lane in L.flag_mask_to_lanes(eff.flag_defs):
            self._def_reg(lane, 1, seq)
            self._undefined[lane] = 0
        for lane in L.flag_mask_to_lanes(eff.flag_maydefs):
            self._def_reg(lane, 1, seq)
            self._undefined[lane] = 1

        if self.options.expand_rep and count <= self.options.max_rep_expansion:
            self._stats["rep_expanded"] += 1
            # Byte-exact expansion is recorded as a note rather than as extra
            # nodes in this build; the bulk node already carries the ranges,
            # and the listing backend can enumerate iterations from them.
            self.ddg.notes.append(
                f"#{seq}: rep expandable into {count} iterations of {size} byte(s)"
            )

    # ------------------------------------------------------------------
    # Edge emission
    # ------------------------------------------------------------------

    def _def_reg(self, lane: int, length: int, seq: int) -> None:
        self.shadow.regs.write(lane, length, seq)
        self.ddg.add_def(SPACE_REG, lane, length)

    def _def_mem(self, address: int, length: int, seq: int) -> None:
        self.shadow.mem.write(address, length, seq)
        self.ddg.add_def(SPACE_MEM, address, length)

    def _emit_reg_reads(self, lane: int, length: int, kind: int, flags: int = 0) -> None:
        undefined = self._undefined
        for writer, start, run in self.shadow.regs.read_runs(lane, length):
            edge_flags = flags
            if any(undefined[i] for i in range(start, start + run)):
                edge_flags |= EF_IMPRECISE
            self.ddg.add_edge(writer, SPACE_REG, start, run, kind, edge_flags)

    def _emit_mem_reads(self, ea: int, size: int, kind: int, flags: int = 0) -> None:
        for writer, start, run in self.shadow.mem.read_runs(ea, size):
            self.ddg.add_edge(writer, SPACE_MEM, start, run, kind, flags)

    # ------------------------------------------------------------------
    # Summaries
    # ------------------------------------------------------------------

    def _apply_summary(self, summary_id: int, args: list[int]) -> None:
        summary = self.summaries.get(summary_id)
        if summary is None:
            self.integrity.note(
                self.ddg.n_nodes, f"unknown summary id {summary_id}; ignored"
            )
            return
        self._stats["summaries"] += 1
        summary.apply(self, args)


def replay(
    bundle: TraceBundle,
    options: ReplayOptions | None = None,
    model: EffectModel | None = None,
    summaries: SummaryTable | None = None,
) -> ReplayResult:
    """Convenience wrapper: build the DDG for a bundle."""
    return Replay(bundle, model=model, options=options, summaries=summaries).run()

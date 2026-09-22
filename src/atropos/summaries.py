"""API and syscall summaries: crossing an untraced call without losing the edge.

Design v0.2 section 4.5.  We do not trace into ``ntdll``, ``kernel32`` or the
CRT — the cost is enormous and the internals are almost never the answer.  But
a ``memcpy`` we do not trace is a hole in the dependence graph: the destination
bytes acquire no last writer, so a slice through them bottoms out in a spurious
"live-in" leaf and the analyst is told the data came from nowhere.

A summary closes the hole.  It is a hand-written statement of what an API does
to storage, in the same vocabulary as the effect model: these byte ranges are
read, these are written, this register is defined.  The capture agent hooks the
export, records the concrete argument values, and emits a ``SUMMARY`` record;
replay expands it into a synthetic node with real edges.

Three classes of summary, and the distinction is what the input report (section
9.4) keys off:

``transform``
    Output is a function of input: ``memcpy``, ``CryptEncrypt``.  The edge
    crosses the call.

``source``
    Output comes from outside the process: ``ReadFile``,
    ``GetVolumeInformationW``, ``BCryptGenRandom``.  The node is a *leaf*, and
    it is the interesting kind — "the key depends on the volume serial number"
    is exactly the answer the crypto workflow wants.

``alloc`` / ``free``
    Region lifecycle: ``VirtualAlloc`` defines a fresh zeroed region;
    ``VirtualFree`` releases the shadow pages so peak memory tracks the live
    working set.

Unknown external calls get :class:`UnknownCall`, which is deliberately weak and
says so: it defines ``RAX`` and marks the node imprecise rather than inventing
byte ranges it cannot know.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .arch import lanes as L
from .arch.effects import EF_SUMMARY, KIND_ADDR, KIND_VALUE
from .ddg import NF_IMPRECISE, NF_SUMMARY, SPACE_MEM, SPACE_REG

#: Microsoft x64 calling convention: the first four integer arguments.
ARG_REGS = ["rcx", "rdx", "r8", "r9"]

#: Pseudo-addresses for summary nodes, so they never collide with real code.
#: Kept below 2**63 because node addresses are stored in a signed 64-bit column.
SUMMARY_ADDRESS_BASE = 0x7FFF_0000_0000_0000


class Ref:
    """A buffer reference: a pointer argument plus a length.

    ``length`` is either another argument index or a literal byte count.
    """

    __slots__ = ("ptr", "length", "scale")

    def __init__(self, ptr: int, length: int | str, scale: int = 1) -> None:
        self.ptr = ptr
        self.length = length
        self.scale = scale

    def resolve(self, args: list[int]) -> tuple[int, int] | None:
        if self.ptr >= len(args):
            return None
        pointer = args[self.ptr]
        if pointer == 0:
            return None
        if isinstance(self.length, int):
            size = self.length
        else:
            index = int(self.length)
            if index >= len(args):
                return None
            size = args[index]
        size *= self.scale
        if size <= 0:
            return None
        return pointer, size


@dataclass
class Summary:
    """A declarative statement of one API's effect on storage."""

    id: int
    name: str
    kind: str = "transform"  # transform | source | alloc | free
    reads: list[Ref] = field(default_factory=list)
    writes: list[Ref] = field(default_factory=list)
    defines_rax: bool = True
    n_args: int = 4
    #: Cap on how many bytes one summary may claim to touch.  A hooked call
    #: with a garbage length argument would otherwise allocate shadow pages
    #: until the process dies.
    max_bytes: int = 64 << 20

    def apply(self, replay, args: list[int]) -> None:
        ddg = replay.ddg
        flags = NF_SUMMARY
        if self.kind == "source":
            flags |= 0  # a source leaf is precise about being a leaf
        seq = ddg.add_node(
            address=SUMMARY_ADDRESS_BASE + self.id,
            block_id=-1,
            insn_index=0,
            code_version=replay._version,
            tid=replay._tid,
            flags=flags,
        )
        ddg.summary_nodes[seq] = self.name
        ddg.summary_kinds[seq] = self.kind

        # The argument registers are genuine address dependences: whatever
        # computed the destination pointer is part of "how this buffer came to
        # be here", and slicing with --mode value+addr should reach it.
        for index in range(min(self.n_args, len(args), len(ARG_REGS))):
            slot = L.lookup(ARG_REGS[index])
            for writer, start, run in replay.shadow.regs.read_runs(slot.lane, slot.size):
                ddg.add_edge(writer, SPACE_REG, start, run, KIND_ADDR, EF_SUMMARY)

        for ref in self.reads:
            resolved = ref.resolve(args)
            if resolved is None:
                continue
            pointer, size = resolved
            if size > self.max_bytes:
                replay.integrity.note(
                    seq, f"{self.name}: read length {size} exceeds cap; truncated"
                )
                size = self.max_bytes
            for writer, start, run in replay.shadow.mem.read_runs(pointer, size):
                ddg.add_edge(writer, SPACE_MEM, start, run, KIND_VALUE, EF_SUMMARY)

        if self.kind == "free":
            for ref in self.writes:
                resolved = ref.resolve(args)
                if resolved is not None:
                    replay.shadow.mem.release(*resolved)
            return

        for ref in self.writes:
            resolved = ref.resolve(args)
            if resolved is None:
                continue
            pointer, size = resolved
            if size > self.max_bytes:
                replay.integrity.note(
                    seq, f"{self.name}: write length {size} exceeds cap; truncated"
                )
                size = self.max_bytes
            replay._def_mem(pointer, size, seq)

        if self.defines_rax:
            slot = L.lookup("rax")
            replay._def_reg(slot.lane, slot.size, seq)


@dataclass
class UnknownCall(Summary):
    """The conservative default for an unrecognised external call.

    It defines ``RAX`` and nothing else, and marks the node imprecise.  The
    alternative — inventing byte ranges for pointer arguments whose lengths we
    do not know — would either miss real dependences (too small) or invent
    them wholesale (too large).  Reporting "we crossed an unmodelled call
    here" is the honest answer, and the precision banner surfaces the count.
    """

    def apply(self, replay, args: list[int]) -> None:
        seq = replay.ddg.add_node(
            address=SUMMARY_ADDRESS_BASE + self.id,
            block_id=-1,
            insn_index=0,
            code_version=replay._version,
            tid=replay._tid,
            flags=NF_SUMMARY | NF_IMPRECISE,
        )
        replay.ddg.summary_nodes[seq] = self.name
        replay.ddg.summary_kinds[seq] = "unknown"
        for index in range(min(len(args), len(ARG_REGS))):
            slot = L.lookup(ARG_REGS[index])
            for writer, start, run in replay.shadow.regs.read_runs(slot.lane, slot.size):
                replay.ddg.add_edge(
                    writer, SPACE_REG, start, run, KIND_VALUE, EF_SUMMARY
                )
        slot = L.lookup("rax")
        replay._def_reg(slot.lane, slot.size, seq)
        replay.integrity.note(
            seq, f"crossed unmodelled external call {self.name}; edges are approximate"
        )


class SummaryTable:
    """Maps the ``summary_id`` in a SUMMARY record to its :class:`Summary`."""

    def __init__(self, summaries: dict[int, Summary] | None = None) -> None:
        self._by_id: dict[int, Summary] = dict(summaries or {})
        self._by_name: dict[str, Summary] = {s.name: s for s in self._by_id.values()}

    def add(self, summary: Summary) -> Summary:
        self._by_id[summary.id] = summary
        self._by_name[summary.name] = summary
        return summary

    def get(self, summary_id: int) -> Summary | None:
        return self._by_id.get(summary_id)

    def by_name(self, name: str) -> Summary | None:
        return self._by_name.get(name)

    def ids(self) -> dict[str, int]:
        """Name to id, for the capture agent to embed in its hook table."""
        return {name: s.id for name, s in self._by_name.items()}

    def __len__(self) -> int:
        return len(self._by_id)

    # ------------------------------------------------------------------

    @classmethod
    def default(cls) -> "SummaryTable":
        """The built-in table.

        Ids are stable and must stay stable: they are baked into captured
        bundles, so renumbering one silently reinterprets every existing trace.
        Append, never renumber.
        """
        table = cls()
        add = table.add

        # -- memory movement ------------------------------------------------
        add(Summary(1, "memcpy", "transform",
                    reads=[Ref(1, 2)], writes=[Ref(0, 2)]))
        add(Summary(2, "memmove", "transform",
                    reads=[Ref(1, 2)], writes=[Ref(0, 2)]))
        add(Summary(3, "memset", "transform",
                    reads=[], writes=[Ref(0, 2)]))
        add(Summary(4, "RtlMoveMemory", "transform",
                    reads=[Ref(1, 2)], writes=[Ref(0, 2)]))
        add(Summary(5, "strcpy", "transform",
                    reads=[Ref(1, 1)], writes=[Ref(0, 1)]))

        # -- region lifecycle ------------------------------------------------
        add(Summary(10, "VirtualAlloc", "alloc",
                    reads=[], writes=[Ref(0, 1)], n_args=4))
        add(Summary(11, "VirtualFree", "free",
                    reads=[], writes=[Ref(0, 1)], defines_rax=True))
        add(Summary(12, "HeapAlloc", "alloc",
                    reads=[], writes=[Ref(0, 2)]))

        # -- external sources ------------------------------------------------
        add(Summary(20, "ReadFile", "source",
                    reads=[], writes=[Ref(1, 2)]))
        add(Summary(21, "GetVolumeInformationW", "source",
                    reads=[], writes=[Ref(1, 8)]))
        add(Summary(22, "GetUserNameW", "source",
                    reads=[], writes=[Ref(0, 1)]))
        add(Summary(23, "BCryptGenRandom", "source",
                    reads=[], writes=[Ref(1, 2)]))
        add(Summary(24, "GetComputerNameW", "source",
                    reads=[], writes=[Ref(0, 1)]))
        add(Summary(25, "NtQuerySystemInformation", "source",
                    reads=[], writes=[Ref(1, 2)]))

        # -- crypto ----------------------------------------------------------
        add(Summary(30, "CryptEncrypt", "transform",
                    reads=[Ref(3, 4)], writes=[Ref(3, 4)]))
        add(Summary(31, "CryptDecrypt", "transform",
                    reads=[Ref(3, 4)], writes=[Ref(3, 4)]))
        add(Summary(32, "CryptDeriveKey", "transform",
                    reads=[Ref(2, 8)], writes=[Ref(3, 8)]))
        add(Summary(33, "BCryptGenerateSymmetricKey", "transform",
                    reads=[Ref(3, 4)], writes=[Ref(2, 8)]))
        add(Summary(34, "CryptHashData", "transform",
                    reads=[Ref(1, 2)], writes=[]))

        # -- NT syscalls that move data --------------------------------------
        add(Summary(40, "NtReadFile", "source",
                    reads=[], writes=[Ref(1, 2)]))
        add(Summary(41, "NtAllocateVirtualMemory", "alloc",
                    reads=[], writes=[Ref(0, 1)]))
        add(Summary(42, "NtReadVirtualMemory", "transform",
                    reads=[Ref(1, 3)], writes=[Ref(2, 3)]))
        add(Summary(43, "NtWriteVirtualMemory", "transform",
                    reads=[Ref(2, 3)], writes=[Ref(1, 3)]))

        add(UnknownCall(99, "<unknown>", "transform"))
        return table


__all__ = ["Ref", "Summary", "UnknownCall", "SummaryTable", "ARG_REGS",
           "SUMMARY_ADDRESS_BASE"]

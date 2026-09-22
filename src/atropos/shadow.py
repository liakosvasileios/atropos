"""Shadow state: the last-writer map that makes dynamic slicing exact.

Design v0.2 section 5.1.  For every storage location we remember one number —
the trace sequence index of the instruction instance that most recently wrote
it.  That is the entire data-dependence analysis.  No fixpoint, no aliasing
question, no may/must distinction: a concrete run has exactly one last writer
per byte.

Two representations, chosen for the shapes of the two address spaces:

* **Registers and flags** live in a dense array of ``N_LANES`` entries.  Every
  lane is touched by something eventually, and the space is tiny.
* **Memory** is sparse — a run touches a few megabytes out of a 2^47 address
  space — so it is a hashed page table of typed arrays, allocated on demand.

Storage is ``array('q')`` rather than a dict of ints throughout.  On a ten
million instruction trace this is the difference between a few hundred
megabytes and several gigabytes (design v0.2 section 10.5), and it is the
representation the Rust port will use natively.
"""

from __future__ import annotations

from array import array
from typing import Iterator

from .arch import lanes as L

#: Sentinel: this location has never been written within the trace.  A read of
#: it is a *live-in leaf* — initial memory, a value set before tracing began,
#: or a write by something we did not trace.
LIVE_IN = -1

PAGE_SHIFT = 12
PAGE_SIZE = 1 << PAGE_SHIFT
PAGE_MASK = PAGE_SIZE - 1


class ShadowRegisters:
    """Dense last-writer map over register lanes and flag bits."""

    __slots__ = ("lanes",)

    def __init__(self) -> None:
        self.lanes = array("q", [LIVE_IN]) * L.N_LANES

    def read_runs(self, lane: int, length: int) -> list[tuple[int, int, int]]:
        """Split ``[lane, lane+length)`` into maximal runs of identical writer.

        Returns ``(writer_seq, start_lane, run_length)`` triples.

        This is the fix from design v0.2 section 5.2.  A read of ``RAX`` after
        ``mov eax, X; mov ah, Y`` has *three* producing definitions, not one,
        and reporting a single one would be both wrong and unhelpfully so —
        it would silently drop a real contributor from the slice.
        """
        buf = self.lanes
        runs: list[tuple[int, int, int]] = []
        start = lane
        current = buf[lane]
        for i in range(lane + 1, lane + length):
            value = buf[i]
            if value != current:
                runs.append((current, start, i - start))
                start = i
                current = value
        runs.append((current, start, lane + length - start))
        return runs

    def write(self, lane: int, length: int, seq: int) -> None:
        self.lanes[lane : lane + length] = array("q", [seq]) * length

    def writer_of(self, lane: int) -> int:
        return self.lanes[lane]

    def snapshot(self) -> array:
        return array("q", self.lanes)


class ShadowMemory:
    """Sparse byte-granular last-writer map over the target's address space.

    Pages are allocated on first touch and can be released when the target
    frees the region (``VirtualFree``), which keeps peak memory proportional to
    the working set of distinct bytes touched rather than to the address space.
    """

    __slots__ = ("pages", "_touched_bytes")

    def __init__(self) -> None:
        self.pages: dict[int, array] = {}
        self._touched_bytes = 0

    # -- internals --------------------------------------------------------

    def _page(self, page_no: int) -> array:
        page = self.pages.get(page_no)
        if page is None:
            page = array("q", [LIVE_IN]) * PAGE_SIZE
            self.pages[page_no] = page
        return page

    # -- public -----------------------------------------------------------

    def read_runs(self, address: int, length: int) -> list[tuple[int, int, int]]:
        """As :meth:`ShadowRegisters.read_runs`, but over linear addresses.

        Byte granularity is what makes partial overlap exact: a four-byte
        write later half-read by a two-byte read produces the right answer
        without any aliasing analysis, because both resolved to concrete
        addresses at capture time (design v0.2 section 5.3).
        """
        runs: list[tuple[int, int, int]] = []
        start = address
        current = self.writer_of(address)
        for addr in range(address + 1, address + length):
            value = self.writer_of(addr)
            if value != current:
                runs.append((current, start, addr - start))
                start = addr
                current = value
        runs.append((current, start, address + length - start))
        return runs

    def writer_of(self, address: int) -> int:
        page = self.pages.get(address >> PAGE_SHIFT)
        if page is None:
            return LIVE_IN
        return page[address & PAGE_MASK]

    def write(self, address: int, length: int, seq: int) -> None:
        end = address + length
        while address < end:
            page_no = address >> PAGE_SHIFT
            offset = address & PAGE_MASK
            span = min(PAGE_SIZE - offset, end - address)
            page = self.pages.get(page_no)
            if page is None:
                page = array("q", [LIVE_IN]) * PAGE_SIZE
                self.pages[page_no] = page
            page[offset : offset + span] = array("q", [seq]) * span
            address += span

    def release(self, address: int, length: int) -> int:
        """Drop shadow pages fully covered by a freed region.

        Returns the number of pages released.  Partially covered pages are
        kept: a page straddling the edge of a freed allocation may still hold
        live neighbours, and inventing ``LIVE_IN`` for them would turn a real
        dependence into a spurious input leaf.
        """
        first_full = (address + PAGE_MASK) >> PAGE_SHIFT
        last_full = (address + length) >> PAGE_SHIFT
        released = 0
        for page_no in range(first_full, last_full):
            if self.pages.pop(page_no, None) is not None:
                released += 1
        return released

    # -- diagnostics ------------------------------------------------------

    @property
    def resident_pages(self) -> int:
        return len(self.pages)

    @property
    def resident_bytes(self) -> int:
        """Approximate resident size of the shadow map, for the diagnostics."""
        return len(self.pages) * PAGE_SIZE * 8  # 8 bytes per 'q' entry

    def regions(self) -> Iterator[tuple[int, int]]:
        """Yield ``(page_address, page_size)`` for every resident page."""
        for page_no in sorted(self.pages):
            yield page_no << PAGE_SHIFT, PAGE_SIZE


class ShadowState:
    """Registers plus memory, the complete last-writer state of a replay."""

    __slots__ = ("regs", "mem")

    def __init__(self) -> None:
        self.regs = ShadowRegisters()
        self.mem = ShadowMemory()

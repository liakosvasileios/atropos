"""Trace bundle: the on-disk artifact produced by capture and consumed by the host.

A bundle is a directory::

    run.atrace/
        meta.json     run metadata, capture configuration, initial module map
        code.bin      block descriptors, keyed by (address, code_version)
        trace.bin     the execution record stream

The split exists because ``code.bin`` is written once per newly instrumented
block (small, bounded by the target's code size) while ``trace.bin`` is written
once per executed block (large, bounded by the run length).  Keeping them apart
lets the agent drain the hot stream to a memory-mapped file without ever
rewriting the cold one.

Soundness note (design v0.2 section 4.6): a block descriptor is identified by
``block_id``, which is globally unique *across code versions*.  Two blocks at the
same address under different versions are different descriptors, even if their
bytes happen to be identical.  Nothing in this module or downstream is permitted
to key code by address alone.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .format import (
    CODE_MAGIC,
    CTAG_BLOCK,
    CTAG_MODULE,
    TAG_NAMES,
    TRACE_MAGIC,
    ByteReader,
    ByteWriter,
    HEADER_SIZE,
    TraceFormatError,
    read_header,
    write_header,
)

BUNDLE_SUFFIX = ".atrace"


# --------------------------------------------------------------------------
# Code descriptors
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class InsnDescriptor:
    """One static instruction, as captured at instrument time."""

    address: int
    raw: bytes

    @property
    def size(self) -> int:
        return len(self.raw)


@dataclass
class BlockDescriptor:
    """A Stalker basic block under one code version."""

    block_id: int
    code_version: int
    start_address: int
    insns: list[InsnDescriptor]

    @property
    def end_address(self) -> int:
        if not self.insns:
            return self.start_address
        last = self.insns[-1]
        return last.address + last.size

    def __len__(self) -> int:
        return len(self.insns)


@dataclass(frozen=True)
class Module:
    """A loaded image, for rebasing absolute addresses to ``module+RVA``."""

    name: str
    base: int
    size: int
    path: str = ""

    def contains(self, address: int) -> bool:
        return self.base <= address < self.base + self.size


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------


class BundleWriter:
    """Writes a bundle.  Used by the capture drain and by the test kit.

    The writer is intentionally dumb — it does not validate the semantic
    coherence of what it is given.  Validation belongs to
    :mod:`atropos.integrity`, which runs on read, so that a bundle produced by
    a third-party capture agent is checked on exactly the same terms as our own.
    """

    def __init__(self, path: str | os.PathLike[str], meta: dict | None = None) -> None:
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self.meta: dict = {
            "format_version": 1,
            "arch": "x86_64",
            "os": "windows",
            "capture": {},
            "modules": [],
        }
        if meta:
            self.meta.update(meta)
        self._code = ByteWriter()
        self._trace = ByteWriter()
        self._next_block_id = 0
        self._last_ea = 0

    # -- code stream ------------------------------------------------------

    def add_block(
        self, code_version: int, start_address: int, insns: list[bytes]
    ) -> int:
        """Register a block descriptor and return its ``block_id``."""
        block_id = self._next_block_id
        self._next_block_id += 1
        w = self._code
        w.u8(CTAG_BLOCK)
        w.uvarint(block_id)
        w.uvarint(code_version)
        w.uvarint(start_address)
        w.uvarint(len(insns))
        for raw in insns:
            w.blob(raw)
        return block_id

    def add_module(self, name: str, base: int, size: int, path: str = "") -> None:
        w = self._code
        w.u8(CTAG_MODULE)
        w.string(name)
        w.uvarint(base)
        w.uvarint(size)
        w.string(path)

    # -- trace stream -----------------------------------------------------

    def emit(self, tag: int, *args: int) -> None:
        """Emit a record with an all-uvarint payload."""
        self._trace.u8(tag)
        for arg in args:
            self._trace.uvarint(arg)

    def emit_block(self, block_id: int) -> None:
        from .format import TAG_BLOCK

        self._trace.u8(TAG_BLOCK)
        self._trace.uvarint(block_id)

    def emit_mem(self, insn_index: int, ea: int, size: int, rw: int) -> None:
        """Emit a resolved memory access.

        ``ea`` is stored as a zig-zag delta against the previous emitted EA:
        real programs access memory with strong locality, so the delta is
        usually one or two bytes where the absolute address is eight.
        """
        from .format import TAG_MEM

        w = self._trace
        w.u8(TAG_MEM)
        w.uvarint(insn_index)
        w.svarint(ea - self._last_ea)
        self._last_ea = ea
        w.u8(size)
        w.u8(rw)

    def emit_bytes(self, tag: int, payload: bytes) -> None:
        self._trace.u8(tag)
        self._trace.blob(payload)

    # -- finish -----------------------------------------------------------

    def close(self) -> Path:
        with open(self.path / "code.bin", "wb") as fh:
            write_header(fh, CODE_MAGIC)
            fh.write(self._code.getvalue())
        with open(self.path / "trace.bin", "wb") as fh:
            write_header(fh, TRACE_MAGIC)
            fh.write(self._trace.getvalue())
        with open(self.path / "meta.json", "w", encoding="utf-8") as fh:
            json.dump(self.meta, fh, indent=2)
        return self.path

    def __enter__(self) -> "BundleWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------


@dataclass
class Record:
    """One decoded trace record.

    Kept as a light mutable object rather than a tuple because the replay loop
    reuses a single instance; allocating ten million of these is measurably the
    wrong thing to do (design v0.2 section 10.5).
    """

    tag: int = 0
    a: int = 0
    b: int = 0
    c: int = 0
    d: int = 0
    payload: bytes = b""
    args: list[int] = field(default_factory=list)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        name = TAG_NAMES.get(self.tag, f"0x{self.tag:02x}")
        return f"<{name} a={self.a} b={self.b} c={self.c} d={self.d}>"


class TraceBundle:
    """A read-only view over a bundle directory."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        if not self.path.is_dir():
            raise FileNotFoundError(f"not a bundle directory: {self.path}")
        with open(self.path / "meta.json", encoding="utf-8") as fh:
            self.meta: dict = json.load(fh)

        self._code_bytes = (self.path / "code.bin").read_bytes()
        self._trace_bytes = (self.path / "trace.bin").read_bytes()

        self.blocks: dict[int, BlockDescriptor] = {}
        self.modules: list[Module] = [
            Module(
                name=m.get("name", "?"),
                base=int(m["base"]),
                size=int(m["size"]),
                path=m.get("path", ""),
            )
            for m in self.meta.get("modules", [])
        ]
        self._load_code()

    # -- code -------------------------------------------------------------

    def _load_code(self) -> None:
        r = ByteReader(self._code_bytes, read_header(self._code_bytes, CODE_MAGIC))
        while not r.eof():
            tag = r.u8()
            if tag == CTAG_BLOCK:
                block_id = r.uvarint()
                code_version = r.uvarint()
                start = r.uvarint()
                n = r.uvarint()
                insns: list[InsnDescriptor] = []
                addr = start
                for _ in range(n):
                    raw = r.blob()
                    insns.append(InsnDescriptor(addr, raw))
                    addr += len(raw)
                if block_id in self.blocks:
                    raise TraceFormatError(
                        f"duplicate block_id {block_id} in code stream"
                    )
                self.blocks[block_id] = BlockDescriptor(
                    block_id, code_version, start, insns
                )
            elif tag == CTAG_MODULE:
                name = r.string()
                base = r.uvarint()
                size = r.uvarint()
                path = r.string()
                self.modules.append(Module(name, base, size, path))
            else:
                raise TraceFormatError(f"unknown code-stream tag 0x{tag:02x}")

    # -- trace ------------------------------------------------------------

    def records(self) -> Iterator[Record]:
        """Iterate the trace stream, yielding a *reused* :class:`Record`.

        Callers must not retain the yielded object across iterations.
        """
        from .format import (
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

        data = self._trace_bytes
        r = ByteReader(data, read_header(data, TRACE_MAGIC))
        rec = Record()
        last_ea = 0
        while not r.eof():
            tag = r.u8()
            rec.tag = tag
            rec.payload = b""
            rec.args = []
            if tag == TAG_BLOCK:
                rec.a = r.uvarint()
            elif tag == TAG_MEM:
                rec.a = r.uvarint()  # insn_index
                last_ea += r.svarint()
                rec.b = last_ea  # effective address
                rec.c = r.u8()  # access size
                rec.d = r.u8()  # rw flags
            elif tag in (TAG_VERSION, TAG_THREAD, TAG_ABORT, TAG_MARK, TAG_SHIFTCNT):
                rec.a = r.uvarint()
            elif tag in (TAG_REP, TAG_REP_POST):
                rec.a = r.uvarint()  # rcx
                rec.b = r.uvarint()  # rsi
                rec.c = r.uvarint()  # rdi
                rec.d = r.uvarint()  # df
            elif tag == TAG_SUMMARY:
                rec.a = r.uvarint()  # summary id
                n = r.uvarint()
                rec.b = n
                rec.args = [r.uvarint() for _ in range(n)]
            elif tag == TAG_VALUE:
                rec.a = r.uvarint()  # slot
                rec.payload = r.blob()
            else:
                raise TraceFormatError(
                    f"unknown trace tag 0x{tag:02x} at offset {r.pos - 1}"
                )
            yield rec

    # -- helpers ----------------------------------------------------------

    def module_for(self, address: int) -> Module | None:
        for module in self.modules:
            if module.contains(address):
                return module
        return None

    def rebase(self, address: int) -> str:
        """Render an absolute address as ``module+0xRVA`` where possible."""
        module = self.module_for(address)
        if module is None:
            return f"0x{address:x}"
        return f"{module.name}+0x{address - module.base:x}"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<TraceBundle {self.path.name} "
            f"blocks={len(self.blocks)} modules={len(self.modules)} "
            f"trace={len(self._trace_bytes) - HEADER_SIZE}B>"
        )

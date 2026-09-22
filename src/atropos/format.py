"""Binary trace-format primitives.

The Atropos trace bundle is deliberately language-neutral: varint-encoded, tagged
records with no host-endianness or pointer-size assumptions baked in, so the
planned Rust replay core (design v0.2 section 10.5) is a mechanical port.

See ``docs/trace-format.md`` for the normative specification.  This module is
the reference implementation of the encoding layer and nothing more: it knows
about bytes, not about x86.
"""

from __future__ import annotations

import struct
from typing import BinaryIO

# --------------------------------------------------------------------------
# Magic / versioning
# --------------------------------------------------------------------------

TRACE_MAGIC = b"ATRT"
CODE_MAGIC = b"ATRC"
FORMAT_VERSION = 1

# --------------------------------------------------------------------------
# Trace stream tags  (design v0.2 section 4.4)
# --------------------------------------------------------------------------

TAG_BLOCK = 0x01
TAG_MEM = 0x02
TAG_VERSION = 0x03
TAG_THREAD = 0x04
TAG_ABORT = 0x05
TAG_MARK = 0x06
TAG_SUMMARY = 0x07
TAG_REP = 0x08
TAG_SHIFTCNT = 0x09
TAG_VALUE = 0x0A
TAG_REP_POST = 0x0B

TAG_NAMES = {
    TAG_BLOCK: "BLOCK",
    TAG_MEM: "MEM",
    TAG_VERSION: "VERSION",
    TAG_THREAD: "THREAD",
    TAG_ABORT: "ABORT",
    TAG_MARK: "MARK",
    TAG_SUMMARY: "SUMMARY",
    TAG_REP: "REP",
    TAG_SHIFTCNT: "SHIFTCNT",
    TAG_VALUE: "VALUE",
    TAG_REP_POST: "REP_POST",
}

# --------------------------------------------------------------------------
# Code stream tags
# --------------------------------------------------------------------------

CTAG_BLOCK = 0x01
CTAG_MODULE = 0x02

# --------------------------------------------------------------------------
# Memory access direction flags (the ``rw`` field of a MEM record)
# --------------------------------------------------------------------------

RW_READ = 0x1
RW_WRITE = 0x2


class TraceFormatError(Exception):
    """The byte stream does not conform to the trace format."""


# --------------------------------------------------------------------------
# Varint / zig-zag
# --------------------------------------------------------------------------


def encode_uvarint(value: int) -> bytes:
    """LEB128-style unsigned varint."""
    if value < 0:
        raise ValueError(f"uvarint cannot encode negative value {value}")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def zigzag_encode(value: int) -> int:
    """Map a signed integer onto the naturals, small magnitudes to small values."""
    return (value << 1) ^ (value >> 63) if value < 0 else (value << 1)


def zigzag_decode(value: int) -> int:
    return (value >> 1) ^ -(value & 1)


def encode_svarint(value: int) -> bytes:
    return encode_uvarint(zigzag_encode(value))


class ByteWriter:
    """Append-only varint writer over a bytearray."""

    __slots__ = ("buf",)

    def __init__(self) -> None:
        self.buf = bytearray()

    def u8(self, value: int) -> "ByteWriter":
        self.buf.append(value & 0xFF)
        return self

    def uvarint(self, value: int) -> "ByteWriter":
        self.buf += encode_uvarint(value)
        return self

    def svarint(self, value: int) -> "ByteWriter":
        self.buf += encode_svarint(value)
        return self

    def blob(self, data: bytes) -> "ByteWriter":
        self.uvarint(len(data))
        self.buf += data
        return self

    def string(self, text: str) -> "ByteWriter":
        return self.blob(text.encode("utf-8"))

    def raw(self, data: bytes) -> "ByteWriter":
        self.buf += data
        return self

    def __len__(self) -> int:
        return len(self.buf)

    def getvalue(self) -> bytes:
        return bytes(self.buf)


class ByteReader:
    """Random-access varint reader over an immutable buffer.

    Deliberately index-based rather than file-based so that a memory-mapped
    bundle can be read without copying.
    """

    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes, pos: int = 0, end: int | None = None) -> None:
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end

    def eof(self) -> bool:
        return self.pos >= self.end

    def remaining(self) -> int:
        return self.end - self.pos

    def u8(self) -> int:
        if self.pos >= self.end:
            raise TraceFormatError("unexpected end of stream reading u8")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def uvarint(self) -> int:
        shift = 0
        result = 0
        data = self.data
        pos = self.pos
        while True:
            if pos >= self.end:
                raise TraceFormatError("unexpected end of stream reading varint")
            byte = data[pos]
            pos += 1
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
            if shift > 70:
                raise TraceFormatError("varint too long (corrupt stream)")
        self.pos = pos
        return result

    def svarint(self) -> int:
        return zigzag_decode(self.uvarint())

    def blob(self) -> bytes:
        length = self.uvarint()
        if self.pos + length > self.end:
            raise TraceFormatError("blob length runs past end of stream")
        out = self.data[self.pos : self.pos + length]
        self.pos += length
        return out

    def string(self) -> str:
        return self.blob().decode("utf-8")

    def raw(self, length: int) -> bytes:
        if self.pos + length > self.end:
            raise TraceFormatError("raw read runs past end of stream")
        out = self.data[self.pos : self.pos + length]
        self.pos += length
        return out


# --------------------------------------------------------------------------
# Section headers
# --------------------------------------------------------------------------

_HEADER = struct.Struct("<4sHH")


def write_header(fh: BinaryIO, magic: bytes) -> None:
    fh.write(_HEADER.pack(magic, FORMAT_VERSION, 0))


def read_header(data: bytes, expect_magic: bytes) -> int:
    """Validate a section header and return the offset of the first record."""
    if len(data) < _HEADER.size:
        raise TraceFormatError("section is shorter than its header")
    magic, version, _reserved = _HEADER.unpack_from(data, 0)
    if magic != expect_magic:
        raise TraceFormatError(
            f"bad section magic: expected {expect_magic!r}, found {magic!r}"
        )
    if version != FORMAT_VERSION:
        raise TraceFormatError(
            f"unsupported trace format version {version} "
            f"(this build reads version {FORMAT_VERSION})"
        )
    return _HEADER.size


HEADER_SIZE = _HEADER.size

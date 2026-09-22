"""Encoding-layer tests.

The trace format is the contract between the capture agent and the host, and
the one thing a Rust port must reproduce byte for byte.  These tests pin it.
"""

from __future__ import annotations

import pytest

from atropos.format import (
    ByteReader,
    ByteWriter,
    TraceFormatError,
    encode_uvarint,
    zigzag_decode,
    zigzag_encode,
)


@pytest.mark.parametrize(
    "value", [0, 1, 127, 128, 255, 300, 0xFFFF, 0x7FFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF]
)
def test_uvarint_roundtrip(value):
    reader = ByteReader(encode_uvarint(value))
    assert reader.uvarint() == value
    assert reader.eof()


@pytest.mark.parametrize(
    "value", [0, 1, -1, 63, -64, 1 << 20, -(1 << 20), (1 << 62), -(1 << 62)]
)
def test_zigzag_roundtrip(value):
    assert zigzag_decode(zigzag_encode(value)) == value


def test_zigzag_keeps_small_deltas_small():
    """The point of zig-zag: a small backward jump must not cost ten bytes.

    Effective addresses are delta-coded, and a loop walking a buffer backwards
    produces small negative deltas.  Two's complement would encode -8 as
    0xFFFF_FFFF_FFFF_FFF8 and pay ten varint bytes for it.
    """
    assert len(encode_uvarint(zigzag_encode(-8))) == 1
    assert len(encode_uvarint(zigzag_encode(8))) == 1


def test_writer_reader_roundtrip():
    writer = ByteWriter()
    writer.u8(0x42).uvarint(300).svarint(-7).blob(b"\x01\x02").string("ntdll.dll")

    reader = ByteReader(writer.getvalue())
    assert reader.u8() == 0x42
    assert reader.uvarint() == 300
    assert reader.svarint() == -7
    assert reader.blob() == b"\x01\x02"
    assert reader.string() == "ntdll.dll"
    assert reader.eof()


def test_truncated_varint_is_an_error_not_a_guess():
    """A truncated stream must raise, never return a plausible number.

    This is the format-layer half of success criterion 4: silently decoding
    corruption into a valid-looking value is exactly the failure mode the whole
    integrity story exists to prevent.
    """
    with pytest.raises(TraceFormatError):
        ByteReader(b"\x80\x80\x80").uvarint()


def test_overlong_varint_is_rejected():
    with pytest.raises(TraceFormatError):
        ByteReader(b"\x80" * 12 + b"\x01").uvarint()


def test_blob_past_end_is_rejected():
    with pytest.raises(TraceFormatError):
        ByteReader(b"\x10\x01\x02").blob()

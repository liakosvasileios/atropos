"""The disassembler bridge: getting the slice into IDA and Ghidra.

Design v0.2 section 9.3, and it is first-class rather than an afterthought for
a simple reason: RE workflows live in the disassembler.  An analyst has a
database with their names, their comments, their structs, and their
understanding of the binary.  A slice that arrives as a terminal listing makes
them do the join by hand; a slice that arrives as colour and comments *in that
database* is immediately usable.

The exchange format is deliberately dumb — module, RVA, occurrence count, edge
kinds — so a third-party script can consume it without importing anything from
Atropos.  The two scripts below are conveniences, not the interface.
"""

from __future__ import annotations

import json

from ..arch.effects import KIND_NAMES
from ..shadow import LIVE_IN
from ..slicer import SliceResult


def to_bridge_json(analysis, slice_result: SliceResult) -> str:
    """Per-static-address rollup of the slice, keyed by ``module + RVA``."""
    ddg = analysis.ddg
    bundle = analysis.bundle

    rollup: dict[tuple[str, int, int], dict] = {}
    summaries: list[dict] = []
    for seq in slice_result.nodes:
        if ddg.node_block[seq] < 0:
            # A summary node stands for an untraced call and has a pseudo-address
            # (summaries.SUMMARY_ADDRESS_BASE), not a real one.  Rolling it up
            # with the rest would hand the disassembler script a nonsense RVA to
            # colour.  It is still worth reporting — "the chain passes through
            # GetVolumeInformationW" is often the answer — so it goes in its own
            # list that a script can render as a message rather than a location.
            summaries.append({
                "seq": seq,
                "name": ddg.summary_nodes.get(seq, "<summary>"),
                "kind": ddg.summary_kinds.get(seq, "unknown"),
            })
            continue
        address = ddg.node_addr[seq]
        module = bundle.module_for(address)
        name = module.name if module else "?"
        rva = address - module.base if module else address
        key = (name, rva, ddg.node_version[seq])
        entry = rollup.setdefault(
            key,
            {
                "module": name,
                "rva": rva,
                "code_version": ddg.node_version[seq],
                "occurrences": 0,
                "seqs": [],
                "edge_kinds": set(),
            },
        )
        entry["occurrences"] += 1
        if len(entry["seqs"]) < 32:
            entry["seqs"].append(seq)
        inclusion = slice_result.inclusions.get(seq)
        if inclusion is not None:
            entry["edge_kinds"].add(KIND_NAMES.get(inclusion.kind, "?"))

    entries = []
    for entry in rollup.values():
        entry = dict(entry)
        entry["edge_kinds"] = sorted(entry["edge_kinds"])
        entries.append(entry)
    entries.sort(key=lambda e: (e["module"], e["rva"]))

    return json.dumps(
        {
            "atropos_bridge": 1,
            "criterion": slice_result.criterion.render(),
            "mode": slice_result.mode.describe(),
            "precision": analysis.precision_banner(),
            "instructions": entries,
            "summaries": summaries,
        },
        indent=2,
    )


IDA_SCRIPT = r'''"""Atropos -> IDA Pro.

Usage:  File > Script file... and pick this, then choose the bridge JSON.

Colours every instruction in the slice and comments it with how many times it
appeared and which edge kinds pulled it in.  Addresses are rebased from the
recorded module base onto the one this database uses, so a run under ASLR still
lands in the right place.
"""

import json
import ida_kernwin
import ida_bytes
import idc

VALUE_COLOUR = 0xD7F0D7   # green-ish: pure data flow
ADDR_COLOUR = 0xF0E0D7    # blue-ish: pointer arithmetic
CONTROL_COLOUR = 0xD7D7F0 # red-ish: control dependence


def colour_for(kinds):
    if "control" in kinds:
        return CONTROL_COLOUR
    if "addr" in kinds:
        return ADDR_COLOUR
    return VALUE_COLOUR


def main():
    path = ida_kernwin.ask_file(False, "*.json", "Atropos bridge JSON")
    if not path:
        return
    with open(path) as fh:
        data = json.load(fh)

    base = idaapi.get_imagebase()
    applied = 0
    for entry in data["instructions"]:
        ea = base + entry["rva"]
        if not ida_bytes.is_loaded(ea):
            print("atropos: skipping unmapped %#x" % ea)
            continue
        idc.set_color(ea, idc.CIC_ITEM, colour_for(entry["edge_kinds"]))
        comment = "atropos: x%d [%s]" % (
            entry["occurrences"], ",".join(entry["edge_kinds"]) or "-"
        )
        if entry.get("code_version"):
            comment += " v%d" % entry["code_version"]
        idc.set_cmt(ea, comment, 0)
        applied += 1

    print("atropos: annotated %d instruction(s)" % applied)
    for entry in data.get("summaries", []):
        print("atropos: chain passes through %s [%s]" % (entry["name"], entry["kind"]))
    print("atropos: criterion %s (mode %s)" % (data["criterion"], data["mode"]))
    for line in data.get("precision", []):
        print("atropos: %s" % line)


main()
'''


GHIDRA_SCRIPT = r'''# Atropos -> Ghidra
# @category Atropos
# @description Colour and comment a backward dynamic slice in the listing.
#
# Run from the Script Manager. Choose the bridge JSON when prompted.

import json

from java.awt import Color
from ghidra.program.model.address import AddressSet

VALUE_COLOUR = Color(0xD7, 0xF0, 0xD7)
ADDR_COLOUR = Color(0xD7, 0xE0, 0xF0)
CONTROL_COLOUR = Color(0xF0, 0xD7, 0xD7)


def colour_for(kinds):
    if "control" in kinds:
        return CONTROL_COLOUR
    if "addr" in kinds:
        return ADDR_COLOUR
    return VALUE_COLOUR


def run():
    chosen = askFile("Atropos bridge JSON", "Load")
    with open(chosen.getAbsolutePath()) as fh:
        data = json.load(fh)

    base = currentProgram.getImageBase()
    service = state.getTool().getService(
        ghidra.app.services.ColorizingService
    )
    applied = 0
    for entry in data["instructions"]:
        addr = base.add(entry["rva"])
        if getInstructionAt(addr) is None:
            print("atropos: no instruction at %s" % addr)
            continue
        if service is not None:
            service.setBackgroundColor(addr, addr, colour_for(entry["edge_kinds"]))
        comment = "atropos: x%d [%s]" % (
            entry["occurrences"], ",".join(entry["edge_kinds"]) or "-"
        )
        setPreComment(addr, comment)
        applied += 1

    print("atropos: annotated %d instruction(s)" % applied)
    for entry in data.get("summaries", []):
        print("atropos: chain passes through %s [%s]" % (entry["name"], entry["kind"]))
    print("atropos: criterion %s (mode %s)" % (data["criterion"], data["mode"]))
    for line in data.get("precision", []):
        print("atropos: %s" % line)


run()
'''


def write_scripts(directory) -> list[str]:
    """Drop both loader scripts next to a bridge JSON."""
    from pathlib import Path

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name, body in (
        ("atropos_ida.py", IDA_SCRIPT),
        ("atropos_ghidra.py", GHIDRA_SCRIPT),
    ):
        path = directory / name
        path.write_text(body, encoding="utf-8")
        written.append(str(path))
    return written

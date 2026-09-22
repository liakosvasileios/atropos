"""A synthetic capture path: assemble, interpret, and emit a trace bundle.

Design v0.2 section 11.1 requires that the unit suite run "on any platform with
no Frida and no target process".  This module is how.  It contains three small
pieces:

:class:`Assembler`
    A hand-written encoder for the subset of x86-64 the fixtures use.  Small on
    purpose — it exists so tests can be written in assembly rather than in hex,
    and it refuses anything it does not encode exactly rather than guessing.

:class:`MiniVM`
    An interpreter for that same subset.  It executes the program concretely,
    which is what produces *real* effective addresses for the trace.  Hand-writing
    EAs into fixtures would make the fixtures agree with whatever the model
    believes, which is precisely the bug a fixture is supposed to catch.

:func:`build_bundle`
    Wraps a run into an on-disk bundle indistinguishable, to the host, from one
    the Frida agent produced.  That is the point: the entire offline pipeline is
    exercised end to end, including the trace format and the integrity checks.

The VM also records its own last-writer log (:attr:`MiniVM.writes`), computed
from its own knowledge of what each instruction does rather than from the effect
model.  That log is the seed of the differential oracle in
:mod:`atropos.oracle` — two independent implementations that must agree.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .bundle import BundleWriter, TraceBundle
from .format import RW_READ, RW_WRITE, TAG_MARK, TAG_REP, TAG_SHIFTCNT, TAG_SUMMARY

# --------------------------------------------------------------------------
# Assembler
# --------------------------------------------------------------------------

REG64 = {
    "rax": 0, "rcx": 1, "rdx": 2, "rbx": 3,
    "rsp": 4, "rbp": 5, "rsi": 6, "rdi": 7,
    "r8": 8, "r9": 9, "r10": 10, "r11": 11,
    "r12": 12, "r13": 13, "r14": 14, "r15": 15,
}
REG32 = {
    "eax": 0, "ecx": 1, "edx": 2, "ebx": 3,
    "esp": 4, "ebp": 5, "esi": 6, "edi": 7,
}
REG8 = {"al": 0, "cl": 1, "dl": 2, "bl": 3, "ah": 4, "ch": 5, "dh": 6, "bh": 7}

ALU_OPCODES = {  # /r form, r/m <- reg  (opcode for the 8-bit and 32/64-bit form)
    "add": (0x00, 0x01, 0),
    "or": (0x08, 0x09, 1),
    "adc": (0x10, 0x11, 2),
    "sbb": (0x18, 0x19, 3),
    "and": (0x20, 0x21, 4),
    "sub": (0x28, 0x29, 5),
    "xor": (0x30, 0x31, 6),
    "cmp": (0x38, 0x39, 7),
}


class AssemblyError(ValueError):
    """The assembler does not encode this instruction."""


def _rex(w: int, r: int, x: int, b: int) -> int:
    return 0x40 | (w << 3) | ((r >> 3) << 2) | ((x >> 3) << 1) | (b >> 3)


def _modrm(mod: int, reg: int, rm: int) -> int:
    return (mod << 6) | ((reg & 7) << 3) | (rm & 7)


def _imm(value: int, size: int) -> bytes:
    return (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")


_MEM_RE = re.compile(r"^\[\s*(?P<base>[a-z0-9]+)\s*(?P<sign>[-+])?\s*(?P<disp>0x[0-9a-f]+|\d+)?\s*\]$")
_MEM_INDEX_RE = re.compile(
    r"^\[\s*(?P<base>[a-z0-9]+)\s*\+\s*(?P<index>[a-z0-9]+)\s*\*\s*(?P<scale>[1248])\s*\]$"
)


@dataclass(frozen=True)
class MemOperand:
    base: str
    index: str | None = None
    scale: int = 1
    disp: int = 0


def _parse_mem(text: str) -> MemOperand | None:
    match = _MEM_INDEX_RE.match(text)
    if match:
        return MemOperand(match.group("base"), match.group("index"), int(match.group("scale")))
    match = _MEM_RE.match(text)
    if match:
        disp = int(match.group("disp"), 0) if match.group("disp") else 0
        if match.group("sign") == "-":
            disp = -disp
        return MemOperand(match.group("base"), None, 1, disp)
    return None


def _encode_mem(reg: int, mem: MemOperand) -> bytes:
    base = REG64[mem.base]
    if mem.index is not None:
        index = REG64[mem.index]
        scale = {1: 0, 2: 1, 4: 2, 8: 3}[mem.scale]
        sib = (scale << 6) | ((index & 7) << 3) | (base & 7)
        return bytes([_modrm(0, reg, 4), sib])
    if mem.disp == 0 and (base & 7) != 5:
        return bytes([_modrm(0, reg, base)])
    if -128 <= mem.disp <= 127:
        return bytes([_modrm(1, reg, base)]) + _imm(mem.disp, 1)
    return bytes([_modrm(2, reg, base)]) + _imm(mem.disp, 4)


class Assembler:
    """Encodes the fixture subset of x86-64.  Raises on anything else."""

    def encode(self, text: str) -> bytes:
        parts = text.strip().lower().split(None, 1)
        mnem = parts[0]
        operands = [p.strip() for p in parts[1].split(",")] if len(parts) > 1 else []

        handler = getattr(self, f"_asm_{mnem}", None)
        if handler is not None:
            return handler(operands)
        if mnem in ALU_OPCODES:
            return self._asm_alu(mnem, operands)
        raise AssemblyError(f"assembler does not encode {text!r}")

    # -- simple forms -----------------------------------------------------

    def _asm_nop(self, ops) -> bytes:
        return b"\x90"

    def _asm_ret(self, ops) -> bytes:
        return b"\xc3"

    def _asm_cqo(self, ops) -> bytes:
        return b"\x48\x99"

    def _asm_push(self, ops) -> bytes:
        reg = REG64[ops[0]]
        prefix = b"\x41" if reg >= 8 else b""
        return prefix + bytes([0x50 + (reg & 7)])

    def _asm_pop(self, ops) -> bytes:
        reg = REG64[ops[0]]
        prefix = b"\x41" if reg >= 8 else b""
        return prefix + bytes([0x58 + (reg & 7)])

    def _asm_inc(self, ops) -> bytes:
        reg = REG64[ops[0]]
        return bytes([_rex(1, 0, 0, reg), 0xFF, _modrm(3, 0, reg)])

    def _asm_dec(self, ops) -> bytes:
        reg = REG64[ops[0]]
        return bytes([_rex(1, 0, 0, reg), 0xFF, _modrm(3, 1, reg)])

    def _asm_test(self, ops) -> bytes:
        dst, src = ops
        if dst in REG64 and src in REG64:
            return bytes([_rex(1, REG64[src], 0, REG64[dst]), 0x85,
                          _modrm(3, REG64[src], REG64[dst])])
        if dst in REG8 and src in REG8:
            return bytes([0x84, _modrm(3, REG8[src], REG8[dst])])
        raise AssemblyError(f"test {ops}")

    def _asm_shl(self, ops) -> bytes:
        dst, src = ops
        if src != "cl":
            raise AssemblyError("only `shl r64, cl` is encoded")
        reg = REG64[dst]
        return bytes([_rex(1, 0, 0, reg), 0xD3, _modrm(3, 4, reg)])

    def _asm_shr(self, ops) -> bytes:
        dst, src = ops
        if src != "cl":
            raise AssemblyError("only `shr r64, cl` is encoded")
        reg = REG64[dst]
        return bytes([_rex(1, 0, 0, reg), 0xD3, _modrm(3, 5, reg)])

    def _asm_lea(self, ops) -> bytes:
        dst, src = ops
        mem = _parse_mem(src)
        if mem is None or dst not in REG64:
            raise AssemblyError(f"lea {ops}")
        reg = REG64[dst]
        base = REG64[mem.base]
        index = REG64[mem.index] if mem.index else 0
        return bytes([_rex(1, reg, index, base), 0x8D]) + _encode_mem(reg, mem)

    # -- branches ---------------------------------------------------------

    def _rel8(self, opcode: bytes, ops) -> bytes:
        target = ops[0]
        if target.startswith("@"):
            # Placeholder; Program.link() patches the displacement once every
            # block has an address.  rel8 is always one byte, so patching never
            # changes a block's size and the layout stays valid.
            return opcode + bytes(1)
        return opcode + _imm(int(target, 0), 1)

    def _asm_jmp(self, ops) -> bytes:
        if ops[0] in REG64:
            reg = REG64[ops[0]]
            prefix = bytes([_rex(0, 0, 0, reg)]) if reg >= 8 else b""
            return prefix + bytes([0xFF, _modrm(3, 4, reg)])
        return self._rel8(b"\xeb", ops)

    def _asm_jz(self, ops) -> bytes:
        return self._rel8(b"\x74", ops)

    _asm_je = _asm_jz

    def _asm_jnz(self, ops) -> bytes:
        return self._rel8(b"\x75", ops)

    _asm_jne = _asm_jnz

    def _asm_call(self, ops) -> bytes:
        if ops[0].startswith("@"):
            return b"\xe8" + bytes(4)  # patched by Program.link()
        return b"\xe8" + _imm(int(ops[0], 0), 4)

    # -- rep string ops ---------------------------------------------------

    def _asm_rep(self, ops) -> bytes:
        raise AssemblyError("write `rep movsb` as a single token: use 'rep_movsb'")

    def _asm_rep_movsb(self, ops) -> bytes:
        return b"\xf3\xa4"

    def _asm_rep_stosb(self, ops) -> bytes:
        return b"\xf3\xaa"

    def _asm_movsb(self, ops) -> bytes:
        return b"\xa4"

    # -- mov --------------------------------------------------------------

    def _asm_mov(self, ops) -> bytes:
        dst, src = ops

        # register <- immediate
        if dst in REG64 and _is_imm(src):
            reg = REG64[dst]
            return bytes([_rex(1, 0, 0, reg), 0xB8 + (reg & 7)]) + _imm(int(src, 0), 8)
        if dst in REG32 and _is_imm(src):
            return bytes([0xB8 + REG32[dst]]) + _imm(int(src, 0), 4)
        if dst in REG8 and _is_imm(src):
            return bytes([0xB0 + REG8[dst]]) + _imm(int(src, 0), 1)

        # register <- register
        if dst in REG64 and src in REG64:
            return bytes([_rex(1, REG64[src], 0, REG64[dst]), 0x89,
                          _modrm(3, REG64[src], REG64[dst])])
        if dst in REG32 and src in REG32:
            return bytes([0x89, _modrm(3, REG32[src], REG32[dst])])
        if dst in REG8 and src in REG8:
            return bytes([0x88, _modrm(3, REG8[src], REG8[dst])])

        # register <- memory / memory <- register
        mem = _parse_mem(src)
        if mem is not None:
            if dst in REG64:
                reg = REG64[dst]
                return bytes([_rex(1, reg, REG64.get(mem.index or "rax", 0), REG64[mem.base]),
                              0x8B]) + _encode_mem(reg, mem)
            if dst in REG8:
                return bytes([0x8A]) + _encode_mem(REG8[dst], mem)
        mem = _parse_mem(dst)
        if mem is not None:
            if src in REG64:
                reg = REG64[src]
                return bytes([_rex(1, reg, REG64.get(mem.index or "rax", 0), REG64[mem.base]),
                              0x89]) + _encode_mem(reg, mem)
            if src in REG8:
                return bytes([0x88]) + _encode_mem(REG8[src], mem)

        raise AssemblyError(f"mov {ops}")

    # -- ALU --------------------------------------------------------------

    def _asm_alu(self, mnem: str, ops) -> bytes:
        dst, src = ops
        op8, op32, ext = ALU_OPCODES[mnem]

        if dst in REG64 and src in REG64:
            return bytes([_rex(1, REG64[src], 0, REG64[dst]), op32,
                          _modrm(3, REG64[src], REG64[dst])])
        if dst in REG8 and src in REG8:
            return bytes([op8, _modrm(3, REG8[src], REG8[dst])])
        if dst in REG64 and _is_imm(src):
            value = int(src, 0)
            reg = REG64[dst]
            if -128 <= value <= 127:
                return bytes([_rex(1, 0, 0, reg), 0x83, _modrm(3, ext, reg)]) + _imm(value, 1)
            return bytes([_rex(1, 0, 0, reg), 0x81, _modrm(3, ext, reg)]) + _imm(value, 4)
        if dst in REG8 and _is_imm(src):
            return bytes([0x80, _modrm(3, ext, REG8[dst])]) + _imm(int(src, 0), 1)
        mem = _parse_mem(src)
        if mem is not None and dst in REG64:
            reg = REG64[dst]
            return bytes([_rex(1, reg, 0, REG64[mem.base]), op32 + 2]) + _encode_mem(reg, mem)
        mem = _parse_mem(dst)
        if mem is not None and src in REG64:
            reg = REG64[src]
            return bytes([_rex(1, reg, 0, REG64[mem.base]), op32]) + _encode_mem(reg, mem)
        raise AssemblyError(f"{mnem} {ops}")


def _is_imm(text: str) -> bool:
    try:
        int(text, 0)
        return True
    except ValueError:
        return False


ASSEMBLER = Assembler()


def assemble(text: str) -> bytes:
    return ASSEMBLER.encode(text)


# --------------------------------------------------------------------------
# Interpreter
# --------------------------------------------------------------------------


@dataclass
class Access:
    """One memory access, as the capture agent would have recorded it."""

    insn_index: int
    ea: int
    size: int
    rw: int


@dataclass
class ExecutedBlock:
    block_id: int
    accesses: list[Access] = field(default_factory=list)
    reps: list[tuple[int, int, int, int]] = field(default_factory=list)
    shift_counts: list[int] = field(default_factory=list)


class MiniVM:
    """A concrete interpreter for the assembler's subset.

    Its purpose is to generate *real* effective addresses, not to be a complete
    x86 implementation.  It raises on anything it cannot execute, so a fixture
    can never silently drift into being about an instruction the VM guessed at.
    """

    def __init__(self, memory: dict[int, int] | None = None) -> None:
        self.regs: dict[str, int] = {name: 0 for name in REG64}
        self.regs["rsp"] = 0x7FFF_0000
        self.mem: dict[int, int] = dict(memory or {})
        self.flags = {"zf": 0, "cf": 0, "sf": 0, "of": 0, "pf": 0, "af": 0, "df": 0}
        #: Independent last-writer log: (space, location, length) -> step index.
        #: Computed from the VM's own semantics, never from the effect model.
        self.writes: list[tuple[str, int, int, int]] = []
        self.step = 0

    # -- memory ------------------------------------------------------------

    def read(self, address: int, size: int) -> int:
        return int.from_bytes(
            bytes(self.mem.get(address + i, 0) for i in range(size)), "little"
        )

    def write(self, address: int, size: int, value: int) -> None:
        data = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
        for i, byte in enumerate(data):
            self.mem[address + i] = byte

    # -- registers ---------------------------------------------------------

    def get(self, name: str) -> int:
        if name in REG64:
            return self.regs[name]
        if name in REG32:
            return self.regs["r" + name[1:]] & 0xFFFFFFFF
        if name in REG8:
            parent = {"al": "rax", "cl": "rcx", "dl": "rdx", "bl": "rbx",
                      "ah": "rax", "ch": "rcx", "dh": "rdx", "bh": "rbx"}[name]
            value = self.regs[parent]
            return (value >> 8) & 0xFF if name.endswith("h") else value & 0xFF
        raise AssemblyError(f"unknown register {name}")

    def set(self, name: str, value: int) -> None:
        if name in REG64:
            self.regs[name] = value & 0xFFFFFFFFFFFFFFFF
            return
        if name in REG32:
            self.regs["r" + name[1:]] = value & 0xFFFFFFFF  # zero-extends
            return
        if name in REG8:
            parent = {"al": "rax", "cl": "rcx", "dl": "rdx", "bl": "rbx",
                      "ah": "rax", "ch": "rcx", "dh": "rdx", "bh": "rbx"}[name]
            old = self.regs[parent]
            if name.endswith("h"):
                self.regs[parent] = (old & ~0xFF00) | ((value & 0xFF) << 8)
            else:
                self.regs[parent] = (old & ~0xFF) | (value & 0xFF)
            return
        raise AssemblyError(f"unknown register {name}")


# --------------------------------------------------------------------------
# Program construction
# --------------------------------------------------------------------------


@dataclass
class Block:
    """A basic block of source assembly, laid out at a chosen address."""

    name: str
    source: list[str]
    address: int = 0
    block_id: int = -1
    raw: list[bytes] = field(default_factory=list)

    def assemble(self) -> None:
        self.raw = [assemble(line) for line in self.source]

    @property
    def size(self) -> int:
        return sum(len(r) for r in self.raw)


class Program:
    """Assembles blocks, runs them, and emits a bundle.

    The execution model is deliberately explicit: the caller supplies the
    *block execution order* rather than the VM inferring it from branches.  That
    keeps the VM tiny and, more importantly, lets a fixture construct traces
    that a real target could produce but that would be tedious to arrange —
    including the pathological ones the integrity checker is supposed to catch.
    """

    def __init__(self, base_address: int = 0x1400_1000, module: str = "target.exe") -> None:
        self.base_address = base_address
        self.module = module
        self.blocks: list[Block] = []
        self._next_address = base_address

    def block(self, name: str, source: list[str]) -> Block:
        blk = Block(name, source, self._next_address)
        blk.assemble()
        self.blocks.append(blk)
        self._next_address += blk.size
        return blk

    def link(self) -> None:
        """Resolve ``@label`` branch targets now that every block has an address.

        Fixtures that hand-compute relative displacements are a liability: the
        integrity checker legitimately rejects a trace whose branches do not
        reach the blocks that follow them, so a miscounted offset shows up as a
        confusing failure in an unrelated test.  Labels remove the arithmetic.
        """
        targets = {blk.name: blk.address for blk in self.blocks}
        for blk in self.blocks:
            address = blk.address
            for index, line in enumerate(blk.source):
                raw = blk.raw[index]
                _, _, operand = line.strip().lower().partition(" ")
                operand = operand.strip()
                if operand.startswith("@"):
                    label = operand[1:]
                    if label not in targets:
                        raise AssemblyError(f"unknown label @{label}")
                    next_address = address + len(raw)
                    displacement = targets[label] - next_address
                    if len(raw) == 2:
                        if not -128 <= displacement <= 127:
                            raise AssemblyError(
                                f"@{label} is {displacement} bytes away; too far for rel8"
                            )
                        blk.raw[index] = raw[:1] + _imm(displacement, 1)
                    else:
                        blk.raw[index] = raw[:1] + _imm(displacement, 4)
                address += len(raw)

    def by_name(self, name: str) -> Block:
        for blk in self.blocks:
            if blk.name == name:
                return blk
        raise KeyError(name)

    # ------------------------------------------------------------------

    def run(
        self,
        order: list[str],
        vm: MiniVM | None = None,
    ) -> tuple[MiniVM, list[ExecutedBlock]]:
        """Execute the named blocks in order, recording memory accesses."""
        self.link()
        vm = vm or MiniVM()
        executed: list[ExecutedBlock] = []
        for name in order:
            blk = self.by_name(name)
            record = ExecutedBlock(block_id=blk.block_id)
            for index, line in enumerate(blk.source):
                self._step(vm, line, index, record)
                vm.step += 1
            executed.append(record)
        return vm, executed

    def _step(self, vm: MiniVM, line: str, index: int, record: ExecutedBlock) -> None:
        parts = line.strip().lower().split(None, 1)
        mnem = parts[0]
        ops = [p.strip() for p in parts[1].split(",")] if len(parts) > 1 else []

        def mem_ea(text: str) -> int | None:
            operand = _parse_mem(text)
            if operand is None:
                return None
            ea = vm.get(operand.base) + operand.disp
            if operand.index:
                ea += vm.get(operand.index) * operand.scale
            return ea & 0xFFFFFFFFFFFFFFFF

        if mnem == "mov":
            dst, src = ops
            ea = mem_ea(src)
            if ea is not None:
                size = 8 if dst in REG64 else 1
                record.accesses.append(Access(index, ea, size, RW_READ))
                vm.set(dst, vm.read(ea, size))
                return
            ea = mem_ea(dst)
            if ea is not None:
                size = 8 if src in REG64 else 1
                record.accesses.append(Access(index, ea, size, RW_WRITE))
                vm.write(ea, size, vm.get(src))
                vm.writes.append(("mem", ea, size, vm.step))
                return
            value = int(src, 0) if _is_imm(src) else vm.get(src)
            vm.set(dst, value)
            vm.writes.append(("reg", _lane_of(dst), _width_of(dst), vm.step))
            return

        if mnem in ALU_OPCODES:
            dst, src = ops
            dst_ea = mem_ea(dst)
            if dst_ea is not None:
                # Read-modify-write on memory: one operand, both directions.
                # The single access record carries RW_READ|RW_WRITE, and the
                # replay's read-before-write ordering makes the dependence on
                # the previous value fall out with no special case.
                right = int(src, 0) if _is_imm(src) else vm.get(src)
                record.accesses.append(Access(index, dst_ea, 8, RW_READ | RW_WRITE))
                result = _alu(mnem, vm.read(dst_ea, 8), right, vm)
                if mnem != "cmp":
                    vm.write(dst_ea, 8, result)
                    vm.writes.append(("mem", dst_ea, 8, vm.step))
                return
            ea = mem_ea(src)
            if ea is not None:
                record.accesses.append(Access(index, ea, 8, RW_READ))
                right = vm.read(ea, 8)
            else:
                right = int(src, 0) if _is_imm(src) else vm.get(src)
            left = vm.get(dst)
            result = _alu(mnem, left, right, vm)
            if mnem != "cmp":
                vm.set(dst, result)
                vm.writes.append(("reg", _lane_of(dst), _width_of(dst), vm.step))
            return

        if mnem in ("inc", "dec"):
            reg = ops[0]
            value = vm.get(reg) + (1 if mnem == "inc" else -1)
            vm.set(reg, value)
            vm.flags["zf"] = 1 if (value & 0xFFFFFFFFFFFFFFFF) == 0 else 0
            vm.writes.append(("reg", _lane_of(reg), _width_of(reg), vm.step))
            return

        if mnem == "test":
            left, right = vm.get(ops[0]), vm.get(ops[1])
            vm.flags["zf"] = 1 if (left & right) == 0 else 0
            return

        if mnem == "lea":
            dst, src = ops
            operand = _parse_mem(src)
            value = vm.get(operand.base) + operand.disp
            if operand.index:
                value += vm.get(operand.index) * operand.scale
            vm.set(dst, value)
            vm.writes.append(("reg", _lane_of(dst), _width_of(dst), vm.step))
            return

        if mnem in ("shl", "shr"):
            dst = ops[0]
            count = vm.get("cl") & 0x3F
            record.shift_counts.append(count)
            if count:
                value = vm.get(dst)
                value = value << count if mnem == "shl" else value >> count
                vm.set(dst, value)
                vm.writes.append(("reg", _lane_of(dst), _width_of(dst), vm.step))
            return

        if mnem == "push":
            vm.regs["rsp"] -= 8
            ea = vm.regs["rsp"]
            record.accesses.append(Access(index, ea, 8, RW_WRITE))
            vm.write(ea, 8, vm.get(ops[0]))
            vm.writes.append(("mem", ea, 8, vm.step))
            return

        if mnem == "pop":
            ea = vm.regs["rsp"]
            record.accesses.append(Access(index, ea, 8, RW_READ))
            vm.set(ops[0], vm.read(ea, 8))
            vm.regs["rsp"] += 8
            vm.writes.append(("reg", _lane_of(ops[0]), _width_of(ops[0]), vm.step))
            return

        if mnem == "ret":
            ea = vm.regs["rsp"]
            record.accesses.append(Access(index, ea, 8, RW_READ))
            vm.regs["rsp"] += 8
            return

        if mnem == "rep_movsb":
            count = vm.regs["rcx"]
            record.reps.append((count, vm.regs["rsi"], vm.regs["rdi"], vm.flags["df"]))
            for i in range(count):
                vm.mem[vm.regs["rdi"] + i] = vm.mem.get(vm.regs["rsi"] + i, 0)
            if count:
                vm.writes.append(("mem", vm.regs["rdi"], count, vm.step))
            vm.regs["rsi"] += count
            vm.regs["rdi"] += count
            vm.regs["rcx"] = 0
            return

        if mnem == "rep_stosb":
            count = vm.regs["rcx"]
            record.reps.append((count, vm.regs["rsi"], vm.regs["rdi"], vm.flags["df"]))
            value = vm.get("al")
            for i in range(count):
                vm.mem[vm.regs["rdi"] + i] = value
            if count:
                vm.writes.append(("mem", vm.regs["rdi"], count, vm.step))
            vm.regs["rdi"] += count
            vm.regs["rcx"] = 0
            return

        if mnem in ("nop", "jmp", "jz", "je", "jnz", "jne", "cqo", "call"):
            if mnem == "call":
                vm.regs["rsp"] -= 8
                ea = vm.regs["rsp"]
                record.accesses.append(Access(index, ea, 8, RW_WRITE))
                vm.write(ea, 8, 0)
                vm.writes.append(("mem", ea, 8, vm.step))
            return

        raise AssemblyError(f"MiniVM cannot execute {line!r}")


def _alu(mnem: str, left: int, right: int, vm: MiniVM) -> int:
    mask = 0xFFFFFFFFFFFFFFFF
    if mnem == "add":
        result = left + right
    elif mnem == "sub" or mnem == "cmp":
        result = left - right
    elif mnem == "xor":
        result = left ^ right
    elif mnem == "and":
        result = left & right
    elif mnem == "or":
        result = left | right
    else:
        raise AssemblyError(f"MiniVM cannot execute {mnem}")
    vm.flags["zf"] = 1 if (result & mask) == 0 else 0
    vm.flags["sf"] = 1 if (result >> 63) & 1 else 0
    vm.flags["cf"] = 1 if result < 0 or result > mask else 0
    return result & mask


def _lane_of(reg: str) -> int:
    from .arch import lanes as L

    return L.lookup(reg).lane


def _width_of(reg: str) -> int:
    from .arch import lanes as L

    slot = L.lookup(reg)
    # A 32-bit write zero-extends, so it defines the whole parent register.
    return slot.parent_size if slot.size == 4 else slot.size


# --------------------------------------------------------------------------
# Bundle emission
# --------------------------------------------------------------------------


def build_bundle(
    path,
    program: Program,
    order: list[str],
    vm: MiniVM | None = None,
    marks: dict[int, int] | None = None,
    summaries: list[tuple[int, int, list[int]]] | None = None,
    code_version: int = 0,
) -> tuple[TraceBundle, MiniVM]:
    """Assemble, run, and write a bundle the host cannot distinguish from a
    real capture.

    ``marks`` maps a position in ``order`` to a mark id; ``summaries`` is a list
    of ``(position, summary_id, args)`` injected before that block runs.
    """
    writer = BundleWriter(
        path,
        meta={
            "capture": {"agent": "testkit.MiniVM", "expand_rep": False},
            "modules": [
                {
                    "name": program.module,
                    "base": program.base_address,
                    "size": max(0x1000, program._next_address - program.base_address),
                    "path": f"C:\\\\fixtures\\\\{program.module}",
                }
            ],
        },
    )

    program.link()
    for blk in program.blocks:
        blk.block_id = writer.add_block(code_version, blk.address, blk.raw)

    vm, executed = program.run(order, vm)

    marks = marks or {}
    pending_summaries = summaries or []
    by_position: dict[int, list[tuple[int, list[int]]]] = {}
    for position, summary_id, args in pending_summaries:
        by_position.setdefault(position, []).append((summary_id, args))

    for position, record in enumerate(executed):
        if position in marks:
            writer.emit(TAG_MARK, marks[position])
        for summary_id, args in by_position.get(position, ()):
            writer._trace.u8(TAG_SUMMARY)
            writer._trace.uvarint(summary_id)
            writer._trace.uvarint(len(args))
            for arg in args:
                writer._trace.uvarint(arg)
        writer.emit_block(record.block_id)
        rep_iter = iter(record.reps)
        shift_iter = iter(record.shift_counts)
        blk = program.blocks[[b.block_id for b in program.blocks].index(record.block_id)]
        for index, line in enumerate(blk.source):
            mnem = line.strip().lower().split(None, 1)[0]
            if mnem in ("shl", "shr"):
                count = next(shift_iter, None)
                if count is not None:
                    writer.emit(TAG_SHIFTCNT, count)
            if mnem.startswith("rep_"):
                rep = next(rep_iter, None)
                if rep is not None:
                    writer.emit(TAG_REP, *rep)
            for access in record.accesses:
                if access.insn_index == index:
                    writer.emit_mem(index, access.ea, access.size, access.rw)

    writer.close()
    return TraceBundle(writer.path), vm

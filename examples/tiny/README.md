# tiny — minimal capture targets

Two x86-64 console programs with no input and no output, built to take the
target out of the equation when `python -m atropos.capture` misbehaves.  Both
compute the same thing and differ only in how much runtime surrounds it.

Rebuild both with one command:

    examples\tiny\build.bat

## The payload

`tiny_common.h` holds a 16-byte `volatile` static buffer (`buf[i] = i`), a
`volatile` key of `0x5A`, and a loop that XORs each byte with the key, stores
it back, and accumulates the sum.  Because everything is `volatile` and the
build is `/Od`, the loop cannot be folded away.

For `i < 16`, `i ^ 0x5A == 0x50 + (i ^ 0x0A)`, so the sum is
`16 * 0x50 + (0 + 1 + ... + 15)` = `1280 + 120` = **1400** (`0x578`).  Both
programs exit `0` when the sum matches and `1` when it does not.

## The two binaries

| | `tiny_nocrt.exe` | `tiny_crt.exe` |
|---|---|---|
| C runtime | none (`/ENTRY:start /NODEFAULTLIB`, kernel32 only) | default dynamic (`/MD`) |
| size | 3 072 bytes | 9 728 bytes |
| entry point RVA | `0x1090` (`start` itself) | `0x1324` (`mainCRTStartup`) |
| imports | `KERNEL32.dll` only | `KERNEL32.dll`, `VCRUNTIME140.dll`, and six `api-ms-win-crt-*` |
| exits with | `ExitProcess(0)` | `return 0` through CRT shutdown |

`tiny_nocrt.exe` is the purer test: its whole `.text` runs from `0x1000` to
`0x10C8`, about sixty instructions, with no CRT startup, no TLS callbacks and
no static initialisers between the entry point and `ExitProcess`.

## Slice criteria

The RVAs are identical in both binaries — same translation unit, same layout,
with `tiny_compute` at `0x1000` and `start`/`main` at `0x1090`.  Image base is
`0x140000000` in both.

| instruction | RVA | disassembly |
|---|---|---|
| the XOR in the loop | `0x1044` | `33 C1  xor eax,ecx` |
| the compare against `0x578` | `0x109D` | `81 7C 24 24 78 05 00 00  cmp dword ptr [rsp+24h],578h` |
| the conditional jump | `0x10A5` | `75 0A  jne` |

Used as `--at` points (occurrence is 0-based; the XOR executes sixteen times):

    --at addr=tiny_nocrt.exe+0x1044@0     # first iteration
    --at addr=tiny_nocrt.exe+0x1044@15    # last iteration
    --at addr=tiny_nocrt.exe+0x109D       # the compare
    --at addr=tiny_nocrt.exe+0x10A5       # the branch

Module-relative form matters: the images are ASLR-enabled, so an absolute
address from one run will not resolve in the next.

## Verified

Both were run natively and exited immediately:

    .\tiny_nocrt.exe ; $LASTEXITCODE   ->  0
    .\tiny_crt.exe   ; $LASTEXITCODE   ->  0

Built with MSVC 14.44.35207 (Visual Studio 2022 Community), x64.

## What a correct capture looks like

    python -m atropos.capture --spawn examples	iny	iny_nocrt.exe --out nocrt.atrace --duration 20
    atropos slice nocrt.atrace --at addr=tiny_nocrt.exe+0x10A5 --loc zf

Both targets must capture the same way every time. A capture that differs from the table below points
at the capture pipeline, not at the target:

| | `tiny_nocrt.exe` | `tiny_crt.exe` |
|---|---|---|
| host exit | `0`, "target exiting; trace flushed" | same |
| instructions / blocks | 388 / 39 | 650 / 117 |
| first `BLOCK` | `tiny_nocrt.exe+0x1090` (`start`) | `tiny_crt.exe+0x1324` (`mainCRTStartup`) |
| code outside the image | none | none |
| `SUMMARY` records | 0 | 19, all from the CRT's own ucrtbase calls |
| `atropos verify` | OK | OK |
| slice of `zf` at `+0x10A5` | 180 instances | 180 instances |

The branch slice is the same 180 instances in both binaries, because the CRT contributes nothing to
the sum. Its inputs are the `sum = 0` constant, the 16 bytes of `tiny_buf` (`image+0x3000..+0x300f`)
and the key (`image+0x3010`, read once per iteration): 32 initial-image reads. The last-iteration XOR
(`--at addr=tiny_nocrt.exe+0x1044@15 --loc eax`) is 5 instances with two inputs, `buf[15]` and the key.

Verified 2026-09-23 with Frida 17.17.0 on Python 3.14: 60 of 60 captures clean on V8 and 20 of 20 on
QuickJS. Bundles captured before the fixes in `docs/reference.md` §16.3, including any `ok_*.atrace`
kept here, do not match this table. Re-capture them.

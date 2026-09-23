/*
 * tiny_nocrt.exe -- no C runtime at all.
 *
 * Built with /ENTRY:start /NODEFAULTLIB against kernel32 only, so the image
 * holds nothing but tiny_compute, start, and the ExitProcess thunk.  There is
 * no CRT startup, no TLS callbacks, no static initialisers: the process
 * begins at `start` and ends at ExitProcess a few dozen instructions later.
 *
 * ExitProcess is declared by hand rather than via windows.h to keep the
 * translation unit free of anything the CRT would otherwise drag in.
 */

#include "tiny_common.h"

__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);

void __stdcall start(void)
{
    unsigned int sum = tiny_compute();

    ExitProcess(sum == TINY_EXPECTED ? 0u : 1u);   /* the CMP and its Jcc */
}

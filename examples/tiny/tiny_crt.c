/*
 * tiny_crt.exe -- the same payload behind a normal main() and the default
 * dynamic CRT (/MD).  Identical arithmetic to tiny_nocrt.exe; the only
 * difference is the CRT startup and shutdown wrapped around it, which is
 * exactly the variable under test.  Still no I/O.
 */

#include "tiny_common.h"

int main(void)
{
    unsigned int sum = tiny_compute();

    return (sum == TINY_EXPECTED) ? 0 : 1;   /* the CMP and its Jcc */
}

/*
 * Shared payload for the two tiny capture targets.
 *
 * Everything the loop touches is a `volatile` static global, so /Od plus
 * volatile means the compiler may neither fold the loop nor keep the buffer
 * in registers: every iteration really does load, XOR and store.
 *
 * buf[i] starts as i, so buf[i] ^ 0x5A == 0x50 + (i ^ 0x0A) for i < 16, and
 * the sum over i = 0..15 is 16 * 0x50 + (0 + 1 + ... + 15) = 1280 + 120 = 1400.
 */

#define TINY_BUFLEN      16
#define TINY_KEY         0x5A
#define TINY_EXPECTED    1400u   /* 0x578 -- the constant in the compare */

static volatile unsigned char tiny_buf[TINY_BUFLEN] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};
static volatile unsigned char tiny_key = TINY_KEY;
static volatile unsigned int  tiny_sum = 0;

static unsigned int tiny_compute(void)
{
    unsigned int sum = 0;
    int i;

    for (i = 0; i < TINY_BUFLEN; ++i) {
        unsigned char v = (unsigned char)(tiny_buf[i] ^ tiny_key);  /* the XOR */
        tiny_buf[i] = v;
        sum += v;
    }

    tiny_sum = sum;
    return sum;
}

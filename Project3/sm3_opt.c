// sm3_opt.c
#include "sm3.h"
#include <string.h>

#define ROTL32(x,n) ((uint32_t)(((x) << (n)) | ((x) >> (32 - (n)))))
#define P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x),17))
#define P1(x) ((x) ^ ROTL32((x),15) ^ ROTL32((x),23))

// Tj <<< j 预计算表
static const uint32_t TJ[64] = {
    0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
    0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
    0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce,
    0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1f, 0xec53d43e,
    0xd8a7a87d, 0xb14f50fb, 0x629ea1f7, 0xc53d43ee,
    0x8a7a87dd, 0x14f50fbb, 0x29ea1f77, 0x53d43eee,
    0xa7a87ddd, 0x4f50fbbb, 0x9ea1f777, 0x3d43eeee,
    0x7a87dddd, 0xf50fbbbb, 0xea1f7777, 0xd43eeee,
    0xa87ddddd, 0x50fbbbbb, 0xa1f77777, 0x43eeeeee,
    0x87dddddd, 0x0fbbbbbb, 0x1f777777, 0x3eeeeeee,
    0x7ddddddd, 0xfbbbbbbb, 0xf7777777, 0xeeeeeeee,
    0xdddddddd, 0xbbbbbbbb, 0x77777777, 0xeeeeeeee,
    0xdddddddd, 0xbbbbbbbb, 0x77777777, 0xeeeeeeee,
    0xdddddddd, 0xbbbbbbbb, 0x77777777, 0xeeeeeeee
};

#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x,y,z) ((x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ((~x) & (z)))

// on-the-fly 消息扩展压缩函数
static void sm3_compress(uint32_t st[8], const uint8_t block[64]) {
    uint32_t W[16];
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[4*i] << 24) | ((uint32_t)block[4*i+1] << 16) |
               ((uint32_t)block[4*i+2] << 8)  | ((uint32_t)block[4*i+3]);
    }

    uint32_t A = st[0], B = st[1], C = st[2], D = st[3];
    uint32_t E = st[4], F = st[5], G = st[6], H = st[7];

    #define ROUND(j, FF, GG) do { \
        uint32_t Wj, Wj4, Wp; \
        if (j >= 16) { \
            uint32_t tmp = W[(j-16)&0x0f] ^ W[(j-9)&0x0f] ^ ROTL32(W[(j-3)&0x0f], 15); \
            Wj = P1(tmp) ^ ROTL32(W[(j-13)&0x0f], 7) ^ W[(j-6)&0x0f]; \
            W[(j)&0x0f] = Wj; \
        } else { \
            Wj = W[j]; \
        } \
        Wj4 = W[(j+4)&0x0f]; \
        Wp = Wj ^ Wj4; \
        uint32_t SS1 = ROTL32((ROTL32(A,12) + E + TJ[j]), 7); \
        uint32_t SS2 = SS1 ^ ROTL32(A, 12); \
        uint32_t TT1 = FF(A,B,C) + D + SS2 + Wp; \
        uint32_t TT2 = GG(E,F,G) + H + SS1 + Wj; \
        D = C; \
        C = ROTL32(B, 9); \
        B = A; \
        A = TT1; \
        H = G; \
        G = ROTL32(F, 19); \
        F = E; \
        E = P0(TT2); \
    } while(0)

    for (int j = 0; j < 16; j += 4) {
        ROUND(j+0, FF0, GG0);
        ROUND(j+1, FF0, GG0);
        ROUND(j+2, FF0, GG0);
        ROUND(j+3, FF0, GG0);
    }
    for (int j = 16; j < 64; j += 4) {
        ROUND(j+0, FF1, GG1);
        ROUND(j+1, FF1, GG1);
        ROUND(j+2, FF1, GG1);
        ROUND(j+3, FF1, GG1);
    }

    st[0] ^= A; st[1] ^= B; st[2] ^= C; st[3] ^= D;
    st[4] ^= E; st[5] ^= F; st[6] ^= G; st[7] ^= H;
}

void sm3_init(sm3_ctx *ctx) {
    static const uint32_t IV[8] = {
        0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
        0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
    };
    memcpy(ctx->state, IV, sizeof(IV));
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

void sm3_update(sm3_ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    ctx->bitlen += (uint64_t)len * 8;
    if (ctx->buffer_len) {
        size_t need = 64 - ctx->buffer_len;
        if (need > len) need = len;
        memcpy(ctx->buffer + ctx->buffer_len, p, need);
        ctx->buffer_len += need;
        p += need; len -= need;
        if (ctx->buffer_len == 64) {
            sm3_compress(ctx->state, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
    while (len >= 64) {
        sm3_compress(ctx->state, p);
        p += 64; len -= 64;
    }
    if (len) {
        memcpy(ctx->buffer, p, len);
        ctx->buffer_len = len;
    }
}

void sm3_final(sm3_ctx *ctx, uint8_t out[32]) {
    uint8_t pad[64] = {0x80};
    size_t nzero = (ctx->buffer_len <= 55) ? (55 - ctx->buffer_len) : (119 - ctx->buffer_len);
    uint64_t be_bits = ctx->bitlen;

    sm3_update(ctx, pad, 1);
    if (nzero) {
        uint8_t z[64] = {0};
        sm3_update(ctx, z, nzero);
    }
    uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++) lenbuf[7-i] = (uint8_t)((be_bits >> (8*i)) & 0xFF);
    sm3_update(ctx, lenbuf, 8);

    for (int i = 0; i < 8; i++) {
        out[4*i  ] = (uint8_t)(ctx->state[i] >> 24);
        out[4*i+1] = (uint8_t)(ctx->state[i] >> 16);
        out[4*i+2] = (uint8_t)(ctx->state[i] >> 8);
        out[4*i+3] = (uint8_t)(ctx->state[i]);
    }
}

void sm3_hash(const void *data, size_t len, uint8_t out[32]) {
    sm3_ctx c;
    sm3_init(&c);
    sm3_update(&c, data, len);
    sm3_final(&c, out);
}

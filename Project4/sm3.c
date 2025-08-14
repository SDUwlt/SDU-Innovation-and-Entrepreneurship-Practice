// sm3.c
#include "sm3.h"
#include <string.h>

#define ROTL32(x,n) ((uint32_t)(((x) << (n)) | ((x) >> (32 - (n)))))
#define P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x),17))
#define P1(x) ((x) ^ ROTL32((x),15) ^ ROTL32((x),23))

static const uint32_t T[64] = {
  // j=0..15: 0x79cc4519, j=16..63: 0x7a879d8a
  0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
  0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a
};

static inline uint32_t FF(uint32_t x,uint32_t y,uint32_t z,int j){
    return (j<=15)?(x^y^z):((x&y)|(x&z)|(y&z));
}
static inline uint32_t GG(uint32_t x,uint32_t y,uint32_t z,int j){
    return (j<=15)?(x^y^z):((x&y)|((~x)&z));
}

static void sm3_compress(uint32_t st[8], const uint8_t block[64]){
    uint32_t W[68], Wp[64];
    // 大端读取
    for(int i=0;i<16;i++){
        W[i] = ((uint32_t)block[4*i]<<24)|((uint32_t)block[4*i+1]<<16)|
               ((uint32_t)block[4*i+2]<<8)|((uint32_t)block[4*i+3]);
    }
    for(int j=16;j<68;j++){
        uint32_t x = W[j-16] ^ W[j-9] ^ ROTL32(W[j-3],15);
        W[j] = P1(x) ^ ROTL32(W[j-13],7) ^ W[j-6];
    }
    for(int j=0;j<64;j++) Wp[j] = W[j] ^ W[j+4];

    uint32_t A=st[0],B=st[1],C=st[2],D=st[3],E=st[4],F=st[5],G=st[6],H=st[7];
    for(int j=0;j<64;j++){
        uint32_t Tj = ROTL32(T[j], j);
        uint32_t SS1 = ROTL32((ROTL32(A,12) + E + Tj),7);
        uint32_t SS2 = SS1 ^ ROTL32(A,12);
        uint32_t TT1 = (FF(A,B,C,j) + D + SS2 + Wp[j]);
        uint32_t TT2 = (GG(E,F,G,j) + H + SS1 + W[j]);
        D = C;
        C = ROTL32(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F,19);
        F = E;
        E = P0(TT2);
    }
    st[0]^=A; st[1]^=B; st[2]^=C; st[3]^=D;
    st[4]^=E; st[5]^=F; st[6]^=G; st[7]^=H;
}

void sm3_init(sm3_ctx *ctx){
    static const uint32_t IV[8]={
        0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
        0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
    };
    memcpy(ctx->state, IV, sizeof(IV));
    ctx->bitlen=0; ctx->buffer_len=0;
}

void sm3_update(sm3_ctx *ctx, const void *data, size_t len){
    const uint8_t *p=(const uint8_t*)data;
    ctx->bitlen += (uint64_t)len*8;
    if(ctx->buffer_len){
        size_t need=64-ctx->buffer_len;
        if(need>len) need=len;
        memcpy(ctx->buffer+ctx->buffer_len, p, need);
        ctx->buffer_len += need; p+=need; len-=need;
        if(ctx->buffer_len==64){ sm3_compress(ctx->state, ctx->buffer); ctx->buffer_len=0; }
    }
    while(len>=64){
        sm3_compress(ctx->state, p); p+=64; len-=64;
    }
    if(len){ memcpy(ctx->buffer, p, len); ctx->buffer_len=len; }
}

void sm3_final(sm3_ctx *ctx, uint8_t out[32]){
    uint8_t pad[64]={0x80}; // 1 后跟 0
    size_t nzero = (ctx->buffer_len<=55)? (55-ctx->buffer_len) : (119-ctx->buffer_len);
    uint64_t be_bits = ((uint64_t)(ctx->bitlen) & 0xFFFFFFFFFFFFFFFFULL);

    sm3_update(ctx, pad, 1);
    if(nzero) { uint8_t z[64]={0}; sm3_update(ctx, z, nzero); }
    uint8_t lenbuf[8];
    for(int i=0;i<8;i++) lenbuf[7-i] = (uint8_t)((be_bits>>(8*i))&0xFF);
    sm3_update(ctx, lenbuf, 8);

    for(int i=0;i<8;i++){
        out[4*i  ]=(uint8_t)(ctx->state[i]>>24);
        out[4*i+1]=(uint8_t)(ctx->state[i]>>16);
        out[4*i+2]=(uint8_t)(ctx->state[i]>>8);
        out[4*i+3]=(uint8_t)(ctx->state[i]);
    }
}

void sm3_hash(const void *data, size_t len, uint8_t out[32]){
    sm3_ctx c; sm3_init(&c); sm3_update(&c,data,len); sm3_final(&c,out);
}

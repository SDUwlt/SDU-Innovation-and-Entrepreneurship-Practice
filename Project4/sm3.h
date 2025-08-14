// sm3.h
#ifndef SM3_H
#define SM3_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;     // 已处理的比特数
    uint8_t  buffer[64]; // 分组缓冲
    size_t   buffer_len;
} sm3_ctx;

void sm3_init(sm3_ctx *ctx);
void sm3_update(sm3_ctx *ctx, const void *data, size_t len);
void sm3_final(sm3_ctx *ctx, uint8_t out[32]);


void sm3_hash(const void *data, size_t len, uint8_t out[32]);

#endif

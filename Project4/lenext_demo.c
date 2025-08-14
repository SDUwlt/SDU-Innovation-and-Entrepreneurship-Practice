// lenext_demo.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "sm3.h"

/*
  目标：验证 SM3 的 length-extension 攻击
  场景：
    服务端的不安全 MAC: MAC(m) = SM3(secret || m)
    攻击者已知：m 和 MAC(m)
    目标：在猜测 secret 长度的情况下，构造 m' = m || glue_pad(secret||m) || suffix
         并计算 tag'，使服务端验证通过：SM3(secret || m') == tag'

  关键点：
    - SM3 与 SHA-256 同属 Merkle–Damgård 结构，存在长度扩展特性
    - 我们可以把已知的 digest 当作“新的初始向量”，将 bitlen 设置为
      原始消息(含 secret) + padding 之后的总比特数，然后继续喂入 suffix
    - 由于 sm3_ctx 的结构对外可见，我们无需改 sm3.c，就能“从 digest 继续哈希”
*/

#define HASHLEN 32

static void print_hex(const uint8_t *p, size_t n){
    for(size_t i=0;i<n;i++) printf("%02x", p[i]);
    printf("\n");
}

/* 将 32 字节摘要转为 8 个 32-bit 大端字，写入 state */
static void digest_to_state_be(const uint8_t digest[HASHLEN], uint32_t state_out[8]){
    for(int i=0;i<8;i++){
        state_out[i] =
            ((uint32_t)digest[4*i  ] << 24) |
            ((uint32_t)digest[4*i+1] << 16) |
            ((uint32_t)digest[4*i+2] <<  8) |
            ((uint32_t)digest[4*i+3]);
    }
}

/* 计算 Merkle–Damgård padding（SM3 与 SHA-256 一样，最后 8 字节为消息比特长度的大端编码）
   输入：原始字节长度 msg_len（注意：这里是 secret||m 的总长度）
   输出：返回 malloc 的缓冲区，内容为 0x80 + 0x00... + 8 字节长度；返回长度写入 *pad_len
*/
static uint8_t* md_pad(uint64_t msg_len, size_t *pad_len){
    uint64_t bit_len = msg_len * 8ULL;

    // 先加一个 0x80，再补零到 (len + 1 + padzero + 8) % 64 == 0
    size_t rem = (size_t)((msg_len + 1) % 64);
    size_t zeros;
    if(rem <= 56) zeros = 56 - rem;
    else          zeros = 56 + (64 - rem);

    *pad_len = 1 + zeros + 8;
    uint8_t *pad = (uint8_t*)malloc(*pad_len);
    pad[0] = 0x80;
    memset(pad+1, 0x00, zeros);
    // 写入 64-bit 大端 bit_len
    for(int i=0;i<8;i++){
        pad[1+zeros+7 - i] = (uint8_t)((bit_len >> (8*i)) & 0xFF);
    }
    return pad;
}

/* 不安全服务器：MAC = SM3(secret || msg) */
typedef struct {
    uint8_t *secret;
    size_t   secret_len;
} server_t;

static void server_init(server_t *svr, size_t sec_len){
    svr->secret = (uint8_t*)malloc(sec_len);
    svr->secret_len = sec_len;
    for(size_t i=0;i<sec_len;i++) svr->secret[i] = (uint8_t)(rand() & 0xFF);
}

static void server_free(server_t *svr){
    if(svr->secret){ free(svr->secret); svr->secret = NULL; }
    svr->secret_len = 0;
}

static void server_mac(const server_t *svr, const uint8_t *msg, size_t msg_len, uint8_t out[HASHLEN]){
    sm3_ctx c;
    sm3_init(&c);
    sm3_update(&c, svr->secret, svr->secret_len);
    sm3_update(&c, msg, msg_len);
    sm3_final(&c, out);
}

/* 服务器验证：检查 SM3(secret || forged) == tag */
static int server_verify(const server_t *svr, const uint8_t *forged, size_t forged_len, const uint8_t tag[HASHLEN]){
    uint8_t calc[HASHLEN];
    server_mac(svr, forged, forged_len, calc);
    return memcmp(calc, tag, HASHLEN) == 0;
}

/* 攻击者侧：给定
     - 已知消息 m、其长度 m_len
     - 已知标签 tag = SM3(secret || m)
     - 追加数据 suffix / suffix_len
     - 猜测的 secret_len_guess
   过程：
     1) 计算 glue = md_pad(secret_len_guess + m_len)
     2) 令 ctx.state = tag（转为 8×32 位大端），
        ctx.bitlen = (secret_len_guess + m_len + glue_len) * 8
        ctx.buffer_len = 0
     3) 再 update(suffix)，final 得到新的 tag'
   输出：
     - forged_msg = m || glue || suffix
     - forged_tag
*/
typedef struct {
    uint8_t *forged_msg;
    size_t forged_len;
    uint8_t forged_tag[HASHLEN];
    size_t secret_len_guess;
    size_t glue_len;
} attack_result_t;

static attack_result_t do_lenext_attack(const uint8_t known_tag[HASHLEN],
                                        const uint8_t *m, size_t m_len,
                                        const uint8_t *suffix, size_t suffix_len,
                                        size_t secret_len_guess)
{
    attack_result_t res;
    memset(&res, 0, sizeof(res));

    // 1) 计算 glue padding 针对 (secret||m) 的总长度
    size_t glue_len = 0;
    uint8_t *glue = md_pad((uint64_t)secret_len_guess + m_len, &glue_len);

    // 2) 构造“从已知 digest 继续”的 SM3 状态
    uint32_t state[8];
    digest_to_state_be(known_tag, state);

    sm3_ctx c;
    // 直接写 ctx（结构对外可见，无需改 sm3.c）
    memcpy(c.state, state, sizeof(state));
    c.bitlen = ((uint64_t)secret_len_guess + m_len + glue_len) * 8ULL; // 已处理的总比特数
    c.buffer_len = 0;

    // 3) 继续喂入 suffix，得到新标签
    sm3_update(&c, suffix, suffix_len);
    sm3_final(&c, res.forged_tag);

    // 4) 伪造出的消息：m || glue || suffix
    res.forged_len = m_len + glue_len + suffix_len;
    res.forged_msg = (uint8_t*)malloc(res.forged_len);
    memcpy(res.forged_msg, m, m_len);
    memcpy(res.forged_msg + m_len, glue, glue_len);
    memcpy(res.forged_msg + m_len + glue_len, suffix, suffix_len);

    res.secret_len_guess = secret_len_guess;
    res.glue_len = glue_len;

    free(glue);
    return res;
}

static void free_attack_result(attack_result_t *r){
    if(r->forged_msg){ free(r->forged_msg); r->forged_msg = NULL; }
    r->forged_len = 0;
}

/* 演示主程序 */
int main(void){
    srand((unsigned)time(NULL));

    // 1) 初始化一个“服务器”，随机 secret 长度（攻击者未知）
    server_t svr;
    size_t real_secret_len = 8 + (rand() % 25); // 8..32 字节
    server_init(&svr, real_secret_len);

    // 2) 攻击者已知的消息与其 MAC
    const char *msg = "comment=10&uid=1001&role=user"; // 示例明文
    size_t msg_len = strlen(msg);

    uint8_t tag[HASHLEN];
    server_mac(&svr, (const uint8_t*)msg, msg_len, tag);

    printf("Known message m: \"%s\"\n", msg);
    printf("Known tag MAC(m)=SM3(secret||m): ");
    print_hex(tag, HASHLEN);

    // 3) 攻击者希望追加的后缀（例如把用户角色升级）
    const char *suffix = "&role=admin";
    size_t suffix_len = strlen(suffix);
    printf("Attacker wants to append suffix: \"%s\"\n", suffix);

    // 4) 攻击：在一个合理的 secret 长度范围内猜（1..64），直到服务器验证通过
    int success = 0;
    attack_result_t win = {0};

    for(size_t guess = 1; guess <= 64; ++guess){
        attack_result_t attempt =
            do_lenext_attack(tag, (const uint8_t*)msg, msg_len,
                             (const uint8_t*)suffix, suffix_len, guess);

        if(server_verify(&svr, attempt.forged_msg, attempt.forged_len, attempt.forged_tag)){
            printf("\n[+] Length-extension SUCCESS with secret_len_guess=%zu\n", guess);
            printf("Forged tag: ");
            print_hex(attempt.forged_tag, HASHLEN);

            printf("Forged message (hex preview, first 128 bytes at most):\n");
            size_t preview = attempt.forged_len < 128 ? attempt.forged_len : 128;
            for(size_t i=0;i<preview;i++) printf("%02x", attempt.forged_msg[i]);
            if(preview < attempt.forged_len) printf("...");
            printf("\n");

            // 同时打印可读形式（中间包含不可见的 glue padding）
            printf("\nForged message (printable view, non-printables as '.'):\n");
            for(size_t i=0;i<attempt.forged_len;i++){
                unsigned char c = attempt.forged_msg[i];
                if(c >= 32 && c <= 126) putchar(c);
                else putchar('.');
            }
            putchar('\n');

            win = attempt; // 保存成功的那个
            success = 1;
            break;
        } else {
            free_attack_result(&attempt);
        }
    }

    if(!success){
        printf("\n[-] Attack failed in the tested secret length range.\n");
        server_free(&svr);
        return 1;
    }

    // 5) 额外确认：直接计算 SM3(secret || forged_msg) 与 forged_tag 一致
    uint8_t check[HASHLEN];
    server_mac(&svr, win.forged_msg, win.forged_len, check);
    printf("\nServer recomputed MAC(secret||forged_msg): ");
    print_hex(check, HASHLEN);
    printf("Matches forged_tag? %s\n", memcmp(check, win.forged_tag, HASHLEN)==0 ? "YES" : "NO");

    // 打印真实的 secret 长度以验证我们确实不知道它，但攻击仍成功
    printf("\n[Info] Real secret length was %zu bytes.\n", real_secret_len);

    free_attack_result(&win);
    server_free(&svr);
    return 0;
}

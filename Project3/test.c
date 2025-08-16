// main.c
#include <stdio.h>
#include <stdint.h>
#include "sm3.h"
#include <sys/time.h>
static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(void) {
    struct timeval start, end;
    double elapsed_time;

    gettimeofday(&start, NULL); 
    srand(time(NULL));

    char *msg1 = (char *)malloc(4 * sizeof(char));
    if (msg1 == NULL) {
        fprintf(stderr, "内存分配失败\n");
        return 1;
    }

    // 生成 3 个随机字母（A-Z）
    for (int i = 0; i < 3; i++) {
        msg1[i] = 'A' + (rand() % 26);  // 生成 A-Z 的随机字母
    }
    msg1[3] = '\0';  // 字符串结尾

    const char *msg = msg1;
    uint8_t out[32];

    sm3_hash(msg, 3, out);

    printf("Input: \"%s\"\n", msg);
    printf("SM3:   ");
    print_hex(out, 32);
    gettimeofday(&end, NULL); 
    elapsed_time = (end.tv_sec - start.tv_sec) + 
                   (end.tv_usec - start.tv_usec) / 1000000.0; 

    printf("执行时间: %f 秒\n", elapsed_time);
    return 0;
}

#include <stdint.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include "fpe.h"
#include "fpe_locl.h"

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>

#define HARDWARE
#define SOFTWARE
#define DEBUG
#define PIPO64_128
//#define PIPO64_256
#ifdef PIPO64_128
#define ROUND 13
#define SIZE 2
#define BIT 8
#define MASTER_KEY_SIZE 16
#elif defined PIPO64_256
#define ROUND 17
#define SIZE 2
#define INT_NUM 2
#define MASTER_KEY_SIZE 4
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
/*
unsigned char ff1_P256[256];
unsigned char ff1_R256[256];
unsigned char ff1_Ri256[256];
unsigned char *S = (unsigned char *)OPENSSL_malloc(Slen);
*/
union {
        long one;
        char little;
    } is_endian = { 1 };

// convert numeral string to number
void str2num(BIGNUM *Y, const unsigned int *X, unsigned long long radix, unsigned int len, BN_CTX *ctx){
    BN_CTX_start(ctx);
    BIGNUM *r = BN_CTX_get(ctx),
           *x = BN_CTX_get(ctx);

    BN_set_word(Y, 0);
    BN_set_word(r, radix);
    for (int i = 0; i < len; ++i) {
        // Y = Y * radix + X[i]
        BN_set_word(x, X[i]);
        BN_mul(Y, Y, r, ctx);
        BN_add(Y, Y, x);
    }

    BN_CTX_end(ctx);
    return;
}
// convert number to numeral string
void num2str(const BIGNUM *X, unsigned int *Y, unsigned int radix, int len, BN_CTX *ctx){
    BN_CTX_start(ctx);
    BIGNUM *dv = BN_CTX_get(ctx),
           *rem = BN_CTX_get(ctx),
           *r = BN_CTX_get(ctx),
           *XX = BN_CTX_get(ctx);

    BN_copy(XX, X);
    BN_set_word(r, radix);
    memset(Y, 0, len << 2);

    for (int i = len - 1; i >= 0; --i) {
        // XX / r = dv ... rem
        BN_div(dv, rem, XX, r, ctx);
        // Y[i] = XX % r
        Y[i] = BN_get_word(rem);
        // XX = XX / r
        BN_copy(XX, dv);
    }

    BN_CTX_end(ctx);
    return;
}


void GEN_ROUND_KEY(uint16_t round_key[14][8], uint16_t master_key[16]){           // 마스터키는 하나고 라운드키는 14갠데, 평문이 여러개여도 같은 라운드키로 함

    uint16_t RCON = 0x00;

    for(int round = 0 ; round < ROUND+1 ; round++){
        for(int byte = 0 ; byte < 8 ; byte++ ){
            round_key[round][byte] = master_key[((BIT*round) + byte) % (MASTER_KEY_SIZE)];
        }

        round_key[round][0] ^= RCON;
        RCON++;

    }
}

void KEYADD(__m256i T256[7], uint16_t round_key[14][8], uint8_t round){

    __m256i RK256[8];

    RK256[0] = _mm256_set1_epi16(round_key[round][0]);
    RK256[1] = _mm256_set1_epi16(round_key[round][1]);
    RK256[2] = _mm256_set1_epi16(round_key[round][2]);
    RK256[3] = _mm256_set1_epi16(round_key[round][3]);
    RK256[4] = _mm256_set1_epi16(round_key[round][4]);
    RK256[5] = _mm256_set1_epi16(round_key[round][5]);
    RK256[6] = _mm256_set1_epi16(round_key[round][6]);
    RK256[7] = _mm256_set1_epi16(round_key[round][7]);

    T256[0] = _mm256_xor_si256(T256[0], RK256[0]);
    T256[1] = _mm256_xor_si256(T256[1], RK256[1]);
    T256[2] = _mm256_xor_si256(T256[2], RK256[2]);
    T256[3] = _mm256_xor_si256(T256[3], RK256[3]);
    T256[4] = _mm256_xor_si256(T256[4], RK256[4]);
    T256[5] = _mm256_xor_si256(T256[5], RK256[5]);
    T256[6] = _mm256_xor_si256(T256[6], RK256[6]);
    T256[7] = _mm256_xor_si256(T256[7], RK256[7]);
}

void Slayer(__m256i T256[8], __m256i T[8]){

    __m256i Notmask;
    T[3] = _mm256_set1_epi16(0x00);              // 0으로 전체 초기화
    Notmask = _mm256_set1_epi16(0xFF);           // 낫연산이 없어서 앤드낫씀 그래서 1로 전체 초기화한 거를 마스크로 쓰려고 만든것

    T256[5] = _mm256_xor_si256(T256[5],_mm256_and_si256(T256[7],T256[6]));
    T256[4] = _mm256_xor_si256(T256[4],_mm256_and_si256(T256[3],T256[5]));
    T256[7] = _mm256_xor_si256(T256[7],T256[4]);
    T256[6] = _mm256_xor_si256(T256[6],T256[3]);

    T256[3] = _mm256_xor_si256(T256[3],_mm256_or_si256(T256[4],T256[5]));
    T256[5] = _mm256_xor_si256(T256[5],T256[7]);
    T256[4] = _mm256_xor_si256(T256[4],_mm256_and_si256(T256[5],T256[6]));

    T256[2] = _mm256_xor_si256(T256[2],_mm256_and_si256(T256[1],T256[0]));
    T256[0] = _mm256_xor_si256(T256[0],_mm256_or_si256(T256[2],T256[1]));
    T256[1] = _mm256_xor_si256(T256[1],_mm256_or_si256(T256[2],T256[0]));
    T256[2] = _mm256_andnot_si256(T256[2],Notmask);

    T256[7] = _mm256_xor_si256(T256[7],T256[1]);
    T256[3] = _mm256_xor_si256(T256[3],T256[2]);
    T256[4] = _mm256_xor_si256(T256[4],T256[0]);

    T[0] = T256[7];  T[1] = T256[3];    T[2] =  T256[4];
    T256[6] = _mm256_xor_si256(T256[6],_mm256_and_si256(T[0],T256[5]));
    T[0] = _mm256_xor_si256(T[0],T256[6]);
    T256[6] = _mm256_xor_si256(T256[6],_mm256_or_si256(T[2],T[1]));
    T[1] = _mm256_xor_si256(T[1],T256[5]);
    T256[5] = _mm256_xor_si256(T256[5],_mm256_or_si256(T256[6],T[2]));
    T[2] = _mm256_xor_si256(T[2],_mm256_and_si256(T[1],T[0]));

    T256[2] = _mm256_xor_si256(T256[2],T[0]);
    T[0] = _mm256_xor_si256(T256[1],T[2]);
    T256[1] = _mm256_xor_si256(T256[0],T[1]);

    T256[0] = T256[7];
    T256[7] = T[0];
    T[1] = T256[3];        T256[3] = T256[6];        T256[6] = T[1];
    T[2] = T256[4];        T256[4] = T256[5];        T256[5] = T[2];

}

void Rlayer(__m256i T256[8]){


    
    __m256i ANDmaskl, ANDmaskr, res[2];
    
    // <<7

    ANDmaskr = _mm256_set1_epi16(0x00FE);
    
    res[1] = _mm256_and_si256(T256[1], ANDmaskr);
    
    res[0] = _mm256_slli_epi16(T256[1], 7);
    res[1] = _mm256_srli_epi16(res[1], 1);
    
    T256[1] = _mm256_or_si256(res[0], res[1]);
    
    // <<4

    ANDmaskr = _mm256_set1_epi16(0x00F0);
    
    res[1] = _mm256_and_si256(T256[2], ANDmaskr);
    
    res[0] = _mm256_slli_epi16(T256[2], 4);
    res[1] = _mm256_srli_epi16(res[1], 4);
    
    T256[2] = _mm256_or_si256(res[0], res[1]);
    
    
    // <<3
    
    ANDmaskr = _mm256_set1_epi16(0x00E0);
    
    res[1] = _mm256_and_si256(T256[3], ANDmaskr);
    
    res[0] = _mm256_slli_epi16(T256[3], 3);
    res[1] = _mm256_srli_epi16(res[1], 5);
    
    T256[3] = _mm256_or_si256(res[0], res[1]);
    
    // <<6
    
    ANDmaskr = _mm256_set1_epi16(0x00FC);
    
    res[1] = _mm256_and_si256(T256[4], ANDmaskr);
    
    res[0] = _mm256_slli_epi16(T256[4], 6);
    res[1] = _mm256_srli_epi16(res[1], 2);
    
    T256[4] = _mm256_or_si256(res[0], res[1]);
    
    // <<5

    ANDmaskr = _mm256_set1_epi16(0x00F8);
   
    res[1] = _mm256_and_si256(T256[5], ANDmaskr);
    
    res[0] = _mm256_slli_epi16(T256[5], 5);
    res[1] = _mm256_srli_epi16(res[1], 3);
    
    T256[5] = _mm256_or_si256(res[0], res[1]);
    
    // <<1

    ANDmaskr = _mm256_set1_epi16(0x0080);
    
    res[1] = _mm256_and_si256(T256[6], ANDmaskr);
    
    res[0] = _mm256_slli_epi16(T256[6], 1);
    res[1] = _mm256_srli_epi16(res[1], 7);
    
    T256[6] = _mm256_or_si256(res[0], res[1]);
    
    // <<2

    ANDmaskr = _mm256_set1_epi16(0x00C0);
    

    res[1] = _mm256_and_si256(T256[7], ANDmaskr);
    
    res[0] = _mm256_slli_epi16(T256[7], 2);
    res[1] = _mm256_srli_epi16(res[1], 6);
    
    T256[7] = _mm256_or_si256(res[0], res[1]);
    
}

void PIPO_encrypt(unsigned char P_gather_16[128],unsigned char R_gather_16[128], uint8_t round_key[14][8]) {    // split 16 pt into 32 plaintext

    __m256i T256[8];
    __m256i T[8];
    uint8_t plain[16][8];

// 8개의 128비트 평문을 16개의 64비트 평문으로 변환 

    for (int i = 0 ; i < 8 ; ++i){
        for(int j = 0 ; j < 8; ++j){
            plain[2*i][j] = P_gather_16[(16*i)+j];  //
            plain[2*i+1][j] = P_gather_16[(16*i)+(j+8)];
        }
    }  // 이 부분 없애고 그냥 한 번에 TEMP로??

    uint8_t temp[8][16];

    for(int i = 0 ; i < 8; i++){
        for(int j = 0 ; j < 16 ; j++)
            temp[i][j] = plain[j][i];
    }

    T256[0] = _mm256_loadu_si256((__m256i*)&temp[0]);
    T256[1] = _mm256_loadu_si256((__m256i*)&temp[1]);
    T256[2] = _mm256_loadu_si256((__m256i*)&temp[2]);
    T256[3] =_mm256_loadu_si256((__m256i*)&temp[3]);
    T256[4] =_mm256_loadu_si256((__m256i*)&temp[4]);
    T256[5] =_mm256_loadu_si256((__m256i*)&temp[5]);
    T256[6] =_mm256_loadu_si256((__m256i*)&temp[6]);
    T256[7] =_mm256_loadu_si256((__m256i*)&temp[7]);

 //printf("\n======= ROUND 0 =======\n");
    KEYADD(T256,round_key,0);

    for(int round = 1 ; round < ROUND+1; round++){

        //printf("\n======= ROUND %d =======\n", round);

        Slayer(T256,T);
        Rlayer(T256);
        KEYADD(T256,round_key,round);

    }



//    for(int i = 7 ; i >= 0 ; i--){
//        //printf("T256[%d] (%d BYTE for each block)\n",i,i);
//        for(int j = 1 ; j < 16 ; j+=2){
//            printf("%02x ", lastT256[(i*32)+j]);
//        }
//        printf("\n");
//    }


        //  T256을 R_gather에 output 모아야함 ;

	u8* To_R_gather16 = (u8*)T256;

        for (int row = 0 ; row < 8 ; ++row){
                for (int col = 0 ; col < 8; ++col){

                    R_gather_16[(16*row) + col] = To_R_gather16[(16*col)+(2*row)];
                    R_gather_16[(16*row) + 8 + col] = To_R_gather16[(16*col)+(2*row)+1];
                }
            }

}

void FF1_encrypt_AES(const unsigned int *in, unsigned int *out, AES_KEY *aes_enc_ctx, const unsigned char *userKey,const unsigned char *tweak, const unsigned int radix, size_t inlen, size_t tweaklen){
    BIGNUM *bnum = BN_new(),
           *y = BN_new(),
           *c = BN_new(),
           *anum = BN_new(),
           *qpow_u = BN_new(),
           *qpow_v = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    union {
        long one;
        char little;
    } is_endian = { 1 };
     uint8_t round_key[14][8];
    GEN_ROUND_KEY(round_key,userKey);  //userkey is masterkey


    memcpy(out, in, inlen << 2);
    int u = floor2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, radix, u, v, ctx);

    unsigned int temp = (unsigned int)ceil(v * log2(radix));
    const int b = ceil2(temp, 3);
    const int d = 4 * ceil2(b, 2) + 4;

    int pad = ( (-tweaklen - b - 1) % 16 + 16 ) % 16;
    int Qlen = tweaklen + pad + 1 + b;
    unsigned char P[16];
    unsigned char *Q = (unsigned char *)OPENSSL_malloc(Qlen), *Bytes = (unsigned char *)OPENSSL_malloc(b);

    unsigned char ENC_Ri256[128];
    unsigned char ENC_R256[128];
    unsigned char ENC_P256[128];

    // initialize P
    P[0] = 0x1;
    P[1] = 0x2;
    P[2] = 0x1;
    P[7] = u % 256;
    if (is_endian.little) {
        temp = (radix << 8) | 10;
        P[3] = (temp >> 24) & 0xff;
        P[4] = (temp >> 16) & 0xff;
        P[5] = (temp >> 8) & 0xff;
        P[6] = temp & 0xff;
        P[8] = (inlen >> 24) & 0xff;
        P[9] = (inlen >> 16) & 0xff;
        P[10] = (inlen >> 8) & 0xff;
        P[11] = inlen & 0xff;
        P[12] = (tweaklen >> 24) & 0xff;
        P[13] = (tweaklen >> 16) & 0xff;
        P[14] = (tweaklen >> 8) & 0xff;
        P[15] = tweaklen & 0xff;
    } else {
        *( (unsigned int *)(P + 3) ) = (radix << 8) | 10;
        *( (unsigned int *)(P + 8) ) = inlen;
        *( (unsigned int *)(P + 12) ) = tweaklen;
    }

    // initialize Q
    memcpy(Q, tweak, tweaklen);
    memset(Q + tweaklen, 0x00, pad);
    assert(tweaklen + pad - 1 <= Qlen);

    unsigned char R[16];
    int cnt = ceil2(d, 4) - 1;
    int Slen = 16 + cnt * 16;
    unsigned char *S = (unsigned char *)OPENSSL_malloc(Slen);
    //unsigned char *S = (unsigned char *)OPENSSL_malloc(Slen*16);




    for (int i = 0; i < FF1_ROUNDS; ++i) {
        // v
        int m = (i & 1)? v: u;

        // i
        Q[tweaklen + pad] = i & 0xff;
        str2num(bnum, B, radix, inlen - m, ctx);
        int BytesLen = BN_bn2bin(bnum, Bytes);
        memset(Q + Qlen - b, 0x00, b);

        int qtmp = Qlen - BytesLen;
        memcpy(Q + qtmp, Bytes, BytesLen);

        // ii PRF(P || Q), P is always 16 bytes long
        AES_encrypt(P, R, aes_enc_ctx);

        int count = Qlen / 16;
        unsigned char Ri[16];
        unsigned char *Qi = Q;


        for (int block = 0; block < count; ++block) {   // 이게 뭔가 그거임... 블록 여러개
            for (int j = 0; j < 16; ++j){
                Ri[j] = Qi[j] ^ R[j];
                ENC_Ri256[16*block+j] = Ri[j];
            }
            Qi += 16;
        }

        PIPO_encrypt(ENC_Ri256, ENC_R256, round_key);  // output is ENC_R256

        // ENC_R256 to R

        // iii

        unsigned char tmp[16], SS[16];              // tmp SS 256?
        memset(S, 0x00, Slen);                      // S
        assert(Slen >= 16);
        memcpy(S, R, 16);

        // ENC_R256



        for (int j = 1; j <= cnt; ++j) {            //
            memset(tmp, 0x00, 16);

            if (is_endian.little) {
                // convert to big endian
                // full unroll
                tmp[15] = j & 0xff;
                tmp[14] = (j >> 8) & 0xff;
                tmp[13] = (j >> 16) & 0xff;
                tmp[12] = (j >> 24) & 0xff;
            } else *( (unsigned int *)tmp + 3 ) = j;

            for (int k = 0; k < 16; ++k)    tmp[k] ^= R[k];

            //AES_encrypt(tmp, SS, aes_enc_ctx);                       // SS is output
            PIPO_encrypt(tmp, SS, round_key);
            assert((S + 16 * j)[0] == 0x00);
            assert(16 + 16 * j <= Slen);
            memcpy(S + 16 * j, SS, 16);
        }

        // iv
        BN_bin2bn(S, d, y);
        // vi
        // (num(A, radix, m) + y) % qpow(radix, m);
        str2num(anum, A, radix, m, ctx);
        // anum = (anum + y) mod qpow_uv
        if (m == u)    BN_mod_add(c, anum, y, qpow_u, ctx);
        else    BN_mod_add(c, anum, y, qpow_v, ctx);

        // swap A and B
        assert(A != B);
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
        B = (unsigned int *)( (uintptr_t)B ^ (uintptr_t)A );
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
        num2str(c, B, radix, m, ctx);
    }

    // free the space
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(c);
    BN_clear_free(y);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(ctx);
    OPENSSL_free(Bytes);
    OPENSSL_free(Q);
    OPENSSL_free(S);
    return;
}

void FF1_decrypt_AES(const unsigned int *in, unsigned int *out, AES_KEY *aes_enc_ctx, const unsigned char *userKey, const unsigned char *tweak, const unsigned int radix, size_t inlen, size_t tweaklen){
    BIGNUM *bnum = BN_new(),
           *y = BN_new(),
           *c = BN_new(),
           *anum = BN_new(),
           *qpow_u = BN_new(),
           *qpow_v = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    union {
        long one;
        char little;
    } is_endian = { 1 };

    uint8_t round_key[14][8];
    GEN_ROUND_KEY(round_key,userKey);  //userkey is masterkey

    memcpy(out, in, inlen << 2);
    int u = floor2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, radix, u, v, ctx);

    unsigned int temp = (unsigned int)ceil(v * log2(radix));
    const int b = ceil2(temp, 3);
    const int d = 4 * ceil2(b, 2) + 4;

    int pad = ( (-tweaklen - b - 1) % 16 + 16 ) % 16;
    int Qlen = tweaklen + pad + 1 + b;
    unsigned char P[16];
    unsigned char *Q = (unsigned char *)OPENSSL_malloc(Qlen), *Bytes = (unsigned char *)OPENSSL_malloc(b);

    unsigned char ENC_Ri256[128];
    unsigned char ENC_R256[128];
    unsigned char ENC_P256[128];


    // initialize P
    P[0] = 0x1;
    P[1] = 0x2;
    P[2] = 0x1;
    P[7] = u % 256;
    if (is_endian.little) {
        temp = (radix << 8) | 10;
        P[3] = (temp >> 24) & 0xff;
        P[4] = (temp >> 16) & 0xff;
        P[5] = (temp >> 8) & 0xff;
        P[6] = temp & 0xff;
        P[8] = (inlen >> 24) & 0xff;
        P[9] = (inlen >> 16) & 0xff;
        P[10] = (inlen >> 8) & 0xff;
        P[11] = inlen & 0xff;
        P[12] = (tweaklen >> 24) & 0xff;
        P[13] = (tweaklen >> 16) & 0xff;
        P[14] = (tweaklen >> 8) & 0xff;
        P[15] = tweaklen & 0xff;
    } else {
        *( (unsigned int *)(P + 3) ) = (radix << 8) | 10;
        *( (unsigned int *)(P + 8) ) = inlen;
        *( (unsigned int *)(P + 12) ) = tweaklen;
    }

    // initialize Q
    memcpy(Q, tweak, tweaklen);
    memset(Q + tweaklen, 0x00, pad);
    assert(tweaklen + pad - 1 <= Qlen);

   unsigned char R[16];
    int cnt = ceil2(d, 4) - 1;
    int Slen = 16 + cnt * 16;
    //unsigned char *S = (unsigned char *)OPENSSL_malloc(Slen);
    unsigned char *S = (unsigned char *)OPENSSL_malloc(Slen);

    for (int i = FF1_ROUNDS - 1; i >= 0; --i) {
        // v
        int m = (i & 1)? v: u;

        // i
        Q[tweaklen + pad] = i & 0xff;
        str2num(anum, A, radix, inlen - m, ctx);
        memset(Q + Qlen - b, 0x00, b);
        int BytesLen = BN_bn2bin(anum, Bytes);
        int qtmp = Qlen - BytesLen;
        memcpy(Q + qtmp, Bytes, BytesLen);


       // ii PRF(P || Q), P is always 16 bytes long
        AES_encrypt(P, R, aes_enc_ctx);

        int count = Qlen / 16;
        unsigned char Ri[16];
        unsigned char *Qi = Q;

        for (int block = 0; block < count; ++block) {   // 이게 뭔가 그거임... 블록 여러개
            for (int j = 0; j < 16; ++j){
                Ri[j] = Qi[j] ^ R[j];
                ENC_Ri256[16*block+j] = Ri[j];
            }

            Qi += 16;
        }

        PIPO_encrypt(ENC_Ri256, ENC_R256, round_key);  // output is ENC_R256

        // iii
        unsigned char tmp[16], SS[16];
        memset(S, 0x00, Slen);
        memcpy(S, R, 16);
        for (int j = 1; j <= cnt; ++j) {
            memset(tmp, 0x00, 16);

            if (is_endian.little) {
                // convert to big endian
                // full unroll
                tmp[15] = j & 0xff;
                tmp[14] = (j >> 8) & 0xff;
                tmp[13] = (j >> 16) & 0xff;
                tmp[12] = (j >> 24) & 0xff;
            } else *( (unsigned int *)tmp + 3 ) = j;

            for (int k = 0; k < 16; ++k)    tmp[k] ^= R[k];
            PIPO_encrypt(tmp, SS, round_key);
            assert((S + 16 * j)[0] == 0x00);
            memcpy(S + 16 * j, SS, 16);
        }

        // iv
        BN_bin2bn(S, d, y);
        // vi
        // (num(B, radix, m) - y) % qpow(radix, m);
        str2num(bnum, B, radix, m, ctx);
        if (m == u)    BN_mod_sub(c, bnum, y, qpow_u, ctx);
        else    BN_mod_sub(c, bnum, y, qpow_v, ctx);

        // swap A and B
        assert(A != B);
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
        B = (unsigned int *)( (uintptr_t)B ^ (uintptr_t)A );
        A = (unsigned int *)( (uintptr_t)A ^ (uintptr_t)B );
        num2str(c, A, radix, m, ctx);

    }

    // free the space
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(y);
    BN_clear_free(c);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(ctx);
    OPENSSL_free(Bytes);
    OPENSSL_free(Q);
    OPENSSL_free(S);
    return;
}

int FPE_set_ff1_key(const unsigned char *userKey, const int bits, const unsigned char *tweak, const unsigned int tweaklen, const int radix, FPE_KEY *key){
    int ret;



    if (bits != 128 && bits != 192 && bits != 256) {
        ret = -1;
        return ret;
    }
    key->radix = radix;
    key->tweaklen = tweaklen;
    key->tweak = (unsigned char *)OPENSSL_malloc(tweaklen);
    memcpy(key->tweak, tweak, tweaklen);
    ret = AES_set_encrypt_key(userKey, bits, &key->aes_enc_ctx); // userkey is aes- master key?

    printf("ret : %d\n", ret);
    //ret = GEN_ROUND_KEY(round_key, userKey);

    return ret;
}

void FPE_unset_ff1_key(FPE_KEY *key){
    OPENSSL_free(key->tweak);
}

void Insert_EncData(unsigned int *in, unsigned int *out, unsigned int inlen, FPE_KEY *key, const int enc ,const unsigned char *userKey)    {          // x, y, xlen, &ff1, FPE_ENCRYPT{
    
    if (enc){

//시간 재는 코드
 struct timeval start, end;
    double mtime, seconds, useconds;

    gettimeofday(&start, NULL);

    for(int rr = 0 ; rr < 1000000; ++rr)
        FF1_encrypt_AES(in, out, &key->aes_enc_ctx, userKey, key->tweak, key->radix, inlen, key->tweaklen);       


    gettimeofday(&end, NULL);

    seconds  = end.tv_sec  - start.tv_sec;
    useconds = end.tv_usec - start.tv_usec;
    mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
    printf("time %lf \n",mtime);

  
// 시간 재는 코드
	}
    else
       FF1_decrypt_AES(in, out, &key->aes_enc_ctx,userKey, key->tweak,key->radix, inlen, key->tweaklen);

}


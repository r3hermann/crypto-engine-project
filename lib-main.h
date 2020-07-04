#ifndef  LIB_main_H
#define LIB_main_H

#include "lib-mesg.h"
#include <assert.h>
#include <gmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <strings.h>
#include <nettle/sha1.h>
#include <nettle/sha3.h>

#define sampling_time 5 /* secondi */
#define max_samplessha3 (sampling_time * 200)


#define mr_iterations 15
#define BYTEREAD sizeof(char)*4

//module input N=p*q, (p,q safe-prime)
#define default_p_bits 512
#define default_q_bits 512
#define SIZE_BUFFER (default_p_bits+default_q_bits)
#define MAXSIZE 2000

#define _EXIT(string)({fprintf(stderr,"%s %s, line %d.\n", string, __FILE__, __LINE__);exit(EXIT_FAILURE);})

/*
#define  perform_hashing_sha3(STRUCT_CTX, FNC_INIT, FNC_UPDATE, FNC_DIGEST, DGST_SIZE, STR, STRLEN, DIGESTSXXX)({ \
    struct STRUCT_CTX context;                                                                           \
    FNC_INIT(&context);                                                                                        \
    char buffer[2048]={0};                                                                                   \
    size_t block_size=strlen(STRLEN);                                                                        \
    uint8_t block_to_hash[block_size];                                                                   \
    for(size_t i=0; i<block_size;i++){                                                          \
                                                        \
        block_to_hash[i]=(uint8_t)STR[i];                                                                  \
    }                                                                                                                       \
    FNC_UPDATE(&context, block_size, block_to_hash);                                        \
    FNC_DIGEST(&context, DGST_SIZE, DIGESTSXXX);                                           \
    pmesg_hex(msg_verbose, buffer, DGST_SIZE, DIGESTSXXX);                            \
    printf("originale\n\n");\
})*/

#define  perform_hashing_sha3_generic(FNC_UPDATE, FNC_DIGEST, DGST_SIZE, BLOCK2HASH,               \
                                                                BYTE2WRITE, DIGESTSXXX, DGST_OUTPUT )({                              \
    char buffer[2048]={0};                                                                                                                              \
    size_t bit=0,offset_dgst=0;                                                                                                                        \
    uint8_t *sha3_tmp=malloc(sizeof(uint8_t)*BYTE2WRITE+1);                                                                     \
    uint8_t digest[SHA3_512_DIGEST_SIZE]={0};                                                                                             \
                                                                                                                                                                          \
    for(size_t i=0; i<=SIZE_BUFFER; i+=SIZE_BUFFER){                                                                                   \
        memcpy(sha3_tmp, share_buffer, BYTE2WRITE*sizeof(uint8_t));                                                              \
        memcpy(sha3_tmp+BYTE2WRITE, &bit, sizeof(uint8_t));                                                                          \
                                                                                                                                                                           \
        FNC_UPDATE(&static_context_512, BYTE2WRITE+1, sha3_tmp);                                                             \
        FNC_DIGEST(&static_context_512, SHA3_512_DIGEST_SIZE, digest);                                                        \
                                                                                                                                                                           \
        memcpy(DIGESTSXXX+offset_dgst, digest, SHA3_512_DIGEST_SIZE);                                                     \
        offset_dgst+=SHA3_512_DIGEST_SIZE;                                                                                                    \
        bit++;                                                                                                                                                        \
                                                                                                                                                                           \
    }                                                                                                                                                                      \
    snprintf(buffer, sizeof(buffer), "digest (%d bit)", DGST_OUTPUT );                                                                 \
    pmesg_hex(msg_verbose, buffer, DGST_OUTPUT/8, DIGESTSXXX);                                                                \
    free(sha3_tmp);                                                                                                                                               \
                                                                                                                                                                            \
})

//display_hex(128, DIGESTSXXX);
#define  perform_hashing_sha3_512(FNC_UPDATE, FNC_DIGEST, DGST_SIZE, BLOCK2HASH, LEN, DIGESTSXXX,       \
                                                            DGST_OUTPUT )({                                                                                              \
    char buffer[2048]={0};                                                                                                                                            \
    stats_t timing;                                                                                                                                                          \
    perform_timestamp_sampling_period( timing, sampling_time, max_samplessha3, tu_millis,                                     \
    {                                                                                                                                                                                   \
        FNC_UPDATE(&static_context_512, LEN, BLOCK2HASH);                                                                                          \
        FNC_DIGEST(&static_context_512, DGST_SIZE, DIGESTSXXX);                                                                                  \
    },                                                                                                                                                                              \
        {});                                                                                                                                                                    \
    snprintf(buffer, sizeof(buffer), "digest (%d bit)", DGST_OUTPUT* 8);                                                                         \
    pmesg_hex(msg_verbose, buffer, DGST_SIZE, DIGESTSXXX);                                                                             \
})



/*
 * sha3 family
 */

//H1 sha3-512
#define k1_sec_parameter_H1_hash_functions (uint16_t)512

//H2 sha3-384 (right shift)
#define n_sec_parameter_H2_hash_functions   (uint16_t)128//bit-lenghth msg to be encrypted

//H3 sha3-256 (right shift)
#define k2_sec_parameter_H3_hash_functions (uint16_t)256

//sha3-224 generic user (right shift)
#define generic_hash_functions (uint16_t)288



/** static variable **/

uint8_t *dump_sigma;
uint8_t *dump_msg;
uint8_t *dump_beta_dot;
uint8_t *dump_c;
uint8_t share_buffer[SIZE_BUFFER];


struct sha3_512_ctx static_context_512;

/*
 * ciphertext type. k_1= (A, B, D, c, s), k_2=K=(A, A', B, C, A_dot, B_dot, C_dot)
 */
typedef enum { ciphertext_type_k_1, ciphertext_type_k_2, items_k1=5, items_k2=7, } ciphertext_type_t;

/*
 * undirectional ReEncrypt key
 */
struct public_undirectional_Re_encryption_key_struct {

    mpz_t k2_x2y;
    mpz_t A_dot;
    mpz_t B_dot;
    mpz_t C_dot;
};
typedef struct public_undirectional_Re_encryption_key_struct re_encryption_key_t;


/*
 * public key
 */
typedef struct public_key_struct public_key_t;

struct public_key_struct {
    
    uint32_t id_hash;
    mpz_t N;
    mpz_t g0;
    mpz_t g1;
    mpz_t g2;
    mpz_t NN;

    public_key_t *delegator; /* delegator's key */
};


/*
 * private key 
 */
struct private_key_struct {

    mpz_t p;
    mpz_t p_1;
    mpz_t q;
    mpz_t q_1;
};
typedef struct private_key_struct private_key_t;


/*
 * weak secret key
 */
struct weak_secret_key_struct {

    mpz_t a;
    mpz_t b;
};
typedef struct weak_secret_key_struct weak_secret_key_t;

/*
 * parametri condivisi
 */
struct keygen_params_struct {
    
    unsigned int N_bits;
    
    unsigned int p_bits;
    unsigned int p_1_bits;
    
    unsigned int q_bits;
    unsigned int q_1_bits;

    mpz_t N;
    
    mpz_t p;
    mpz_t p_1;//p'
    
    mpz_t q;
    mpz_t q_1;//q'
};
typedef struct keygen_params_struct keygen_params_t;

/*
 * state (parametri pubblici)
 */
struct PRE_scheme_state_struct {
    
    uint32_t h_1;
    uint32_t h_2;
    uint32_t h_3;
    
    uint16_t k1;
    uint16_t k2;
    uint16_t n;
};
typedef struct PRE_scheme_state_struct state_t;


/*
 * plaintext
 */
struct plaintext_struct{
    mpz_t m;
};
typedef struct plaintext_struct plaintext_t;

/*
 * ciphertext
 */
typedef struct ciphertext_struct_ABCDcs{
    
    mpz_t A;
    mpz_t B;
    mpz_t C;
    mpz_t D;
    mpz_t c;
    mpz_t s;
} ciphertext_tip_1;

typedef struct ciphertext_struct_ABA_1CABC_dot{
    
    mpz_t A;
    mpz_t A_1;
    mpz_t B;
    mpz_t C;
    mpz_t A_dot;
    mpz_t B_dot;
    mpz_t C_dot;
} ciphertext_tip_2;

typedef struct info_type_ciphertext {
    
    ciphertext_type_t ciphertext_type;
    
    union {
        ciphertext_tip_1 K_1;
        ciphertext_tip_2 K_2;
    }info_cipher;
    
}ciphertext_t;


//random seed
long random_seed(void);

//init
void keygen_params_init(keygen_params_t *params);
void state_init(state_t state);
//void msg_init(msg_t *msg);
void plaintext_init(plaintext_t *plaintext);
void ciphertext_init(ciphertext_t *K);
void public_key_init(public_key_t *pk);
void private_key_init(private_key_t *sk);
void weak_secret_key_init(weak_secret_key_t *wsk);
void ReKeyGen_keys_init(re_encryption_key_t *RE_enc_key);
void ciphertext_RE_init(ciphertext_t *K);

//clear
void keygen_params_clear(keygen_params_t *params);
void state_clear(state_t state);

void public_key_clear(public_key_t *pk);
void private_key_clear(private_key_t *sk);
void weak_secret_key_clear(weak_secret_key_t *wsk);
void ReKeyGen_keys_clear(re_encryption_key_t *RE_enc_key);

void plaintext_clear(plaintext_t *plaintext);
void ciphertext_clear(ciphertext_t *K);
void ciphertextK2_clear(ciphertext_t *K);
//void ciphertextK1_clear(ciphertext_t *K);


//keyGen
void generate_keys(keygen_params_t *params, unsigned p_bits, unsigned q_bits, public_key_t *pk,
                   private_key_t *sk, weak_secret_key_t *wsk, gmp_randstate_t prng, const uint32_t idX_hash);

//RekeyGen
void RekeyGen(gmp_randstate_t prng, re_encryption_key_t *RE_enc_key, const state_t *PRE_state,
                            const public_key_t *pkY, const private_key_t *skX, weak_secret_key_t *wskX);

//
void PRE_scheme_state (state_t *PRE_state, gmp_randstate_t prng);

//encrypt
void encrypt(gmp_randstate_t prng, const plaintext_t *msg,  const public_key_t *pk,
                        ciphertext_t *K, const state_t *PRE_state);

//
void ReEncrypt(ciphertext_t *K, const re_encryption_key_t *RE_enc_key, const state_t *PRE_state,
                            const public_key_t *pkX);

//
void decryption(const ciphertext_t *K, const public_key_t *pk,
                        const state_t *PRE_state, const weak_secret_key_t *wsk, const private_key_t *sk, gmp_randstate_t prng);


#endif /* LIB_main_H */

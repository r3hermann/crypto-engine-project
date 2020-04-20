#ifndef  LIB_main_H
#define LIB_main_H

#include "lib-mesg.h"
#include <assert.h>
#include <gmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <strings.h>
#include <nettle/sha1.h>

#define mr_iterations 15
#define BYTEREAD sizeof(char)*4



//step di progressione
typedef enum {
    progression_ready_to_start,
    progression_contrib_sent,
    progression_completed,
}progression_t;

/*
 * keys
 */
typedef enum { public_key_type, secret_key_type } key_type_t;

/*
 * public key
 */
struct public_key_struct {
    
    /*elementi pubblici*/
    mpz_t id_hash;
    mpz_t N;
    mpz_t g0;
    mpz_t g1;
    mpz_t g2;

};
typedef struct public_key_struct public_key_t[1];

/*
 * private key 
 */
struct private_key_struct {

    /*elementi privati*/
    mpz_t p;
    mpz_t p_1;
    mpz_t q;
    mpz_t q_1;
};
typedef struct private_key_struct private_key_t[1];

/*
 * weak secret key
 */
struct weak_secret_key_struct {

    /*elementi privati*/
    mpz_t a;
    mpz_t b;
    
};
typedef struct weak_secret_key_struct weak_secret_key_t[1];

/*
 * parametri condivisi
 */
struct shared_params_struct {
    
    unsigned int N_bits;
    
    unsigned int p_bits;//
    unsigned int p_1_bits;
    
    unsigned int q_bits;
    unsigned int q_1_bits;

    mpz_t N;
    
    mpz_t p;
    mpz_t p_1;//p'
    
    mpz_t q;
    mpz_t q_1;//q'

};

//puntatore alla params_struct
typedef struct shared_params_struct *shared_params_ptr;

//array di shared_params_struct, in questo caso si hanno due array struct
typedef struct shared_params_struct shared_params_t[1];

/*
 * state
 */
struct PRE_scheme_state_struct {
    
    unsigned long int h_1;
    unsigned long int h_2;
    unsigned long int h_3;
    
    progression_t progression; //0
    mpz_t eph_exp; //1
    mpz_t key; //2
};
typedef struct PRE_scheme_state_struct *state_ptr;
typedef struct PRE_scheme_state_struct state_t[1];


/*
 * msg
 */
struct msg_struct {
    mpz_t contrib;
};
typedef struct msg_struct *msg_ptr;
typedef struct msg_struct msg_t[1];

/*
 * plaintext
 */
struct plaintext_struct{
    mpz_t m;
};
typedef struct plaintext_struct *plaintext_ptr;
typedef struct plaintext_struct plaintext_t[1];

/*
 * ciphertext
 */
struct ciphertext_struct{
    
    mpz_t A;
    mpz_t B;
    mpz_t C;
    mpz_t D;
    mpz_t A_1;
    mpz_t A_p;
    mpz_t B_p;
    mpz_t C_p;
    
};
typedef struct ciphertext_struct ciphertext_t[1];


/*metodi*/

//random seed
long random_seed();

//parametri condivisi
void generate_shared_params(shared_params_t params, unsigned int p_bits, gmp_randstate_t prng);

//computazione chiave
bool compute_key(state_t state, const msg_t other_msg, const shared_params_t params);

//init
void state_init(state_t state);
void msg_init(msg_t msg);
void plaintext_init(plaintext_t plaintext);
void ciphertext_init(ciphertext_t ciphertext);

//clear
void shared_params_clear(shared_params_t params);
void msg_clear(msg_t msg);
void state_clear(state_t state);

void public_key_clear(public_key_t pk);
void private_key_clear(private_key_t sk);
void weak_secret_key_clear(weak_secret_key_t wsk);

void plaintext_clear(plaintext_t plaintext);
void ciphertext_clear(ciphertext_t ciphertext);

//keyGen
void generate_keys(public_key_t pk, private_key_t sk, weak_secret_key_t wsk,msg_t msg, state_t state, const shared_params_t params, gmp_randstate_t prng,
                                const state_t PRE_state);

//get id hash
void PRE_scheme_state (state_t PRE_state);

//encrypt
void encrypt(const shared_params_t params, gmp_randstate_t prng, const plaintext_t msg, const public_key_t pk,
                        ciphertext_t ciphertext_K, const state_t PRE_state);

void decript(plaintext_t plaintext, const ciphertext_t ciphertext_K);

//
//void hashing(struct_ctx, fnc_init,fnc_update, fnc_difest, dgst_size);

//verifiche
bool verify_params(const shared_params_t params);

#endif /* LIB_main_H */

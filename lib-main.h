#ifndef  LIB_main_H
#define LIB_main_H

#include "lib-mesg.h"
#include <assert.h>
#include <gmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <strings.h>
#include <nettle/sha1.h>

#define mr_iterations 12
#define BYTEREAD sizeof(char)*4

#define hashing(struct_ctx, fnc_init,fnc_update, fnc_difest, dgst_size)

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
 * keys
 */
struct keys_struct {
  
    //tipo chiave
    key_type_t type;
    unsigned int n_bits;
    
    /*elementi pubblici*/
    struct sha1_ctx ctx;
    mpz_t N;
    mpz_t g0;
    mpz_t g1;
    mpz_t g2;
    
    /*elementi privati*/
    mpz_t p;
    mpz_t p_1;
    mpz_t q;
    mpz_t q_1;
};
typedef struct keys_struct *keys_ptr;
typedef struct keys_struct keys_t[1];

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
    mpz_t p_1;//q
    
    mpz_t q;
    mpz_t q_1;//q

};

//puntatore alla params_struct
typedef struct shared_params_struct *shared_params_ptr;

//array di shared_params_struct, in questo caso si hanno due array struct
typedef struct shared_params_struct shared_params_t[1];

/*
 * state
 */
struct state_struct {
    
    progression_t progression; //0
    mpz_t eph_exp; //1
    mpz_t key; //2
};
typedef struct state_struct *state_ptr;
typedef struct state_struct state_t[1];


/*
 * msg
 */
struct msg_struct {
    mpz_t contrib;
};
typedef struct msg_struct *msg_ptr;
typedef struct msg_struct msg_t[1];


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

//clear
void shared_params_clear(shared_params_t params);
void msg_clear(msg_t msg);
void state_clear(state_t state);
void keys_clear(keys_t keys);

//keyGen
void generate_keys(keys_t keys, msg_t msg, state_t state, const shared_params_t params, gmp_randstate_t prng);

//
void encrypt(keys_t keys);

//
//void hashing(struct_ctx, fnc_init,fnc_update, fnc_difest, dgst_size);

//verifiche
bool verify_params(const shared_params_t params);

#endif /* LIB_main_H */


#include"lib-main.h"
#include "lib-mesg.h"
#include "lib-misc.h"
#include "lib-timing.h"
#include <gmp.h>
#include <libgen.h>
#include <stdbool.h>
#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nettle/sha1.h>
//#include <stdbool.h> //gcc usa C90

#define prng_sec_level 96
#define default_p_bits 512 //safe-prime piccoli

#define block_size (1 << 20) // 1 MiB
#define blocks_to_hash 5

#define bench_sampling_time 5 /* secondi */
#define max_samples (bench_sampling_time * 1000)

int main (int argc, char* argv[]){
    
    long fixed_msg = 0;
    
    //time
    elapsed_time_t time;
    stats_t timing;
    long int applied_sampling_time = 0;
    
    //bench
    bool do_bench = false;
    
    gmp_randstate_t prng;
    int p_bits=default_p_bits; //512

    state_t alice_state, bob_state, proxy_state;
    msg_t a2b_msg, b2a_msg, a2p_msg;
    plaintext_t plaintext_msg;

    //shared params N
    shared_params_t params;
    
    //key
    public_key_t pk;
    private_key_t sk;
    weak_secret_key_t wsk;
    
    ciphertext_t K;
    state_t PRE_state;
    
    int exit_status=0;
    
    long prng_seed=random_seed();
    //printf("random_seed %ld\n",seed);
    
    if (argv[1] == NULL) {
        printf("esecuzione minimale...\n\n");
    }
    
	for(int i=1; i<argc; i++){
        
         if (strcmp(argv[i], "verbose") == 0)
            set_messaging_level(msg_very_verbose);
         
         else if (strcmp(argv[i], "bench") == 0) {
             
            applied_sampling_time = bench_sampling_time;
            do_bench =true;
             
        } else if (strcmp(argv[i], "message") == 0) {
            
            
            if(i+1 >= argc) {
                printf("error: \"message\" errato o mancante \n");
                exit(1);
            }
            assert(argv[i+1]);
            fixed_msg = atoi(argv[i+1]);
            i++;
        }
        
        else {
            printf("utilizzo eseguibile: ./%s [verbose] [message <n> ]"
                     "[bench]\nusare il comando ./%s per un esecuzione minimale\n",
                basename(argv[0]), basename(argv[0]));
            exit(1);
        }
        //...
    }
    
    printf("Calibrazione strumenti per il timing...\n");
    calibrate_clock_cycles_ratio();
    detect_clock_cycles_overhead();
    detect_timestamp_overhead();
    
    if (do_bench){
        set_messaging_level(msg_silence);
    }
    detect_clock_cycles_overhead();
    detect_timestamp_overhead();
    
    
    printf("\nInizializzazione PRNG");
    gmp_randinit_default(prng);
    
    /*
     * Set an initial seed value into state
     */
    if(prng_seed>=0){
         printf("(modalità deterministica: seme = %ld...\n", prng_seed);
        gmp_randseed_ui(prng, (unsigned long int)prng_seed);
        
    } else {
        printf("modalita' sicura \n");
        gmp_randseed_os_rng(prng, prng_sec_level);
    }
    
    //get N=p*q
    printf("\nGenerazione dei parametri comuni. Gruppo di ordine %d bit...\n",p_bits);
    perform_oneshot_timestamp_sampling(time, tu_sec, {
        generate_shared_params(params, p_bits, prng);
        });
    if (do_bench)
        printf_et("generate_shared_params: ", time, tu_sec,"\n");
    
    
    //PRE_state
    PRE_scheme_state(params, prng, PRE_state);
    
    //check sui parametri
    if(!verify_params(params)){
        printf("il controllo dei parametri e' fallito\n");
        exit(1);
    }
   
    //state
    //state_init(alice_state);
    //state_init(bob_state);
   // state_init(proxy_state);
    
    //msg
    //msg_init(a2p_msg);

    
    //alice= a, g^a
    printf("\n\nGenerazione parametri di Alice\n");
    generate_keys(pk, sk, wsk, a2p_msg,alice_state, params,prng, PRE_state);
    plaintext_init(plaintext_msg);
    
    if (fixed_msg > 0) {
        mpz_set_ui(plaintext_msg->m,fixed_msg);
    }
    else {
        if (fixed_msg < 0)
            mpz_sub_ui(plaintext_msg->m, params->N, labs(fixed_msg));
        else
            mpz_urandomm(plaintext_msg->m, prng, params->N);
    }
    //gmp_printf("check plaintext->m: %Zd\n", plaintext_msg->m);
    //gmp_printf("check N: %Zd\n", params->N);
    
    
    ciphertext_init(K);
   printf("\nCifratura...\n");
   perform_clock_cycles_sampling_period(
       timing, applied_sampling_time, max_samples, tu_millis,{
           encrypt(params, prng, plaintext_msg,pk, K, PRE_state);},{});
   if (do_bench)
            printf_short_stats(" rsa_encryption", timing, "");
   
    /*
    //bob= b, g^b
    printf("Generazione parametri di Bob\n");
    generate_contrib(b2a_msg,bob_state,params,prng);
    //printf("prng_seed: %ld",prng_seed);
    
    printf("\nCalcolo chiave condivisa da parte di Alice...\n");
    compute_key(alice_state,b2a_msg,params);
    
    printf("\nCalcolo chiave condivisa da parte di Bob...\n");
    compute_key(bob_state,a2b_msg,params);

    //check sulla chiave
    if(mpz_cmp(alice_state->key,bob_state->key)){
        printf("errore: le chiavi calcolate non coincidono\n");
        exit_status=1;
    }
    */
    
    
    //clear
    //msg_clear(a2b_msg);
    //msg_clear(b2a_msg);
    //state_clear(alice_state);
    //state_clear(bob_state);
    
    
    public_key_clear(pk);
    private_key_clear(sk);
    weak_secret_key_clear(wsk);
    shared_params_clear(params);
    ciphertext_clear(K);
    plaintext_clear(plaintext_msg);
    gmp_randclear(prng);
    exit(exit_status);
}


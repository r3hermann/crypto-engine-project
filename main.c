
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
#include<errno.h>

#define prng_sec_level 96
#define default_p_bits 512 //safe-prime piccoli


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
    msg_t wska_msg, b_msg;
    plaintext_t plaintext_msg;

    //shared params N
    shared_params_t params;
    
    //pk key
    public_key_t pk, *pkX;
    
    //sk keys
    private_key_t sk;
    weak_secret_key_t wsk;
    
    //ReGen
    re_encryption_key_t RE_enc_key;
    
    ciphertext_t K;
    state_t PRE_state;
    
    int exit_status=0;
    long prng_seed=-1;//random_seed();
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
                _EXIT("messaggio errato o mancante. ");
            }
            assert(argv[i+1]);
            fixed_msg = atoi(argv[i+1]);
            i++;
        }
        
        else {
            fprintf(stderr,"utilizzo eseguibile: ./%s [verbose] [message <n> ]"
                     "[bench]\nusare il comando ./%s per un esecuzione minimale\n",
                basename(argv[0]), strerror(errno));
            exit(EXIT_FAILURE);
        }
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
        generate_shared_params(&params, p_bits, prng);
        });
    if (do_bench)
        printf_et("generate_shared_params: ", time, tu_sec,"\n");
    
    
    //generazione id
    PRE_scheme_state(&PRE_state);
    
    //check sui parametri
    /*if(!verify_params(params)){
        _EXIT("controllo dei parametri e' fallito. ");
    }*/
   
  
    public_key_init(&pk);
    
    //msg
    msg_init(&wska_msg);
    msg_init(&b_msg);
    
    printf("\n\nGenerazione parametri di Alice\n");
    generate_keys(&pk, sk, wsk, &params, prng, &PRE_state, &wska_msg);
    pkX=&pk;

    
    //K.flag=1;
    ciphertext_init(&K);
    plaintext_init(&plaintext_msg);
    
    
    if (fixed_msg > 0) {
        mpz_set_ui(plaintext_msg.m,fixed_msg);
    }
    else { //random msg
        if (fixed_msg < 0)
            mpz_sub_ui(plaintext_msg.m, params.N, labs(fixed_msg));
        else
            mpz_urandomm(plaintext_msg.m, prng, params.N);
    }
        
    
    
    printf("\n\nCifratura plaintext...\n");
    perform_clock_cycles_sampling_period(
        timing, applied_sampling_time, max_samples, tu_millis,{
            encrypt(prng, &plaintext_msg, &pk, &K, &PRE_state); },{});
     if (do_bench)
            printf_short_stats(" Cifratura", timing, "");
            
    printf("\nDecifratura del messaggio ricevuto...\n");
    perform_clock_cycles_sampling_period(
        timing, applied_sampling_time, max_samples, tu_millis,{
            decryption(&K, &pk, &PRE_state, &wska_msg, sk, prng); },{});
    if (do_bench)
            printf_short_stats(" Decifratura", timing, "");
    
    printf("\n\nGenerazione parametri di Bob\n");
    generate_keys(&pk, sk, wsk, &params, prng, &PRE_state, &b_msg);

    printf("\navvio richiesta di re_encryption...\n");
    printf("ReKeygen dal Proxy in corso...\n");
    RekeyGen(prng, &RE_enc_key, &PRE_state, &pk, sk, &wska_msg);
    

    //printf("\ncifratura del ciphertext K dal Proxy...\n");
    //ReEncrypt(&K, &RE_enc_key, &PRE_state, pkX);
    
    
    //printf("\nDecifratura del messaggio ricevuto...\n");
    
    //clear
    
    msg_clear(&b_msg);
    msg_clear(&wska_msg);

    shared_params_clear(&params);
    private_key_clear(sk);
    //public_key_clear(pkX);
    public_key_clear(&pk);
    weak_secret_key_clear(wsk);
    plaintext_clear(&plaintext_msg);
    ciphertext_clear(&K);
    ReKeyGen_keys_clear(&RE_enc_key);
    gmp_randclear(prng);
    exit(exit_status);
}

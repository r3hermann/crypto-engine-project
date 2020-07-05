 /*
 * 
 *  H1 sha3_512, H2 sha3_384, H3 sha3_256
 * 
 * 
 * esperimenti da eseguire:
 * - ./main verbose
 * - ./main bench
 * - ./main verbose message <number>
 * 
 */


#include"lib-main.h"
#include "lib-mesg.h"
#include "lib-misc.h"
#include <gmp.h>
#include <libgen.h>
#include <stdbool.h>
#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nettle/sha1.h>
#include<errno.h>

#define prng_sec_level 96

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
    unsigned int p_bits=default_p_bits;
    unsigned int q_bits=default_q_bits;

    plaintext_t plaintext_msg;

    //KeyGen params N
    keygen_params_t params;
    
    //pk keys
    public_key_t pk, pkX;
    private_key_t skX;
    
    //sk keys
    private_key_t sk;
    weak_secret_key_t wsk, wskX;
    
    //ReGen
    re_encryption_key_t RE_enc_key;
    
    ciphertext_t K;
    state_t PRE_state;
    
    long prng_seed=random_seed();
    //printf("random_seed %ld\n",seed);
    

    extern struct sha3_512_ctx static_context_512;
    sha3_512_init(&static_context_512);
    
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
            fixed_msg = (unsigned long)atoi(argv[i+1]);
            i++;
        }
        
        else {
            fprintf(stderr,"utilizzo eseguibile: ./%s [verbose] [message <n> ]"
                     "[bench]\nusare il comando ./%s per un esecuzione minimale\n",
                basename(argv[0]), strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    
    if (do_bench)
        set_messaging_level(msg_silence);
    
    printf("Calibrazione strumenti per il timing...\n");
    calibrate_clock_cycles_ratio();
    detect_clock_cycles_overhead();
    detect_timestamp_overhead();
    
    printf("\nInizializzazione PRNG");
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, prng_sec_level);
    
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
    
    keygen_params_init(&params);
    
    //id gen
    PRE_scheme_state(&PRE_state, prng);
        
    //init keys
    public_key_init(&pk);
    private_key_init(&sk);
    weak_secret_key_init(&wsk);
    
    printf("\n\nGenerazione parametri di Alice\n");
    perform_clock_cycles_sampling_period(
        timing, applied_sampling_time, max_samples, tu_millis,
        {generate_keys(&params, p_bits, q_bits, &pk, &sk, &wsk, prng, PRE_state.h_1);},{});
    if (do_bench)
         printf_short_stats("Generazione parametri di Alice: ", timing, "");
    
    pkX=pk;
    skX=sk;
    wskX=wsk;
    ciphertext_init(&K);
    plaintext_init(&plaintext_msg);
    
    if (fixed_msg > 0) {
        mpz_set_ui(plaintext_msg.m, (unsigned long int)fixed_msg);
    }
    else { //random msg
        if (fixed_msg < 0) {
            unsigned long sub=n_msg_length-((unsigned long int)labs(fixed_msg));
            mpz_set_ui(plaintext_msg.m, sub);
        }
        else
            mpz_urandomb(plaintext_msg.m, prng, n_msg_length);
    }

    printf("\n\nCifratura plaintext...\n");
    perform_clock_cycles_sampling_period(
        timing, applied_sampling_time, max_samples, tu_millis,
        {encrypt(prng, &plaintext_msg, &pk, &K, &PRE_state);},{});
        printf("\nciphertext generato di tipo K=(A, B, D, c, s)\n\n");
    if (do_bench)
        printf_short_stats(" Cifratura plaintext...", timing, "");

   printf("\nDecifratura del messaggio ricevuto...\n");
    printf("ricevuto in input un ciphertext K di tipo K=(A, B, D, c, s)...\n");
    printf("controllo idonieta' su K in corso...\n");
    printf("chiave input  per la decifrazione secret key weak\n\n");

    perform_clock_cycles_sampling_period(
                timing, applied_sampling_time, max_samples, tu_millis,{
                    decryption(&K, &pk, &PRE_state, &wsk, &sk, prng);},{});
    if (do_bench)
        printf_short_stats("Decifratura del messaggio ricevuto... ", timing, "");
        
    printf("   decifratura avvenuta correttamente...\n");

    printf("\n\nseconda decifratura, caso secret key long term secret key\n");
    printf("controllo idonieta' su K in corso...\n");
    printf("chiave input  per la decifrazione long term secret key\n\n");

    perform_clock_cycles_sampling_period(
                timing, applied_sampling_time, max_samples, tu_millis,{
            decryption(&K, &pk, &PRE_state, NULL, &sk, prng);},{});
    if (do_bench)
        printf_short_stats("seconda decifratura, caso long term secret key....", timing, "");
    
    public_key_init(&pk);
    private_key_init(&sk);
    weak_secret_key_init(&wsk);
    
    printf("\n\nGenerazione parametri di Bob\n");
    perform_oneshot_clock_cycles_sampling(time, tu_millis,{
        generate_keys(&params, p_bits, q_bits, &pk, &sk, &wsk, prng, PRE_state.h_2);
    });
    if (do_bench)
        printf_et("Generazione parametri di Bob...: ", time, tu_sec,"\n");
    
    printf("\navvio richiesta di re_encryption...\n");
    printf("avvio procedura ReKeygen dal Proxy in corso...\n");
    ReKeyGen_keys_init(&RE_enc_key);//P2
    
    perform_clock_cycles_sampling_period(
        timing, applied_sampling_time, max_samples, tu_millis,{
            RekeyGen(prng, &RE_enc_key, &PRE_state, &pk, &skX, &wskX); //pk bob
            },{});
    printf("\nrk1_X -> Y= (A_dot, B_dot, C_dot)\n");
    printf("output re-KeyGen: undirectional re-encryption key rkX -> Y = (rk1_X -> Y, rk2_X -> Y)\n\n");
    if (do_bench)
        printf_short_stats("ReKeygen Proxy......", timing, "");
    
    printf("\navvio cifratura del ciphertext K dal Proxy...\n");
    printf("controllo del ciphertext K ricevuto in input in corso...\n");
    printf("ricevuto in input un ciphertext K di tipo K=(A, A', B, C, A_dot, B_dot, C_dot)...\n");
    
    ciphertext_RE_init(&K);
    perform_oneshot_clock_cycles_sampling(time, tu_millis,{
            //mpz_init(K.info_cipher.K_2.C_dot);
            ReEncrypt(&K, &RE_enc_key, &PRE_state, &pkX); //re-enc cipher under alices pk
        });
    printf("cifratura ciphertext= (A, A', B, C, A_dot, B_dot, C_dot)\n");
    if (do_bench)
          printf_et("cifratura del ciphertext K dal Proxy......", time, tu_sec,"\n");
    
    // pk delegator
    pk.delegator=&pkX;
    
    printf("\n\nDecifratura del messaggio ricevuto dal Proxy...\n");
    printf("controllo idonieta' su K in corso...\n");
    printf("chiave input  per la decifrazione secret key weak\n\n");
    
    perform_clock_cycles_sampling_period(
        timing, applied_sampling_time, max_samples, tu_millis,{
            decryption(&K, &pk, &PRE_state, &wsk, &sk, prng); //bob decryption
        },{});
    
    if (do_bench)
          printf_short_stats("Decifratura del messaggio ricevuto dal Proxy....", timing, "");

    printf("\n\nseconda decifratura ciphertext dal Procy\n");
    printf("chiave input  per la decifrazione long term secret key\n");
    printf("controllo idonieta' su K in corso...\n");
    perform_clock_cycles_sampling_period(
        timing, applied_sampling_time, max_samples, tu_millis,{
            decryption(&K, &pk, &PRE_state, NULL, &sk, prng);
    },{});
    
    if (do_bench)
        printf_short_stats("decifratura caso long term secret key con ciphertext dal Proxy....",timing, "");

    //clear
    private_key_clear(&skX);//P2
    weak_secret_key_clear(&wskX);//P2
    private_key_clear(&sk);
    public_key_clear(&pkX);//P2
    public_key_clear(&pk);
    weak_secret_key_clear(&wsk);
    plaintext_clear(&plaintext_msg);
    ciphertextK2_clear(&K);
    ReKeyGen_keys_clear(&RE_enc_key);//P2
    gmp_randclear(prng);
    keygen_params_clear(&params);
    exit(EXIT_SUCCESS);
}

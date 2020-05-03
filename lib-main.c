#include "lib-main.h"
#include <unistd.h>
#include <sys/types.h>
#include<sys/wait.h>
#include <nettle/sha3.h>
#include <nettle/sha1.h>
#include <errno.h> 

#define CHECK(filepointer) ({FILE* __val=(filepointer); ( __val ==NULL ?                                      \
                                ({fprintf(stderr, "ERROR (" __FILE__ ":%d) %s\n",__LINE__,strerror(errno));     \
                                exit(EXIT_FAILURE);}): (*(int*)__val)); })


#define _EXIT(string)({fprintf(stderr, "%s %s, line %d.\n", string, __FILE__, __LINE__); exit(EXIT_FAILURE);})
                                                    
#define  perform_hashing_sha3(STRUCT_CTX, FNC_INIT, FNC_UPDATE, FNC_DIGEST, DGST_SIZE, STR, STRLEN, DIGESTSXXX)({ \
    struct STRUCT_CTX context;                                                                           \
    FNC_INIT(&context);                                                                                        \
    char buffer[2048]={0};                                                                                   \
    int block_size=strlen(STRLEN);                                                                        \
    uint8_t block_to_hash[block_size];                                                                   \
    for(size_t i=0; i<block_size;i++){                                                                    \
                                                                                                                             \
        block_to_hash[i]=(uint8_t)STR[i];                                                                  \
    }                                                                                                                       \
    FNC_UPDATE(&context, block_size, block_to_hash);                                        \
    FNC_DIGEST(&context, DGST_SIZE, DIGESTSXXX);                                           \
    pmesg_hex(msg_verbose, buffer, DGST_SIZE, DIGESTSXXX);                            \
})
                                
static inline void TestingHash(char *str, uint8_t print_digest[], long size_digest) {
    

    printf("test hash %s: ",str);
    long size_array=(size_digest)/sizeof(uint8_t);
    for(int i=0; i<size_array; i++)
        printf("%02x",print_digest[i]);
    printf("\n");
    /*int len=0;
    while(print_digest[len]!='\0') {                 
        printf("%u",print_digest[len]);
        len++;                                            
    }*/                                                      
}

 static inline void ul_to_char(unsigned long int h_X, char *result){
     
     const int n= snprintf(NULL, 0, "%lu", h_X);
     //printf("valore da convertire= %lu, n= %d\n",h_X,n);
    assert(n>0);
    int c= snprintf(result, n+1, "%lu", h_X);
    assert(c==n);
}

static inline  char *cnt_string( char *str, char *str1, uint32_t id){
    
    char  converion [16]={0};
    if (!str1) {
        
        ul_to_char(id, converion);
        char * concatString= (char *) malloc(1+strlen(str)+strlen(converion));
        strcpy(concatString, str);
        strcat(concatString, converion);
        return concatString;
    }    
    else {

        ul_to_char(id, converion);
        char * concatString= (char *) malloc(1+strlen(str)+strlen(str1)+strlen(converion));
        strcpy(concatString, str);
        strcat(concatString, str1);
        strcat(concatString,converion);
        return concatString;
    }
}

long random_seed () {
    
    FILE *dev_random;
    int byte_count;
    int seed=0;
	byte_count = BYTEREAD;
	CHECK(dev_random = fopen("/dev/random", "r"));
	
	fread(&seed, sizeof(char), byte_count, dev_random);
    //printf("\ndati letti: (hex) %x, (int) %d, (int senza segno) %u\n",seed,seed,seed);
    //printf("byte allocati= %ld. byte_count= %d\n",(byte_count)*sizeof(char),byte_count);
	fclose(dev_random);
    return seed;
}


/* 
 * get shared params
 */
void generate_shared_params(shared_params_t params, unsigned n_bits, gmp_randstate_t prng) {

    pmesg(msg_verbose, "generazione parametri comuni...");
      
    //assert
    assert(params);
    assert(n_bits>1);
    assert(prng);

    mpz_inits(params->N, params->NN, params->p,params->p_1,params->q, params->q_1, NULL);

    //scelta delle taglie di p e q
    params->p_bits=n_bits;
    params->q_bits=n_bits;
    params->p_1_bits=n_bits-1; // p' da 511 bit 
    params->q_1_bits=n_bits-1; // q' da 511 bit
    
    //scelta della taglia di p e q con un N fissato (secondo modo)
    //params->p_bits = n_bits >> 1;
    //params->q_bits = n_bits - params->p_bits;


    //p della forma 2*p'+1 con p' e p primi
    //q della forma 2*q'+1 con q' e q primi
    
    //possibile ottimizzazione
    do {
        do {
            
            //cerco un primo p' random range 0-2^(p_1_bits)-1
            mpz_urandomb(params->p_1, prng, params->p_1_bits);
        }while((mpz_sizeinbase(params->p_1, 2) < params->p_1_bits) ||
                    (!mpz_probab_prime_p(params->p_1, mr_iterations)));
        
        //calcolo p=2*p'+1
        mpz_mul_ui(params->p,params->p_1,2);
        mpz_add_ui(params->p,params->p,1);
        }while(!mpz_probab_prime_p(params->p,mr_iterations));
    
    do {
        do{
            //cerco un primo q'
            mpz_urandomb(params->q_1,prng,params->q_1_bits);
        }while((mpz_sizeinbase(params->q_1, 2)<params->q_1_bits) || 
                    ( !mpz_probab_prime_p(params->q_1, mr_iterations)));
        
        //calcolo q=2*q'+1
        mpz_mul_ui(params->q,params->q_1,2);
        mpz_add_ui(params->q,params->q,1);
    }while ( !mpz_probab_prime_p(params->q,mr_iterations) );

    
    //N=p*q
    mpz_mul(params->N,params->p,params->q);
    
    //N^2
    mpz_mul(params->NN, params->N, params->N);

    pmesg_mpz(msg_very_verbose, "modulo p =",params->p);
    pmesg_mpz(msg_very_verbose, "modulo q =",params->q);
    pmesg_mpz(msg_very_verbose, "modulo p*q =",params->N);
    pmesg_mpz(msg_very_verbose, "primo divisore p' dell'ordine", params->p_1);
    pmesg_mpz(msg_very_verbose, "primo divisore p' dell'ordine", params->q_1);
}


void PRE_scheme_state (state_t PRE_state) {
    
    unsigned int buffer[3];
    int byte_count=15;
    FILE *dev_random;
    CHECK(dev_random = fopen("/dev/random", "r"));

	fread(&buffer,sizeof(char), byte_count, dev_random);
    
    PRE_state->h_1=(*(&buffer[0])%10000);
    PRE_state->h_2=(*(&buffer[1])%10000);
    PRE_state->h_3=(*(&buffer[2])%10000);
    
    for(int i=0;i<3;i++)
        printf(" buffer[%d] = %u", i, buffer[i]%10000);
    fclose(dev_random);
}

/*
 * contrib KeyGen
 */
void generate_keys(public_key_t pk, private_key_t sk, weak_secret_key_t wsk, msg_t msg,
                   state_t state, const shared_params_t params, gmp_randstate_t prng, const state_t PRE_state){
    
    assert(msg);
    assert(state);
    //assert(state->progression>=progression_ready_to_start);
    assert(params);
    assert(prng);
    
    pmesg(msg_verbose, "generazione del contributo...");
    
    mpz_t alpha,tmp;
    mpz_inits(alpha, tmp, NULL);
    mpz_inits(pk->N, pk->id_hash, pk->g0, pk->g1, pk->g2, NULL);
    mpz_inits(sk->p,sk->q, sk->p_1, sk->q_1, NULL);    
    mpz_inits(wsk->a, wsk->b, NULL);
    
    //set N e id_hash
    mpz_set(pk->N,params->N);
    mpz_set_ui(pk->id_hash, (PRE_state->h_1)); //primo step alice
    
        
    //set sk keys
    mpz_set(sk->p,params->p);
    mpz_set(sk->p_1,params->p_1);
    mpz_set(sk->q,params->q);
    mpz_set(sk->q_1,params->q_1);
    
    
    //apha in Z*n^2
    do {
        mpz_urandomm(alpha, prng, params->NN);
        mpz_gcd(tmp, alpha, params->NN);
        gmp_printf("\ngcd(alpha, N^2) = %Zd\n",tmp);
    } while (mpz_get_ui(tmp)!=1L);
    
    // calcolo il range [pp' qq'], maxordG 
    mpz_mul(tmp,params->N, params->p_1);
    mpz_mul(tmp,tmp,params->q_1);
    
    //a,b random in [1,pp' qq'], 0 escluso
    do {
        mpz_urandomm(wsk->a, prng,tmp);
        mpz_urandomm(wsk->b, prng,tmp);
    } while( (mpz_cmp_ui(wsk->a,0)==0) || (mpz_cmp_ui(wsk->b,0)==0)  );
    
    //g0 = alpha^2 mod N^2
    mpz_powm_ui(pk->g0, alpha, 2, params->NN);
    
    //g1 = g0^a mod N^2
    mpz_powm(pk->g1, pk->g0, wsk->a, params->NN);
    
    //g2= g0^b mod N^2
    mpz_powm(pk->g2,pk->g0,wsk->b, params->NN);
    
    //pk
    printf("\npk = (H(.), N, g0, g1, g2)\n");
    pmesg_mpz(msg_very_verbose, "alpha =",alpha);
    pmesg_mpz(msg_very_verbose, "id_Hash =",pk->id_hash);
    pmesg_mpz(msg_very_verbose, "modulo N=",pk->N);
    pmesg_mpz(msg_very_verbose, "g0 =",pk->g0);
    pmesg_mpz(msg_very_verbose, "g1 =",pk->g1);
    pmesg_mpz(msg_very_verbose, "g2=",pk->g2);

    //weak secret
    printf("\nweak secret,");
    pmesg_mpz(msg_very_verbose, "range =", tmp);
    pmesg_mpz(msg_very_verbose, "a =",wsk->a);
    pmesg_mpz(msg_very_verbose, "b =",wsk->b);
    
    //sk
    printf("\nsk = (p, q, p', q')\n");
    pmesg_mpz(msg_very_verbose, "p =",sk->p);
    pmesg_mpz(msg_very_verbose, "q =",sk->q);
    pmesg_mpz(msg_very_verbose, "p' = ", sk->p_1);
    pmesg_mpz(msg_very_verbose, "q' = ", sk->q_1);
    
    pmesg_mpz(msg_very_verbose, "N^2=", params->NN);
    mpz_clears(alpha, tmp,NULL);
}


/*
 * encrypt
 */
void encrypt(const shared_params_t params, gmp_randstate_t prng, const plaintext_t plaintext, const public_key_t pk,
                    ciphertext_t ciphertext_K, const state_t PRE_state) {
    
    assert(params);
    assert(prng);
    assert(plaintext);
    assert(pk);
    assert(ciphertext_K);
    
    mpz_t sigma, tmp, r, t, g0_t, g2_t;
    
    //check plaintext, servono ulteriori controlli?
    assert(mpz_cmp_ui(plaintext->m, 0L)>0);
    assert(mpz_cmp(plaintext->m, params->N) < 0);
    pmesg(msg_verbose, "cifratura...");
    
    mpz_inits(sigma, tmp, r, t, g0_t, g2_t, NULL);
    pmesg_mpz(msg_very_verbose, "testo in chiaro", plaintext->m);
    
    //sigma in Zn random
    mpz_urandomm(sigma, prng, params->N);
    
    //H1 sigma || m || id, (string base 10)
    char * concat_h1=cnt_string(mpz_get_str(NULL, 10, sigma), mpz_get_str(NULL, 10, plaintext->m), PRE_state->h_1);
    
    mpz_set_str(tmp, concat_h1, 10);
    mpz_mod(tmp, tmp, params->NN);
    
    char * tmpH1=mpz_get_str(NULL, 10, tmp);
    
    uint8_t digest_h_1[SHA3_512_DIGEST_SIZE];
    printf("\nhash sigma||m||id\n");
    perform_hashing_sha3(sha3_512_ctx, sha3_512_init, sha3_512_update,
                            sha3_512_digest, SHA3_512_DIGEST_SIZE, tmpH1, &tmpH1[0], digest_h_1);
    
    //r
    mpz_import(r, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_1);//gmp_printf("check r: %Zx\n", r);
    
    //A=go^r mod N^2
    mpz_powm(ciphertext_K->A, pk->g0, r, params->NN);
    
    
    //H_2 (sigma || id )
    char * concat_h2=cnt_string(mpz_get_str(NULL, 10, sigma), NULL, PRE_state->h_2);
    
    mpz_set_str(tmp, concat_h2, 10);
    mpz_mod(tmp, tmp, params->NN);
    char * tmpH2=mpz_get_str(NULL, 10, tmp);
    
    uint8_t digest_h_2[SHA3_384_DIGEST_SIZE]={0};
    printf("\nhash_2 sigma||id\n");
    perform_hashing_sha3(sha3_384_ctx, sha3_384_init, sha3_384_update,
                            sha3_384_digest, SHA3_384_DIGEST_SIZE, tmpH2, &tmpH2[0], digest_h_2);
    
    //C= H_2 (sigma || id ) xor m 
    mpz_import(tmp, SHA3_384_DIGEST_SIZE,1,1,0,0, digest_h_2);
    mpz_xor(ciphertext_K->C, tmp, plaintext->m);
    //TestingHash("digest_h_2", digest_h_2, sizeof(digest_h_2));
    
    
    //D=g2^r mod N^2
    mpz_powm(ciphertext_K->D, pk->g2, r, params->NN);
    
    //B=g1^r * (1+sigma*N) mod N^2  ( a*b mod = mod (a mod * b mod ) )
    
    //(1+sigma*N) mod N^2
    mpz_mul(tmp, sigma,pk->N);
    mpz_add_ui(tmp,tmp,1);
    mpz_mod(tmp, tmp, params->NN);
    
    //g1^r mod N^2
    mpz_powm(ciphertext_K->B, pk->g1, r, params->NN);
    
    //B=x*y mod N^2
    mpz_mul(ciphertext_K->B, ciphertext_K->B, tmp);
    mpz_mod(ciphertext_K->B, ciphertext_K->B, params->NN);
    
    
    /*Sok.Gen*/

    //set t in 0 ,.., 2^(|N^2|+k) -1
    mpz_set_ui(t, mpz_sizeinbase(params->NN,2));
    
    mpz_add_ui(t, t, PRE_state->h_1);
    unsigned long t_exp=mpz_get_ui(t);
    mpz_urandomb(t, prng, t_exp);
    
    
    mpz_powm(g0_t, pk->g0, t, params->NN);
    mpz_powm(g2_t, pk->g2, t, params->NN);
    
    pmesg_mpz(msg_very_verbose, "g0_t from encrypt=", g0_t);
    
    char converion3[16];
    char * str_A=mpz_get_str(NULL, 10, ciphertext_K->A);
    char * str_D=mpz_get_str(NULL, 10, ciphertext_K->D);
    char * str_B=mpz_get_str(NULL, 10, ciphertext_K->B);
    char * str_C=mpz_get_str(NULL, 10, ciphertext_K->C);
    char * str_g0=mpz_get_str(NULL, 10, pk->g0);
    char * str_g2=mpz_get_str(NULL, 10, pk->g2);
    char * str_g0t=mpz_get_str(NULL, 10, g0_t);
    char * str_g2t=mpz_get_str(NULL, 10, g2_t);
    ul_to_char(PRE_state->h_3,converion3);
    
    char* str_BC= (char *) malloc(strlen(str_B)+strlen(str_C));
    strcpy(str_BC, str_B);
    strcat(str_BC, str_C);
    
    char * concatSockGen= (char *) malloc(1+strlen(str_A)+strlen(str_D)+strlen(str_g0)+strlen(str_g2)+
                                                strlen(str_g0t)+strlen(str_g2t)+strlen(str_BC)+strlen(converion3));

    strcpy(concatSockGen,str_A);
    strcat(concatSockGen, str_D);
    strcat(concatSockGen, str_g0);
    strcat(concatSockGen, str_g2);
    strcat(concatSockGen, str_g0t);
    strcat(concatSockGen, str_g2t);
    strcat(concatSockGen, str_BC);
    strcat(concatSockGen, converion3);
    
    mpz_set_str(tmp, concatSockGen, 10);
    mpz_mod(tmp, tmp, params->NN);
    char * tmpH3=mpz_get_str(NULL, 10, tmp);
    
    //c= (H_3 A || D || g0 || g2 || BC)
    uint8_t digest_h_3[SHA3_256_DIGEST_SIZE]={0};
    printf("\nhash_3 c\n");
    perform_hashing_sha3(sha3_256_ctx, sha3_256_init, sha3_256_update,
                            sha3_256_digest, SHA3_256_DIGEST_SIZE, tmpH3, &tmpH3[0], digest_h_3);
    
    mpz_import(ciphertext_K->c, SHA3_256_DIGEST_SIZE,1,1,0,0, digest_h_3);
    TestingHash("c_digest_h_3",digest_h_3, sizeof(digest_h_3));
    
    //s=(t-cx), x=r
    mpz_mul(tmp, ciphertext_K->c, r);//pmesg_mpz(msg_very_verbose, "c*x =", tmp);
    mpz_sub(ciphertext_K->s, t, tmp );
    
    /* scelta del generatore: per ogni k,divisore, di ogni elemento
     * di phi_N la divisione deve essere diverso da 1. In questo caso phi_p=2*q.
     * Occorre verificare g^2!=1 && g^q!=1. Qui
     * e' richiesto che g sia solo conforme alla definizione di generatore
     */
    
    /* .considerare N come il quadrato di due safe prime. es gli elementi che fatt p^2 sono: 4p'^2 e 4p'
     *
     */
    
    /*do {
        
        mpz_add_ui(ciphertext_K->g,ciphertext_K->g,1);//g+=1
        
        //tmp=g^2 mod N^2
        mpz_powm_ui(tmp, ciphertext_K->g, 2, N_2);
        if ((mpz_cmp_ui(tmp,1)==0)) 
            continue;        

    } while((mpz_cmp_ui(tmp,1)==0) );*/
    //
    mpz_powm(tmp, pk->g1, r, params->NN);
    pmesg_mpz(msg_very_verbose, "g^ar  DA OTTENERE =", tmp);
    
    printf("\n\n");
    printf("output ciphertext. K=(A, B, D, c, s)\n");
    pmesg_mpz(msg_very_verbose, "r =",r);
    pmesg_mpz(msg_very_verbose, "sigma =", sigma);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->A =",ciphertext_K->A);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->B =",ciphertext_K->B);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->C =",ciphertext_K->C);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->D =",ciphertext_K->D);
    pmesg_mpz(msg_very_verbose, "c =", ciphertext_K->c);
    pmesg_mpz(msg_very_verbose, "s =", ciphertext_K->s);
    

    free(concat_h1);
    free(concat_h2);
    free(str_BC);
    free(concatSockGen);
    mpz_clears(sigma, r, tmp, t, g0_t, g2_t, NULL);
}


/*
 * decrypt
 */
void decryption (const ciphertext_t K, const public_key_t pk, const shared_params_t params,
                 const state_t PRE_state, const weak_secret_key_t wsk, const private_key_t sk, gmp_randstate_t prng) {
    
    assert(pk);
    assert(params);
    assert(K);
    
    
    //caso 1 K= A, B, C, D, c, s
    
    mpz_t g0_s_A_c, g2_s_D_c, check_c, tmp, cmt_sigma, cmt_m, hash, tmp_g1, pi, lamb_N, a, r, w_1, tmpg, maxordG, tmpg1, tmp1;
    mpz_inits(g0_s_A_c, g2_s_D_c, check_c, tmp, cmt_sigma, cmt_m, hash, tmp_g1, pi, lamb_N, a, r, w_1, tmpg, maxordG, tmpg1, tmp1, NULL);
    
    //g0^s * A^c mod N^2
    mpz_powm(g0_s_A_c, pk->g0, K->s, params->NN);
    mpz_powm(tmp, K->A, K->c, params->NN);
    mpz_mul(g0_s_A_c, g0_s_A_c, tmp);
    mpz_mod(g0_s_A_c, g0_s_A_c, params->NN);
    //gmp_printf("go^t: %Zd\n", g0_s_A_c);
    
    //g2^s * D^c mod N^2
    mpz_powm(g2_s_D_c, pk->g2, K->s, params->NN);
    mpz_powm(tmp, K->D, K->c, params->NN);
    mpz_mul(g2_s_D_c, g2_s_D_c, tmp); 
    mpz_mod(g2_s_D_c, g2_s_D_c, params->NN);
    
    char * str_A= mpz_get_str(NULL, 10, K->A);
    char * str_D= mpz_get_str(NULL, 10, K->D);
    char * str_g0= mpz_get_str(NULL, 10, pk->g0);
    char * str_g2= mpz_get_str(NULL, 10, pk->g2);
    char * str_g0_s_A_c= mpz_get_str(NULL, 10, g0_s_A_c);
    char * str_g2_s_D_c= mpz_get_str(NULL, 10, g2_s_D_c);
    char * str_B= mpz_get_str(NULL, 10, K->B);
    char * str_C= mpz_get_str(NULL, 10, K->C);
    char converion3[16];
    ul_to_char(PRE_state->h_3,converion3);
    
    char *string_c=(char *)malloc(1+strlen(str_A)+strlen(str_D)+strlen(str_g0)+strlen(str_g2)+
                                                strlen(str_g0_s_A_c)+strlen(str_g2_s_D_c)+strlen(str_B)+strlen(str_C)+strlen(converion3));
    strcpy(string_c, str_A);
    strcat(string_c, str_D);
    strcat(string_c, str_g0);
    strcat(string_c, str_g2);
    strcat(string_c, str_g0_s_A_c);
    strcat(string_c, str_g2_s_D_c);
    strcat(string_c, str_B);
    strcat(string_c, str_C);
    strcat(string_c, converion3);
    
    mpz_set_str(tmp, string_c, 10);
    mpz_mod(tmp, tmp, params->NN);
    char * tmpcH3=mpz_get_str(NULL, 10, tmp);
    
    uint8_t digest_c[SHA3_256_DIGEST_SIZE];
    perform_hashing_sha3(sha3_256_ctx, sha3_256_init, sha3_256_update,
                            sha3_256_digest, SHA3_256_DIGEST_SIZE, tmpcH3, &tmpcH3[0], digest_c);

    mpz_import(check_c, SHA3_256_DIGEST_SIZE,1,1,0,0, digest_c);
    /*gmp_printf("K->c: %Zx\n", K->c);
    gmp_printf("check_c: %Zx\n", check_c);*/
    printf("\n");

    
    if(!mpz_cmp(K->c, check_c)==0) {
        _EXIT("ciphertext non conforme, errore in");
    } 
    
     //if input secret key=weak_secret
    else if (wsk){
            printf("digest c valutato correttamente...");
            printf("input secret key weak\n\n");
            mpz_powm(cmt_sigma, K->A, wsk->a, params->NN);
            mpz_invert(cmt_sigma, cmt_sigma, params->NN);
            
            mpz_mul(cmt_sigma, K->B, cmt_sigma);
            mpz_mod(cmt_sigma, cmt_sigma, params->NN);
            
            mpz_sub_ui(cmt_sigma, cmt_sigma, 1);                                                                                                                                                                                                                                                                              
            mpz_mod(cmt_sigma, cmt_sigma, params->NN);
            
            //get sigma
            mpz_cdiv_q(cmt_sigma, cmt_sigma, params->N);
        }
        
    else {
        printf("digest c valutato correttamente...");
        printf("input secret key long term secret key\n\n");
        //p, q, p' e q'
        
        //2p'q' (Carmichael's function)
        mpz_mul(lamb_N, sk->p_1, sk->q_1);
        mpz_mul_ui(lamb_N, lamb_N, 2);
        pmesg_mpz(msg_very_verbose, "lamb_N= ", lamb_N);

        //ordG
        mpz_mul(maxordG, params->N, lamb_N);
        mpz_cdiv_q_ui(maxordG, maxordG, 2);
        pmesg_mpz(msg_very_verbose, "ord(G)= ", maxordG);


        //mpz_set_ui(tmpg, 1);

        //mpz_set_ui(tmpg1)
        do {
            
            //mpz_add_ui(tmpg, tmpg, 1);
            

            mpz_urandomm(tmpg, prng, params->NN);
            
            //tmpg1 in G
            mpz_urandomm(tmpg1, prng, params->NN);
            
            mpz_powm(tmp, tmpg1, maxordG, params->NN);
            
            if(!mpz_cmp_ui(tmp,1)==0)
                continue;

            
            //DPL r
            mpz_powm(r, tmpg, lamb_N, params->NN);
            mpz_sub_ui(r, r, 1);
            mpz_mod(r, r, params->NN);
            mpz_cdiv_q(r, r, params->N);
            
            
            pmesg_mpz(msg_very_verbose, "generatore candidato di massimo ordine", tmpg1);
            
            //DPL a
            mpz_powm(a, tmpg1, lamb_N, params->NN);
            mpz_sub_ui(a, a, 1);
            mpz_mod(a, a, params->NN);
            mpz_cdiv_q(a, a, params->N);

            //mpz_powm(tmp, tmp, a, maxordG);

            /*mpz_mul(tmp, a, r);
            mpz_mod(tmp, tmp, params->N);
            
            mpz_mul(tmpg, a, r);
            mpz_mod(tmpg, tmpg, maxordG);
            
            mpz_sub(tmp, tmpg, tmp);
            mpz_cdiv_q(tmp, tmp, params->N);
            
            pmesg_mpz(msg_very_verbose, "gamma2", tmp);*/
            
            
            mpz_powm(tmp, pk->g0, a, params->NN);
        
            //test
        } while ( !mpz_cmp(tmp, pk->g1)==0);
        
        pmesg_mpz(msg_very_verbose, "PDL: r mod N", r);
        pmesg_mpz(msg_very_verbose, "PDL: a mod N", a);

    
        
        //w_1= a*r mod N
        mpz_mul(w_1, a, r);
        mpz_mod(w_1, w_1, params->N);
        
        
        pmesg_mpz(msg_very_verbose, "w_1= a*r mod N", w_1);     
        
        
        //mpz_powm(cmt_sigma, K->A, a, params->NN);
        mpz_powm(cmt_sigma, pk->g0, w_1, params->NN);
        
        mpz_invert(cmt_sigma, cmt_sigma, params->NN);
        mpz_mul(cmt_sigma, K->B, cmt_sigma);
        mpz_powm(cmt_sigma, cmt_sigma, lamb_N, params->NN);
        
        //D
        mpz_sub_ui(cmt_sigma, cmt_sigma, 1);
        mpz_mod(cmt_sigma, cmt_sigma, params->NN);
        mpz_cdiv_q(cmt_sigma, cmt_sigma, params->N);
        
        //get pi
        mpz_invert(pi, lamb_N, params->N);
        
        //get sigma
        mpz_mul(cmt_sigma, cmt_sigma, pi);
        mpz_mod(cmt_sigma, cmt_sigma, params->N);
        
    }
    
    /* computing */
    
    char * str_cmt_sigma=cnt_string(mpz_get_str(NULL, 10, cmt_sigma), NULL, PRE_state->h_2);
    mpz_set_str(tmp, str_cmt_sigma, 10);
    mpz_mod(tmp, tmp, params->NN);
    char * tmpsig=mpz_get_str(NULL, 10, tmp);
    
    //H2 sgima
    uint8_t digest_cmt_sigma [SHA3_384_DIGEST_SIZE];
    perform_hashing_sha3(sha3_384_ctx, sha3_384_init, sha3_384_update,
                        sha3_384_digest, SHA3_384_DIGEST_SIZE, tmpsig, &tmpsig[0], digest_cmt_sigma);
                
    
    //get m
    mpz_import(tmp, SHA3_384_DIGEST_SIZE,1,1,0,0, digest_cmt_sigma);
    mpz_xor(cmt_m, K->C, tmp);
    
    char * str_h_sm=cnt_string(mpz_get_str(NULL, 10, cmt_sigma), mpz_get_str(NULL, 10, cmt_m), PRE_state->h_1);
    mpz_set_str(tmp, str_h_sm, 10);
    mpz_mod(tmp, tmp, params->NN);
    char * tmp_hsm=mpz_get_str(NULL, 10, tmp);
    
    uint8_t digest_h_sm[SHA3_512_DIGEST_SIZE];
    printf("\n");
    perform_hashing_sha3(sha3_512_ctx, sha3_512_init, sha3_512_update,
                        sha3_512_digest, SHA3_512_DIGEST_SIZE, tmp_hsm, &tmp_hsm[0], digest_h_sm);
    
    mpz_import(hash, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_sm);
    
    //g1^r mod N^2
    mpz_powm(tmp_g1, pk->g1, hash, params->NN);
    
    //g1^r * (1+sigma*N) mod N^2  ( a*b mod = mod (a mod * b mod ) )
    //(1+sigma*N) mod N^2
    mpz_mul(tmp, cmt_sigma, pk->N);
    mpz_add_ui(tmp,tmp,1);
    mpz_mod(tmp, tmp, params->NN);
    
    //get B
    mpz_mul(tmp, tmp_g1, tmp);
    mpz_mod(tmp, tmp, params->NN);

    printf("\n");
    pmesg_mpz(msg_very_verbose, "compute sigma =", cmt_sigma);
    
    if(mpz_cmp(tmp,K->B)==0) {
        printf("\nciphertext conforme, messaggio decifrato correttamente.\n");
        pmesg_mpz(msg_very_verbose, "message =", cmt_m);
        
    } else { _EXIT("Errore in fase di decryption. ");}

    
    
    
    
    
    
    
    //caso2
    
    
    
    
    
    mpz_clears(g0_s_A_c, g2_s_D_c, check_c, tmp, cmt_sigma, cmt_m, hash, tmp_g1, pi, lamb_N, a, r, w_1, tmpg, maxordG, tmpg, tmp1, NULL);
    free(string_c);
}



/*
 * verifica la correttezza dei parametri
 *
 */
bool verify_params(const shared_params_t params) {
    
    bool return_value = true;
    assert(params);
 if ((params->p_1_bits >= params->p_bits) || (params->q_1_bits >= params->q_bits))
        return_value = false;
    
    return (return_value);
}


/*
 * init method
 */

void state_init(state_t state){
    assert(state);
    //state->progression=progression_ready_to_start;
    mpz_inits(state->eph_exp, state->key,NULL);
}

void msg_init(msg_t msg) {
    assert(msg);
    mpz_init(msg->contrib);
}

void plaintext_init(plaintext_t plaintext) {
    assert(plaintext);
    mpz_init(plaintext->m);
}

void ciphertext_init(ciphertext_t K) {
    assert(K);
    mpz_inits(K->A, K->B, K->C, K->D, K->A_1, K->A_p,  K->B_p,
                    K->C_p, K->c, K->s, NULL);
}

/*
 * clear method
 */

void public_key_clear(public_key_t pk) {
    assert(pk);
    mpz_clears(pk->N, pk->g0, pk->g1, pk->g2, NULL);
}

void private_key_clear(private_key_t sk) {
    assert(sk);
    mpz_clears(sk->p, sk->q, sk->p_1, sk->q_1, NULL);
}

void weak_secret_key_clear(weak_secret_key_t wsk){
    assert(wsk);
    mpz_clears(wsk->a, wsk->b, NULL);
}

void shared_params_clear(shared_params_t params) {
    assert(params);
    mpz_clears(params->N, params->p, params->p_1, params->q, params->q_1, NULL);
}

void plaintext_clear(plaintext_t plaintext) {
    assert(plaintext);
    mpz_clear(plaintext->m);
}

void ciphertext_clear(ciphertext_t K) {
    assert(K);
        mpz_clears(K->A, K->B, K->C, K->D, K->A_1, K->A_p,  K->B_p,
                    K->C_p, K->c, K->s, NULL);
}

    
/****/

//2 modo meno efficiente
    /*do {
        do {
            if ( fparent) {
                
                //cerco un primo p' random range 0-2^(p_1_bits)-1
                mpz_urandomb(params->p_1,prng,params->p_1_bits);
                if(mpz_sizeinbase(params->p_1, 2) == params->p_1_bits){
                    if ((mpz_probab_prime_p(params->p_1, mr_iterations)>=1)){
                        //pmesg_mpz(msg_very_verbose, "CONDIZIONE IF su p' ", params->p_1);
                        fchild=0;
                        fparent=0;

                    }
                }
            }
            if ( fparent1) {
                //cerco un primo q'
                mpz_urandomb(params->q_1,prng,params->q_1_bits);
                if ( (mpz_sizeinbase(params->q_1, 2)==params->q_1_bits)) {
                    if( mpz_probab_prime_p(params->q_1, mr_iterations)>=1) {
                        //pmesg_mpz(msg_very_verbose, "CONDIZIONE IF su Q' ", params->q_1);
                        fchild1=0;
                        fparent1=0;

                    }
                }
           }
           countv2++;
        }while(fchild || fchild1);
        //printf("fchild %d . fchild1 %d\n",fchild,fchild1);
        //pmesg_mpz(msg_very_verbose, "safeprime PP' ", params->p_1);
        //pmesg_mpz(msg_very_verbose, "safeprime Q' ", params->q_1);
        //printf("\n\n");
        
        if( !fchild ) {

            //calcolo p=2*p'+1
            mpz_mul_ui(params->p,params->p_1,2);
            mpz_add_ui(params->p,params->p,1);
            
            //0=not prime def
            if( !mpz_probab_prime_p(params->p,mr_iterations) ) {
                fparent=1;
                fchild=1;
            }
        } 
         if (!fchild1) {
             
             //calcolo q=2*q'+1
            mpz_mul_ui(params->q,params->q_1,2);
            mpz_add_ui(params->q,params->q,1);
            if(!mpz_probab_prime_p(params->q,mr_iterations)) {
                fparent1=1;
                fchild1=1;
            }
         }
         countv2++;
         //mcountv2+=countv2;
        } while ( fchild || fchild1 );
        printf("countv2= %d\n\n",countv2);*/

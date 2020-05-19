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
    
    // printf("%c", STR[i]);
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

 static inline void ul_to_char(uint16_t h_X, char *result){
     
     const int n= snprintf(NULL, 0, "%u", h_X);
     //printf("valore da convertire= %lu, n= %d\n",h_X,n);
    assert(n>0);
    snprintf(result, n+1, "%u", h_X);
}

static inline  char *cnt_string( char *str, char *str1, uint16_t id ){
    
    char  converion [16]={0};
    if (!str1) {
        
        ul_to_char(id, converion);
        char * concatString= (char *) malloc(strlen(str)+strlen(converion)+1);
        strcpy(concatString, str);
        strcat(concatString, converion);
        return concatString;
    }    
    else {

        ul_to_char(id, converion);
        char * concatString= (char *) malloc(strlen(str)+strlen(str1)+strlen(converion)+1);
        strcpy(concatString, str);
        strcat(concatString, str1);
        strcat(concatString,converion);
        return concatString;
    }
}

static inline char * cnt_check_c(char *str, char *str1, char *str2, char *str3, char *str4, char *str5,
                                                char *str6, char *str7, uint16_t id){
    
    char converion[16];
    ul_to_char(id,converion);
    
    char *string_c=(char *)malloc(strlen(str)+strlen(str1)+strlen(str2)+strlen(str3)+
                                                strlen(str4)+strlen(str5)+strlen(str6)+strlen(str7)+strlen(converion)+1);
    strcpy(string_c, str);
    strcat(string_c, str1);
    strcat(string_c, str2);
    strcat(string_c, str3);
    strcat(string_c, str4);
    strcat(string_c, str5);
    strcat(string_c, str6);
    strcat(string_c, str7);
    strcat(string_c, converion);
     return string_c;
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
    dev_random=NULL;
    return seed;
}


/* 
 * get shared params
 */
void generate_shared_params(shared_params_t *params, unsigned n_bits, gmp_randstate_t prng) {

    pmesg(msg_verbose, "generazione parametri...");
      
    if (params==NULL)
        _EXIT("errore nella generazione dei parametri");
    
    assert(n_bits>1);
    assert(prng);

    //scelta delle taglie di p e q
    params->p_bits=n_bits;
    params->q_bits=n_bits;
    params->p_1_bits=n_bits-1; // p'
    params->q_1_bits=n_bits-1; // q'
    
    //scelta della taglia di p e q con un N fissato (secondo modo)
    //params->p_bits = n_bits >> 1;
    //params->q_bits = n_bits - params->p_bits;


    //p della forma 2*p'+1 con p' e p primi
    //q della forma 2*q'+1 con q' e q primi
    

    do {
        do {
            
            //cerco un primo p' random range 0-2^(p_1_bits)-1
            mpz_urandomb(params->p_1, prng, params->p_1_bits);
        }while((mpz_sizeinbase(params->p_1, 2) < params->p_1_bits) ||
                    !mpz_probab_prime_p(params->p_1, mr_iterations));
        
        //calcolo p=2*p'+1
        mpz_mul_ui(params->p, params->p_1, 2);
        mpz_add_ui(params->p,params->p,1);
        }while(!mpz_probab_prime_p(params->p,mr_iterations));
    
    do {
        do{
            //cerco un primo q'
            mpz_urandomb(params->q_1, prng,params->q_1_bits);
        }while((mpz_sizeinbase(params->q_1, 2)< params->q_1_bits) || 
                    !mpz_probab_prime_p(params->q_1, mr_iterations));
        
        //calcolo q=2*q'+1
        mpz_mul_ui(params->q, params->q_1, 2);
        mpz_add_ui(params->q, params->q,1);
    }while ( !mpz_probab_prime_p(params->q, mr_iterations) );
    
    //N=p*q
    mpz_mul(params->N, params->p, params->q);

    pmesg_mpz(msg_very_verbose, "modulo p =",params->p);
    pmesg_mpz(msg_very_verbose, "modulo q =",params->q);
    pmesg_mpz(msg_very_verbose, "modulo p*q =",params->N);
    pmesg_mpz(msg_very_verbose, "primo divisore p' dell'ordine", params->p_1);
    pmesg_mpz(msg_very_verbose, "primo divisore p' dell'ordine", params->q_1);
}


void PRE_scheme_state (state_t *PRE_state) {
    
    unsigned int buffer[3];
    int byte_count=16;
    FILE *dev_random;
    CHECK(dev_random = fopen("/dev/random", "r"));

	fread(&buffer,sizeof(char), byte_count, dev_random);
    
    PRE_state->h_1=(*(&buffer[0])%10000);
    PRE_state->h_2=(*(&buffer[1])%10000);
    PRE_state->h_3=(*(&buffer[2])%10000);
    
    for(int i=0;i<3;i++)
        printf(" buffer[%d] = %u", i, buffer[i]%10000);
    fclose(dev_random);
    dev_random=NULL;
    
}

/*
 * contrib KeyGen
 */
void generate_keys(public_key_t *pk, private_key_t *sk, weak_secret_key_t *wsk,
                        const shared_params_t *params, gmp_randstate_t prng,
                            const state_t *PRE_state,msg_t *wsk_2proxy, char *secret, char *name){

    assert(prng);
    
    if ( pk==NULL || sk==NULL || PRE_state==NULL || params==NULL || wsk==NULL ||
         wsk_2proxy==NULL)
        _EXIT("encryption fallita");
    
    pmesg(msg_verbose, "generazione del contributo...");
    
    mpz_t alpha, tmp,test_1,test_2,test_3,test_a,alpha2, pp, qq;
    mpz_inits(alpha, tmp, test_1,test_2,test_3,test_a,alpha2,pp, qq,  NULL);
    
    //set N, NN e id_hash
    mpz_set(pk->N, params->N);
    mpz_mul(pk->NN, pk->N, pk->N);
    
    
    //set sk keys
    mpz_set(sk->p, params->p);
    mpz_set(sk->p_1, params->p_1);
    mpz_set(sk->q, params->q);
    mpz_set(sk->q_1, params->q_1);
    
    //p^2, q^2 
    mpz_mul(pp, sk->p, sk->p);
    mpz_mul(qq, sk->q, sk->q);
    
    //apha in Z*n^2
    /*do {
        mpz_urandomm(alpha, prng, pk->NN);
        mpz_gcd(tmp, alpha, pk->NN);
        gmp_printf("\ngcd(alpha, N^2) = %Zd\n",tmp);
    } while (mpz_get_ui(tmp)!=1L);*/
    
    //testing
        mpz_urandomm(alpha, prng, pk->N);
        mpz_urandomm(alpha2, prng, pk->N);
        mpz_mul(alpha2, alpha2, pk->N);
        mpz_add(alpha, alpha, alpha2);
    
        
    // calcolo il range [pp' qq'], maxordG 
    mpz_mul(tmp, pk->N, sk->p_1);
    mpz_mul(tmp, tmp, sk->q_1);
        
    //a,b random in [1,pp' qq'], 0 escluso
    do {
        mpz_urandomm(wsk->a, prng, tmp);
        mpz_urandomm(wsk->b, prng, tmp);
    } while( (mpz_cmp_ui(wsk->a,0)==0) || (mpz_cmp_ui(wsk->b,0)==0));
    

    do {
        
        //g0 = alpha^2 mod N^2
        mpz_powm_ui(pk->g0, alpha, 2, pk->NN);
        if (mpz_jacobi(pk->g0,pk->NN)==1) {
            printf("\n\nQR(g0)=%d, g0 potrebbe essere un QR\n", mpz_jacobi(pk->g0,pk->NN));
            if(!(mpz_legendre(pk->g0, pp)==1 && mpz_legendre(pk->g0, qq)==1))
                continue;
            //check
            else {printf("g0/p^2= %d, g0/q^2= %d\n\n",mpz_legendre(pk->g0, pp), mpz_legendre(pk->g0, qq));}
        }
        else continue;
        
        //g1 = g0^a mod N^2
        mpz_powm(pk->g1, pk->g0, wsk->a, pk->NN);
        if (mpz_jacobi(pk->g1,pk->NN)==1) {
            if(!(mpz_legendre(pk->g1, pp)==1 && mpz_legendre(pk->g1, qq)==1))
                continue;
        }
        else continue;
        
        //g2= g0^b mod N^2
        mpz_powm(pk->g2, pk->g0, wsk->b, pk->NN);
        if(!(mpz_jacobi(pk->g2,pk->NN)==1))
            continue;
        
    }while(!(mpz_legendre(pk->g2, pp)==1 && mpz_legendre(pk->g2, qq)==1));
    
    if (strcmp(secret, "weaka")==0)
        mpz_set(wsk_2proxy->contrib, wsk->a);
    else
        mpz_set(wsk_2proxy->contrib, wsk->b);
    
    //pk
    printf("\npk = (H(.), N, g0, g1, g2)\n");
    pmesg_mpz(msg_very_verbose, "alpha =",alpha);
    pmesg_mpz(msg_very_verbose, "modulo N=",pk->N);
    pmesg_mpz(msg_very_verbose, "g0 =",pk->g0);
    pmesg_mpz(msg_very_verbose, "g1 =",pk->g1);
    pmesg_mpz(msg_very_verbose, "g2=",pk->g2);
    
    if (strcmp(name, "alice")==0)
        pk->id_hash=PRE_state->h_1;
    else
        pk->id_hash=PRE_state->h_2;
    printf("   H (.) = %u\n", pk->id_hash);
    
    //weak secret
    printf("\nweak secret,");
    pmesg_mpz(msg_very_verbose, " range di scelta di a, b in [1, pp'qq'] =", tmp);
    pmesg_mpz(msg_very_verbose, "a =",wsk->a);
    pmesg_mpz(msg_very_verbose, "b =",wsk->b);
    
    //sk
    printf("\nsk = (p, q, p', q')\n");
    pmesg_mpz(msg_very_verbose, "p =",sk->p);
    pmesg_mpz(msg_very_verbose, "q =",sk->q);
    pmesg_mpz(msg_very_verbose, "p' = ", sk->p_1);
    pmesg_mpz(msg_very_verbose, "q' = ", sk->q_1);
    
    pmesg_mpz(msg_very_verbose, "N^2=", pk->NN);
    printf("\n\n");
    
    
    
                   //testing
                    mpz_mul(tmp, sk->p_1, sk->q_1);
                    mpz_mul_ui(tmp, tmp, 2);
                    pmesg_mpz(msg_very_verbose, "lamb_N= ", tmp);
                    
                    mpz_powm(test_a, pk->g1, tmp, pk->NN);
                    pmesg_mpz(msg_very_verbose, "h^(lamb_N) mod N^2 = ", test_a);
                    mpz_sub_ui(test_a, test_a, 1);
                    mpz_mod(test_a, test_a, pk->NN);
                    pmesg_mpz(msg_very_verbose, "C-1 mod N^2 = ", test_a);
                    mpz_cdiv_q(test_a, test_a, pk->N); 
                
                    
                            printf("\n");
                            mpz_mod(test_1, wsk->a, pk->N);
                            
                            pmesg_mpz(msg_very_verbose, "test_1 a mod N atteso= ", test_1);

                
                            pmesg_mpz(msg_very_verbose, "test_a, a mod N computato = ", test_a);
                            
                            mpz_mul(test_a, wsk->a, pk->N);
                            mpz_add_ui(test_a, test_a, 1);
                            mpz_mod(test_a, test_a, pk->NN);
                            pmesg_mpz(msg_very_verbose, "(1+aN) mod N^2 = ", test_a);
                            
    mpz_clears(alpha, tmp, pp, qq, NULL);
    //exit(1);
}


/*
 * encrypt, k=ABCDcs
 */
void encrypt(gmp_randstate_t prng, const plaintext_t *plaintext, public_key_t *pk,//const public_key_t
                    ciphertext_t *ciphertext_K, const state_t *PRE_state) {    

    assert(prng);
    if ( plaintext==NULL || pk==NULL || ciphertext_K==NULL || PRE_state==NULL  )
        _EXIT("encryption fallita");
    
    mpz_t sigma, r, tmp, t, g0_t, g2_t;
    
    //check plaintext, servono ulteriori controlli?
    assert(mpz_cmp_ui(plaintext->m, 0L)>0);
    assert(mpz_cmp(plaintext->m, pk->N) < 0);
    
    mpz_inits(sigma, r, tmp, t, g0_t, g2_t, NULL);
    
    pmesg_mpz(msg_very_verbose, "testo in chiaro", plaintext->m);
    
    //sigma in Zn random
    mpz_urandomm(sigma, prng, pk->N);
    
    //H1 sigma || m || id, (string base 10)
    char *str_sigma=mpz_get_str(NULL, 10, sigma);
    char *str_plaintext=mpz_get_str(NULL, 10, plaintext->m);
    char * concat_h1=cnt_string(str_sigma, str_plaintext, pk->id_hash);
    //printf("pk->id_hash= %u\n\n", pk->id_hash);
    
    mpz_set_str(tmp, concat_h1, 10);
    mpz_mod(tmp, tmp, pk->NN);
    
    char * tmpH1=mpz_get_str(NULL, 10, tmp);
    
    uint8_t digest_h_1[SHA3_512_DIGEST_SIZE];
    printf("\n r=H (sigma||m||id)\n");
    perform_hashing_sha3(sha3_512_ctx, sha3_512_init, sha3_512_update,
                            sha3_512_digest, SHA3_512_DIGEST_SIZE, tmpH1, &tmpH1[0], digest_h_1);
    
    //r
    mpz_import(r, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_1);
    //mpz_set(pk->testing_r, r);
    
    //A=go^r mod N^2
    mpz_powm(ciphertext_K->info_cipher.K_1.A, pk->g0, r, pk->NN);
    
    
    //H_2 (sigma || id )
    char * concat_h2=cnt_string(str_sigma, NULL, PRE_state->h_2);
    
    mpz_set_str(tmp, concat_h2, 10);
    mpz_mod(tmp, tmp, pk->NN);
    
    char * tmpH2=mpz_get_str(NULL, 10, tmp);
    uint8_t digest_h_2[SHA3_384_DIGEST_SIZE]={0};
    printf("\n H=(2 sigma || d)\n");
    perform_hashing_sha3(sha3_384_ctx, sha3_384_init, sha3_384_update,
                            sha3_384_digest, SHA3_384_DIGEST_SIZE, tmpH2, &tmpH2[0], digest_h_2);
    
    //C= H_2 (sigma || id ) xor m 
    mpz_import(tmp, SHA3_384_DIGEST_SIZE,1,1,0,0, digest_h_2);
    mpz_xor(ciphertext_K->info_cipher.K_1.C, tmp, plaintext->m);
    
    
    //D=g2^r mod N^2
    mpz_powm(ciphertext_K->info_cipher.K_1.D, pk->g2, r, pk->NN);
    
    //B=g1^r * (1+sigma*N) mod N^2  ( a*b mod = mod (a mod * b mod ) )
    
    //(1+sigma*N) mod N^2
    mpz_mul(tmp, sigma, pk->N);
    mpz_add_ui(tmp,tmp,1);
    mpz_mod(tmp, tmp, pk->NN);
    
    //g1^r mod N^2
    mpz_powm(ciphertext_K->info_cipher.K_1.B, pk->g1, r, pk->NN);
    pmesg_mpz(msg_very_verbose, ">>g1^r= g0^(ar)= mod N^2= ", ciphertext_K->info_cipher.K_1.B);
    
    
    //B=x*y mod N^2
    mpz_mul(ciphertext_K->info_cipher.K_1.B, ciphertext_K->info_cipher.K_1.B, tmp);
    mpz_mod(ciphertext_K->info_cipher.K_1.B, ciphertext_K->info_cipher.K_1.B, pk->NN);
    
    /** Sok.Gen **/

    //set t in 0 ,.., 2^(|N^2|+k) -1
    mpz_set_ui(t, mpz_sizeinbase(pk->NN,2)); //|N^2| is the bit-lenght of N^2
    mpz_add_ui(t, t, 512);
    //pmesg_mpz(msg_very_verbose, "t= ", t);
    unsigned int t_exp=mpz_get_ui(t);
    
    mpz_urandomb(t, prng, t_exp);
    
    mpz_powm(g0_t, pk->g0, t, pk->NN);
    mpz_powm(g2_t, pk->g2, t, pk->NN);
    
    //pmesg_mpz(msg_very_verbose, "g0_t from encrypt=", g0_t);
    //pmesg_mpz(msg_very_verbose, "g2_t from encrypt=", g2_t);
    
    char converion3[16];
    char * str_A=mpz_get_str(NULL, 10, ciphertext_K->info_cipher.K_1.A);
    char * str_D=mpz_get_str(NULL, 10, ciphertext_K->info_cipher.K_1.D);
    char * str_B=mpz_get_str(NULL, 10, ciphertext_K->info_cipher.K_1.B);
    char * str_C=mpz_get_str(NULL, 10, ciphertext_K->info_cipher.K_1.C);
    char * str_g0=mpz_get_str(NULL, 10, pk->g0);
    char * str_g2=mpz_get_str(NULL, 10, pk->g2);
    char * str_g0t=mpz_get_str(NULL, 10, g0_t);
    char * str_g2t=mpz_get_str(NULL, 10, g2_t);
    ul_to_char(PRE_state->h_3,converion3);
    
    char* str_BC= (char *) malloc(strlen(str_B)+strlen(str_C)+1);
    strcpy(str_BC, str_B);
    strcat(str_BC, str_C);
    
    char * concatSockGen= (char *) malloc(1+strlen(str_A)+strlen(str_D)+strlen(str_g0)+strlen(str_g2)+
                                                strlen(str_g0t)+strlen(str_g2t)+strlen(str_BC)+strlen(converion3)+1);

    strcpy(concatSockGen,str_A);
    strcat(concatSockGen, str_D);
    strcat(concatSockGen, str_g0);
    strcat(concatSockGen, str_g2);
    strcat(concatSockGen, str_g0t);
    strcat(concatSockGen, str_g2t);
    strcat(concatSockGen, str_BC);
    strcat(concatSockGen, converion3);
    
    mpz_set_str(tmp, concatSockGen, 10);
    mpz_mod(tmp, tmp, pk->NN);
    char * tmpH3=mpz_get_str(NULL, 10, tmp);
    
    //c= (H_3 A || D || g0 || g2 || BC)
    uint8_t digest_h_3[SHA3_256_DIGEST_SIZE]={0};
    printf("\n c=H3(A || D || g0 || g2 || BC)\n");
    perform_hashing_sha3(sha3_256_ctx, sha3_256_init, sha3_256_update,
                            sha3_256_digest, SHA3_256_DIGEST_SIZE, tmpH3, &tmpH3[0], digest_h_3);
    
    mpz_import(ciphertext_K->info_cipher.K_1.c, SHA3_256_DIGEST_SIZE,1,1,0,0, digest_h_3);
    
    
    //s=(t-cx), x=r
    mpz_mul(tmp, ciphertext_K->info_cipher.K_1.c, r);
    mpz_sub(ciphertext_K->info_cipher.K_1.s, t, tmp );
    
    ciphertext_K->type="K=(A, B, D, c, s)";
    
    printf("\nciphertext generato di tipo %s\n",ciphertext_K->type);
    pmesg_mpz(msg_very_verbose, "r =",r);
    pmesg_mpz(msg_very_verbose, "sigma =", sigma);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->A =",ciphertext_K->info_cipher.K_1.A);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->B =",ciphertext_K->info_cipher.K_1.B);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->C =",ciphertext_K->info_cipher.K_1.C);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->D =",ciphertext_K->info_cipher.K_1.D);
    pmesg_mpz(msg_very_verbose, "c =", ciphertext_K->info_cipher.K_1.c);
    pmesg_mpz(msg_very_verbose, "s =", ciphertext_K->info_cipher.K_1.s);
    mpz_mod(tmp, r, pk->N);
    pmesg_mpz(msg_very_verbose, "r mod N=",tmp);
    
    gmp_printf("\n\n");

    free(concat_h1);
    concat_h1=NULL;
    free(str_sigma);
    free(str_plaintext);
    str_sigma=NULL;
    str_plaintext=NULL;
    free(tmpH1);
    free(tmpH2);
    tmpH1=NULL;
    tmpH2=NULL;
    free(concat_h2);
    concat_h2=NULL;
    free(str_BC);
    str_BC=NULL;
    free(concatSockGen);
    concatSockGen=NULL;
    free(str_A);
    free(str_D);
    free(str_B);
    free(str_C);
    free(str_g0);
    free(str_g2);
    free(str_g0t);
    free(str_g2t);
    str_A=NULL;
    str_D=NULL;
    str_B=NULL;
    str_C=NULL;
    str_g0=NULL;
    str_g2=NULL;
    str_g0t=NULL;
    str_g2t=NULL;
    free(tmpH3);
    tmpH3=NULL;
    mpz_clears(sigma, r, tmp, t, g0_t, g2_t, NULL);
}


/*
 * decrypt
 */
void decryption (const ciphertext_t *K, const public_key_t *pk,
                 const state_t *PRE_state, const msg_t *wsk_, const private_key_t *sk, gmp_randstate_t prng) {
    
    
    assert(prng);
    
    if (pk==NULL || K==NULL || PRE_state==NULL  || sk==NULL )
        _EXIT("encryption fallita");
    
    mpz_t tmp, cmt_m, hash, cmt_sigma, tmp_g1;
    mpz_inits(tmp, cmt_m, hash, cmt_sigma, tmp_g1, NULL);

    if (strcmp(K->type, "K=(A, B, D, c, s)")==0) {
        
        printf("ricevuto in input un ciphertext K di tipo K=(A, B, D, c, s)...\n\n");
        printf("controllo idonieta' su K in corso...");
        
        mpz_t g0_s_A_c, g2_s_D_c, check_c, tmp;
        mpz_inits(g0_s_A_c, g2_s_D_c, check_c, tmp, NULL);
        
        //g0^s * A^c mod N^2
        mpz_powm(g0_s_A_c, pk->g0, K->info_cipher.K_1.s, pk->NN);
        mpz_powm(tmp, K->info_cipher.K_1.A, K->info_cipher.K_1.c, pk->NN);
        mpz_mul(g0_s_A_c, g0_s_A_c, tmp);
        mpz_mod(g0_s_A_c, g0_s_A_c, pk->NN);
        //gmp_printf("g0_s_A_c: %Zd\n", g0_s_A_c);
        
        //g2^s * D^c mod N^2
        mpz_powm(g2_s_D_c, pk->g2, K->info_cipher.K_1.s, pk->NN);
        mpz_powm(tmp, K->info_cipher.K_1.D, K->info_cipher.K_1.c, pk->NN);
        mpz_mul(g2_s_D_c, g2_s_D_c, tmp); 
        mpz_mod(g2_s_D_c, g2_s_D_c, pk->NN);           
                
        char * str_A=mpz_get_str(NULL, 10, K->info_cipher.K_1.A);
        char * str_D=mpz_get_str(NULL, 10, K->info_cipher.K_1.D);
        char * str_g0=mpz_get_str(NULL, 10, pk->g0);
        char * str_g2=mpz_get_str(NULL, 10, pk->g2);
        char * str_g0_s_A_c=mpz_get_str(NULL, 10, g0_s_A_c);
        char * str_g2_s_D_c=mpz_get_str(NULL, 10, g2_s_D_c);
        
        char * str_B=mpz_get_str(NULL, 10, K->info_cipher.K_1.B);
        char * str_C=mpz_get_str(NULL, 10, K->info_cipher.K_1.C);
        
        char *string_c=cnt_check_c(str_A, str_D, str_g0, str_g2, str_g0_s_A_c, str_g2_s_D_c, str_B,
                                                        str_C, PRE_state->h_3);
        
        mpz_set_str(tmp, string_c, 10);
        mpz_mod(tmp, tmp, pk->NN);
        char * tmpcH3=mpz_get_str(NULL, 10, tmp);

        uint8_t digest_c[SHA3_256_DIGEST_SIZE];
        perform_hashing_sha3(sha3_256_ctx, sha3_256_init, sha3_256_update,
                                sha3_256_digest, SHA3_256_DIGEST_SIZE, tmpcH3, &tmpcH3[0], digest_c);

        mpz_import(check_c, SHA3_256_DIGEST_SIZE,1,1,0,0, digest_c);
        printf("\n");
        
        //check c
        if(!mpz_cmp(K->info_cipher.K_1.c, check_c)==0)
            _EXIT("ciphertext non conforme o corrotto ");
        
        printf("[ OK] ciphertext K idoneo\n\n");
        printf("avvio procedure di decryption...\n");
        
        
         if (wsk_){
             
                printf("chiave input  per la decifrazione secret key weak\n\n");
                printf("digest c valutato correttamente...\n");
                mpz_powm(cmt_sigma, K->info_cipher.K_1.A, wsk_->contrib, pk->NN);
                pmesg_mpz(msg_very_verbose, "A^a=g0^ar= ", cmt_sigma);
                printf("\n");
                mpz_invert(cmt_sigma, cmt_sigma, pk->NN);
                
                mpz_mul(cmt_sigma, K->info_cipher.K_1.B, cmt_sigma);
                mpz_mod(cmt_sigma, cmt_sigma, pk->NN);
                
                mpz_sub_ui(cmt_sigma, cmt_sigma, 1);                                                                                                                                                                                                                                                                              
                mpz_mod(cmt_sigma, cmt_sigma, pk->NN);
                
                //get sigma
                mpz_cdiv_q(cmt_sigma, cmt_sigma, pk->N);
            }
            else {
                printf("chiave input  per la decifrazione long term secret key\n\n");
                printf("digest c valutato correttamente...\n");
                //testing
                mpz_t lamb_N, pi, a, r, w_1,test_1,test_2,test_3;
                mpz_inits (lamb_N, pi, a, r, w_1, test_1,test_2,test_3,NULL);
                
                //2p'q' (Carmichael's function)
                mpz_mul(lamb_N, sk->p_1, sk->q_1);
                mpz_mul_ui(lamb_N, lamb_N, 2);
                pmesg_mpz(msg_very_verbose, "lamb_N= ", lamb_N);

                //DPL a, a mod N
                mpz_powm(a, pk->g1, lamb_N, pk->NN);
                mpz_sub_ui(a, a, 1);
                mpz_mod(a, a, pk->NN);
                mpz_cdiv_q(a, a, pk->N);                
                
                //DPL r
                mpz_powm(r, K->info_cipher.K_1.A, lamb_N, pk->NN);
                mpz_sub_ui(r, r, 1);
                mpz_mod(r, r, pk->NN);
                mpz_cdiv_q(r, r, pk->N);                
                
                pmesg_mpz(msg_very_verbose, "PDL: a mod N", a);
                pmesg_mpz(msg_very_verbose, "PDL: r mod N", r);
                
                //w_1= a*r mod N
                mpz_mul(w_1, a, r);
                mpz_mod(w_1, w_1, pk->N);
                pmesg_mpz(msg_very_verbose, "w_1= a*r mod N", w_1); 
                printf("\n");

                
                                    
                //testing
                        /*    printf("valori passati senza essere computati\n");
                            mpz_mod(test_1, wsk_->contrib, pk->N);
                            pmesg_mpz(msg_very_verbose, "test_1 a mod N atteso= ", test_1);
                            mpz_mod(test_2, pk->testing_r, pk->N);
                            pmesg_mpz(msg_very_verbose, "test_2 r mod N atteso= ", test_2);
                
                            mpz_mul(test_3, test_1, test_2);
                            mpz_mod(test_3, test_3, pk->N);
                            pmesg_mpz(msg_very_verbose, "test_3, ar mod N computato = ", test_3);*/
                            
                            
                
                            

                //mpz_powm(cmt_sigma, pk->g0, test_3, pk->NN);
                mpz_powm(cmt_sigma, pk->g0, w_1, pk->NN);
                
                
                mpz_invert(cmt_sigma, cmt_sigma, pk->NN);
                mpz_mul(cmt_sigma, K->info_cipher.K_1.B, cmt_sigma);
                mpz_mod(cmt_sigma, cmt_sigma, pk->NN);
                
                mpz_powm(cmt_sigma, cmt_sigma, lamb_N, pk->NN);
                
                //D
                mpz_sub_ui(cmt_sigma, cmt_sigma, 1);
                mpz_mod(cmt_sigma, cmt_sigma, pk->NN);
                mpz_cdiv_q(cmt_sigma, cmt_sigma, pk->N);
                
                //get pi
                mpz_invert(pi, lamb_N, pk->N);
                
                //get sigma
                mpz_mul(cmt_sigma, cmt_sigma, pi);
                mpz_mod(cmt_sigma, cmt_sigma, pk->N);
                
                mpz_clears (lamb_N, pi, a, r, w_1, NULL);
            }
            
            // computing //
            char *str_sigma=mpz_get_str(NULL, 10, cmt_sigma);
            char * str_cmt_sigma=cnt_string(str_sigma, NULL, PRE_state->h_2);
            mpz_set_str(tmp, str_cmt_sigma, 10);
            mpz_mod(tmp, tmp, pk->NN);
            char * tmpsig=mpz_get_str(NULL, 10, tmp);
    
            //H2 sgima
            uint8_t digest_cmt_sigma [SHA3_384_DIGEST_SIZE];
            perform_hashing_sha3(sha3_384_ctx, sha3_384_init, sha3_384_update,
                                sha3_384_digest, SHA3_384_DIGEST_SIZE, tmpsig, &tmpsig[0], digest_cmt_sigma);
        
            //get m
            mpz_import(tmp, SHA3_384_DIGEST_SIZE,1,1,0,0, digest_cmt_sigma);
            mpz_xor(cmt_m, K->info_cipher.K_1.C, tmp);
            
            char *str_cmt_m=mpz_get_str(NULL, 10, cmt_m);
            char * str_h_sm=cnt_string(str_sigma, str_cmt_m, PRE_state->h_1);
            mpz_set_str(tmp, str_h_sm, 10);
            mpz_mod(tmp, tmp, pk->NN);
            char * tmp_hsm=mpz_get_str(NULL, 10, tmp);
            
            uint8_t digest_h_sm[SHA3_512_DIGEST_SIZE];// hash decryptor
            printf("\n");
            perform_hashing_sha3(sha3_512_ctx, sha3_512_init, sha3_512_update,
                                sha3_512_digest, SHA3_512_DIGEST_SIZE, tmp_hsm, &tmp_hsm[0], digest_h_sm);
            
            mpz_import(hash, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_sm);    
            
            //g1^r mod N^2
            mpz_powm(tmp_g1, pk->g1, hash, pk->NN);
            
            //g1^r * (1+sigma*N) mod N^2  ( a*b mod = mod (a mod * b mod ) )
            //(1+sigma*N) mod N^2
            mpz_mul(tmp, cmt_sigma, pk->N);
            mpz_add_ui(tmp,tmp,1);
            mpz_mod(tmp, tmp, pk->NN);
            
            //get B
            mpz_mul(tmp, tmp_g1, tmp);
            mpz_mod(tmp, tmp, pk->NN);

            
            pmesg_mpz(msg_very_verbose, "compute sigma= ", cmt_sigma);
            printf("\n");
            
            if(mpz_cmp(tmp, K->info_cipher.K_1.B)==0) {
                
                printf("\nciphertext conforme, messaggio decifrato correttamente.\n");
                pmesg_mpz(msg_very_verbose, "message =", cmt_m);
            
                free(str_sigma);
                free(str_cmt_sigma);
                free(tmpsig);
                free(tmp_hsm);
                free(str_h_sm);
                free(str_cmt_m);
                str_sigma=NULL;
                str_cmt_sigma=NULL;
                tmpsig=NULL;
                tmp_hsm=NULL;
                str_h_sm=NULL;
                str_cmt_m=NULL;
                
                mpz_clears(cmt_m, hash, cmt_sigma, tmp_g1, NULL);
                
            }
            else  _EXIT("[ X] ciphertext K di input corrotto");
            printf("\n");
            
            
            free(str_A);
            free(str_D);
            free(str_g0);
            free(str_g2);
            free(str_g0_s_A_c);
            free(str_g2_s_D_c);
            free(str_B);
            free(str_C);
            free(tmpcH3);
            free(string_c);
            str_A=NULL;
            str_D=NULL;
            str_B=NULL;
            str_C=NULL;
            str_g0=NULL;
            str_g2=NULL;
            str_g0_s_A_c=NULL;
            str_g2_s_D_c=NULL;
            tmpcH3=NULL;
            string_c=NULL;
            
            mpz_clears(g0_s_A_c, g2_s_D_c, check_c, tmp, NULL);
        
    }
    
    else if ( strcmp(K->type, "K=(A, A', B, C, A_dot, B_dot, C_dot)")==0)  {
        
        printf("ricevuto in input un ciphertext K di tipo K=(A, A', B, C, A_dot, B_dot, C_dot)...\n\n");
        printf("controllo idonieta' su K in corso...");
        
        mpz_t tmp, cmt_m, hashd, cmt_sigma_dot, beta_dot_c, tmp_g2;
        mpz_inits(tmp, cmt_m, hashd, cmt_sigma_dot, beta_dot_c, tmp_g2, NULL);
        
        if (wsk_){
                printf("chiave input  per la decifrazione secret key weak\n\n");
                printf("digest c valutato correttamente...\n");
                
                mpz_powm(cmt_sigma_dot, K->info_cipher.K_2.A_dot, wsk_->contrib, pk->NN);
                mpz_invert(cmt_sigma_dot, cmt_sigma_dot, pk->NN);
            
                mpz_mul(cmt_sigma_dot, K->info_cipher.K_2.B_dot, cmt_sigma_dot);
                mpz_mod(cmt_sigma_dot, cmt_sigma_dot, pk->NN);
                
                mpz_sub_ui(cmt_sigma_dot, cmt_sigma_dot, 1);                                                                                                                                                                                                                                                    
                mpz_mod(cmt_sigma_dot, cmt_sigma_dot, pk->NN);
 
                //get sigma dot
                mpz_cdiv_q(cmt_sigma_dot, cmt_sigma_dot, pk->N);
                
                pmesg_mpz(msg_very_verbose, "compute sigma_dot= ", cmt_sigma_dot);
                pmesg_mpz(msg_very_verbose, "K->info_cipher.K_2.C_dot", K->info_cipher.K_2.C_dot);
                pmesg_mpz(msg_very_verbose, "K->info_cipher.K_2.A_dot", K->info_cipher.K_2.A_dot);
                pmesg_mpz(msg_very_verbose, "K->info_cipher.K_2.B_dot", K->info_cipher.K_2.B_dot);
                //pmesg_mpz(msg_very_verbose, "b= ", wsk_->contrib);
                printf("\n");
                
            }
            
            else {
                printf("chiave input  per la decifrazione long term secret key\n\n");
                printf("digest c valutato correttamente...\n");
                
                mpz_t lamb_N, pi, a, r, w_1;
                mpz_inits (lamb_N, pi, a, r, w_1, NULL);
                
                //2p'q' (Carmichael's function)
                mpz_mul(lamb_N, sk->p_1, sk->q_1);
                mpz_mul_ui(lamb_N, lamb_N, 2);
                pmesg_mpz(msg_very_verbose, "lamb_N= ", lamb_N);


                //DPL a, a mod N
                mpz_powm(a, pk->g1, lamb_N, pk->NN);
                mpz_sub_ui(a, a, 1);
                mpz_mod(a, a, pk->NN);
                mpz_cdiv_q(a, a, pk->N);                
                
                //DPL r
                mpz_powm(r, K->info_cipher.K_1.A, lamb_N, pk->NN);
                mpz_sub_ui(r, r, 1);
                mpz_mod(r, r, pk->NN);
                mpz_cdiv_q(r, r, pk->N);                
                
                pmesg_mpz(msg_very_verbose, "PDL: r mod N", r);
                pmesg_mpz(msg_very_verbose, "PDL: a mod N", a);

                
                //w_1= a*r mod N
                mpz_mul(w_1, a, r);
                mpz_mod(w_1, w_1, pk->N);
                
                
                pmesg_mpz(msg_very_verbose, "w_1= a*r mod N", w_1); 

                mpz_powm(tmp, pk->g0, w_1, pk->NN);
                pmesg_mpz(msg_very_verbose, "TESTComputato---g0^ra = ", tmp);
                
                
                //mpz_powm(cmt_sigma, K->info_cipher.K_1.A, a, pk->NN);
                mpz_powm(cmt_sigma, pk->g0, w_1, pk->NN);
                
                mpz_invert(cmt_sigma, cmt_sigma, pk->NN);
                mpz_mul(cmt_sigma, K->info_cipher.K_1.B, cmt_sigma);
                mpz_powm(cmt_sigma, cmt_sigma, lamb_N, pk->NN);
                
                //D
                mpz_sub_ui(cmt_sigma, cmt_sigma, 1);
                mpz_mod(cmt_sigma, cmt_sigma, pk->NN);
                mpz_cdiv_q(cmt_sigma, cmt_sigma, pk->N);
                
                //get pi
                mpz_invert(pi, lamb_N, pk->N);
                
                //get sigma
                mpz_mul(cmt_sigma, cmt_sigma, pi);
                mpz_mod(cmt_sigma, cmt_sigma, pk->N);
                
                mpz_clears (lamb_N, pi, a, r, w_1, NULL);
                
            }
            
            // compute //
            
            //H1 sgima_dot
            char *str_sig_dot=mpz_get_str(NULL, 10, cmt_sigma_dot);
            char * concat_h1=cnt_string(str_sig_dot, NULL, PRE_state->h_1);
            
            mpz_set_str(tmp, concat_h1, 10);
            mpz_mod(tmp, tmp, pk->NN);
            
            char * tmpsig_dot=mpz_get_str(NULL, 10, tmp);
            
            uint8_t digest_cmt_sigma_dot [SHA3_512_DIGEST_SIZE];
            perform_hashing_sha3(sha3_512_ctx, sha3_512_init, sha3_512_update,
                                sha3_512_digest, SHA3_512_DIGEST_SIZE, tmpsig_dot, &tmpsig_dot[0], digest_cmt_sigma_dot);
        
            mpz_import(tmp, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_cmt_sigma_dot);
            
            //get beta_dot_c
            mpz_xor(beta_dot_c, K->info_cipher.K_2.C_dot, tmp);
            
            
            char * srt_beta_dot=mpz_get_str(NULL, 10, beta_dot_c);
            char * concat_h=cnt_string(str_sig_dot, srt_beta_dot, PRE_state->h_2);// decryptor
            
            mpz_set_str(tmp, concat_h, 10);
            mpz_mod(tmp, tmp, pk->NN);
            
            char * tmpsigbeta_dot=mpz_get_str(NULL, 10, tmp);
            
            uint8_t digest_h_2[SHA3_384_DIGEST_SIZE]={0};
            printf("\n H decryptor=( sigma_dot || beta_dot || id)\n");
            perform_hashing_sha3(sha3_384_ctx, sha3_384_init, sha3_384_update,
                            sha3_384_digest, SHA3_384_DIGEST_SIZE, tmpsigbeta_dot, &tmpsigbeta_dot[0], digest_h_2);
            
            mpz_import(hashd, SHA3_384_DIGEST_SIZE,1,1,0,0, digest_h_2);//rX->Y
            printf("\n");
            pmesg_mpz(msg_very_verbose, "B_pk->g2= ", pk->g2);
            
            //g2^() mod N^2(cmt_sigma_dot || beta_dot_c), pk decryptor
            mpz_powm(tmp_g2, pk->g2, hashd, pk->NN);
                
            //(1+cmt_sigma_dot*N) mod N^2
            mpz_mul(tmp, cmt_sigma_dot, pk->N);
            mpz_add_ui(tmp,tmp,1);
            mpz_mod(tmp, tmp, pk->NN);
            
            //B_dot compute
            mpz_mul(tmp, tmp, tmp_g2);
            mpz_mod(tmp, tmp, pk->NN);
        
            if (mpz_cmp(tmp, K->info_cipher.K_2.B_dot)==0) {
                
                printf("\n[ OK] B_dot calcolato correttamente... computazione di sigma\n");
                /*pmesg_mpz(msg_very_verbose, "Alice modulo N= ", pk->delegator.N);
                pmesg_mpz(msg_very_verbose, "Alice modulo NN= ", pk->delegator.NN);
                pmesg_mpz(msg_very_verbose, "beta_dot_c= ", beta_dot_c);*/
                printf("\n\n");
                
                mpz_t tmp_c, check_H, tmpA, tmpB;
                mpz_inits (tmp_c, check_H, tmpA, tmpB, NULL);
                
                //sigma
                mpz_powm(tmp_c, K->info_cipher.K_2.A, beta_dot_c, pk->delegator.NN);
                mpz_mul(cmt_sigma, K->info_cipher.K_2.A_1, tmp_c);
                mpz_mod(cmt_sigma, cmt_sigma, pk->delegator.NN);
             
                mpz_invert(cmt_sigma, cmt_sigma, pk->delegator.NN);
                mpz_mul(cmt_sigma, K->info_cipher.K_2.B, cmt_sigma);
                mpz_mod(cmt_sigma, cmt_sigma, pk->delegator.NN);
        
                mpz_sub_ui(cmt_sigma, cmt_sigma, 1);
                mpz_mod(cmt_sigma, cmt_sigma, pk->delegator.NN);
                mpz_cdiv_q(cmt_sigma, cmt_sigma,  pk->delegator.N);
                printf("\n");

                
                char * srt_sig_computed=mpz_get_str(NULL, 10, cmt_sigma);
                char * concat_h=cnt_string(srt_sig_computed, NULL, PRE_state->h_2);// decryptor
                
                mpz_set_str(tmp, concat_h, 10);
                mpz_mod(tmp, tmp, pk->NN);
                
                char * tmpsig_computed=mpz_get_str(NULL, 10, tmp);
                uint8_t digest_h_2[SHA3_384_DIGEST_SIZE]={0};
                printf("\n H decryptor=( sigma_dot || beta_dot || id)\n");
                perform_hashing_sha3(sha3_384_ctx, sha3_384_init, sha3_384_update,
                                sha3_384_digest, SHA3_384_DIGEST_SIZE, tmpsig_computed, &tmpsig_computed[0], digest_h_2);
                //get m
                mpz_import(tmp, SHA3_384_DIGEST_SIZE,1,1,0,0, digest_h_2);
                mpz_xor(cmt_m, K->info_cipher.K_2.C, tmp);
                
                
                char *str_check_msg=mpz_get_str(NULL, 10, cmt_m);
                char * concat_check=cnt_string(srt_sig_computed, str_check_msg, PRE_state->h_1);
                mpz_set_str(tmp, concat_check, 10);
                mpz_mod(tmp, tmp, pk->NN);
                char * H_delegator=mpz_get_str(NULL, 10, tmp);
                
                uint8_t digest_h_1[SHA3_512_DIGEST_SIZE];
                printf("\n H_check (sigma||m||id)\n");
                perform_hashing_sha3(sha3_512_ctx, sha3_512_init, sha3_512_update,
                            sha3_512_digest, SHA3_512_DIGEST_SIZE, H_delegator, &H_delegator[0], digest_h_1);
                
                mpz_import(check_H, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_1);
                
                //A
                mpz_powm(tmpA, pk->delegator.g0, check_H, pk->delegator.NN);
                
                //B
                mpz_mul(tmp, cmt_sigma, pk->delegator.N);
                mpz_add_ui(tmp, tmp, 1);
                mpz_mod(tmp, tmp, pk->delegator.NN);
                
                mpz_powm(tmpB, pk->delegator.g1, check_H, pk->delegator.NN);
                mpz_mul(tmpB, tmpB, tmp);
                mpz_mod(tmpB, tmpB, pk->delegator.NN);
                
                if (mpz_cmp(tmpA, K->info_cipher.K_2.A)==0  && mpz_cmp(tmpB, K->info_cipher.K_2.B)==0) {
                    
                    printf("\nciphertext conforme, messaggio decifrato correttamente dal Proxy.\n");
                    pmesg_mpz(msg_very_verbose, "message =", cmt_m);
                }
                else _EXIT("[ X] errore in fase di decryption, paramertri corrotti");
                printf("\n");
                
                free(srt_sig_computed);
                free(concat_h);
                free(tmpsig_computed);
                free(str_check_msg);
                free(H_delegator);
                free(concat_check);
                srt_sig_computed=NULL;
                concat_h=NULL;
                tmpsig_computed=NULL;
                str_check_msg=NULL;
                H_delegator=NULL;
                concat_check=NULL;
                
                mpz_clears (tmp_c, check_H, tmpA, tmpB, cmt_sigma, NULL);
            }
            else {_EXIT("[ X]B_bot corrotto");}
            printf("\n");
            
            
            free(tmpsig_dot);
            free(str_sig_dot);
            free(concat_h1);
            free(srt_beta_dot);
            free(concat_h);
            free(tmpsigbeta_dot);
            concat_h=NULL;
            tmpsig_dot=NULL;
            str_sig_dot=NULL;
            concat_h1=NULL;
            srt_beta_dot=NULL;
            tmpsigbeta_dot=NULL;
                       
            mpz_clears(tmp, cmt_m, hashd, cmt_sigma_dot, beta_dot_c, tmp_g2, NULL);
    }
}



/*
 * ReKeyGen
 */
void RekeyGen(gmp_randstate_t prng, re_encryption_key_t *RE_enc_key,
                        const state_t *PRE_state, const public_key_t *pkY, const private_key_t *skX, msg_t *wskX){
  

    assert(prng);

    if( pkY==NULL || PRE_state==NULL || wskX==NULL || RE_enc_key==NULL || skX==NULL)
        _EXIT("ciphertext K di input corrotto");
    
    mpz_t sigma_dot, beta_dot, h_1, tmp, rXY, NYNY;
    mpz_inits (sigma_dot, beta_dot, h_1, tmp, rXY, NYNY, RE_enc_key->k2_x2y, RE_enc_key->A_dot,
               RE_enc_key->B_dot, RE_enc_key->C_dot, NULL);//

    mpz_urandomm(sigma_dot, prng, pkY->N);
    mpz_urandomb(beta_dot, prng, 512); //k1 //testing
    
    mpz_sub(RE_enc_key->k2_x2y, wskX->contrib, beta_dot);
    mpz_mul(tmp, skX->p, skX->q);
    mpz_mul(tmp, tmp, skX->p_1);
    mpz_mul(tmp, tmp, skX->q_1);
    printf("\n\n");
    
    mpz_mod(RE_enc_key->k2_x2y, RE_enc_key->k2_x2y, tmp);
    
    //rX->Y= hY sigma_dot||beta_dot||idY
    char *str_sigma_dot=mpz_get_str(NULL, 10, sigma_dot);
    char *str_beta_dot=mpz_get_str(NULL, 10, beta_dot);
    char * concat_hY=cnt_string(str_sigma_dot, str_beta_dot, pkY->id_hash);
    printf(">>pkY->id_hash= %u\n\n", pkY->id_hash);
    
    
    mpz_set_str(tmp, concat_hY, 10);
    mpz_mod(tmp, tmp, pkY->NN);
    char * tmpHY=mpz_get_str(NULL, 10, tmp);
    
    uint8_t digest_h_Y[SHA3_384_DIGEST_SIZE];//Y
    printf("\n rX->Y=HY= (hash sigma_dot || beta_dot || id)\n");
    perform_hashing_sha3(sha3_384_ctx, sha3_384_init, sha3_384_update,
                            sha3_384_digest, SHA3_384_DIGEST_SIZE, tmpHY, &tmpHY[0], digest_h_Y);
    
    mpz_import(rXY, SHA3_384_DIGEST_SIZE,1,1,0,0, digest_h_Y);
    
    //A_dot
    mpz_mul(NYNY, pkY->N, pkY->N );
    mpz_powm(RE_enc_key->A_dot, pkY->g0, rXY, NYNY);
    
    //C_dot
    char * concat_h1=cnt_string(str_sigma_dot, NULL, PRE_state->h_1);
    mpz_set_str(tmp, concat_h1, 10);
    mpz_mod(tmp, tmp, pkY->NN);
    char * tmpH1=mpz_get_str(NULL, 10, tmp);
    
    uint8_t digest_h_1[SHA3_512_DIGEST_SIZE];
    printf("\n H1= ( sigma || id )\n");
    perform_hashing_sha3(sha3_512_ctx, sha3_512_init, sha3_512_update,
                            sha3_512_digest, SHA3_512_DIGEST_SIZE, tmpH1, &tmpH1[0], digest_h_1);
    
    mpz_import(h_1, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_1);
    
    mpz_xor(RE_enc_key->C_dot, h_1, beta_dot);
    
    //B_dot
    mpz_mul(tmp, sigma_dot, pkY->N);
    mpz_add_ui(tmp, tmp, 1);
    mpz_mod(tmp, tmp, NYNY);
    mpz_powm(RE_enc_key->B_dot, pkY->g2, rXY, NYNY);
    mpz_mul(RE_enc_key->B_dot, tmp, RE_enc_key->B_dot);
    mpz_mod(RE_enc_key->B_dot, RE_enc_key->B_dot, NYNY);
    
    printf("\noutput re-KeyGen: undirectional re-encryption key rkX -> Y = (rk1_X -> Y, rk2_X -> Y)\n\n");
    pmesg_mpz(msg_very_verbose, "rk2_X -> Y", RE_enc_key->k2_x2y);
    
    printf("\nrk1_X -> Y\n");
    pmesg_mpz(msg_very_verbose, "A_dot", RE_enc_key->A_dot);
    pmesg_mpz(msg_very_verbose, "B_dot", RE_enc_key->B_dot);
    pmesg_mpz(msg_very_verbose, "C_dot", RE_enc_key->C_dot);
    pmesg_mpz(msg_very_verbose, "sigma_dot", sigma_dot);
    pmesg_mpz(msg_very_verbose, "beta_dot", beta_dot);
    pmesg_mpz(msg_very_verbose, "rXY", rXY);
    //pmesg_mpz(msg_very_verbose, "wskX-a->contrib", wskX->contrib);
    /*printf("check Y\n");//pk alice
    pmesg_mpz(msg_very_verbose, "modulo N", pkY->N);
    pmesg_mpz(msg_very_verbose, "g0", pkY->g0);
    pmesg_mpz(msg_very_verbose, "g2", pkY->g2);
    pmesg_mpz(msg_very_verbose, "skX->p_1", skX->p_1);*/
    
    free(str_sigma_dot);
    free(concat_h1);
    free(str_beta_dot);
    free(concat_hY);
    free(tmpH1);
    free(tmpHY);
    str_sigma_dot=NULL;
    concat_h1=NULL;
    str_beta_dot=NULL;
    concat_hY=NULL;
    tmpHY=NULL;
    tmpH1=NULL;
    
    mpz_clears (sigma_dot, beta_dot, h_1, tmp, rXY, NYNY, NULL);
}


/*
 * ReEncrypt
 */
void ReEncrypt (ciphertext_t *K, const re_encryption_key_t *RE_enc_key, const state_t *PRE_state,
                            const public_key_t *pkX){
    
    
    if( K==NULL || PRE_state==NULL || pkX==NULL || RE_enc_key==NULL )
        _EXIT("ciphertext K di input corrotto");
    
    mpz_t g0X_s_A_c, g2X_s_D_c, tmp, check_c, tmpA, tmpB, tmpC;
    mpz_inits (g0X_s_A_c, g2X_s_D_c, tmp, check_c, tmpA, tmpB, tmpC, NULL);
    
    pmesg_mpz(msg_very_verbose, "check pkX->g0", pkX->g0);
    pmesg_mpz(msg_very_verbose, "check K->K.s", K->info_cipher.K_1.s);    
    
    //g0X^s * A^c mod N^2
    mpz_powm(g0X_s_A_c, pkX->g0, K->info_cipher.K_1.s, pkX->NN);
    
    mpz_powm(tmp, K->info_cipher.K_1.A, K->info_cipher.K_1.c, pkX->NN);
    mpz_mul(g0X_s_A_c, g0X_s_A_c, tmp);
    mpz_mod(g0X_s_A_c, g0X_s_A_c, pkX->NN);
    //gmp_printf("g0X_s_A_c): %Zd\n", g0X_s_A_c);
    
    //g2X^s * D^c mod N^2
    mpz_powm(g2X_s_D_c, pkX->g2, K->info_cipher.K_1.s, pkX->NN);
    mpz_powm(tmp, K->info_cipher.K_1.D, K->info_cipher.K_1.c, pkX->NN);
    mpz_mul(g2X_s_D_c, g2X_s_D_c, tmp); 
    mpz_mod(g2X_s_D_c, g2X_s_D_c, pkX->NN);

    char * str_A=mpz_get_str(NULL, 10, K->info_cipher.K_1.A);
    char * str_D=mpz_get_str(NULL, 10, K->info_cipher.K_1.D);
    char * str_g0X=mpz_get_str(NULL, 10, pkX->g0);
    char * str_g2X=mpz_get_str(NULL, 10, pkX->g2);
    char * str_g0X_s_A_c=mpz_get_str(NULL, 10, g0X_s_A_c);
    char * str_g2X_s_D_c=mpz_get_str(NULL, 10, g2X_s_D_c);
    char * str_B=mpz_get_str(NULL, 10, K->info_cipher.K_1.B);
    char * str_C=mpz_get_str(NULL, 10, K->info_cipher.K_1.C);
    char *string_c=cnt_check_c(str_A, str_D, str_g0X, str_g2X, str_g0X_s_A_c, str_g2X_s_D_c, str_B, str_C, PRE_state->h_3);
    
    mpz_set_str(tmp, string_c, 10);
    mpz_mod(tmp, tmp, pkX->NN);
    char * tmpcH3=mpz_get_str(NULL, 10, tmp);
    
    uint8_t digest_chec_c[SHA3_256_DIGEST_SIZE];
    perform_hashing_sha3(sha3_256_ctx, sha3_256_init, sha3_256_update,
                            sha3_256_digest, SHA3_256_DIGEST_SIZE, tmpcH3, &tmpcH3[0], digest_chec_c);

    mpz_import(check_c, SHA3_256_DIGEST_SIZE,1,1,0,0, digest_chec_c);
    printf("\n");

    printf("\ncontrollo del ciphertext K ricevuto in input in corso...\n");
    //gmp_printf(".c) = %Zx\n", K->info_cipher.K_1.c);
    //gmp_printf(".check_c = %Zx\n\n", check_c);
    
    if(!mpz_cmp(K->info_cipher.K_1.c, check_c)==0) {
        _EXIT("[ X] ciphertext non conforme, errore in fare di re-encryption. ");
    }
    else {
        printf("[ OK] ciphertext ricevuto conforme alla re-encryption\n\n");
                
        mpz_set(tmpA, K->info_cipher.K_1.A); //A=g0^r, k=1
        mpz_set(tmpB, K->info_cipher.K_1.B);
        mpz_set(tmpC, K->info_cipher.K_1.C);
        //pmesg_mpz(msg_very_verbose, " >>test K_1.A", tmpA);
        
         /*mpz_inits(K->info_cipher.K_2.A, K->info_cipher.K_2.A_1, K->info_cipher.K_2.B,
              K->info_cipher.K_2.C, K->info_cipher.K_2.A_dot, K->info_cipher.K_2.B_dot,
                    K->info_cipher.K_2.C_dot, NULL);*/
        
        //A'
        mpz_powm(K->info_cipher.K_2.A_1, tmpA, RE_enc_key->k2_x2y, pkX->NN);
        pmesg_mpz(msg_very_verbose, "RE_enc_key->k2_x2y", RE_enc_key->k2_x2y);
        
            
        printf("cifratura ciphertext= (A, A', B, C, A_dot, B_dot, C_dot)\n");
        
        K->type="K=(A, A', B, C, A_dot, B_dot, C_dot)";
        
        mpz_set(K->info_cipher.K_2.A, tmpA);
        mpz_set(K->info_cipher.K_2.B, tmpB);
        mpz_set(K->info_cipher.K_2.C, tmpC);
        
        mpz_set(K->info_cipher.K_2.A_dot, RE_enc_key->A_dot);
        mpz_set(K->info_cipher.K_2.B_dot, RE_enc_key->B_dot);
        mpz_set(K->info_cipher.K_2.C_dot, RE_enc_key->C_dot);//
        
        pmesg_mpz(msg_very_verbose, "A", K->info_cipher.K_2.A);
        pmesg_mpz(msg_very_verbose, "A_1", K->info_cipher.K_2.A_1);
        pmesg_mpz(msg_very_verbose, "B", K->info_cipher.K_2.B);
        pmesg_mpz(msg_very_verbose, "C", K->info_cipher.K_2.C);
        pmesg_mpz(msg_very_verbose, "A_dot", K->info_cipher.K_2.A_dot);
        pmesg_mpz(msg_very_verbose, "B_dot", K->info_cipher.K_2.B_dot);
        pmesg_mpz(msg_very_verbose, "C_dot", K->info_cipher.K_2.C_dot);
        pmesg_mpz(msg_very_verbose, "modulo N^2", pkX->NN);
        pmesg_mpz(msg_very_verbose, "rK2X->Y", RE_enc_key->k2_x2y);
    }
    
    free(str_A);
    free(str_D);
    free(str_g0X);
    free(str_g2X);
    free(str_g0X_s_A_c);
    free(str_g2X_s_D_c);
    free(str_B);
    free(str_C);
    free(tmpcH3);
    str_A=NULL;
    str_D=NULL;
    str_g0X=NULL;
    str_g2X=NULL;
    str_g0X_s_A_c=NULL;
    str_g2X_s_D_c=NULL;
    str_B=NULL;
    str_C=NULL;
    free(string_c);
    string_c=NULL;
    tmpcH3=NULL;
    
    mpz_clears (g0X_s_A_c, g2X_s_D_c, tmp, check_c, tmpA, tmpB, tmpC, NULL);
}

/*
 * verifica la correttezza dei parametri
 *
 */
/*
bool verify_params(const shared_params_t params) {
    
    bool return_value = true;
    assert(params);
 if ((params->p_1_bits >= params->p_bits) || (params->q_1_bits >= params->q_bits))
        return_value = false;
    
    return (return_value);
}*/


/*
 * init method
 */

void shared_params_init(shared_params_t *params) {
    if (params==NULL)
        _EXIT("errore nella procedura di generazione dei parametri");
    mpz_inits(params->N, params->p, params->p_1, params->q, params->q_1, NULL);
}

void public_key_init(public_key_t *pk) {
    if(pk!=0)
        mpz_inits(pk->N, pk->NN, pk->g0, pk->g1, pk->g2, NULL);
    else _EXIT("errore sulla public key");
}

void private_key_init(private_key_t *sk) {
    if(sk!=0)
        mpz_inits(sk->p,sk->q, sk->p_1, sk->q_1, NULL);
    else _EXIT("errore sulla private key");
}
void weak_secret_key_init(weak_secret_key_t *wsk){
        if(wsk!=0)
            mpz_inits(wsk->a, wsk->b, NULL);
        else _EXIT("errore sulla weak secret key");
}

void msg_init(msg_t *msg) {
    assert(msg);
    mpz_init(msg->contrib);
}

void plaintext_init(plaintext_t *plaintext) {
    if (plaintext!=0)
        mpz_init(plaintext->m);
    else _EXIT("errore sul plaintext");
}

void ciphertext_init(ciphertext_t *K) {
    if(K!=0) {
    mpz_inits(K->info_cipher.K_1.A, K->info_cipher.K_1.B, K->info_cipher.K_1.C,
              K->info_cipher.K_1.D, K->info_cipher.K_1.c, K->info_cipher.K_1.s, NULL);
    } else{_EXIT("ciphertext nonvalido");}
}

void ciphertext_RE_init(ciphertext_t *K) {
    if(K!=0) {
    mpz_inits(K->info_cipher.K_2.A, K->info_cipher.K_2.A_1, K->info_cipher.K_2.B,
              K->info_cipher.K_2.C, K->info_cipher.K_2.A_dot, K->info_cipher.K_2.B_dot,
                    K->info_cipher.K_2.C_dot, NULL);
    } else{_EXIT("ciphertext nonvalido");}
}

/*
 * clear method
 */

void public_key_clear(public_key_t *pk) {
    if(pk!=0)
        mpz_clears(pk->N, pk->NN, pk->g0, pk->g1, pk->g2, NULL);
    else _EXIT("errore sulla public key");
}

void private_key_clear(private_key_t* sk) {
    if (sk==NULL)
         _EXIT("errore sulla private key");
    mpz_clears(sk->p, sk->q, sk->p_1, sk->q_1, NULL);
}

void weak_secret_key_clear(weak_secret_key_t *wsk){
    if (wsk==NULL)
        _EXIT("errore sulla weak secret key");
    mpz_clears(wsk->a, wsk->b, NULL);
}

void ReKeyGen_keys_clear(re_encryption_key_t *RE_enc_key){
    if (RE_enc_key==NULL)
        _EXIT("errore nella procedura ReKeyGen");
    mpz_clears(RE_enc_key->k2_x2y, RE_enc_key->A_dot,
               RE_enc_key->B_dot, RE_enc_key->C_dot, NULL);
}

void shared_params_clear(shared_params_t *params) {
    if (params==NULL)
        _EXIT("errore nella procedura di generazione dei parametri");
    mpz_clears(params->N, params->p, params->p_1, params->q, params->q_1, NULL);
}

void plaintext_clear(plaintext_t *plaintext) {
    assert(plaintext);
    mpz_clear(plaintext->m);
}

void msg_clear(msg_t *msg) {
    assert(msg);
    mpz_clear(msg->contrib);
}

void ciphertext_clear(ciphertext_t *K) {
    if(K!=0) {
        mpz_clears(K->info_cipher.K_1.A, K->info_cipher.K_1.B, K->info_cipher.K_1.C,
              K->info_cipher.K_1.D, K->info_cipher.K_1.c, K->info_cipher.K_1.s, NULL);
        } else{_EXIT("ciphertext nonvalido");}
}

void ciphertextK2_clear(ciphertext_t *K) {
    if(K!=0) {
        mpz_clears(K->info_cipher.K_2.A, K->info_cipher.K_2.A_1, K->info_cipher.K_2.B,
              K->info_cipher.K_2.C, K->info_cipher.K_2.A_dot, K->info_cipher.K_2.B_dot,
                    K->info_cipher.K_2.C_dot, NULL);
        } else{_EXIT("ciphertext nonvalido");}
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

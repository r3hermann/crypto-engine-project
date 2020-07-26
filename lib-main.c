#include "lib-main.h"
#include <unistd.h>
#include <sys/types.h>
#include<sys/wait.h>
#include <errno.h> 


#define CHECK(filepointer) if(!filepointer) {fprintf(stderr, "ERROR (" __FILE__ ":%d) %s\n",__LINE__,strerror(errno));    \
                                                                     exit(EXIT_FAILURE);}




#define  perform_hashing_sha3_generic(CTX, FNC_UPDATE, FNC_DIGEST, DGST_SIZE, BUFFER,                 \
                                                                BLOCKSIZE, DIGESTSXXX ) do{                                                       \
    char buffer[2048]={0};                                                                                                                               \
    size_t n=0, offset_dgst=0, blocks_to_hash=0;                                                                                             \
    uint8_t *sha3_tmp=malloc(sizeof(uint8_t)*BLOCKSIZE+1);                                                                          \
    uint8_t digest[SHA3_512_DIGEST_SIZE]={0};                                                                                              \
    if (  DGST_SIZE > SHA3_512_DIGEST_SIZE ) {                                                                                              \
       for( size_t i=0; i<DGST_SIZE; i+=SHA3_512_DIGEST_SIZE){                                                                     \
           memcpy(sha3_tmp, BUFFER, BLOCKSIZE*sizeof(uint8_t));                                                                     \
           memcpy(sha3_tmp+BLOCKSIZE, &n, sizeof(uint8_t));                                                                           \
           FNC_UPDATE(&CTX, BLOCKSIZE+1, sha3_tmp);                                                                                    \
           FNC_DIGEST(&CTX, SHA3_512_DIGEST_SIZE, digest);                                                                            \
           memcpy(DIGESTSXXX+offset_dgst, digest, SHA3_512_DIGEST_SIZE);                                                  \
           offset_dgst+=SHA3_512_DIGEST_SIZE;                                                                                                 \
           n++;                                                                                                                                                       \
        }                                                                                                                                                                \
        blocks_to_hash=(BLOCKSIZE+1)*DGST_SIZE;                                                                                           \
    } else {                                                                                                                                                          \
            FNC_UPDATE(&CTX, BLOCKSIZE, BUFFER);                                                                                           \
            FNC_DIGEST(&CTX, DGST_SIZE, DIGESTSXXX);                                                                                    \
            blocks_to_hash=BLOCKSIZE;                                                                                                                 \
    }                                                                                                                                                                    \
    snprintf(buffer, sizeof(buffer), "\nblock hash data: %.2f byte", (float)(blocks_to_hash));                               \
    pmesg(msg_verbose, buffer, blocks_to_hash);                                                                                               \
    snprintf(buffer, sizeof(buffer), "digest (%d bit)", DGST_SIZE*8 );                                                                   \
    pmesg_hex(msg_verbose, buffer, DGST_SIZE, DIGESTSXXX);                                                                         \
    free(sha3_tmp);                                                                                                                                                \
}while(0)
                                                                
                                                                
                                                                                    
                
/*static inline void display_hex(long unsigned int length, uint8_t *data) {
    unsigned int i;
  for (i= 0; i<length; i++)
    printf("%02x", data[i]);
  printf("\n");
}*/

long random_seed () {

    FILE *dev_random;
    unsigned int byte_count;
    int seed=0;
	byte_count = BYTEREAD;
    dev_random = fopen("/dev/random", "r");
	CHECK(dev_random);
	fread(&seed, sizeof(char), byte_count, dev_random);
	fclose(dev_random);
    dev_random=NULL;
    return seed;
}


void PRE_scheme_state (state_t *PRE_state, gmp_randstate_t prng) {
    
    mpz_t id1, id2, id3;
    mpz_inits (id1, id2, id3, NULL);
    
    mpz_urandomb(id1, prng, 16);
    mpz_urandomb(id2, prng, 16);
    mpz_urandomb(id3, prng, 16);

    PRE_state->h_1=(uint32_t)mpz_get_ui(id1);
    PRE_state->h_2=(uint32_t)mpz_get_ui(id2);
    PRE_state->h_3=(uint32_t)mpz_get_ui(id3);

    mpz_clears (id1, id2, id3, NULL);
    
}


/*
 * contrib KeyGen
 */
void generate_keys(keygen_params_t *params, unsigned p_bits, unsigned q_bits, public_key_t *pk, private_key_t *sk,
                   weak_secret_key_t *wsk, gmp_randstate_t prng, const uint32_t idX_hash){

    assert(prng);
    assert(p_bits>1);
    assert(q_bits>1);
    assert(prng);

    mpz_t alpha, tmp, tmp1, alpha2, pp, qq, lamb_N, t, range;
    mpz_inits(alpha, tmp, tmp1, alpha2, pp, qq,  lamb_N, t, range, NULL);

    pmesg(msg_verbose, "generazione parametri...");
    
    if ( pk==NULL || sk==NULL || wsk==NULL)
        _EXIT("encryption fallita");

        //scelta delle taglie di p e q
        params->p_bits=p_bits;
        params->q_bits=q_bits;
        params->p_1_bits=p_bits-1; // p'
        params->q_1_bits=q_bits-1; // q'
        
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
           
        pmesg(msg_verbose, "generazione del contributo...");
        
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
    
        mpz_mul(lamb_N, sk->p_1, sk->q_1);
        mpz_mul_ui(lamb_N, lamb_N, 2);
        
        mpz_set_ui(alpha,1);
        mpz_set_ui(t, 2);
        mpz_set(alpha2, pk->N);
        
        do{        
            
            //mpz_urandomm(alpha, prng, pk->N);
            //mpz_urandomm(alpha2, prng, pk->N);
            //mpz_mul(alpha2, alpha2, pk->N);
                    
            mpz_invert(t, t, pk->N);
            mpz_mul(alpha2, alpha2, t);
            mpz_add(alpha, alpha, alpha2);// 1+K*t*N mod N^2
            mpz_mod(alpha, alpha, pk->NN);
            
            //alpha^lamb_N=1 mod N, alpha^(N*lamb_N)=1 mod N^2
            mpz_powm(tmp, alpha, lamb_N, pk->N);
            mpz_powm(tmp1, alpha, lamb_N, pk->N);
            
        }while(!mpz_cmp_ui(tmp,1)==0 && !mpz_cmp_ui(tmp1,1)==0);
        
        // calcolo il range [pp' qq'], maxordG 
        mpz_mul(range, pk->N, sk->p_1);
        mpz_mul(range, tmp, sk->q_1);
            
        //a,b random in [1,pp' qq'], 0 escluso
        do {
            mpz_urandomm(wsk->a, prng, range);
            mpz_urandomm(wsk->b, prng, range);
        } while( (mpz_cmp_ui(wsk->a,0)==0) || (mpz_cmp_ui(wsk->b,0)==0));

        //set id user generic hush function H (.):{0,1}*->Zn^2
        pk->id_hash=idX_hash;
        
        //g0 = alpha^2 mod N^2
        mpz_powm_ui(pk->g0, alpha, 2, pk->NN);
        if (mpz_jacobi(pk->g0,pk->NN)==1) {
            if(!(mpz_legendre(pk->g0, pp)==1 && mpz_legendre(pk->g0, qq)==1))
                _EXIT("errore generazione del generatore g0. ");
            //else {printf("g0/p^2= %d, g0/q^2= %d\n\n",mpz_legendre(pk->g0, pp), mpz_legendre(pk->g0, qq));}
        }
        else _EXIT("errore generazione del generatore g0. ");
        
        //g1 = g0^a mod N^2
        mpz_powm(pk->g1, pk->g0, wsk->a, pk->NN);
        
        if (mpz_jacobi(pk->g1,pk->NN)==1) {
            if(!(mpz_legendre(pk->g1, pp)==1 && mpz_legendre(pk->g1, qq)==1))
                _EXIT("errore generazione del generatore g1. ");
        }
        else _EXIT("errore generazione del generatore g1. ");
        
        //g2= g0^b mod N^2
        mpz_powm(pk->g2, pk->g0, wsk->b, pk->NN);
        if(mpz_jacobi(pk->g2,pk->NN)==1) {
            if (!(mpz_legendre(pk->g2, pp)==1 && mpz_legendre(pk->g2, qq)==1))
            _EXIT("errore generazione del generatore g2. ");
        }
        else _EXIT("errore generazione del generatore g2. ");
        

        //printf("\npk = (H(.), N, g0, g1, g2)\n");
        mpz_set_ui(tmp, pk->id_hash);
        pmesg_mpz(msg_very_verbose, "\n\nalpha =",alpha);
        pmesg_mpz(msg_very_verbose, "\nmodulo N=",pk->N);
        pmesg_mpz(msg_very_verbose, "\ng0 =",pk->g0);
        pmesg_mpz(msg_very_verbose, "\ng1 =",pk->g1);
        pmesg_mpz(msg_very_verbose, "\ng2=",pk->g2);
        pmesg_mpz(msg_very_verbose, "\nH_id=", tmp);
        
        //weak secret
        //printf("\nweak secret,");
        pmesg_mpz(msg_very_verbose, "\n\nrange di scelta di a, b in [1, pp'qq'] =", range);
        pmesg_mpz(msg_very_verbose, "a =",wsk->a);
        pmesg_mpz(msg_very_verbose, "b =",wsk->b);
        
        //sk
        //printf("\nsk = (p, q, p', q')\n");
        pmesg_mpz(msg_very_verbose, "\n\np = ",sk->p);
        pmesg_mpz(msg_very_verbose, "\nq = ",sk->q);
        pmesg_mpz(msg_very_verbose, "\np' = ", sk->p_1);
        pmesg_mpz(msg_very_verbose, "\nq' = ", sk->q_1);
        pmesg_mpz(msg_very_verbose, "N^2=", pk->NN);                        
                                
        mpz_clears(alpha, tmp, tmp1, alpha2, pp, qq,  lamb_N, t, range, NULL);
}

/*
 * encrypt, k=ABCDcs
 */
void encrypt(gmp_randstate_t prng, const plaintext_t *plaintext,  const public_key_t *pk, ciphertext_t *ciphertext_K,
                                    const state_t *PRE_state, struct sha3_512_ctx context_512, unsigned int size_NN) {    

    assert(prng);
    
    if ( plaintext==NULL || pk==NULL || ciphertext_K==NULL || PRE_state==NULL  )
        _EXIT("encryption fallita");

    mpz_t sigma, r, tmp, t, g0_t, g2_t, vec[BUF_SIZE]={0};
    mpz_inits(sigma, r, tmp, t, g0_t, g2_t, vec[1], vec[2], vec[3], vec[0], vec[4], vec[5], NULL);
    
    size_t byte2write=0, byte2writes=0, offset=0, len;

    uint8_t *tx=malloc(sizeof(mpz_t)*100);
    uint8_t *BC=malloc(sizeof(mpz_t)*64);//1024 byte
    uint8_t *dump_C, *dump_B, *dump_sigma, *dump_msg;
    uint8_t c[BUF_SIZE], dump_buffer[size_NN];
    const int nbyte= snprintf(NULL, 0, "%02x", pk->id_hash);
    
    // range msg 1< m < 2^n -1
    assert(mpz_cmp_ui(plaintext->m, 0L)>0);
    mpz_ui_pow_ui(tmp, 2, n_msg_bitlength);
    mpz_sub_ui(tmp, tmp, 1);
    assert(mpz_cmp(plaintext->m, tmp) < 0);

    pmesg_mpz(msg_very_verbose, "\ntesto in chiaro", plaintext->m);
    
    //sigma in Zn random
    mpz_urandomm(sigma, prng, pk->N);  

    
    dump_msg=mpz_export(NULL, &byte2write, 1,1, 0, 0, plaintext->m);
    dump_sigma=mpz_export(NULL, &byte2writes, 1,1, 0, 0, sigma);

    memcpy(dump_buffer, dump_sigma, byte2writes*sizeof(uint8_t));    
    memcpy(dump_buffer+(byte2writes), dump_msg, byte2write*sizeof(uint8_t));

    //endian host
    memcpy(dump_buffer+byte2writes+byte2write, &(pk->id_hash), (size_t)nbyte);
    
    //printf("output ");
    /*for(size_t i=0; i<(byte2writes+byte2write)+(size_t)nbyte/2; i++){
        printf("%02x", dump_buffer[i]);
    }printf("\nblock= %lu\n",(byte2writes+byte2write)+(size_t)nbyte/2);*/
    
    
    //H generic sigma || msg || id, Zn^n bits outout
    uint8_t digest_h_s_m_Zn2[size_NN];
    
    perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, size_NN,
                                            dump_buffer, (byte2writes+byte2write)+(size_t)nbyte/2, digest_h_s_m_Zn2);
    
    //r
    mpz_import(r, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_s_m_Zn2);
    mpz_mod(r, r, pk->NN);
         
    //A=go^r mod N^2
    mpz_powm(ciphertext_K->info_cipher.K_1.A, pk->g0, r, pk->NN);       
   
    //H2 output sha3-348
    uint8_t digest_h_2_sigma[SHA3_512_DIGEST_SIZE]={0};
    /*perform_hashing_sha3_512(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE,
                                                    dump_sigma, byte2writes, digest_h_2_sigma, SHA3_384_DIGEST_SIZE);*/
    
    perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE,
                                            dump_sigma, byte2writes, digest_h_2_sigma);

    //C= H2 ( ( sigma ) xor m ), output sha3-384 
    mpz_import(tmp, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_2_sigma);
    mpz_fdiv_q_2exp(tmp, tmp, n_sec_parameter_H2_hash_functions);//get sha3-348
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
    
    //B=x*y mod N^2
    mpz_mul(ciphertext_K->info_cipher.K_1.B, ciphertext_K->info_cipher.K_1.B, tmp);
    mpz_mod(ciphertext_K->info_cipher.K_1.B, ciphertext_K->info_cipher.K_1.B, pk->NN);
    
    // (c,s)<-Sok.Gen(A,D,g0,g2,(BC)) //

    //set t in 0,.., 2^(|N^2|+k) -1
    mpz_set_ui(t, mpz_sizeinbase(pk->NN,2)); //|N^2| is the bit-lenght of N^2
    mpz_add_ui(t, t, k2_sec_parameter_H3_hash_functions);//k2 
    unsigned long int t_exp=mpz_get_ui(t);
    
    mpz_urandomb(t, prng, t_exp);
    mpz_powm(g0_t, pk->g0, t, pk->NN);
    mpz_powm(g2_t, pk->g2, t, pk->NN);
    
    mpz_set(vec[0], ciphertext_K->info_cipher.K_1.A);                                    // A
    mpz_set(vec[1], ciphertext_K->info_cipher.K_1.D);                                    // D
    mpz_set(vec[2], pk->g0);                                                                           // g0
    mpz_set(vec[3], pk->g2);                                                                           // g2
    mpz_set(vec[4], g0_t);                                                                               //  g0_t
    mpz_set(vec[5], g2_t);                                                                              //  g2_t
    
       for (size_t i=0; i<6; i++) {
       len=0;
       mpz_export(tx, &len, 1,1, 0, 0, vec[i]);
       memcpy(c+offset, tx, sizeof(uint8_t)*len);
       offset+=len;
    }
                                                                                                                        // BC
                                                                                                                        
    dump_B=mpz_export(NULL, &byte2write, 1,1,0,0, ciphertext_K->info_cipher.K_1.B);
    dump_C=mpz_export(NULL, &len, 1,1,0,0, ciphertext_K->info_cipher.K_1.C);

    memcpy(BC, dump_B, sizeof(uint8_t)*byte2write);
    memcpy(BC+byte2write, dump_C,sizeof(uint8_t)*len);
    
    memcpy(BC+byte2write+len, dump_C,sizeof(uint8_t)*len);
    memcpy(c+offset, BC, sizeof(uint8_t)*(len+byte2write));
    
    
    //H3 output sha3-512
    //c= (H_3 A || D || g0 || g2 || g0_t || g2_t || BC), BC=m
    uint8_t digest_h_3_c[SHA3_512_DIGEST_SIZE]={0};
    /*perform_hashing_sha3_512(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE, c,
                                                    offset+byte2write+len, digest_h_3_c, SHA3_256_DIGEST_SIZE);*/
    
    perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE, c,
                                                    offset+byte2write+len, digest_h_3_c);
    
    mpz_import(ciphertext_K->info_cipher.K_1.c, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_3_c);
    mpz_fdiv_q_2exp(ciphertext_K->info_cipher.K_1.c, ciphertext_K->info_cipher.K_1.c,
                            k2_sec_parameter_H3_hash_functions);//get sha3-256 bits (shift right)
        
    //s=(t-cx), x = log_g(y1) = log_h(y2) = r
    mpz_mul(tmp, ciphertext_K->info_cipher.K_1.c, r);
    mpz_sub(ciphertext_K->info_cipher.K_1.s, t, tmp);
    
    ciphertext_K->ciphertext_type=CIPHERTEXT_TYPE_K_1;//(A, B, D, c, s)
    
    pmesg_mpz(msg_very_verbose, "r =",r);
    pmesg_mpz(msg_very_verbose, "sigma =", sigma);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->A =",ciphertext_K->info_cipher.K_1.A);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->B =",ciphertext_K->info_cipher.K_1.B);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->C =",ciphertext_K->info_cipher.K_1.C);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->D =",ciphertext_K->info_cipher.K_1.D);
    pmesg_mpz(msg_very_verbose, "c =", ciphertext_K->info_cipher.K_1.c);
    pmesg_mpz(msg_very_verbose, "s =", ciphertext_K->info_cipher.K_1.s);
    
    free(dump_sigma);
    free(dump_msg);
    free(dump_C);
    free(dump_B);
    free(tx);
    free(BC);
    BC=NULL;
    tx=NULL;
    dump_B=NULL;
    dump_C=NULL;

    mpz_clears(sigma, r, tmp, t, g0_t, g2_t, vec[1], vec[2], vec[3], vec[0], vec[4], vec[5],NULL);
    
}


/*
 * decrypt
 */
void decryption (const ciphertext_t *K, const public_key_t *pk, const state_t *PRE_state, const weak_secret_key_t *wsk,
                                const private_key_t *sk, gmp_randstate_t prng, struct sha3_512_ctx context_512,
                                    unsigned int size_NN) {
    
    assert(prng);    
    if (pk==NULL || K==NULL || PRE_state==NULL  || sk==NULL )
        _EXIT("encryption fallita");
    
    mpz_t tmpk1, cmt_m, hash, cmt_sigma, tmp_g1, vec[BUF_SIZE]={0};
    mpz_inits(tmpk1, cmt_m, hash, cmt_sigma, tmp_g1, vec[0], vec[1], vec[2],
                        vec[3], vec[4], vec[5], NULL);
    
    size_t byte2write=0, offset=0, len;
    
    uint8_t *tx=malloc(sizeof(mpz_t)*100);
    uint8_t *dump_C, *dump_B, *dump_sigma, *dump_msg;
    uint8_t *dump_beta_dot;
    uint8_t *BC=malloc(sizeof(mpz_t)*64);//1024 byte
    uint8_t c[BUF_SIZE], dump_buffer[size_NN];

    if(K->ciphertext_type == CIPHERTEXT_TYPE_K_1){ //K=(A, B, D, c, s)
        
        mpz_t g0_s_A_c, g2_s_D_c, check_c, tmp_;
        mpz_inits(g0_s_A_c, g2_s_D_c, check_c, tmp_, NULL);
        
        //g0^s * A^c mod N^2
        mpz_powm(g0_s_A_c, pk->g0, K->info_cipher.K_1.s, pk->NN);
        mpz_powm(tmp_, K->info_cipher.K_1.A, K->info_cipher.K_1.c, pk->NN);
        mpz_mul(g0_s_A_c, g0_s_A_c, tmp_);
        mpz_mod(g0_s_A_c, g0_s_A_c, pk->NN);

        
        //g2^s * D^c mod N^2
        mpz_powm(g2_s_D_c, pk->g2, K->info_cipher.K_1.s, pk->NN);
        mpz_powm(tmp_, K->info_cipher.K_1.D, K->info_cipher.K_1.c, pk->NN);
        mpz_mul(g2_s_D_c, g2_s_D_c, tmp_); 
        mpz_mod(g2_s_D_c, g2_s_D_c, pk->NN);

            
        mpz_set(vec[0], K->info_cipher.K_1.A);                                    // A
        mpz_set(vec[1], K->info_cipher.K_1.D);                                    // D
        mpz_set(vec[2], pk->g0);                                                        //  g0
        mpz_set(vec[3], pk->g2);                                                        //  g2
        mpz_set(vec[4], g0_s_A_c);                                                     //  (g0)^s *(A)^c
        mpz_set(vec[5], g2_s_D_c);                                                     //  (g2)^s *(D)^c

        for (size_t i=0; i<6; i++) {
            len=0;
            mpz_export(tx, &len, 1,1, 0, 0, vec[i]);
            memcpy(c+offset, tx, sizeof(uint8_t)*len);
            offset+=len;
        }
        
                                                                                                            // BC

        dump_B=mpz_export(NULL, &byte2write, 1,1,0,0, K->info_cipher.K_1.B);
        dump_C=mpz_export(NULL, &len, 1,1,0,0, K->info_cipher.K_1.C);

        memcpy(BC, dump_B, sizeof(uint8_t)*byte2write);
        memcpy(BC+byte2write, dump_C,sizeof(uint8_t)*len);
        memcpy(BC+byte2write+len, dump_C,sizeof(uint8_t)*len);
        
        memcpy(c+offset, BC, sizeof(uint8_t)*(len+byte2write));
            
        //H3 verify_params, H2 output sha3-512
        uint8_t digest_c[SHA3_512_DIGEST_SIZE]={0};
        /*perform_hashing_sha3_512(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE, c,
                                                        offset+byte2write+len, digest_c, SHA3_256_DIGEST_SIZE);*/
        
        perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE, c,
                                                        offset+byte2write+len, digest_c);
        
        mpz_import(check_c, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_c);
        mpz_fdiv_q_2exp(check_c, check_c, k2_sec_parameter_H3_hash_functions);//get sha3-256 bits (shift right)
        
        
        //check c
        if(!mpz_cmp(K->info_cipher.K_1.c, check_c)==0)
            _EXIT("ciphertext non conforme o corrotto ");
        
        //printf("[ OK] ciphertext K idoneo\n\n");
         if (wsk){
             
                //printf("chiave input  per la decifrazione secret key weak\n\n");
                mpz_powm(cmt_sigma, K->info_cipher.K_1.A, wsk->a, pk->NN);
                mpz_invert(cmt_sigma, cmt_sigma, pk->NN);
                
                mpz_mul(cmt_sigma, K->info_cipher.K_1.B, cmt_sigma);
                mpz_mod(cmt_sigma, cmt_sigma, pk->NN);
                
                mpz_sub_ui(cmt_sigma, cmt_sigma, 1);                                                                                                                                                                                                                                                                              
                mpz_mod(cmt_sigma, cmt_sigma, pk->NN);
                
                //get sigma
                mpz_cdiv_q(cmt_sigma, cmt_sigma, pk->N);
            }
            else {
                //printf("chiave input  per la decifrazione long term secret key\n\n");
                //printf("digest c valutato correttamente...\n");

                mpz_t lamb_N, pi, a, r, w_1;
                mpz_inits (lamb_N, pi, a, r, w_1, NULL);
                
                //2p'q' (Carmichael's function)
                mpz_mul(lamb_N, sk->p_1, sk->q_1);
                mpz_mul_ui(lamb_N, lamb_N, 2);
                pmesg_mpz(msg_very_verbose, "lamb_N= ", lamb_N);

                //DPL a, a mod N
                //mpz_powm(a, pk->g1, lamb_N, pk->NN);
                mpz_set(a, pk->g1);
                mpz_sub_ui(a, a, 1);
                mpz_mod(a, a, pk->NN);
                mpz_cdiv_q(a, a, pk->N);                
                
                //DPL r
                //mpz_powm(r, K->info_cipher.K_1.A, lamb_N, pk->NN);
                mpz_set(r, K->info_cipher.K_1.A);
                mpz_sub_ui(r, r, 1);
                mpz_mod(r, r, pk->NN);
                mpz_cdiv_q(r, r, pk->N);                
                
                pmesg_mpz(msg_very_verbose, "PDL: a mod N", a);
                pmesg_mpz(msg_very_verbose, "PDL: r mod N", r);
    
                //w_1= a*r mod N
                mpz_mul(w_1, a, r);
                mpz_mod(w_1, w_1, pk->N);
                //pmesg_mpz(msg_very_verbose, "w_1= a*r mod N", w_1); 

                
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
            
            size_t byte2write_sigma=0, byte2write_msg=0;
            dump_sigma=mpz_export(NULL, &byte2write_sigma, 1, 1, 0, 0, cmt_sigma);
        
            //H2 output sha3-348
            uint8_t digest_h_2_compute_sigma[SHA3_512_DIGEST_SIZE]={0};
            /*perform_hashing_sha3_512(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE,
                                                        dump_sigma, byte2write_sigma, digest_h_2_compute_sigma, SHA3_384_DIGEST_SIZE);*/
            
            perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, SHA3_384_DIGEST_SIZE,
                                                        dump_sigma, byte2write_sigma, digest_h_2_compute_sigma);
            
            //get m
            mpz_import(tmp_, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_2_compute_sigma);
            mpz_fdiv_q_2exp(tmp_, tmp_, n_sec_parameter_H2_hash_functions);//get sha3-348
            mpz_xor(cmt_m, K->info_cipher.K_1.C, tmp_);
            
            dump_msg=mpz_export(NULL, &byte2write_msg, 1,sizeof(uint8_t), 0, 0, cmt_m);            
            memcpy(dump_buffer, dump_sigma, byte2write_sigma*sizeof(uint8_t));    
            memcpy(dump_buffer+byte2write_sigma, dump_msg, byte2write_msg*sizeof(uint8_t));
            
            const int nbyte= snprintf(NULL, 0, "%02x", (uint32_t)pk->id_hash);
            
            //endian host
            memcpy(dump_buffer+(byte2write_sigma+byte2write_msg), &(pk->id_hash), (size_t)(nbyte)*sizeof(uint8_t));
            
            //H generic ( sigma || msg || id ), Zn^n bits outout
            uint8_t digest_h_s_m_Zn2[size_NN];
            perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, size_NN,
                                                                    dump_buffer,(byte2write_sigma+byte2write_msg+(size_t)nbyte/2),
                                                                            digest_h_s_m_Zn2);           
            
            
            //generic hash function output
            mpz_import(hash, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_s_m_Zn2);
            mpz_mod(hash, hash, pk->NN);

            //g1^r mod N^2
            mpz_powm(tmp_g1, pk->g1, hash, pk->NN);
            
            //g1^r * (1+sigma*N) mod N^2  ( a*b mod = mod (a mod * b mod ) )
            //(1+sigma*N) mod N^2
            mpz_mul(tmp_, cmt_sigma, pk->N);
            mpz_add_ui(tmp_,tmp_,1);
            mpz_mod(tmp_, tmp_, pk->NN);
            
            //get B
            mpz_mul(tmp_, tmp_g1, tmp_);
            mpz_mod(tmp_, tmp_, pk->NN);
            
            if(mpz_cmp(tmp_, K->info_cipher.K_1.B)==0) {
                
                //printf("ciphertext conforme, messaggio decifrato correttamente.\n");
                pmesg_mpz(msg_very_verbose, "message =", cmt_m);
            
                free(dump_sigma);
                free(dump_msg);
                dump_sigma=NULL;
                dump_msg=NULL;
                
                mpz_clears(cmt_m, hash, cmt_sigma, tmp_g1, tmp_, NULL);
                
            }
            else  _EXIT("[ X] ciphertext K di input corrotto");
                        
            free(tx);
            free(dump_B);
            free(dump_C);
            free(BC);  
            tx=NULL;
            BC=NULL;
            dump_B=NULL;
            dump_C=NULL;
            
            mpz_clears(g0_s_A_c, g2_s_D_c, check_c, tmpk1, vec[0], vec[1], vec[2],
                        vec[3], vec[4], vec[5], NULL);
        
    }//type1end
    else if (K->ciphertext_type == CIPHERTEXT_TYPE_K_2)  { //K=(A, A', B, C, A_dot, B_dot, C_dot
                        
        mpz_t tmp, computed_m, hashd, cmt_sigma_dot, beta_dot_c, tmp_g2;
        mpz_inits(tmp, computed_m, hashd, cmt_sigma_dot, beta_dot_c, tmp_g2, NULL);
       
        size_t byte2write_beta_dot=0, byte2write_sigma_dot=0, byte2write_compute_sigma=0,
                    byte2write_msg=0;
        int nbyte=0;
        
        if (wsk){
                
                mpz_powm(cmt_sigma_dot, K->info_cipher.K_2.A_dot, wsk->b, pk->NN);
                mpz_invert(cmt_sigma_dot, cmt_sigma_dot, pk->NN);
            
                mpz_mul(cmt_sigma_dot, K->info_cipher.K_2.B_dot, cmt_sigma_dot);
                mpz_mod(cmt_sigma_dot, cmt_sigma_dot, pk->NN);
                
                mpz_sub_ui(cmt_sigma_dot, cmt_sigma_dot, 1);                                                                                                                                                                                                                                                    
                mpz_mod(cmt_sigma_dot, cmt_sigma_dot, pk->NN);
 
                //get sigma dot
                mpz_cdiv_q(cmt_sigma_dot, cmt_sigma_dot, pk->N);
                
            }
            else {
                //printf("chiave input  per la decifrazione long term secret key\n\n");
                //printf("digest c valutato correttamente...\n");
                
                mpz_t lamb_N, pi, b, r, w_1;
                mpz_inits (lamb_N, pi, b, r, w_1, NULL);
                
                //2p'q' (Carmichael's function)
                mpz_mul(lamb_N, sk->p_1, sk->q_1);
                mpz_mul_ui(lamb_N, lamb_N, 2);
                //pmesg_mpz(msg_very_verbose, "lamb_N= ", lamb_N);

                //DPL a, a mod N
                //mpz_powm(a, pk->g1, lamb_N, pk->NN);
                mpz_set(b, pk->g2);
                mpz_sub_ui(b, b, 1);
                mpz_mod(b, b, pk->NN);
                mpz_cdiv_q(b, b, pk->N);                
                
                //DPL r
                //mpz_powm(r, K->info_cipher.K_1.A, lamb_N, pk->NN);
                mpz_set(r, K->info_cipher.K_2.A_dot);
                mpz_sub_ui(r, r, 1);
                mpz_mod(r, r, pk->NN);
                mpz_cdiv_q(r, r, pk->N);                
                
                //pmesg_mpz(msg_very_verbose, "PDL: r mod N", r);
                //pmesg_mpz(msg_very_verbose, "PDL: b mod N", b);
                
                //w_1= a*r mod N
                mpz_mul(w_1, b, r);
                mpz_mod(w_1, w_1, pk->N);               
                //pmesg_mpz(msg_very_verbose, "w_1= b*rXY mod N", w_1);

                mpz_powm(cmt_sigma_dot, pk->g0, w_1, pk->NN);
                mpz_invert(cmt_sigma_dot, cmt_sigma_dot, pk->NN);
                mpz_mul(cmt_sigma_dot, K->info_cipher.K_2.B_dot, cmt_sigma_dot);
                mpz_mod(cmt_sigma_dot, cmt_sigma_dot, pk->NN);
                mpz_powm(cmt_sigma_dot, cmt_sigma_dot, lamb_N, pk->NN);
                
                //D
                mpz_sub_ui(cmt_sigma_dot, cmt_sigma_dot, 1);
                mpz_mod(cmt_sigma_dot, cmt_sigma_dot, pk->NN);
                mpz_cdiv_q(cmt_sigma_dot, cmt_sigma_dot, pk->N);
                
                //get pi
                mpz_invert(pi, lamb_N, pk->N);
                
                //get sigma
                mpz_mul(cmt_sigma_dot, cmt_sigma_dot, pi);
                mpz_mod(cmt_sigma_dot, cmt_sigma_dot, pk->N);
                mpz_clears (lamb_N, pi, b, r, w_1, NULL);
            }
            
            // compute   //  
            
            dump_sigma=mpz_export(NULL, &byte2write_sigma_dot, 1,1, 0, 0, cmt_sigma_dot);
            
            
            //H1 computed sigma_dot, output sha3-512
            //computed sigma dot
            uint8_t digest_H1_cmt_sigma_dot [SHA3_512_DIGEST_SIZE];
            /*perform_hashing_sha3_512(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE,
                                                dump_sigma, byte2write_sigma_dot,  digest_H1_cmt_sigma_dot, SHA3_512_DIGEST_SIZE);*/
        
            perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE,
                                                dump_sigma, byte2write_sigma_dot,  digest_H1_cmt_sigma_dot);
                        
                        
            mpz_import(tmp, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_H1_cmt_sigma_dot);
            
            //get beta_dot_c
            mpz_xor(beta_dot_c, K->info_cipher.K_2.C_dot, tmp);
                        
            dump_beta_dot=mpz_export(NULL, &byte2write_beta_dot, 1,1,0,0, beta_dot_c);
            memcpy(dump_buffer, dump_sigma, byte2write_sigma_dot*sizeof(uint8_t));
            memcpy(dump_buffer+byte2write_sigma_dot, dump_beta_dot, byte2write_beta_dot*sizeof(uint8_t));
                
            nbyte= snprintf(NULL, 0, "%02x", (uint32_t)pk->id_hash);
            
            //endian host
            memcpy(dump_buffer+byte2write_sigma_dot+byte2write_beta_dot, &(pk->id_hash), (size_t)nbyte);
            
            
            //H generic hash ( sigma_dot || beta_dot || id ), Zn^n bits outout
            uint8_t digest_h_sigma_dot_beta_dot_Zn2[size_NN];
            perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, size_NN,
                                         dump_buffer, byte2write_sigma_dot+byte2write_beta_dot+((size_t)nbyte/2),
                                                    digest_h_sigma_dot_beta_dot_Zn2);
            
            
            mpz_import(hashd, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_sigma_dot_beta_dot_Zn2);
            mpz_mod(hashd, hashd, pk->NN);

            //g2^( H ( cmt_sigma_dot || beta_dot_c )) mod N^2, pk decryptor
            mpz_powm(tmp_g2, pk->g2, hashd, pk->NN);
                
            //(1+cmt_sigma_dot*N) mod N^2
            mpz_mul(tmp, cmt_sigma_dot, pk->N);
            mpz_add_ui(tmp,tmp,1);
            mpz_mod(tmp, tmp, pk->NN);
            
            //B_dot compute
            mpz_mul(tmp, tmp, tmp_g2);
            mpz_mod(tmp, tmp, pk->NN);
            
            free(dump_sigma);//free
            
            if (mpz_cmp(tmp, K->info_cipher.K_2.B_dot)==0) {
                
                //printf("\n[ OK] B_dot calcolato correttamente... computazione di sigma\n");
                mpz_t tmp_c, check_H, tmpA, tmpB;
                mpz_inits (tmp_c, check_H, tmpA, tmpB, NULL);
                
                //sigma cpmputato
                mpz_powm(tmp_c, K->info_cipher.K_2.A, beta_dot_c, pk->delegator->NN);
                mpz_mul(cmt_sigma, K->info_cipher.K_2.A_1, tmp_c);
                mpz_mod(cmt_sigma, cmt_sigma, pk->delegator->NN);
             
                mpz_invert(cmt_sigma, cmt_sigma, pk->delegator->NN);
                mpz_mul(cmt_sigma, K->info_cipher.K_2.B, cmt_sigma);
                mpz_mod(cmt_sigma, cmt_sigma, pk->delegator->NN);
        
                mpz_sub_ui(cmt_sigma, cmt_sigma, 1);
                mpz_mod(cmt_sigma, cmt_sigma, pk->delegator->NN);
                mpz_cdiv_q(cmt_sigma, cmt_sigma,  pk->delegator->N);
                                

                //compute_sigma
                dump_sigma=mpz_export(NULL, &byte2write_compute_sigma, 1,1,0,0, cmt_sigma);
                memcpy(dump_buffer, dump_sigma, byte2write_compute_sigma*sizeof(uint8_t));  

                //H2 sigma computato, output sha3-348
                uint8_t digest_hash_2_compute_sigma[SHA3_512_DIGEST_SIZE]={0};
                /*perform_hashing_sha3_512(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE,
                                                                    dump_sigma, byte2write_compute_sigma, digest_hash_2_compute_sigma,
                                                                                SHA3_384_DIGEST_SIZE);*/
                perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE,
                                                                    dump_sigma, byte2write_compute_sigma, digest_hash_2_compute_sigma);
                
                //get m
                mpz_import(tmp, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_hash_2_compute_sigma);
                mpz_fdiv_q_2exp(tmp, tmp, n_sec_parameter_H2_hash_functions);//get sha3-348
                mpz_xor(computed_m, K->info_cipher.K_2.C, tmp);

                dump_msg=mpz_export(NULL, &byte2write_msg, 1,1,0,0, computed_m);
                memcpy(dump_buffer, dump_sigma, byte2write_compute_sigma*sizeof(uint8_t));    
                //?
                memcpy(dump_buffer+byte2write_compute_sigma, dump_msg, byte2write_msg*sizeof(uint8_t));
                nbyte= snprintf(NULL, 0, "%02x", pk->delegator->id_hash);
                
                //endian host
                memcpy(dump_buffer+byte2write_compute_sigma+byte2write_msg, &(pk->delegator->id_hash),
                                (size_t)nbyte);
                
                    
                //H generic hash from delegator (alice), Zn^n bits outout
                uint8_t digest_check_h_sig_m_Zn2[size_NN];
                perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, size_NN,
                                             dump_buffer, (byte2write_compute_sigma+byte2write_msg)+(size_t)nbyte/2,
                                                        digest_check_h_sig_m_Zn2);
                
                mpz_import(check_H, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_check_h_sig_m_Zn2);
                mpz_mod(check_H, check_H, pk->NN);
                
                //A = (g0')^H'( sigma || m) mod N'^2
                mpz_powm(tmpA, pk->delegator->g0, check_H, pk->delegator->NN);                
                
                //B = (g1')^H'( sigma || m) * (1+N'*sigma) mod N'^2
                mpz_mul(tmp, cmt_sigma, pk->delegator->N);
                mpz_add_ui(tmp, tmp, 1);
                mpz_mod(tmp, tmp, pk->delegator->NN);
                
                mpz_powm(tmpB, pk->delegator->g1, check_H, pk->delegator->NN);
                mpz_mul(tmpB, tmpB, tmp);
                mpz_mod(tmpB, tmpB, pk->delegator->NN);                
                
                if (mpz_cmp(tmpA, K->info_cipher.K_2.A)==0  && mpz_cmp(tmpB, K->info_cipher.K_2.B)==0) {
                    pmesg_mpz(msg_very_verbose, "message =", computed_m);
                }
                else _EXIT("[ X] errore in fase di decryption, paramertri corrotti");
            
                free(dump_sigma);
                free(dump_msg);
                free(dump_beta_dot);
                dump_sigma=NULL;
                dump_msg=NULL;
                dump_beta_dot=NULL;
                
                mpz_clears (tmp_c, check_H, tmpA, tmpB, cmt_sigma, NULL);
            }//end check B
            
            else {_EXIT("[ X] B computato in modo non corretto");}
                        
            free(tx);
            free(BC);
            free(dump_sigma);
            free(dump_msg);
            free(dump_beta_dot);
            tx=NULL;
            dump_sigma=NULL;
            dump_msg=NULL;
            dump_beta_dot=NULL;
            mpz_clears(tmp, computed_m, hashd, cmt_sigma_dot, beta_dot_c, tmp_g2, NULL);
    }
}


/*
 * ReKeyGen
 */
void RekeyGen(gmp_randstate_t prng, re_encryption_key_t *RE_enc_key, const state_t *PRE_state, 
                                        const public_key_t *pkY, const private_key_t *skX, weak_secret_key_t *wskX,
                                                            struct sha3_512_ctx context_512, unsigned int size_NN){
  
    assert(prng);

    if( pkY==NULL || PRE_state==NULL || wskX==NULL || RE_enc_key==NULL || skX==NULL)
        _EXIT("ciphertext K di input corrotto");
    
    mpz_t sigma_dot, beta_dot, h_1, tmp, rXY;
    mpz_inits (sigma_dot, beta_dot, h_1, tmp, rXY, NULL);

    size_t byte2write_sigma_dot=0, byte2write_beta_dot=0;
    uint8_t dump_buffer[size_NN];
    uint8_t *dump_sigma, *dump_msg;
    
    //sigma_dot random in Zn
    mpz_urandomm(sigma_dot, prng, pkY->N);
    
    //beta_dot random in {0,1}^k1
    mpz_urandomb(beta_dot, prng, k1_sec_parameter_H1_hash_functions);
    
    mpz_sub(RE_enc_key->k2_x2y, wskX->a, beta_dot);
    mpz_mul(tmp, skX->p, skX->q);
    mpz_mul(tmp, tmp, skX->p_1);
    mpz_mul(tmp, tmp, skX->q_1);
    
    //rk_X->Y
    mpz_mod(RE_enc_key->k2_x2y, RE_enc_key->k2_x2y, tmp);
    
    dump_msg=mpz_export(NULL, &byte2write_beta_dot, 1,1, 0, 0, beta_dot);//beta_dot
    dump_sigma=mpz_export(NULL, &byte2write_sigma_dot, 1,1, 0, 0, sigma_dot);//sigma_dot
    
    memcpy(dump_buffer, dump_sigma, byte2write_sigma_dot*sizeof(uint8_t));    
    memcpy(dump_buffer+byte2write_sigma_dot, dump_msg, byte2write_beta_dot*sizeof(uint8_t));
    const int nbyte= snprintf(NULL, 0, "%02x", pkY->id_hash);

    //endian host
    memcpy(dump_buffer+byte2write_sigma_dot+byte2write_beta_dot, &(pkY->id_hash), (size_t)nbyte);
        
    //H generic hash Y, Zn^2 bits outout
    //rX->Y= HY ( sigma_dot || beta_dot || idY )
    uint8_t digest_h_Y_rXY_Zn2[size_NN];
    perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, size_NN,
                                                        dump_buffer, (byte2write_sigma_dot+byte2write_beta_dot)+(size_t)nbyte/2,  
                                                            digest_h_Y_rXY_Zn2);
    
    mpz_import(rXY, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_h_Y_rXY_Zn2);
    mpz_mod(rXY, rXY, pkY->NN);
    
    //A_dot
    mpz_powm(RE_enc_key->A_dot, pkY->g0, rXY, pkY->NN);    
    
    //H1 sigma_dot RekeyGen, output sha3-512
    uint8_t digest_H_1_sigma[SHA3_512_DIGEST_SIZE];
    /*perform_hashing_sha3_512(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE, dump_sigma,
                                                       byte2write_sigma_dot, digest_H_1_sigma, SHA3_512_DIGEST_SIZE);*/
    
    perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE,dump_sigma,
                                                        byte2write_sigma_dot, digest_H_1_sigma);
    
    mpz_import(h_1, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_H_1_sigma);
    
    //C_dot
    mpz_xor(RE_enc_key->C_dot, h_1, beta_dot);
    
    //B_dot
    mpz_mul(tmp, sigma_dot, pkY->N);
    mpz_add_ui(tmp, tmp, 1);
    mpz_mod(tmp, tmp, pkY->NN);
    mpz_powm(RE_enc_key->B_dot, pkY->g2, rXY, pkY->NN);

    mpz_mul(RE_enc_key->B_dot, tmp, RE_enc_key->B_dot);
    mpz_mod(RE_enc_key->B_dot, RE_enc_key->B_dot, pkY->NN);
    
    pmesg_mpz(msg_very_verbose, "\nrk2_X -> Y", RE_enc_key->k2_x2y);
    
    //printf("\nrk1_X -> Y\n");
    pmesg_mpz(msg_very_verbose, "\n\nA_dot", RE_enc_key->A_dot);
    pmesg_mpz(msg_very_verbose, "\nB_dot", RE_enc_key->B_dot);
    pmesg_mpz(msg_very_verbose, "\nC_dot", RE_enc_key->C_dot);
    pmesg_mpz(msg_very_verbose, "\nsigma_dot", sigma_dot);
    pmesg_mpz(msg_very_verbose, "\nbeta_dot", beta_dot);
    
    free(dump_sigma);
    free(dump_msg);
    mpz_clears (sigma_dot, beta_dot, h_1, tmp, rXY, NULL);
}


/*
 * ReEncrypt
 */
void ReEncrypt (ciphertext_t *K, const re_encryption_key_t *RE_enc_key, const state_t *PRE_state,
                            const public_key_t *pkX, struct sha3_512_ctx context_512){    
    
    if( K==NULL || PRE_state==NULL || pkX==NULL || RE_enc_key==NULL )
        _EXIT("ciphertext K di input corrotto");
    
    mpz_t g0X_s_A_c, g2X_s_D_c, tmp, check_c, tmpA, tmpB, tmpC, vec[BUF_SIZE]={0};
    mpz_inits (g0X_s_A_c, g2X_s_D_c, tmp, check_c, tmpA, tmpB, tmpC, vec[0], vec[1], vec[2],
                        vec[3], vec[4], vec[5], NULL);
    
    size_t byte2write=0, offset=0, len;
    uint8_t *tx=malloc(sizeof(mpz_t)*100);
    uint8_t *dump_C, *dump_B;
    uint8_t *BC=malloc(sizeof(mpz_t)*64);//1024 byte
    uint8_t c[BUF_SIZE];
     
    //g0X^s * A^c mod N^2
    mpz_powm(g0X_s_A_c, pkX->g0, K->info_cipher.K_1.s, pkX->NN);
    
    mpz_powm(tmp, K->info_cipher.K_1.A, K->info_cipher.K_1.c, pkX->NN);
    mpz_mul(g0X_s_A_c, g0X_s_A_c, tmp);
    mpz_mod(g0X_s_A_c, g0X_s_A_c, pkX->NN);

    
    //g2X^s * D^c mod N^2
    mpz_powm(g2X_s_D_c, pkX->g2, K->info_cipher.K_1.s, pkX->NN);
    mpz_powm(tmp, K->info_cipher.K_1.D, K->info_cipher.K_1.c, pkX->NN);
    mpz_mul(g2X_s_D_c, g2X_s_D_c, tmp); 
    mpz_mod(g2X_s_D_c, g2X_s_D_c, pkX->NN);
    
    mpz_set(vec[0], K->info_cipher.K_1.A);                                     // A
    mpz_set(vec[1], K->info_cipher.K_1.D);                                     // D
    mpz_set(vec[2], pkX->g0);                                                        //  g0X
    mpz_set(vec[3], pkX->g2);                                                        //  g2X
    mpz_set(vec[4], g0X_s_A_c);                                                     //  (g0X)^s *(A)^c
    mpz_set(vec[5], g2X_s_D_c);                                                     //  (g2X)^s *(D)^c

       for (size_t i=0; i<6; i++) {
       len=0;
       mpz_export(tx, &len, 1,1, 0, 0, vec[i]);
       memcpy(c+offset, tx, sizeof(uint8_t)*len);
       offset+=len;
    }
    
                                                                                                                //BC

    dump_B=mpz_export(NULL, &byte2write, 1,1,0,0, K->info_cipher.K_1.B);
    dump_C=mpz_export(NULL, &len, 1,1,0,0, K->info_cipher.K_1.C);

    memcpy(BC, dump_B, sizeof(uint8_t)*byte2write);
    memcpy(BC+byte2write, dump_C,sizeof(uint8_t)*len);
    memcpy(BC+byte2write+len, dump_C,sizeof(uint8_t)*len);
    
    memcpy(c+offset, BC, sizeof(uint8_t)*(len+byte2write));
    
    
    //c=H3( A, D, g0X, g2X, (g0X)^s *(A)^c, (g2X)^s *(D)^c), output sha3-256
    uint8_t digest_chec_c[SHA3_512_DIGEST_SIZE]={0};
    /*perform_hashing_sha3_512(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE, c,
                                                    offset+byte2write+len, digest_chec_c, SHA3_256_DIGEST_SIZE);*/
    
    perform_hashing_sha3_generic(context_512, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE, c,
                                                    offset+byte2write+len, digest_chec_c);
        
    mpz_import(check_c, SHA3_512_DIGEST_SIZE,1,1,0,0, digest_chec_c);
    mpz_fdiv_q_2exp(check_c, check_c, k2_sec_parameter_H3_hash_functions);//get sha3-256 bits (shift right)
    

    //verify_params c = H3
    if(!mpz_cmp(K->info_cipher.K_1.c, check_c)==0) {
        _EXIT("[ X] ciphertext non conforme, errore in fare di re-encryption. ");
    }
    else {
        printf("[ OK] ciphertext ricevuto conforme alla re-encryption\n\n");
        mpz_set(tmpA, K->info_cipher.K_1.A); //A=g0^r, k=1
        mpz_set(tmpB, K->info_cipher.K_1.B);
        mpz_set(tmpC, K->info_cipher.K_1.C);

        
        //A'
        mpz_powm(K->info_cipher.K_2.A_1, tmpA, RE_enc_key->k2_x2y, pkX->NN);
        pmesg_mpz(msg_very_verbose, "RE_enc_key->k2_x2y", RE_enc_key->k2_x2y);
        
        
        K->ciphertext_type=CIPHERTEXT_TYPE_K_2;//K=(A, A', B, C, A_dot, B_dot, C_dot)
        
        mpz_set(K->info_cipher.K_2.A, tmpA);
        mpz_set(K->info_cipher.K_2.B, tmpB);
        mpz_set(K->info_cipher.K_2.C, tmpC);
        
        mpz_set(K->info_cipher.K_2.A_dot, RE_enc_key->A_dot);
        mpz_set(K->info_cipher.K_2.B_dot, RE_enc_key->B_dot);
        mpz_set(K->info_cipher.K_2.C_dot, RE_enc_key->C_dot);
        
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
    free(tx);
    free(BC);
    free(dump_C);
    free(dump_B);
    dump_C=NULL;
    dump_B=NULL;
    tx=NULL;
    BC=NULL;
    
    mpz_clears (g0X_s_A_c, g2X_s_D_c, tmp, check_c, tmpA, tmpB, tmpC, vec[0], vec[1], vec[2],
                        vec[3], vec[4], vec[5], NULL);
}


/*
 * init method
 */
void keygen_params_init(keygen_params_t *params) {
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

void ReKeyGen_keys_init(re_encryption_key_t *RE_enc_key){
    if (RE_enc_key==NULL)
        _EXIT("errore nella procedura ReKeyGen");
    mpz_inits(RE_enc_key->k2_x2y, RE_enc_key->A_dot,
               RE_enc_key->B_dot, RE_enc_key->C_dot, NULL);
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
    mpz_init(K->info_cipher.K_2.C_dot);
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

void keygen_params_clear(keygen_params_t *params) {
    if (params==NULL)
        _EXIT("errore nella procedura di generazione dei parametri");
    mpz_clears(params->N, params->p, params->p_1, params->q, params->q_1, NULL);
}

void plaintext_clear(plaintext_t *plaintext) {
    assert(plaintext);
    mpz_clear(plaintext->m);
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

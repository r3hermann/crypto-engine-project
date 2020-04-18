#include "lib-main.h"
#include <unistd.h>
#include <sys/types.h>
#include<sys/wait.h>
#include <nettle/sha3.h>
#include <nettle/sha1.h>
#include <time.h> 

#define perform_hashing(STRUCT_CTX, FNC_INIT, FNC_UPDATE, FNC_DIGEST,DGST_SIZE)    \
                                ({                                                                                                              \
                                        struct STRUCT_CTX context;                                                             \
                                        FNC_INIT(&context);                                                                          \
                                        uint8_t digest[DGST_SIZE];                                                               \
                                        char buffer[2048];                                                                             \
                                                                                                                                                  \
                                        FNC_UPDATE(&context, block_size, block_to_hash);                         \
                                        FNC_DIGEST(&context, DGST_SIZE, digest);                                     \
                                                                                                                                                  \
                                        pmesg_hex(msg_verbose, buffer, DGST_SIZE, digest);                     \
                                        digest;                                                                                               \
                                })

                                
#define ul_to_char(HASHID)                                                                \
                    ({                                                                                     \
                          const int n= snprintf(NULL, 0, "%lu", HASHID);         \
                          assert(n>0);                                                              \
                          char buffer[19+1];                                                     \
                          int c = snprintf(buffer, 19+1, "%lu", HASHID);          \
                          assert(c==n);                                                           \
                          buffer;                                                                       \
                    })

#define TestingHash(DIGEST)                                       \
                    ({                                                               \
                            printf("test hash online: ");                \
                            int len=0;                                           \
                            while(DIGEST[len]!='\0') {                 \
                                printf("%02x",DIGEST[len]);           \
                                len++;                                            \
                            }                                                         \
                        })
                    
/*printf("bufferMACRO= %s, n=%d, c=%d, sizeBuffer= %ld\n",buffer,n,c,sizeof(buffer));         \
 * get seed
 */
long random_seed () {
    
    FILE *dev_random;
    int byte_count;
    int seed=0;
	byte_count = BYTEREAD;
	dev_random = fopen("/dev/random", "r");
	
    if(dev_random == NULL) {
		fprintf(stderr, "cannot open random number device!\n");
		exit(1);
	}
    
	//genera bytes con /dev/random
	fread(&seed, sizeof(char), byte_count, dev_random);

    //printf("\ndati letti: (hex) %x, (int) %d, (int senza segno) %u\n",seed,seed,seed);
    //printf("byte allocati= %ld. byte_count= %d\n",(byte_count)*sizeof(char),byte_count);
	fclose(dev_random);
    return seed;
}


/*void state {
    
        unsigned int buffer;
    int byte_count=4;
    FILE *dev_random;
	dev_random = fopen("/dev/random", "r");
    if(dev_random == NULL) {
		fprintf(stderr, "cannot open random number device!\n");
		exit(1);
	}
    
	fread(&buffer,sizeof(char), byte_count, dev_random);
	fclose(dev_random);
    
}*/

/* 
 * get shared params
 */
void generate_shared_params(shared_params_t params, unsigned n_bits, gmp_randstate_t prng) {

    pmesg(msg_verbose, "generazione parametri comuni...");
      
    //assert
    assert(params);
    assert(n_bits>1);
    assert(prng);

    mpz_inits(params->N,params->p,params->p_1,params->q, params->q_1,NULL);

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


    /* scelta del generatore in Z*: per ogni k,divisore, di ogni elemento
     * di phi_p, la divisione deve essere diverso da 1. In questo caso phi_p=2*q.
     * Occorre verificare g^2!=1 && g^q!=1. Qui
     * e' richiesto che g sia solo conforme alla definizione di generatore
     */
    
    //N=p*q
    mpz_mul(params->N,params->p,params->q);
    
    //test divisione
    /*mpz_cdiv_q(tmp,params->N,params->p);
    pmesg_mpz(msg_very_verbose, "N/p =",tmp);
    mpz_cdiv_q(tmp2,params->N,params->q);
    pmesg_mpz(msg_very_verbose, "mN/q =",tmp2);*/
    
    //N varia tra 1023-1024
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
    dev_random = fopen("/dev/random", "r");

    if(dev_random == NULL) {
		fprintf(stderr, "cannot open random number device!\n");
		exit(1);
	}
    
	fread(&buffer,sizeof(char), byte_count, dev_random);
    
    PRE_state->h_1=*(&buffer[0]);
    PRE_state->h_2=*(&buffer[1]);
    PRE_state->h_3=*(&buffer[2]);
    
    for(int i=0;i<3;i++)
        printf(" buffer[%d] = %u", i, buffer[i]);
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
    
    //time_t seconds=time(NULL); //secondi dal 1 gennaio 1970
    
    pmesg(msg_verbose, "generazione del contributo...");
    
    mpz_t N_2, alpha,tmp;
    mpz_inits(N_2, alpha, tmp, NULL);
    
    //init keys
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
    
    
    //apha random
    mpz_pow_ui(N_2,params->N,2);
    mpz_urandomm(alpha,prng, N_2);
    
    // calcolo il range [pp' qq'] +1
    mpz_mul(tmp,params->p,params->p_1);
    mpz_mul(tmp,tmp,params->q);
    mpz_mul(tmp,tmp,params->q_1);
    mpz_add_ui(tmp,tmp,1); // ultimo elemento da escudere;
    
    //a,b random in [1,pp' qq'], 0 escluso
    do {
        mpz_urandomm(wsk->a,prng,tmp);
        mpz_urandomm(wsk->b,prng,tmp);
    } while( (mpz_cmp_ui(wsk->a,0)==0) || (mpz_cmp_ui(wsk->b,0)==0)  );
    
    //test generatori?
    
    //g0 = alpha^2 mod N^2
    mpz_powm_ui(pk->g0,alpha,2,N_2);
    
    //g1 = g0^a mod N^2
    mpz_powm(pk->g1,pk->g0,wsk->a,N_2);
    
    //g2= g0^b mod N^2
    mpz_powm(pk->g2,pk->g0,wsk->b,N_2);
    
    //pk
    printf("\npk = (H(.), N, g0, g1, g2)\n");
    pmesg_mpz(msg_very_verbose, "alpha =",alpha);
    pmesg_mpz(msg_very_verbose, "id_Hash =",pk->id_hash);
    pmesg_mpz(msg_very_verbose, "modulo N=",pk->N);
    pmesg_mpz(msg_very_verbose, "g0 =",pk->g0);
    pmesg_mpz(msg_very_verbose, "g1 =",pk->g1);
    pmesg_mpz(msg_very_verbose, "g2=",pk->g2);

    //weak secret
    printf("\nweak secret\n");
    pmesg_mpz(msg_very_verbose, "a =",wsk->a);
    pmesg_mpz(msg_very_verbose, "b =",wsk->b);
    
    //sk
    printf("\nsk = (p, q, p', q')\n");
    pmesg_mpz(msg_very_verbose, "p =",sk->p);
    pmesg_mpz(msg_very_verbose, "q =",sk->q);
    pmesg_mpz(msg_very_verbose, "p' = ", sk->p_1);
    pmesg_mpz(msg_very_verbose, "q' = ", sk->q_1);
    
    mpz_clears(N_2, alpha, tmp,NULL);
}


/*
 * encrypt
 */
void encrypt(const shared_params_t params, gmp_randstate_t prng, const plaintext_t plaintext, const public_key_t pk,
                    ciphertext_t ciphertext_K, const state_t PRE_state) {
    
    mpz_t sigma, tmp, r, N_2;
    assert(prng);
    assert(params);
    assert(plaintext);
    assert(ciphertext_K);
    
    //check plaintext, servono ulteriori controlli?
    assert(mpz_cmp_ui(plaintext->m, 0L)>0);
    assert(mpz_cmp(plaintext->m, params->N) < 0);
    pmesg(msg_verbose, "cifratura...");
    
    mpz_inits(sigma, tmp, r, N_2, NULL);
    pmesg_mpz(msg_very_verbose, "testo in chiaro", plaintext->m);
    
    
    //sigma in Zn random
    mpz_urandomm(sigma,prng, params->N);
    
    //sigma || m || id, (string base 10)
    char *strsig=0;
    
    
   /*const int n= snprintf(NULL, 0, "%lu", PRE_state->h_1);
    assert(n>0);
    char buffp[n+1];
    int c = snprintf(buffp, n+1, "%lu",PRE_state->h_1);*/
    /*assert(buff[n]=='\0');
    assert(c==n);*/
    
    //attenzione alla dimesione PRE_state->h_1, 
    //viene passata quella del puntatore    
    char *str_s_m=mpz_get_str(strsig, 10, sigma);
    strcat(str_s_m, mpz_get_str(strsig, 10, plaintext->m));
    strcat(str_s_m,  ul_to_char(PRE_state->h_1)); //H_1
    //printf("Size PRE_state->h_1= %ld, n=%d, c=%d, sizeBuffp= %ld\n",sizeof(PRE_state->h_1),n,c,sizeof(buffp));
    
    //length str_s_m
    char *str_s_m_length=&str_s_m[0];
    int const block_size=strlen(str_s_m_length);
    //printf("length (str_s_m)= %d\n",(s_m_length));
    
    
    uint8_t block_to_hash[block_size];
    
    printf("\n(sigma||m||id)= ");
    for(int i=0; i<block_size;i++){
        printf("%c",str_s_m[i]);
        block_to_hash[i]=(uint8_t)str_s_m[i];
    }printf("\n\n");

    
    uint8_t *digestsha3_512=(perform_hashing(sha3_512_ctx, sha3_512_init, sha3_512_update, sha3_512_digest, SHA3_512_DIGEST_SIZE));
    printf("\n");
    
    //test stampa hash
    //TestingHash(digestsha3_512);
    
    
    mpz_import(r, SHA3_512_DIGEST_SIZE,1,1,0,0,digestsha3_512);
    //gmp_printf("check r: %Zd\n", r);
    
    mpz_pow_ui(N_2,params->N,2);
    
    //A=go^r mod N^2
    mpz_powm(ciphertext_K->A, pk->g0,r,N_2);
    
    //C= H_2 (sigma ) xor m
    
    
    
    //D=g2^r mod N^2
    mpz_powm(ciphertext_K->D, pk->g2,r,N_2);
    
    //B=g1^r * (1+sigma*N) mod N^2  ( a*b mod = mod (a mod * b mod ) )
    
    //y=(1+sigma*N) mod N^2
    mpz_mul(tmp,sigma,pk->N);
    mpz_add_ui(tmp,tmp,1);
    mpz_mod(tmp, tmp, N_2);
    
    //x=g1^r mod N^2
    mpz_powm(ciphertext_K->B, pk->g1, r, N_2);
    
    //B=x*y mod N^2
    mpz_mul(ciphertext_K->B, ciphertext_K->B, tmp);
    mpz_mod(ciphertext_K->B, ciphertext_K->B, N_2);
    
    
    
    
    
    printf("\n\n");
    
    printf("output ciphertext. K=(A, B, D, c, s)\n");
    pmesg_mpz(msg_very_verbose, "r =",r);
    pmesg_mpz(msg_very_verbose, "sigma =",sigma);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->A =",ciphertext_K->A);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->B =",ciphertext_K->B);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->C =",ciphertext_K->C);
    pmesg_mpz(msg_very_verbose, "ciphertext_K->D =",ciphertext_K->D);
    //pmesg_mpz(msg_very_verbose, "c =",c);
    //pmesg_mpz(msg_very_verbose, "s =",s);
    

    mpz_clears(sigma,r, N_2, NULL);
}


/*
 * decrypt
 */
void decript(plaintext_t plaintext, const ciphertext_t ciphertext_K) {
    
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

void ciphertext_init(ciphertext_t ciphertext) {
    assert(ciphertext);
    mpz_inits(ciphertext->A, ciphertext->A_1, ciphertext->A_p, ciphertext->B, ciphertext->B_p,
                   ciphertext->C, ciphertext->C_p,ciphertext->D, NULL);
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

void ciphertext_clear(ciphertext_t ciphertext) {
    assert(ciphertext);
    mpz_inits(ciphertext->A, ciphertext->A_1, ciphertext->A_p, ciphertext->B, ciphertext->B_p,
                   ciphertext->C, ciphertext->C_p,ciphertext->D, NULL);
}
    /*do {
        
        mpz_add_ui(params->g,params->g,1);//g+=1
        
        //tmp=g^2 mod N
        mpz_powm_ui(tmp, params->g,2,params->N);
        if ((mpz_cmp_ui(tmp,1)==0)){

            continue;//go to loop next
        }
        
        //tmp=g^4 mod N
        mpz_powm_ui(tmp, params->g,4,params->N);
        if ((mpz_cmp_ui(tmp,1)==0)) 
            continue;
        
        //tmp=g^p' mpd N  
        mpz_powm(tmp, params->g,params->p_1, params->N);
        if ((mpz_cmp_ui(tmp,1)==0)) 
            continue;   
        
        //tmp=g^q' mpd N
        mpz_powm(tmp, params->g,params->q_1, params->N);

    } while((mpz_cmp_ui(tmp,1)==0) );*/
    
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

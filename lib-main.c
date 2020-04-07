#include "lib-main.h"
#include <unistd.h>
#include <sys/types.h>
#include<sys/wait.h>
#include <nettle/sha1.h>

/*
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


/* 
 * get shared params
 */
void generate_shared_params(shared_params_t params, unsigned p_bits, gmp_randstate_t prng) {
    
    int fparent=1, fchild=1;
    int fparent1=1,fchild1=1;

    mpz_t tmp;
    pmesg(msg_verbose, "generazione parametri comuni...");
      
    //assert
    assert(params);
    assert(p_bits>1);
    assert(prng);
    
    //init
    mpz_init(tmp);
    mpz_inits(params->p,params->p_1,params->q, params->q_1,params->N,NULL);

    //
    params->N_bits=p_bits*p_bits;
    params->p_bits=p_bits;
    params->q_bits=p_bits;
    
    params->p_1_bits=p_bits-1; // p' da 511 bit 
    params->q_1_bits=p_bits-1; // q' da 511 bit 


    //p della forma 2*p'+1 con p' e p primi
    //q della forma 2*q'+1 con q' e q primi
    do {
        do {
            
            if ( fparent) {
                
                //cerco un primo p' random range 0-2^(p_1_bits)-1
                mpz_urandomb(params->p_1,prng,params->p_1_bits);
                if(mpz_sizeinbase(params->p_1, 2) == params->p_1_bits){
                    if ((mpz_probab_prime_p(params->p_1, mr_iterations)>=1)){
                       // pmesg_mpz(msg_very_verbose, "CONDIZIONE IF su p' ", params->p_1);
                        fchild=0;
                        fparent=0;
                    }
                }
            }//else {printf(" controlli falliti = %d, fparent= %d\n",count++,fparent);}
            
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
        
        }while(fchild || fchild1);
       // printf("fchild= %d, fchild1= %d\n",fchild,fchild1);

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
         
        } while ( fchild || fchild1 );
        //gmp_printf("modulo params->p: %Zd\n", params->p);
    
    /* scelta del generatore in Z*: per ogni k,divisore, di ogni elemento
     * di phi_p, la divisione deve essere diverso da 1. In questo caso phi_p=2*q.
     * Occorre verificare g^2!=1 && g^q!=1. Qui
     * e' richiesto che g sia solo conforme alla definizione di generatore
     */
    
    mpz_mul(params->N,params->q,params->q);
    //mpz_set_ui(params->g,1);//set g=1
   
    pmesg_mpz(msg_very_verbose, "modulo p =",params->p);
    pmesg_mpz(msg_very_verbose, "modulo q =",params->q);
    pmesg_mpz(msg_very_verbose, "modulo p*q =",params->N);
    
    pmesg_mpz(msg_very_verbose, "primo divisore p' dell'ordine", params->p_1);
    pmesg_mpz(msg_very_verbose, "primo divisore p' dell'ordine", params->q_1);

    mpz_clear(tmp);
}

/*
 * init: state, msg
 */
void state_init(state_t state){
    assert(state);
    state->progression=progression_ready_to_start;
    mpz_inits(state->eph_exp, state->key,NULL);
}

void msg_init(msg_t msg) {
    assert(msg);
    mpz_init(msg->contrib);
}

/*
 * contrib KeyGen
 */
void generate_keys(keys_t keys, msg_t msg, state_t state, const shared_params_t params, gmp_randstate_t prng){
    
    assert(msg);
    assert(state);
    //assert(state->progression>=progression_ready_to_start);
    assert(params);
    assert(prng);
    pmesg(msg_verbose, "generazione del contributo...");
    
    mpz_t N_2, alpha,a,b,tmp;

    struct sha1_ctx ctx;//sha-1
    uint8_t digest[SHA1_DIGEST_SIZE*8]; 
    char buffer[2048]; 
    sha1_init(&ctx);
    
    
    mpz_inits(N_2, alpha,a,b, tmp, NULL);
    mpz_inits(keys->N, keys->g0, keys->g1, keys->g2, keys->p,keys->q,
                    keys->p_1, keys->q_1, NULL);
    
    sha1_init(&ctx);
    
    //keys->N
    mpz_set(keys->N,params->N);
    
    //set sk keys
    mpz_set(keys->p,params->p);
    mpz_set(keys->p_1,params->p_1);
    mpz_set(keys->q,params->q);
    mpz_set(keys->q_1,params->q_1);
    
    //set hash ?
    
    
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
        mpz_urandomm(a,prng,tmp);
        mpz_urandomm(b,prng,tmp);
    } while( (mpz_cmp_ui(a,0)==0) || (mpz_cmp_ui(a,0)==0)  );
    
    /*test generatori?*/
    
    //g0 = alpha^2 mod N^2
    mpz_powm_ui(keys->g0,alpha,2,N_2);
    
    //g1 = g0^a mod N^2
    mpz_powm(keys->g1,keys->g0,a,N_2);
    
    //g2= g0^b mod N^2
    mpz_powm(keys->g2,keys->g0,b,N_2);
    
    //pk
    printf("\npk = (H(.), N, g0, g1, g2)\n");
    pmesg_mpz(msg_very_verbose, "alpha =",alpha);
    pmesg_mpz(msg_very_verbose, "modulo N=",keys->N);
    pmesg_mpz(msg_very_verbose, "g0 =",keys->g0);
    pmesg_mpz(msg_very_verbose, "g1 =",keys->g1);
    pmesg_mpz(msg_very_verbose, "g2=",keys->g2);

    //weak secret
    printf("\nweak secret\n");
    pmesg_mpz(msg_very_verbose, "a =",a);
    pmesg_mpz(msg_very_verbose, "b =",b);
    
    //sk
    printf("\nsk = (p, q, p', q')\n");
    pmesg_mpz(msg_very_verbose, "p =",keys->p);
    pmesg_mpz(msg_very_verbose, "q =",keys->q);
    pmesg_mpz(msg_very_verbose, "p' = ", keys->p_1);
    pmesg_mpz(msg_very_verbose, "q' = ", keys->q_1);
    
    mpz_clears(N_2, alpha,a,b, tmp, NULL);

}

/*
 * encrypt
 */
void encrypt( keys_t keys) {
    
    uint8_t block_to_hash[block_size]; //block_size=1MiB = 1024 KB
    
    for (size_t i = 0; i < block_size; i++)
        block_to_hash[i] = (uint8_t)rand();
}


/*
 * verifica la correttezza dei parametri
 *
 */
bool verify_params(const shared_params_t params) {
    
    mpz_t tmp;
    bool return_value = true;

    assert(params);

    mpz_init(tmp);
    //printf("verifica\n\n");
    
    //check su N
    if (params->N_bits < 1024) {
        printf("false");
        return_value = false;
        
    }else if ((params->p_1_bits >= params->p_bits) || (params->q_1_bits >= params->p_bits)){
        
        return_value = false;
    }
    
    return (return_value);
}

/*
 * clear: shared_params,msg_clear,state_clear
 */
void shared_params_clear(shared_params_t params) {
    assert(params);
    mpz_clears(params->p,params->q,NULL);
}

void keys_clear(keys_t keys) {
    assert(keys);
    mpz_clears(keys->N, keys->g0, keys->g1, keys->g2, keys->p,keys->q,
                    keys->p_1, keys->q_1, NULL);
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
 

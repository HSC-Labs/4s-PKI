// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 *
 * \file shamic.c
 *
 * \brief Shamir secret sharing implementation
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <gmp.h>

#define DEEPDEBUG 1

#include "utils.h"
#include "shamir.h"
#include "sha3.h"

#define SUCCESS     (EXIT_SUCCESS)
#define FAIL_INPUTS (EINVAL)
#define FAIL_ALLOC  (ENOMEM)
#define FAIL_MATH   (EDOM)

//////////////////////////////////////////////////////// Low level functions

static int split_secret(
	const mpz_t secret,
	const unsigned int num_shares,
	const unsigned int threshold,
	const mpz_t prime,
	mpz_t * shares_xs,
	mpz_t * shares_ys)
{
	unsigned int i = 0, j = 0;
	size_t prime_size = 0;
	
	mpz_t * coefficients = NULL;
	mpz_t y, tmp, degree;
	gmp_randstate_t rng_state;

	/* Check the inputs */
	if (mpz_cmp(secret, prime) >= 0 ||
		shares_xs == NULL || shares_ys == NULL ||
		threshold > num_shares || threshold < 1 || num_shares < 1) {
		warn("Shamir secret splitting failed: invalid parameters");
		return FAIL_INPUTS;
	}

	coefficients = (mpz_t *) malloc((threshold - 1) * sizeof(mpz_t));
	/*CSN: Ici tu as un problème si tu arrives à faire un integer overflow, car ton coefficients va être un pointer sur une mémoire alloué à 0, et pas null
	il faudrait mettre:
	if(coefficients){

	}
	*/
	if (NULL == coefficients) {
		warn("Failed coefficients allocation in Shamir secret processing");
		return FAIL_ALLOC;
	}

	srand(time(NULL));
	gmp_randinit_default(rng_state);
	gmp_randseed_ui(rng_state, rand());
	prime_size = mpz_sizeinbase(prime, 2);

	/* Initialize coefficients and shares_xs */
	for (i = 0; i < (threshold - 1); i++) {
		mpz_init(coefficients[i]);
		mpz_urandomb(coefficients[i], rng_state, prime_size - 1);
		mpz_add_ui(coefficients[i], coefficients[i], 1);
	}

	for (i = 0; i < num_shares; i++) {
		mpz_init(shares_xs[i]);
		mpz_urandomb(shares_xs[i], rng_state, prime_size - 1);
		mpz_add_ui(shares_xs[i], shares_xs[i], 1);
	}

	mpz_init(tmp);
	int retval = SUCCESS;
	for (i = 0; i < num_shares; i++) {
		mpz_init_set(y, secret);
		mpz_init_set_ui(degree, 1);
		for (j = 0; j < (threshold - 1); j++) {
			mpz_powm_sec(tmp, shares_xs[i], degree, prime);
			mpz_addmul(y, coefficients[j], tmp);
			mpz_add_ui(degree, degree, 1);
		}
		mpz_clear(degree);
		mpz_init(shares_ys[i]);
		mpz_mod(y, y, prime);
		mpz_set(shares_ys[i], y);
		mpz_clear(y);
		if (mpz_cmp(shares_xs[i], secret) == 0 ||
			mpz_cmp(shares_ys[i], secret) == 0) {
			retval = FAIL_MATH;
			break;
		}

	}
	mpz_clear(tmp);

	if (retval != SUCCESS) {
		warn("Shamir splitting failed : %d", retval);
		for (i = 0; i < num_shares; i++) {
			mpz_init_set_ui(shares_xs[i], 0);
			mpz_init_set_ui(shares_ys[i], 0);
		}
	}

	gmp_randclear(rng_state);
	/* Clear data */
	/*CSN: Ca ferait pas un double free ton code la ?
	*/
	for (i = 0; i < (threshold - 1); i++) {
		mpz_set_si(coefficients[i],0);
		mpz_clear(coefficients[i]);
	}
	free(coefficients);
	coefficients = NULL;

	return retval;
}//eo split_secret


static int reconstruct_secret
(
	const unsigned int num_shares,
	const mpz_t * shares_xs,
	const mpz_t * shares_ys,
	const mpz_t prime,
	mpz_t secret
) {
	
	unsigned int j = 0, m = 0;
	
    mpz_t product, d, r;
	mpz_t reconstructed;

	if (shares_xs == NULL || shares_ys == NULL) {
		warn("Invalid input to Shamir secret reconstruction");
		return  FAIL_INPUTS;
	}

	for (j = 0; j < num_shares; j++) {
		if (mpz_cmp(shares_xs[j], prime) >= 0 ||
			mpz_cmp(shares_ys[j], prime) >= 0) {
			warn("Invalid values in parameters to Shamir secret reconstruction");
			return FAIL_MATH;
		}
	}

	mpz_init_set_ui(reconstructed, 0);

    int retval = -1;
	for (j = 0; j < num_shares; j++) {
		mpz_init_set_ui(product, 1);
		for (m = 0; m < num_shares; m++) {
			mpz_init(d);
			mpz_init(r);
			if (m != j) {
				mpz_sub(d, shares_xs[m], shares_xs[j]);
				retval = mpz_invert(d, d, prime);
                if( retval == 0 ){
                	warn("Failed Shamir reconstruction");
                    return FAIL_MATH;
                }
				mpz_mul(r, shares_xs[m], d);
				mpz_mul(product, product, r);
			}
			mpz_set_si(d,0);
			mpz_clear(d);
			mpz_set_si(r,0);
			mpz_clear(r);
		}
		mpz_addmul(reconstructed, shares_ys[j], product);
		mpz_mod(reconstructed, reconstructed, prime);
		mpz_clear(product);
	}
	mpz_init_set(secret, reconstructed);
	mpz_clear(reconstructed);

	return SUCCESS;
}//eo reconstruct_secret


//////////////////////////////////////////////////////// High level functions

int do_shamir_split( int quorum, int nb_share, const uint8_t * secret_val, const size_t sec_len, s_share_t *shares ) 
{
	DEBUG_PRN("do_shamir_split(quorum:%d, nb_share:%d, secret:%p, sec_len:%u, shares:%p)", 
		                          quorum,    nb_share, secret_val,   sec_len, shares );

    mpz_t 
        secret, 
        prime, 
        xs[nb_share], 
        ys[nb_share], 
        int_from;
	gmp_randstate_t rng_state;

	// Hex encode password and load it in a mpz
	DDEBUG_PRN("do_shamir_split: encoding secret");
	const size_t hex_len = (sec_len*2)+1;
	char hex_password[hex_len];
	secure_memzero(hex_password,hex_len);
	ssize_t enc_res = hex_encode( hex_password, hex_len, secret_val, sec_len);
	DDEBUG_PRN("do_shamir_split:hex_encode(%u) returned %d", sec_len, enc_res );	
	if( enc_res<0 ) {
		warn("failed to encode password before splitting");
		return -1;
	}
	mpz_init_set_str( secret, hex_password, 36 ); // loading the hex encoded password
	secure_memzero( hex_password, hex_len);	

	// Get a long random 
	DDEBUG_PRN("do_shamir_split: getting basis number");	
	mpz_init(int_from);
	srand( time(NULL) );
	gmp_randinit_default (rng_state );
	gmp_randseed_ui( rng_state, rand() );
	mpz_rrandomb( int_from, rng_state, RING_SIZE );

	// Find a prime next to it
	DDEBUG_PRN("do_shamir_split: finding next prime");	
	mpz_init(prime);
	mpz_nextprime(prime,int_from);


	// Initialisation
	DDEBUG_PRN("do_shamir_split: initialization");
	while( mpz_cmp( secret, prime ) >= 0 ){
		srand(time(NULL));
		gmp_randinit_default( rng_state );
		gmp_randseed_ui( rng_state, rand() );
		mpz_rrandomb( int_from, rng_state, RING_SIZE );
		mpz_nextprime( prime,int_from );
	}
    
    // doing the split
    DDEBUG_PRN("do_shamir_split: splitting");
    int res = split_secret(secret, nb_share, quorum, prime, xs, ys);
    if( res != 0 ) {
    	warn("Failed low level secret splitting: %d",res);
        return res;
    }

    // copying the secrets
    DDEBUG_PRN("do_shamir_split: copying share");
    for( int i = 0; i< nb_share; i++ ) {
		// zero things
		secure_memzero( shares[i].X, SHARED_SECRETS_STR_MAX);
		secure_memzero( shares[i].Y, SHARED_SECRETS_STR_MAX);
		secure_memzero( shares[i].prime, SHARED_SECRETS_STR_MAX);

		//Copying
		mpz_get_str( shares[i].X,36,xs[i]);
		mpz_get_str( shares[i].Y,36,ys[i]);
		mpz_get_str( shares[i].prime,36,prime);
    }

    // TODO: zero mpz: secret, prime, xs[], ys[]
    DDEBUG_PRN("do_shamir_split: done");
    return 0;
}//eo do_split

int do_shamir_recovery( const int nb_participants, const s_share_t* shares, uint8_t * result, size_t max_result ) 
{
	DEBUG_PRN("do_shamir_recovery( nb_participants:%d, shares:%x, result:%x, max_resize:%u )", nb_participants, shares, result, max_result);

    int retval = 0;
	mpz_t xs[nb_participants], 
          ys[nb_participants], 
          prime;
	mpz_t reconstructed;
	
	const size_t hex_len = (2*max_result)+1;
	char hex_val[hex_len];

	// Get Xs Ys et prime from each share
	mpz_init(reconstructed);
	for( int i=0; i<nb_participants; i++ ){
		mpz_init_set_str( xs[i], shares[i].X, 36);
		mpz_init_set_str( ys[i], shares[i].Y, 36);
	}	
	mpz_init_set_str( prime, shares[0].prime, 36);

	// Recontruct secret
	retval = reconstruct_secret( nb_participants, (const mpz_t *)xs, (const mpz_t *)ys,prime, reconstructed);
	if( retval != EXIT_SUCCESS ) {
		warn("Failed low level Shamir secret reconstruction: %d",retval );
		return retval;
	}

	// hex decode the pass phrase	
	mpz_get_str( hex_val, 36, reconstructed); // TODO check we do not overflow hex_val
	DDEBUG_PRN("hex val: %s", hex_val);*
	ssize_t dec_res = hex_decode( result, max_result, hex_val );
	if( dec_res < 0 ) {
		warn("Failed to hex decode the Shamir recovered value");
		return -1;
	}
	DDEBUG_PRN("Shamir_recov:%s", hex_val);
	secure_memzero( hex_val, hex_len );	
    result[max_result]='\0';
    	    
    return 0;

}//eo do_recover

/////////////////////////////////////////////////////////////////////////// Encoding secret



/////////////////////////////////////////////////////////////////////////// IO
#define SHAMIR_SHARE_HEADER ("----- BEGIN SHAMIR SHARE -----")
#define SHAMIR_SHARE_FOOTER ("----- END SHAMIR SHARE -----")


int load_shamir_secret( const char* filename, s_share_t* share ) 
{
	size_t max_str_sze = SHARED_SECRETS_STR_MAX;
	char line[255];

	secure_memzero( share->X,     max_str_sze );
	secure_memzero( share->Y,     max_str_sze );
	secure_memzero( share->prime, max_str_sze );

	FILE *fp = fopen(filename,"r");
	if( fp == NULL){
		warn("Failed to open file '%s' for Shamir secret reading", filename);
		return -1;
	}
	rewind(fp);

	int in_share = 0;
	while( fgets(line, sizeof(line), fp)!=NULL ) {	
		chomp(line);	
		int x = strcmp( SHAMIR_SHARE_HEADER, line );
		DDEBUG_PRN("load_shamir_secret: loaded [%s]==[%s]=> (%d)", line, SHAMIR_SHARE_HEADER, x);
		if(  x == 0 ){
			DDEBUG_PRN("load_shamir_secret: header found [%s]", line);
			in_share = 1;
			break;
		}
	}
	if( !in_share ) {
		warn("Failed to find Shamir secret header in '%s'", filename );
		return -1;
	}

	fgets( share->X, max_str_sze, fp);
	strtok( share->X, "\n");

	fgets( share->Y, max_str_sze, fp);
	strtok( share->Y, "\n");

	fgets( share->prime, max_str_sze, fp);

	fclose(fp);

	return 0;

}//eo read_share


int save_shamir_secret( const char* filename, const s_share_t* share)
{
    size_t buffer_size = (3*SHARED_SECRETS_STR_MAX)+4;
    char buffer[ buffer_size ];

    snprintf(buffer, buffer_size-1, "%s\n%s\n%s\n%s\n%s\n", SHAMIR_SHARE_HEADER, share->X, share->Y, share->prime, SHAMIR_SHARE_FOOTER );
    buffer[buffer_size-1] ='\0';
    size_t len = strnlen( buffer, buffer_size);

	ssize_t res = write_to_file(filename, len, buffer);

	if ( res > 0 ) return 0;

	warn("Error when saving Shamir secret to file: %s", filename);
    return -1;
}//eo save_share

ssize_t shamir_share_fingerprint( const s_share_t* share, char *fingerprint, const size_t max_size )
{
	sha3_context sha_ctx;

	sha3_init256(&sha_ctx);
	sha3_update( &sha_ctx, share->X,     strlen(share->X) );
	sha3_update( &sha_ctx, share->Y,     strlen(share->Y) );
	sha3_update( &sha_ctx, share->prime, strlen(share->prime) );
	const uint8_t *hash = sha3_finalize(&sha_ctx);
	return hex_encode( fingerprint, max_size, hash, 32 );

}//eo shamir_share_fingerprint

// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 * 
 * \file has_shared_secret.c
 * 
 * \brief Program middleware: communication between modules, initalisation, context ...
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

//#define DEEPDEBUG 1

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <dirent.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <errno.h>

#include "utils.h"
#include "shared_secret.h"


s_s4context* s4_init_context()
{
     
    s_s4context * ctx = (s_s4context*) malloc( sizeof( s_s4context ) );
    if( NULL == ctx ) {
        warn("Failed to allocate memory for context structure");
        return NULL;
    }
    secure_memzero( ctx, sizeof( s_s4context ));

    ctx->quorum    = DEFAULT_QUORUM;
    ctx->nb_share  = DEFAULT_NB_SHARE;

    ctx->pki_params.ca_key_size    = DEFAULT_KEY_SIZE;
    ctx->pki_params.ca_life_len    = DEFAULT_CA_LIFE_IN_DAYS;
    ctx->pki_params.subca_life_len = DEFAULT_SUBCA_LIFE_IN_DAYS;
    ctx->pki_params.crl_life_len   = DEFAULT_CRL_LIFE_DAYS;

    ctx->op_status = "uninitialized";
    ctx->nb_share_exported=0;
    ctx->nb_share_loaded=0;
    ctx->secret_unlocked=1;

    return ctx;
}//eo s4_init_context


void s4_destroy_context( s_s4context* s4c )
{   
    if( NULL == s4c ) {
        return;
    }
    DDEBUG_PRN("erasing(%p,%lu)\n", s4c, sizeof(struct SS4Context));
    secure_memzero( s4c, sizeof(struct SS4Context) );
    DDEBUG_PRN("freeing(%p)\n", s4c);
    free(s4c);

}//eo s4_destroy_context

// returns 0 on success
int check_pki_root_dir( const char* dirname )
{
    //TODO checks that the passed string is the name of an appropriate directory
	// checking if PKI directory is accessible	
	DIR * pDir = opendir(dirname);
	if ( pDir == NULL ) {
        warn( "Cannot open directory '%s'\n", dirname);
		return -1;
	}
	closedir(pDir);

    return 0;
}//eo checkPKIRootDir


// returns 0 on success
int check_pki_subject( const char* subject ) 
{
    //TODO check that Subject is properly formed for openssl
    // /CN=XXXX/OU=YYYY/O=ZZZZ/C=AAA
    // or
    // /CN=XXXX/DC=YYYY/DC=ZZZZ/DC=AAA
    //
    return 0;
}//eo checkPKISubject


int s4_split(s_s4context *s4c, s_s4eventhandlers_t * s4evt )
{
    uint8_t pass_converted[ MAX_HEX_ENC_PASS_SIZE+1 ];
    memset(pass_converted, 0, MAX_HEX_ENC_PASS_SIZE );
    secure_memzero( s4c->shares, MAX_SHAMIR_SHARE_NUMBER );

    ssize_t dec_len = base64_decode( pass_converted, sizeof(pass_converted)-1, s4c->passphrase );
    if(  dec_len <0 ) {
        warn( "Share decoding failed" );
        return -1;
    }

    int split_res = do_shamir_split( s4c->quorum, s4c->nb_share, pass_converted, dec_len, s4c->shares );
    if( split_res != 0 ) {
        warn("Shamir split failed");
        return split_res;
    }

    return 0;
}//eo s4_split

int s4_splitnsave(s_s4context *s4c, s_s4eventhandlers_t * s4evt )
{

    if( s4c->nb_share < s4c->quorum ) {
        warn("Number of shares must be greater than quorum");
        return -1;
    }

    if( (NULL==s4evt->do_file_prompt)  && s4c->nb_share_provided < s4c->nb_share ) {
        warn( "Only %d shares provided when %d are required", s4c->nb_share_provided, s4c->nb_share);
        return -1;
    }

    if( s4_split(s4c, s4evt )  ) {
        warn("Shamir secret splitting failed");
        return -1;
    }
    
	//Write on file
    char fname[MAX_FILE_PATH+1];
	for( unsigned i=0; i<s4c->nb_share; i++ ){        
        const char * dest = NULL;            

        // pausing if planned for
        if( s4c->should_pause_for_secrets ) {
            if( NULL != s4evt->do_message ) {
                s4evt->do_message( s4evt->data, "Shamir secret loading","Insert or copy the secret storage before going on.");
            } else {
                warn("Internal error: pause demanded but no pause handler provided");
                return -1;
            }
        }

        // if a file prompter is provided
        if( NULL != s4evt->do_file_prompt ) {
            if( s4evt->do_file_prompt( s4evt->data, "Please Enter the file to write the Shamir share to", fname, MAX_FILE_PATH) ) {        
                warn("Getting file name failed");
		        return -2;
    	    }
            dest = fname;
        } else {
            dest = s4c->shamir_secrets[i];
            if( NULL == dest ) {
                warn("Undefined Shamir secret destination filename");
                return -2;   
            }
        }

        // saving the secret
        if( save_shamir_secret( dest, &(s4c->shares[i]) ) ) {
            warn("Shamir secret saving to %s failed", dest);
            return -3;
        }
        s4c->nb_share_exported++;
	}//eo foreach secret

	return 0;	
}//eo s4_split

int s4_load_all_shares( s_s4context *s4c, s_s4eventhandlers_t * s4evt ) 
{
    assert( NULL!=s4c   );
    assert( NULL!=s4evt );

    s_share_t* shares = s4c->shares;

    if( (NULL==s4evt->do_file_prompt)  && s4c->nb_share_provided < s4c->quorum) {
        warn( "Only %d shares provided when at least %d are required", s4c->nb_share_provided, s4c->quorum );
        return -1;
    }

    char fname[MAX_FILE_PATH+1];
    for( unsigned i=0; i<s4c->nb_share_provided; i++ ){        
        const char * src = NULL;            

       // pausing if planned for
        if( s4c->should_pause_for_secrets ) {
            if( NULL != s4evt->do_message ) {
                s4evt->do_message( s4evt->data, "Shamir secret loading","Insert or copy the secret before going on.");
            } else {
                warn("Internal error: pause demanded but no pause handler provided");
                return -1;
            }
        }

        // if a file prompter is provided
        if( NULL != s4evt->do_file_prompt ) {
            if( s4evt->do_file_prompt( s4evt->data, "Please Enter the file to read the Shamir share from", fname, MAX_FILE_PATH) ) {        
                warn("Getting file name failed");
                return -2;
            }
            src = fname;
        } else {
            src = s4c->shamir_secrets[i];
            if( NULL == src ) {
                warn("Undefined Shamir share source filename");
                return -2;   
            }
        }
        if( load_shamir_secret(  src, &(shares[i]) ) ) {
            warn("Loading share secret from %s failed", src);
            return -2;
        }
        s4c->nb_share_loaded++;
    }//foreach share   

    return 0;
}//eo s4_load_all_shares

int s4_reconstruct( s_s4context *s4c, s_s4eventhandlers_t * s4evt )
{
    assert( NULL!=s4c   );
    assert( NULL!=s4evt );

    size_t  secret_max_size = MAX_HEX_ENC_PASS_SIZE+1;
    uint8_t secret[secret_max_size];

    // read all the secrets
    int res = s4_load_all_shares( s4c, s4evt );
    if( res ) {
        warn("Share loading failed");
        return res;
    }

	//Recontruct secret
    int r1 = do_shamir_recovery( s4c->nb_share_provided, s4c->shares, secret, secret_max_size );
	if( r1 != EXIT_SUCCESS ) {
        warn("Shamir recovery failed");
		return r1;
	}

	//base64_ encode the pass phrase 
    ssize_t r2 = base64_encode( s4c->passphrase, MAX_B64_ENC_PASS_SIZE, secret, PASS_SIZE);
	if( r2 <0 ) {
        die( -1, "base64 encoding of the passphrase failed");
    }    
    s4c->passphrase_len = r2;

	return 0;
}//eo reconstruct


int try_to_open_pki_info( s_s4context * ctx, const char *dirname ) 
{
    assert( NULL!=ctx );
    assert( NULL!=dirname );

    DDEBUG_PRN("try_to_open_pki_info(%d)", dirname);
    
    ctx->nb_share_exported=0;
    ctx->nb_share_loaded=0;
    ctx->nb_share_provided=0;
    ctx->secret_unlocked=0;

    secure_memzero( ctx->csr_path, MAX_FILE_PATH+1);
    secure_memzero( ctx->crl_path, MAX_FILE_PATH+1);
    secure_memzero( ctx->shares, MAX_SHAMIR_SHARE_NUMBER*sizeof(s_share_t) );
    secure_memzero( ctx->shares_loaded, MAX_SHAMIR_SHARE_NUMBER*sizeof(int) );
    secure_memzero( ctx->passphrase, MAX_B64_ENC_PASS_SIZE+1 );
    secure_memzero( ctx->shamir_secrets, MAX_SHAMIR_SHARE_NUMBER*sizeof(char*));

    DDEBUG_PRN("try_to_open_pki_info: copying '%s' to %p", dirname, ctx->pki_params.root_dir );
    size_t res = strlcpy( ctx->pki_params.root_dir, dirname, MAX_FILE_PATH);
    if( res > MAX_FILE_PATH ) {
        DEBUG_PRN("try_to_open_pki_info: Failed to copy directory name to context (%u>%u)", res, MAX_FILE_PATH);
        return -1;
    }

    int failed_to_read = read_ca_infos( 
        dirname, ctx->pki_params.subject, MAX_PKI_SUBJECT_LEN, 
        &(ctx->nb_share),   &(ctx->quorum),  
        &(ctx->nb_emitted), &(ctx->nb_revoqued)      
    );

    if ( failed_to_read ) {
        DEBUG_PRN("try_to_open_pki_info: Failed to read or invalid INI file from directory '%s'", dirname);
        return -1;
    }
    return 0;
}//eo try to open pki info


//eof

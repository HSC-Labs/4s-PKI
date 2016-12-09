// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 *
 * \file 4s-cli.c
 *
 * \brief 4s-cli: command line call of the 4s functions
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include "shamir.h"
#include "utils.h"
#include "cliopt.h"
#include "pki.h"
#include "shared_secret.h"


#define MAX_USER_INPUT (2048)

#define FREE_CTX(ctx) 					\
if(1) { 								\
	DEBUG_PRN("destroying(%p)",(ctx));	\
	s4_destroy_context((ctx)); 			\
	(ctx)=NULL; 						\
} 

static void s4cli_progress_handler( void* data, int pct, const char * msg ) 
{
    printf("\t+ PKI init (%02d pct): %s\n", pct, msg );
}//eo pki_progress_handler


static void s4cli_warn_handler( void* data, const char* fmt, ...)
{
	va_list args;
	va_start (args, fmt);   
    vwarn( fmt, args);
	va_end(args);
}//eo pki_warn_handler

static void s4cli_message_handler( void* data, const char* title, const char* message )
{
	char line[MAX_USER_INPUT];
	printf("%s <press enter to continue>\n", title);
	prompt(message, line, MAX_USER_INPUT );
}

static void s4cli_init( s_s4context *s4c, s_s4eventhandlers_t * s4evt )
{
	if( (NULL==s4c) || (NULL==s4evt) ) {
		die(-1, "Invalid initialisation: program internal error");
	}

	// Parameters check	
    if( check_pki_root_dir( s4c->pki_params.root_dir ) ) {
    	warn("%s is not an appropriate PKI root dir", s4c->pki_params.root_dir);
    	FREE_CTX(s4c);
		die( -1, "Terminating initialisation");
    }

    if( check_pki_subject( s4c->pki_params.subject) ) {
    	warn(
    		"%s is not an appropriate PKI subject (expected format: /CN=pki_name/OU=organisational_unit/O=organisation or /CN=pki_name/DC=dom_comp/DC=dom_comp", 
    		s4c->pki_params.subject);
    	FREE_CTX(s4c);
   		die( -1, "Terminating initialisation");
    }

    if( s4c->nb_share_provided < s4c->nb_share ) {
    	warn("Insufficient number of share secret path provided (%d/%d)", s4c->nb_share_provided, s4c->nb_share );
    	FREE_CTX(s4c);
    	die( -1, "Terminating initialisation");
    }

	// generate passphrase
	ssize_t pwd_sze = gen_pass( s4c->passphrase, MAX_B64_ENC_PASS_SIZE );
	if( pwd_sze < 0 ) {		
		FREE_CTX(s4c);
		die( -1, "failed to generate passphrase");
	} else {
		s4c->passphrase_len = pwd_sze;
	}

	if( gen_self_signed( s4c->pki_params.root_dir, &(s4c->pki_params), s4c->passphrase, s4c->nb_share, s4c->quorum, s4evt) ) {
		FREE_CTX(s4c);
		die( -1, "Failed to generate PKI");
	}

	//TODO manage exports and filenames from s4c
	if( s4_splitnsave( s4c, s4evt ) ) {
		FREE_CTX(s4c);
		die( -1, "Split failed ");
	}
	// TODO file saving in here

  	printf("Split ok. \n");

}//eo 4scli_init


static void s4cli_sign( s_s4context *s4c, s_s4eventhandlers_t * s4evt )
{

	// Reconstruct the passphrase 
	if( s4_reconstruct( s4c, s4evt ) ) {
		FREE_CTX(s4c);
		die(-1, "Failed to recover root passphrase");
	}
	DDEBUG_PRN("Reconstructed passphrase: %s",s4c->passphrase);

	// Do the sub CA signing
	if( sign_subca( s4c->pki_params.root_dir, s4c->csr_path, s4c->cert_path, s4c->passphrase, s4evt) != 0 ) {
		warn("Failed to sign CSR: %s", s4c->csr_path );	
		FREE_CTX(s4c);
		die( -1, "Sub-CA signature failed.");
	}

}//eo 4scli_sign

static void s4cli_revoke( s_s4context *s4c, s_s4eventhandlers_t * s4evt )
{
	// Reconstruct the passphrase 
	if( s4_reconstruct( s4c, s4evt ) ) {
		FREE_CTX(s4c);
		die(-1, "Failed to recover root passphrase");		
	}
	DEBUG_PRN("Reconstructed passphrase: [%s]",s4c->passphrase);

	if( revoke_subca( s4c->pki_params.root_dir, s4c->cert_path, s4c->passphrase, s4evt) != 0 ) {
		warn("Failed to revoke cert:%s", s4c->cert_path );			
		FREE_CTX(s4c);
		die(-1, "Failed to revoke sub-CA");
	}

	if( generate_crl( s4c->pki_params.root_dir, s4c->crl_path, s4c->passphrase, s4evt) != 0 ) {
		warn("Failed to generate crl:%s", s4c->crl_path );			
		FREE_CTX(s4c);
		die(-1, "Failed to revoke sub-CA");
	}
	
}//eo 4scli_revoke

static unsigned load_secrets( const char*exe_name, s_s4context *s4c, s_clioption* options, unsigned nb_options )
{
	unsigned i=0;
//	cli_find_nth_option(           var, nth, options_list, nb_options, const char** val );
	while( 0==cli_find_nth_option( OPTION_SECRET, i, options, nb_options, &(s4c->shamir_secrets[i]) )) {
		i++;
	}
	s4c->nb_share_provided = i;
		
	DDEBUG_PRN("share lists");
	for( i=0; i<s4c->nb_share_provided; i++ ) {
		DDEBUG_PRN("\t- share[%d]:%s", i, s4c->shamir_secrets[i]);
	}	

	return s4c->nb_share_provided;
}//eo load_secrets

#define REQUIRE_PARAM(pname,var,len)   cli_require_option(      (pname), argv[0], options, opt_count, (var), (len) )
#define REQUIRE_INT_PARAM(pname,var)   cli_require_int_option(  (pname), argv[0], options, opt_count, &(var) )
#define REQUIRE_UINT_PARAM(pname,var)  cli_require_int_option(  (pname), argv[0], options, opt_count, (int*)&(var) )
#define REQUIRE_BOOL_PARAM(pname,var)  cli_require_bool_option( (pname), argv[0], options, opt_count, &(var) )

#define OPTIONAL_PARAM(pname,var,len,dfl)    cli_optional_option(      (pname), argv[0], options, opt_count, (var), (len), (dfl) )
#define OPTIONAL_INT_PARAM(pname,var,dfl)    cli_optional_int_option(  (pname), argv[0], options, opt_count, &(var), (dfl) )
#define OPTIONAL_UINT_PARAM(pname,var,dfl)   cli_optional_int_option(  (pname), argv[0], options, opt_count, (int*)&(var), (dfl) )
#define OPTIONAL_BOOL_PARAM(pname,var,dfl)   cli_optional_bool_option( (pname), argv[0], options, opt_count, &(var), (dfl) )

/**
 * Program entry point
 */
int main( int argc, char** argv)
{

	s_s4eventhandlers_t s4evt;
	s4evt.data = NULL;
	s4evt.on_progress    = s4cli_progress_handler;
	s4evt.on_warning     = s4cli_warn_handler;
	s4evt.do_message     = s4cli_message_handler;
	s4evt.do_file_prompt = NULL;

    /**
     * context init
     */
    s_s4context *s4c = s4_init_context();
    if( NULL == s4c ) {
        die( -1, "Application context initialisation failed.");
    }

	/* 
	 * Command line parsing
	 */
	e_climodes opt_mode;
	unsigned   opt_count;
	s_clioption* options = cli_parse_params( argc, argv, &opt_mode,  &opt_count );
	if( NULL == options ) {
		DEBUG_PRN("parameters parsing failed");
		FREE_CTX(s4c);
		cli_usage(argv[0]);
		die(-1, "Failed to parse command line");
	}

	cli_print_mode(opt_mode);
	cli_print_opt(options, opt_count);

	// Getting the common parameters
	REQUIRE_PARAM( OPTION_ROOT_DIR, s4c->pki_params.root_dir , MAX_FILE_PATH);
	int n=0;
	if( (n=load_secrets( argv[0], s4c, options, opt_count )) < 2 ) {
		DEBUG_PRN("number of secrets is insufficient(%d)", n);
		FREE_CTX(s4c);
		die( -1, "Not enough path for share secrets provided:%d", n);
	}			

	// Processing by mode
	switch ( opt_mode ){
		case CLIModeInit:   
			// Init mode
			DEBUG_PRN("CA creation mode");
			REQUIRE_PARAM( OPTION_SUBJECT,       s4c->pki_params.subject,     MAX_PKI_SUBJECT_LEN);
			OPTIONAL_PARAM(OPTION_CERT,          s4c->cert_path,              MAX_FILE_PATH, "" );			
			OPTIONAL_UINT_PARAM(OPTION_KEY_SIZE, s4c->pki_params.ca_key_size, MIN_KEY_SIZE );
			OPTIONAL_UINT_PARAM(OPTION_QUORUM,   s4c->quorum,                 DEFAULT_QUORUM);
			OPTIONAL_UINT_PARAM(OPTION_NB_SHARE, s4c->nb_share,               DEFAULT_NB_SHARE);	
			OPTIONAL_BOOL_PARAM(OPTION_PAUSED,   s4c->should_pause_for_secrets, 0  );
			s4cli_init( s4c, &s4evt );
			break;

		case CLIModeSign:   
			// Sub CA signature mode	
			DEBUG_PRN("SubCA signature mode");	
			REQUIRE_PARAM(OPTION_CSR,  s4c->csr_path,  MAX_FILE_PATH );
			REQUIRE_PARAM(OPTION_CERT, s4c->cert_path, MAX_FILE_PATH );
			s4cli_sign( s4c, &s4evt );
			break;

		case CLIModeRevoke: 
			// Sub CA revocation mode
			DEBUG_PRN("SubCA revocation mode");
			REQUIRE_PARAM(OPTION_CRL,  s4c->crl_path,  MAX_FILE_PATH );
			REQUIRE_PARAM(OPTION_CERT, s4c->cert_path, MAX_FILE_PATH );
			s4cli_revoke( s4c, &s4evt );
			break;

		default: 
			// We should never get there (dying before in cli_parse_params)
			DEBUG_PRN("unexpected command line mode");
			cli_usage(argv[0]);
			die(-1, "unknown mode (and internal error)");
	};
	printf("done.\n");

	// cleanup
	FREE_CTX(s4c);
	cli_destroy_options(options, opt_count);

	return 0;
}//eo main

#undef REQUIRE_PARAM
#undef REQUIRE_INT_PARAM
#undef REQUIRE_BOOL_PARAM
#undef OPTIONAL_PARAM
#undef OPTIONAL_INT_PARAM
#undef OPTIONAL_BOOL_PARAM

//eof

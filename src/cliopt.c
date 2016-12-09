// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 * 
 * \file cliopt.c
 *
 * \brief Command line options handling implementation
 *
 */
#include <stdlib.h>
#include <string.h>
#include <values.h>

#include "utils.h"
#include "shared_secret.h"
#include "cliopt.h"

static const char * cliopt_usage_str = 
"\n"
"%s\t-\tA small root pki operation program based on Shamir secret sharing\n"
"\n"
"USAGE:\n"
"\n"
"    %s <mode> <mode parameters>\n"
"\n"
"MODES\n"
"    --help     show this screen\n"
"    --init     initialise a new PKI\n"
"    --sign     sign a subca CSR\n"
"    --revoke   revoke a subca\n"   
"\n"
"COMMON PARAMETERS\n"
"    --rootdir=<path>  - [required] path to the PKI root directory\n"
"    --secret=<path>   - [required] path to a secret. Must be specified for each shamir secret\n"
"    --paused=<yes|no> - [optional] specifies wether the user should be prompted between secret file selection (default:no)\n"
"\n"
"INIT MODE PARAMETERS\n"
"    --quorum=<n>      - [required] minimum number of secrets holders required to authorize operations\n"
"    --nbshares=<m>    - [required] number of secrets holders\n"
"    --keysize=<m>     - [optional] size in bits of the RSA root key\n"
"    --cert=<path>     - [optional] path where optionnaly copy the root-CA certificate\n"
"\n"
"SIGN MODE PARAMETERS\n"
"    --csr=<path>     - [required] path to the CSR to sign\n"
"    --cert=<path>    - [required] path where to save the sub-CA certificate\n"
"\n"
"REVOKE MODE PARAMETERS\n"
"    --cert=<certificate> - [required] path to certificate file to revoke\n"
"    --crl=<path>         - [required] path where to write CRL\n"
"\n"
"RETURN VALUES\n"
"  0 on success\n"
"  non 0 on problem\n"
"\n"
"EXAMPLES\n"
"\n"
"#Creating a new PKI with 5 secrets holders\n"
"    %s --init --rootdir=/home/pki --subject=\"/CN=mypki/OU=it/O=company/C=FR\" --quorum=3 --nbshares=5\n"
"\n"
"#Revocation of a certificate\n"
"    %s --revoke --rootdir=/home/pki --secret=secret1.smr --secret=secret2.smr --secret=secret3.smr --cert=subcacert.pem --crl=rootca.crl\n"
"\n"
"#Signature of a sub-ca certificate\n"
"    %s --sign --rootdir=/home/pki --secret=secret1.smr --secret=secret3.smr --secret=secret5.smr --csr=subcacsr.pem\n"
"\n"
"---\n"
"Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016\n"
"\n";



static int parseopt( const char* raw, s_clioption* opt )
{
	char * wk = strdup(raw);
	if( NULL == wk ){  
		die(-1,"failed to duplicate a parameter string in parameter parsing"); 
	}

	
	// checking -- prefix
	if( wk[0]!='-' || wk[1] != '-') {
		warn("invalid option [%s]", wk);		
		free(wk);
		return -1;
	}
	char * ptr = wk+2;
	char * dst = opt->var; 

	// copying until we reach '='
	DDEBUG_PRN("parsing [%s]", raw);
	while( *ptr != '\0' && (ptr-wk)< MAX_CLIOPTION_NAME_LEN ) {
		DDEBUG_PRN("\t%c\n", *ptr);
		if( *ptr == '=') {
			ptr++;	
			break;
		}
		*dst = *ptr;
		dst++;
		ptr++;
	}//eo name copy
	*dst='\0';
	DEBUG_PRN("parsed option [%s]", opt->var);

	size_t r = strlcpy( opt->val, ptr, MAX_CLIOPTION_VAL_LEN); 
	if( r> MAX_CLIOPTION_VAL_LEN ) {
		die( -1, "option [%s] is too long for this program", opt->var );
	}
	opt->val[MAX_CLIOPTION_VAL_LEN]='\0';	
	DDEBUG_PRN("parsed value [%s]", opt->val);

	free(wk);
	return 0;
}//eo parseopt

void cli_destroy_options(s_clioption* options, unsigned optcount)
{
	secure_memzero( options, sizeof(s_clioption)*optcount );
	free(options);
}//eo cli_destroy_options

s_clioption* cli_parse_params( int argc, char *argv[], e_climodes *mode,  unsigned* optcount )
{
	if( argc < 2 ) {
		warn("no operation mode was specified");
		return NULL;
	}

	//debug print parameters
	DDEBUG_PRN("call: %s", argv[0]);
	for( int anum=1; anum<argc; anum ++ ) {
		DDEBUG_PRN("\targ:%s", argv[anum] );	
	}

	// checking the mode of operation
	const char * mode_arg = argv[1];
    *mode = CLIModeUnknown;

    // checking mode prefix
    if( mode_arg[0]!='-' || mode_arg[1]!='-' ) {
    	warn("'%s' is not an option (not starting with --)", mode_arg);
   	    return NULL;
    }

    if( strcmp( CLI_MODE_INIT_STR, mode_arg+2 ) == 0 )        { *mode = CLIModeInit;   } 
    else if( strcmp( CLI_MODE_SIGN_STR, mode_arg+2 ) == 0 )   { *mode = CLIModeSign;   } 
    else if( strcmp( CLI_MODE_REVOKE_STR, mode_arg+2 ) == 0 ) { *mode = CLIModeRevoke; } 
    else {
   	    warn("'%s' is not a recognized mode", mode_arg);
   	    return NULL;
    }

    // creating the options list
    unsigned count = argc -2;
    if( 0 == count ) {
    	warn("missing parameters");
    	return NULL;
    }
    s_clioption* options_list = (s_clioption*)calloc( count, sizeof(s_clioption) );
    if( NULL == options_list ) {
    	die(-1, "memory allocation failed in command line parsing for %u bytes", sizeof(s_clioption) );    	
    }

    for( unsigned i=0; i<count; i++ ) {
    	if( parseopt( argv[i+2], &(options_list[i]) ) ) {
    		free(options_list);
    		return NULL;
    	}  
    }

    *optcount = count;
    return options_list;
}//eo parse_params


void cli_usage( const char* exec_name )
{
	printf(cliopt_usage_str, exec_name, exec_name, exec_name, exec_name, exec_name);
}//eo usage


int cli_find_option( const char * var, s_clioption *options_list, unsigned nb_options, const char** val )
{
	return cli_find_nth_option(var, 0, options_list, nb_options, val );
}


int cli_find_nth_option( const char * var, unsigned nth, s_clioption *options_list, unsigned nb_options, const char** val )
{	
	unsigned skipped = 0;
	for ( unsigned i=0; i<nb_options; i++ ) {
		if( strncmp(options_list[i].var, var, MAX_CLIOPTION_NAME_LEN)==0 ) {
			if( skipped==nth ) {
				*val = options_list[i].val;
				return 0;
			} else {
				skipped++;
			}
		}
	}	
	return 1;
}//eo cli_find_nth_option


void cli_print_opt( s_clioption *options_list, unsigned nb_opt )
{
	printf("CLI options:\n");
	for( unsigned i=0; i<nb_opt; i++){
		printf(" - [%s]=[%s]\n", options_list[i].var, options_list[i].val);
	}
}//eo cli_print_opt


void cli_print_mode( e_climodes mode)
{
	const char * str=NULL;
	switch( mode ) {
		case CLIModeInit:   
			str = CLI_MODE_INIT_STR;
			break;
		case CLIModeSign:   
			str = CLI_MODE_SIGN_STR;		
			break;
		case CLIModeRevoke: 
			str = CLI_MODE_REVOKE_STR;
			break;
		default: 
			str = "Unknown mode";
	}
	printf("CLI Mode: %s\n", str);
}//eo cli_print_mode

static void find_required_opt( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, const char** res )
{
	
	if( cli_find_option( opt_name, options_list, nb_options, res ) ) {  
		cli_destroy_options(options_list, nb_options);
        cli_usage(exe_name); 
        die(-1,"%s parameter is required", opt_name ); 
    }
}//eo find_required_opt

void cli_require_option( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, char* dest, size_t max_len )
{

    const char* res = NULL;
    find_required_opt( opt_name, exe_name, options_list, nb_options, &res );
    DDEBUG_PRN("copying option result(%s): [%x]=> [%x] = %s", opt_name, res, dest, res);
    size_t r = strlcpy(dest,res,max_len);
   	if( r > max_len ) {
   		die( -1, "option [%s] is too long", opt_name);
   	}
   	
}//eo cli_require_option

void cli_require_int_option( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, int* dest)
{
    const char* res=NULL;
    find_required_opt( opt_name, exe_name, options_list, nb_options, &res );
    if( strtoint(res, dest) ) {
    	cli_destroy_options(options_list, nb_options);
    	cli_usage(exe_name); 
    	die(-1,"parameter %s=%s is not an acceptable integer", opt_name, res);
   	} 
}//eo cli_require_int_option

void cli_require_bool_option( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, int* dest)
{
    const char* res=NULL;
    find_required_opt( opt_name, exe_name, options_list, nb_options, &res );
    if( strtobool(res, dest) ) {
    	cli_destroy_options(options_list, nb_options);
    	cli_usage(exe_name); 
    	die(-1,"parameter %s=%s shall be boolean(yes/no/true/false", opt_name, res); 
    }
}//eo cli_require_int_option


int cli_optional_option( 
	const char* opt_name, const char* exe_name, s_clioption *options_list, 
	unsigned nb_options, char* dest, size_t max_len, const char * dflt 
)
{
	const char* res=NULL;
	if( cli_find_option( opt_name, options_list, nb_options, &res ) ) {
		size_t r = strlcpy( dest, dflt, max_len);  
		if( r > max_len ) {
		   	die( -1, "default for option [%s] is too long", opt_name);
		}
		return -1;
    } else {
    
        size_t r = strlcpy( dest, res, max_len);
   		if( r > max_len ) {
   			die( -1, "option [%s] is too long", opt_name);	
   		}
    	return 0;
    }    
}//eo cli_optional_option

int cli_optional_int_option( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, int* dest, int dflt)
{
	const char* res=NULL;
	if( cli_find_option( opt_name, options_list, nb_options, &res ) ) {
		*dest=dflt;
		return -1;  
    } else {
    	if( strtoint(res, dest) ) {
    		*dest=dflt;
    		return -1;
    	}
    	return 0;
    }
}//eo cli_otpional_int_option

int cli_optional_bool_option( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, int* dest, int dflt)
{
	const char* res=NULL;
	if( cli_find_option( opt_name, options_list, nb_options, &res ) ) {
		*dest=dflt;
		return -1;  
    } else {
    	if( strtobool(res, dest) ) {
    		*dest=dflt;
    		return -1;
    	}
    	return 0;
    }
}//eo cli_optional_bool_option


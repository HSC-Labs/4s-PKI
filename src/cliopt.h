/**
 * 
 * \file cliopt.h
 *
 * \brief Command line options handling definitions
 *
 */
#if !defined( _S4_CLIOPT_H_ )
#define _S4_CLIOPT_H_

#define MAX_CLIOPTION_NAME_LEN (255)
#define MAX_CLIOPTION_VAL_LEN  (4096)

/**
 * Command line interface option
 */
typedef struct SCLIOption {
	char var[MAX_CLIOPTION_NAME_LEN+1];
	char val[MAX_CLIOPTION_VAL_LEN+1];	
} s_clioption;


/**
 * Command line mode of operation
 */
typedef enum ECLIModes  {
    CLIModeUnknown = 0,
    CLIModeInit    = 1,
    CLIModeSign    = 2,
    CLIModeRevoke  = 3
} e_climodes;


#define CLI_MODE_INIT_STR   ("init")
#define CLI_MODE_SIGN_STR   ("sign")
#define CLI_MODE_REVOKE_STR ("revoke")

#define OPTION_ROOT_DIR ("rootdir")
#define OPTION_SECRET   ("secret")
#define OPTION_SUBJECT  ("subject")
#define OPTION_QUORUM   ("quorum")
#define OPTION_NB_SHARE ("nbshares")
#define OPTION_KEY_SIZE ("keysize")
#define OPTION_PAUSED   ("paused")
#define OPTION_CERT     ("cert")
#define OPTION_CSR      ("csr") 
#define OPTION_CRL      ("crl") 

/**
 *
 * Parse the command line into options
 * 
 * \param argc          count of parameters
 * \param argv          values of parameters
 * \param e_climode     mode of operation
 * \param options_list  list of parameters (except the mode)
 * \param optcount      count of the options stored in the options_list
 *
 * \return NULL on error, a non NULL pointer to the cli_option array on success
 *
 */
s_clioption*  cli_parse_params( int argc, char ** argv, e_climodes *mode, unsigned* optcount );

/**
 *
 * Cleanup the option structure
 * 
 * \param options the option structure to cleanup
 */
void cli_destroy_options(s_clioption* options, unsigned optcount);


/**
 * find and option in the option list
 *
 * \param var           name of the option to find
 * \param nth           instance number (starting at 0)
 * \param options_list  list of the parameters
 * \param nb_options    number of parameters in the options list
 * \param val           pointer to the value of the option found
 *
 * \return 0 on success, 1 if none was found, -1 on error
 */
int cli_find_nth_option( const char * var, unsigned nth, s_clioption *options_list, unsigned nb_options, const char** val );


/**
 * find and option in the option list
 *
 * \param var           name of the option to find
 * \param options_list  list of the parameters
 * \param nb_options    number of parameters in the options list
 * \param val           pointer to the value of the option found
 *
 * \return 0 on success, 1 if none was found, -1 on error
 */
int cli_find_option( const char * var, s_clioption *options_list, unsigned nb_options, const char** val );



/**
 *  
 * Display the usage message on stdout
 *
 * \param exename  name of the executable file
 * 
 */
void cli_usage( const char * exename );


/**
 * Dump the content of the parameter list
 */
void cli_print_opt( s_clioption *options_list, unsigned nb_opt );

/**
 * Print the current CLI mode
 */
void cli_print_mode( e_climodes mode);


void cli_require_option( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, char* dest, size_t max_len );

void cli_require_int_option( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, int* dest);

void cli_require_bool_option( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, int* dest);

int cli_optional_option( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, char* dest, size_t max_len, const char * dlft );

int cli_optional_int_option( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, int* dest, int dflt);

int cli_optional_bool_option( const char* opt_name, const char* exe_name, s_clioption *options_list, unsigned nb_options, int* dest, int dflt);




 #endif
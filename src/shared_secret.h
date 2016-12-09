/**
 *
 * \file shared_secret.h
 *
 * \brief Program middleware: communication between modules, initalisation, context ...
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#if !defined( _S4_SHARED_SECRET_H_ )
#define _S4_SHARED_SECRET_H_

#include "shamir.h"
#include "pki.h"

#define PASS_SIZE             (40)
#define B64_ENC_PASS_SIZE     (4 * ( (PASS_SIZE + 2) / 3))
#define HEX_ENC_PASS_SIZE    ( PASS_SIZE * 2 )

//512 Max otherwise Shamir does not work
#define MAX_PASS_SIZE     (512) 
#define MAX_HEX_ENC_PASS_SIZE (2 * MAX_PASS_SIZE) 
#define MAX_B64_ENC_PASS_SIZE  (4 * ( (MAX_PASS_SIZE + 2) / 3))



/**
 * \brief Application context
 */
typedef struct SS4Context {

    unsigned    quorum;
    unsigned    nb_share;

    unsigned    nb_share_exported;
    unsigned    nb_share_loaded;
    unsigned    nb_share_provided;
    unsigned    nb_emitted;
    unsigned    nb_revoqued;

    int         secret_unlocked;
    int         should_pause_for_secrets;
    
    s_pki_parameters_t pki_params;

    char        cert_path[MAX_FILE_PATH+1];
    char        csr_path[MAX_FILE_PATH+1];
    char        crl_path[MAX_FILE_PATH+1];    

    s_share_t   shares[MAX_SHAMIR_SHARE_NUMBER];
    int         shares_loaded[MAX_SHAMIR_SHARE_NUMBER];
    const char *shamir_secrets[MAX_SHAMIR_SHARE_NUMBER];

    char        passphrase[MAX_B64_ENC_PASS_SIZE+1];
    size_t      passphrase_len;

    const char *op_status;
} s_s4context;


typedef void (*progress_handler_t)   ( void* data, int pct, const char *descr);
typedef void (*warning_handler_t)    ( void* data, const char * fmd, ... );
typedef int  (*fileprompt_handler_t) ( void* data, const char * prompt, char* filepath, size_t  filepath_max);
typedef void (*dialog_handler_t)     ( void* data, const char * title, const char* message );

/**
 * \brief Event handlers
 */
typedef struct SS4EventHandlers {
	void * data;
	progress_handler_t   on_progress;
	warning_handler_t    on_warning;
    fileprompt_handler_t do_file_prompt;
    dialog_handler_t     do_message;
} s_s4eventhandlers_t;

/**
 * Create an initialized application context
 *
 * \return NULL on error, a pointer to the context otherwise
 */
s_s4context* s4_init_context();

/**
 * Destroy an initialized application context
 *
 * \param s4c an initialized context to destroy
 */
void s4_destroy_context( s_s4context* s4c );


/**
 * Check whether a directory path is illigible as a PKI root
 *
 * \param dirname    path to the candidate directory
 *
 * \return 0 on success, -1 on failure
 */
int check_pki_root_dir( const char* dirname );

/**
 * Check whether a string is a proper root certificate subject
 *
 * \param subject candidate subject
 *
 * \return 0 on success, -1 on failure
 */
int check_pki_subject( const char* subject );


/**
 * \brief Split function for command line interface 
 *
 * Split a passphrase in a quorum of N/M 
 *
 * \param s4c   application context
 * \param s4evt application events handlers
 *
 * \return 0 on success, non 0 on failure
 */
int s4_split( s_s4context *s4c, s_s4eventhandlers_t * s4evt );

/**
 * \brief Split function for command line interface 
 *
 * Split a passphrase in a quorum of N/M et write them in several file
 *
 * \param s4c   application context
 * \param s4evt application events handlers
 *
 * \return 0 on success, non 0 on failure
 */
int s4_splitnsave( s_s4context *s4c, s_s4eventhandlers_t * s4evt );


/**
 * Reconstruct passphrase function for command line interface
 * 
 * \param s4c   application context
 * \param s4evt application events handlers
 *
 * \return O on success, non 0 on failure
 */
int s4_reconstruct( s_s4context *s4c, s_s4eventhandlers_t * s4evt );


/**
 * try to load pki informations from a candidate PKI 
 */ 
int try_to_open_pki_info( s_s4context* s4w, const char *dirname );



#endif 

/**
 *
 * \file pki.h
 *
 * \brief Key and certificate management functions definitions
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#if !defined( _S4_PKI_H_ )
#define _S4_PKI_H_

#define MAX_PKI_SUBJECT_LEN (512)
#define MAX_URL_LEN         (256)
#define MAX_CRYPTO_ALG_LEN  (128)

#define MIN_CERT_LIFE_DAYS        (365)
#define MAX_CERT_LIFE_DAYS        (365*20)
#define DEFAULT_CA_LIFE_IN_DAYS (365*10)
#define DEFAULT_SUBCA_LIFE_IN_DAYS (365*5)

#define MIN_CRL_LIFE_DAYS     (30)
#define MAX_CRL_LIFE_DAYS     (365*20)
#define DEFAULT_CRL_LIFE_DAYS (365)

#define MAX_SHAMIR_SHARE_NUMBER (15)

#define DEFAULT_QUORUM    (3)
#define DEFAULT_NB_SHARE  (5)

#define MIN_KEY_SIZE     (1024)
#define MAX_KEY_SIZE     (32768)
#define DEFAULT_KEY_SIZE (2048)

typedef struct SPKIParameters {

    char        subject[MAX_PKI_SUBJECT_LEN+1]; 
    char        cdp_url[MAX_URL_LEN+1];
    char        hash_algorithm[MAX_CRYPTO_ALG_LEN+1];
    char        root_dir[MAX_FILE_PATH+1];

	unsigned    ca_key_size;

    unsigned    ca_life_len;
    unsigned    subca_life_len;
    unsigned    crl_life_len;
    unsigned    cert_default_keysize;

} s_pki_parameters_t;


struct SS4EventHandlers;
/**
 * Generate a strong password
 *
 * \param  out      destination buffer for the password
 * \param  max_size out buffer size
 *
 * \return the password size on success, -1 on error
 *
 */
ssize_t gen_pass(char *out, const size_t max_size);

/**
 * \brief Init the PKI
 *
 * Create initial PKI files and directory and generate Self signed CA and the CRL associated
 *
 * \param directory     root directory for the PKI
 * \param subject       subject for the root certificate encoded "openssl style" /Field1=val1/Field2=val2/Field3=val3
 * \param password      password for the root private key
 * \param nb_share     number of shared secrets
 * \param quorum        quorum required to unlock the root private key
 * \param evt_handlers  structure of application events (progress, errors) handlers
 *
 * \return 0 on success, 1 on error
 *
 */
int gen_self_signed(
		const char *directory, 
		const s_pki_parameters_t *params, 
		const char *password, 
		const unsigned nb_share, 
		const unsigned quorum, struct SS4EventHandlers* evt_handlers 
);

/**
 * \brief Sign SubCA function 
 *
 * Sign a SubCA and generate the CRL associated
 *
 * \param directory      root directory of the PKI
 * \param csr_filename   path to the CSR file to sign
 * \param cert_filename  path to an optionnal copy of the certificate (no copy is performed if empty or NULL)
 * \param password       password of the root private key
 * \param evt_handlers   structure of application events (progress, errors) handlers
 *
 * \return 0 on success, 1 on error
 *
 */
int sign_subca(const char *directory, const char *csr_filename, const char *cert_filename, const char *password, struct SS4EventHandlers* evt_handlers );


/**
 * \brief Revoke subCA function 
 *
 * Revoke the provided certificate 
 *
 * \param directory      root directory of the PKI
 * \param cert_filename  path to the subca certificate to revoke 
 * \param password       paswword of the root private key
 * \param evt_handlers  structure of application events (progress, errors) handlers
 *
 * \return 0 on success, 1 on error
 * 
 */
int revoke_subca(const char *directory, const char *cert_filename,  const char *password, struct SS4EventHandlers* evt_handlers );

/**
 * \brief Emit a new CRL
 *
 * Revoke the provided certificate 
 *
 * \param directory      root directory of the PKI
 * \param crl_filename   path of where to save the CRL
 * \param password       paswword of the root private key
 * \param evt_handlers  structure of application events (progress, errors) handlers
 *
 * \return 0 on success, 1 on error
 * 
 */
int generate_crl(const char *dir, const char *crl_filename, const char *password, struct SS4EventHandlers* evt_handlers );

/**
 * \brief Read CA informations
 *
 * Load the CA configuration file and load the status variables
 *
 * \param directory      root directory of the PKI
 * \param psubject       pointer to an allocated buffer for the CA subject 
 * \param subject_max    maximum number of char for the subject
 * \param pnb_share      pointer to an allocated unsigned for the number of shared secrets
 * \param pquorum        pointer to an allocated unsigned for the quorum required to unlock the root private key
 * \param pemitted       pointer to an allocated unsigned for the number of signed subca
 * \param pnb_revoqued   pointer to an allocated unsigned for the number of revocated subca
 *
 * \return 0 on success, 1 on error
 * 
 */
int read_ca_infos( const char * directory, 
				   char *subject, size_t subject_max, 
				   unsigned *pnb_holders, 
				   unsigned *pquorum,  
				   unsigned *pnb_emitted, 
				   unsigned *pnb_revoqued 
);

/**
 * \brief Read CA informations
 *
 * Write the CA configuration file and fromm status variables
 *
 * \param directory      root directory of the PKI
 * \param psubject       pointer to an allocated buffer for the CA subject 
 * \param pnb_share      pointer to an allocated unsigned for the number of shared secrets
 * \param pquorum        pointer to an allocated unsigned for the quorum required to unlock the root private key
 * \param pemitted       pointer to an allocated unsigned for the number of signed subca
 * \param pnb_revoqued   pointer to an allocated unsigned for the number of revocated subca
 *
 * \return 0 on success, 1 on error
 * 
 */
int write_ca_infos( const char * directory, 
				   const char *subject, 
				   const unsigned nb_holders, 
				   const unsigned quorum,  
				   const unsigned nb_emitted, 
				   const unsigned nb_revoqued 
);

/**
 * Load the textual description of the PKI root certificate
 */
ssize_t read_ca_cert_infos( const char *dir, char* buffer, const size_t max_size );



#endif


/**
 *
 * \file shamir.h
 *
 * \brief Shamir secret sharing declarations
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#if !defined( SHAMIR_SECRET_SHARING_H_ )
#define SHAMIR_SECRET_SHARING_H_

#include <gmp.h>
#include <assert.h>

#include "utils.h"

#define RING_SIZE (512)
#define SHARED_SECRETS_STR_MAX (1024)


/**
 *
 * Structure containing a Shamir secret for a single holder
 *
 */
typedef struct SShare {
    char X[SHARED_SECRETS_STR_MAX];
    char Y[SHARED_SECRETS_STR_MAX];
    char prime[SHARED_SECRETS_STR_MAX];
} s_share_t;




/**
 * Encode string in hex format
 *
 * \param in    string in
 * \param out   string in hex format
 * 
 * \return 0 on success, non 0 on error
 */
//int hex_encode( const char *in, char **out );

/**
 * Decode string in hex format
 *
 * \param in    string in hex format
 * \param out   string original
 * 
 * \return 0 on success, non 0 on error
 */
//int hex_decode( const char *in, char **out );

/**
 * Perform the Shamir secret splitting
 *
 * \param quorum     minimal number of partial secrets holders required to reconstruct the password
 * \param nb_share   total number of partial secrets holders
 * \param password   secret to be splitter amont the holders
 * \param shares     a pointer to an allocated array of nb_share secret share structures
 * 
 * \return 0 on success, non 0 on error
 */
int do_shamir_split( int quorum, int nb_share, const uint8_t * secret_val, const size_t sec_len, s_share_t *shares );

/**
 * Try to recover Shamir splitted secret from a holders quorum
 * 
 * \param nb_participants  number of participants to the reconstruction
 * \param shares           pointer to an array of at least nb_participants shares
 * \param result           allocated char array of at least max_result size+1 for the resulting secret
 * \param max_result       size of result, and maximum size for the resulting secret
 *  
 * \return 0 on success, non 0 on error
 */
int do_shamir_recovery( const int nb_participants, const s_share_t* shares, uint8_t * result, size_t max_resize );

/**
 *
 * Save a Shamir secret to a file
 *
 * \param filename  path to the file to save the secret to
 * \param share     pointer to the share to save
 *
 * \return 0 on success, non 0 on error
 */
int save_shamir_secret( const char* filename, const s_share_t* share);


/**
 *
 * Load a Shamir secret from a file
 *
 * \param filename path to the file to read the secret from
 * \param share    pointer to the share to read
 *
 * \return 0 on success, non ° on error
 */
int load_shamir_secret( const char* filename, s_share_t* share );


/**
 *
 *
 */
ssize_t shamir_share_fingerprint( const s_share_t* share, char *fingerprint, const size_t max_size );

#endif

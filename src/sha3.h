/**
 * 
 * \file sha3.h
 *
 * \brief SHA3 interface
 *
 * Based on : https://github.com/brainhub/SHA3IUF
 * From  Andrey Jivsov.
 *
 * License: see LICENSE.md file
 *
 */
#if !defined( _S4_SHA3_H_ )
#define _S4_SHA3_H_



/* 'Words' here refers to uint64_t */
#define SHA3_KECCAK_SPONGE_WORDS \
    (((1600)/8/*bits to byte*/)/sizeof(uint64_t))

typedef struct sha3_context_ {
    uint64_t saved;             /* the portion of the input message that we
                                 * didn't consume yet */
    union {                     /* Keccak's state */
        uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
        uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
    };
    unsigned byteIndex;         /* 0..7--the next byte after the set one
                                 * (starts from 0; 0--none are buffered) */
    unsigned wordIndex;         /* 0..24--the next word to integrate input
                                 * (starts from 0) */
    unsigned capacityWords;     /* the double size of the hash output in
                                 * words (e.g. 16 for Keccak 512) */
} sha3_context;

/**
 * Initialisation  for a 256 bits hash
 */
void sha3_init256( sha3_context *priv);

/**
 * Initialisation  for a 384 bits hash
 */
void sha3_init384( sha3_context *priv);

/**
 * Initialisation  for 512 bits hash
 */
void sha3_init512( sha3_context *priv);

/**
 * Add some data to the hash
 *
 * \param priv
 * \param bufIn
 * \param len
 */
void sha3_update( sha3_context *priv, void const *bufIn, size_t len);

/**
 * Finish the computation
 *
 * \param priv
 *
 * \return a pointer to the hash
 *
 */
void const * sha3_finalize( sha3_context *priv);

#endif //_S4_SHA3_H_

//eof

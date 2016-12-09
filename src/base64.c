// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 *
 * \file base64.c
 *
 * \brief Base64 encoding / decoding
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */


//#define DEEPDEBUG 1

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include "utils.h"

static uint8_t encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


ssize_t base64_encode(char *encoded, const size_t max_size, const uint8_t *data, size_t input_length )
{
    static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *ptr = encoded;

    size_t output_length = 4 * ( (input_length + 2) / 3);
    if( max_size < output_length) {
        DEBUG_PRN("base64_encode: destination buffer is too small (%u<%u)", max_size, output_length );
        return -1;
    }

    unsigned i;
    for( i=0; i<(input_length-2); i+=3 ) {
        *ptr++ = encoding_table[ (data[i] >> 2) & 0x3F];
        *ptr++ = encoding_table[ ( (data[i] & 0x3) << 4)   | ( (int)(data[i+1] & 0xF0) >> 4) ];
        *ptr++ = encoding_table[ ( (data[i+1] & 0xF) << 2) | ( (int)(data[i+2] & 0xC0) >> 6) ];
        *ptr++ = encoding_table[ data[i+2] & 0x3F ];
    }

    if( i<input_length ) {
        *ptr++ = encoding_table[ (data[i] >> 2) & 0x3F ];
        if( i == (input_length-1) ) {
            *ptr++ = encoding_table[((data[i] & 0x3) << 4)];
            *ptr++ = '=';
        } else {
            *ptr++ = encoding_table[((data[i] & 0x3) << 4) 
                | ((int)(data[i+1] & 0xF0) >> 4)];
            *ptr++ = encoding_table[((data[i+1] & 0xF) << 2)];
        }
        *ptr++ = '=';
    }

    *ptr++ = '\0';
    
    DDEBUG_PRN("base64_encode finished [%s]", encoded );
    return ptr - encoded;
}//eo base64_encode


ssize_t base64_decode( uint8_t *decoded, const size_t max_size, const char *encoded )
{
    assert( NULL != encoded  );
    assert( NULL != decoded  );
    assert( max_size > 1     );

    const uint8_t * ptr = (uint8_t*)encoded;

    size_t input_length = strlen(encoded);
    if ( input_length % 4 != 0 ) {
        DEBUG_PRN("base64_decode: invalid content size for base64");
        return -1;
    }

    // init decoding table
    static uint8_t decoding_table[256];
    for (unsigned i = 0; i < 64; i++) {
        decoding_table[ encoding_table[i] ] = i;
    }

    size_t output_length = input_length / 4 * 3;
    if (encoded[input_length - 1] == '=') output_length--;
    if (encoded[input_length - 2] == '=') output_length--;

    if( max_size < output_length) {
        DEBUG_PRN("base64_decode: destination buffer is too small (%u<%u)", max_size, output_length);
        return -1;
    }

    uint32_t i = 0, j = 0; 
    while( i < input_length ) {
        uint32_t a = 
            ( encoded[i] == '=' )? 
            (0 & i++ ): 
            decoding_table[ ptr[i++] ];
        uint32_t b = 
            ( encoded[i] == '=' )? 
            (0 & i++ ): 
            decoding_table[ ptr[i++] ];
        uint32_t c = 
            ( encoded[i] == '=' )? 
            (0 & i++ ): 
            decoding_table[ ptr[i++] ];
        uint32_t d = 
            ( encoded[i] == '=' )? 
            (0 & i++ ): 
            decoding_table[ ptr[i++] ];

        uint32_t triple = 
              (a << 3 * 6)
            + (b << 2 * 6)
            + (c << 1 * 6)
            + (d << 0 * 6);

        if ( j<output_length ) { 
            decoded[j++] = (triple >> 2 * 8) & 0xFF; 
        }
        if ( j<output_length ) { 
            decoded[j++] = (triple >> 1 * 8) & 0xFF; 
        }
        if ( j<output_length ) { 
            decoded[j++] = (triple >> 0 * 8) & 0xFF; 
        }
    }

    DDEBUG_PRN("base64_decode finished");

    return output_length;
}//eo base64_decode



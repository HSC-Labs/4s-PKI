 /**
 *
 * \file utils.h
 *
 * \brief Basic utilities declarations
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#if !defined( _S4_UTILS_H_ )
#define _S4_UTILS_H_

#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h> 
#include <stdint.h>
#include <string.h>
#include <math.h>


void _print_debug(const char* prefix, const char* fname, const int lnum, const char *fmt, ... );

#if !defined(NDEBUG)
#define DEBUG_PRN(...) ( _print_debug("DEBUG", __FILE__, __LINE__, __VA_ARGS__ ))
#else
#define DEBUG_PRN(...)
#endif

#if defined(DEEPDEBUG)
#define DDEBUG_PRN(...) ( _print_debug("DDEBUG", __FILE__, __LINE__, __VA_ARGS__ ))
#else
#define DDEBUG_PRN(...)
#endif

#define INTPCT(max,val) (int)rint( 100 * (double)(val) / (double)(max) )

 /**
  * Maximum number of characters in a file path
  */
#define MAX_FILE_PATH (512)


/**
 * Call a system command
 *
 * \param cmd       path to the command to call
 * \param variable  list of parameters to pass to the command
 *
 * \return 0 on success, non 0 on error
 */ 
int call_command( const char* cmd, ... );

/**
 * Call the openssl command line 
 *
 * \return 0 on success, -1 otherwise
 *
 */
int call_openssl( const char * format, ...);

/** 
 * Securely erase some memory 
 *
 */
void secure_memzero(void* buffer, size_t sze);

/** 
 * Print an error message and die returning code
 */
 void die( int code, const char * fmt, ...);

/** 
 * Print an error message 
 */
 void warn( const char * fmt, ...);

/**
 * Print variadic parameters as error message
 */
void vwarn( const char * fmt, va_list args );

/**
 * Copy a file from A to B
  */
int file_copy(const char * filepath, const char * dest_path );

/** 
 * Dump a buffer to a file 
 */
ssize_t write_to_file(const char* fname, size_t size, const char * data);

/**
 * Read a whole file to a buffer
 */
ssize_t slurp( const char *fname, uint8_t* buffer, const size_t max_size );

/** 
 * Prompts the user for an input untils something si answered ***
 * 
 * \param prompt to display, 
 * \param buffer for the result, 
 * \param maximum content size
 *
 * \return size of the input on success, -1 on failure
 */
 ssize_t prompt( const char* message, char * result, size_t max_size );


/**
 * Convert a null terminated string to a boolean value 0/1
 * 
 * Acceptable input values are
 *     YES OUI TRUE  VRAI for 1
 *     NO  NON FALSE FAUX for 0
 * values are case independant.
 * 
 * Any other value will be considered an error
 *
 * \param str  the input string
 * \param bval pointer to an allocated int for the result
 *
 * \return 0 on success, -1 on failure
 *
 */
int strtobool(const char* str, int* bval);

/**
 * Convert a null terminated string to an integer 
 *
 * \param str  the input string
 * \param ival pointer to an allocated int for the result
 *
 * \return 0 on success, -1 on failure
 *
 */
int strtoint(const char* str, int* ival);

/**
 * OpenBSD string copy function to replace strncpy
 *
 * \param dst    destination buffer
 * \param src    string to copy 
 * \param dsize  destination size
 *
 * \return src size
 *
 */ 
size_t strlcpy(char *dst, const char *src, size_t dsize);

/**
 * Encode a binary buffer to an hexadecimal value
 *
 * \param encoded   buffer to encode to
 * \param max_size  destination buffer size
 * \param data      message to encode
 * \param data_size number of byte to encode from msg
 * 
 * \return size of the encoded data on success, -1 on error
 *
 */
ssize_t hex_encode(char *out, const size_t max_out, const uint8_t *data, const size_t data_size );

/**
 * Decode an hex encoded string to a binary buffer
 *
 * \param decoded      buffer to decode to
 * \param max_size     destination buffer size
 * \param encoded      message to decode
 *
 * \return size of the decoded data on success, -1 on error
 *
 */
ssize_t hex_decode(uint8_t* decoded, const size_t max_size, const char *encoded );


/**
 *
 * Encode a buffer to a base64 string
 *
 * \param encoded      buffer to encode to
 * \param max_size     destination buffer size
 * \param data         message to encode
 * \param data_size    number of byte to encode from msg
 * 
 * \return size of encoded data on success, -1 on error
 *
 */
ssize_t base64_encode( char *encoded, const size_t max_size, const uint8_t *data, const size_t data_size );

/**
 * 
 * Decode a base64 string to a buffer
 *
 * \param decoded      buffer to decode to
 * \param max_size     destination buffer size
 * \param encoded      message to decode
 *
 * \return size of decoded data on success, -1 on error
 */
ssize_t base64_decode( uint8_t *decoded, const size_t max_size, const char *encoded ); 




/**
 * Extract prefix from a filename: path and drive
 *
 * \var fullpath full path to examine
 * \var prefix   allocated buffer to copy the prefix to
 * \var max_size size of the buffer
 *
 * \return size if the prefix on success, -1 on error
 */
ssize_t filename_prefix( const char * fullpath, char* prefix, size_t max_size  );

/**
 * Extract prefix from a filename: path and drive
 *
 * \var fullpath full path to examine
 * \var prefix   allocated buffer to copy the basename to
 * \var max_size size of the buffer
 *
 * \return size if the prefix on success, -1 on error
 */
ssize_t filename_base( const char * fullpath, char* basename, size_t max_size  );

/**
 * Extract prefix from a filename: path and drive
 *
 * \var fullpath full path to examine
 * \var ext   allocated buffer to copy the extension to
 * \var max_size size of the buffer
 *
 * \return size if the prefix on success, -1 on error
 */
ssize_t filename_extension( const char * fullpath, char* ext, size_t max_size  );

/**
 * remove the eventual end of  line of a string
 */
void chomp( char * line );


ssize_t file_slurp( const char *fname, uint8_t* buffer, const size_t max_size );

#endif


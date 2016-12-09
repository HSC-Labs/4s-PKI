// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 *
 * \file utils.c
 *
 * \brief Basic utilities functions
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

//#define DEEpDEBUG 1

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "utils.h"

#define MAX_COMMAND_LEN (2048)

#if defined(__linux__)
#define OPENSSL_PATH ("/usr/bin/openssl")
#elif defined(_WIN32_)
#define OPENSSL_PATH (".\\openssl")
#else
#define OPENSSL_PATH ("openssl")
#endif



#if defined (__WIN32__)
// using Win32 un-optimizable zero call
void secure_memzero( void* buffer, size_t sze) {
	SecureZeroMemory(buffer,sze);
}
#elif defined(__GNUC__)
// prevent GCC from function optimization
void __attribute__((optimize("O0"))) secure_memzero(void* buffer, size_t sze) 
{
	memset(buffer,0,sze);	
}
#else
// best effort to avoid optimisation
static void * (* const volatile memset_ptr_)(void *, int, size_t) = memset;
void secure_memzero( const void* buffer, size_t sze) 
{
	(memset_ptr_)(buffer, 0, sze);	
}
#endif




#if defined( __WIN32__ )
/////////////////////////////////////////////////////////////////////// Win32 World
ssize_t filename_prefix( const char * fullpath, char* prefix, size_t max_size  )
{
	char drive[3];
	char dir[MAX_FILE_pATH];
	char fname[MAX_FILE_pATH];
	char ext[32];

	errno_t err = _splitpath_s(
		fullpath, 
		drive,	sizeof(drive), 
		dir,    sizeof(dir),
   		fname,  sizeof(fname),
   		ext, sizeof(ext)
	);
	if( err ) {
		DEBUG_PRN("filename_prefix: splitpath(%s) failed %d", fullpath, err );
		return -1;
	}

	size_t s1 = strlcpy(prefix, max_size, drive);
	if( s1>max_size ) {
		DEBUG_PRN("filename_prefix: insufficient size for storing drive in prefix (%u<%u)", max_size, s1 );
		return -1;
	}

	size_t s2 = strlcat(prefix, max_size, dir);
	if( s2+s1>max_size ){
		DEBUG_PRN("filename_prefix: insufficient size for storing drive in prefix (%u<%u)", max_size, s1+s2 );
		return -1;
	}

	return s2+s1;
}//eo filename_prefix

ssize_t filename_base( const char * fullpath, char* bname, size_t max_size  )
{
	char drive[3];
	char dir[MAX_FILE_pATH];
	char fname[MAX_FILE_pATH];
	char ext[32];

	errno_t err = _splitpath_s(
		fullpath, 
		drive,	sizeof(drive), 
		dir,    sizeof(dir),
   		fname,  sizeof(fname),
   		ext, sizeof(ext)
	);
	if( err ) {
		DEBUG_PRN("filename_base: splitpath(%s) failed %d", fullpath, err );
		return -1;
	}

	size_t sze = strlcpy(bname, max_size, drive);
	if( sze>max_size ) {
		DEBUG_PRN("filename_base: insufficient size for storing the basename (%u<%u)", max_size, sze );
		return -1;
	}

	return sze;
}//eo filename_base

ssize_t filename_extension( const char * fullpath, char* ext, size_t max_size  )
{
	char drive[3];
	char dir[MAX_FILE_pATH];
	char fname[MAX_FILE_pATH];
	char ext[32];

	errno_t err = _splitpath_s(
		fullpath, 
		drive,	sizeof(drive), 
		dir,    sizeof(dir),
   		fname,  sizeof(fname),
   		ext,    sizeof(ext)
	);
	if( err ) {
		DEBUG_PRN("filename_extension: splitpath(%s) failed %d", fullpath, err );
		return -1;
	}

	size_t sze = strlcpy(ext, max_size, ext);
	if( sze>max_size ) {
		DEBUG_PRN("filename_extension: insufficient size for storing the extension (%u<%u)", max_size, sze );
		return -1;
	}

	return sze;
}//eo filename_extension


#else 
/////////////////////////////////////////////////////////////////////// pOSIX World

#include <libgen.h>

ssize_t filename_prefix( const char * fullpath, char* prefix, size_t max_size  )
{
	char * var_path = strdup(fullpath);
	if ( NULL==var_path  ){
		die(-1,"filename_prefix: allocation failed in directory name extraction");
	}
	char *res = dirname(var_path);
	if( NULL ==res ) {
		DEBUG_PRN("filename_prefix: directory name extraction failed for %s",fullpath);
		return -1;
	}
	size_t sze = strlcpy(prefix, res, max_size);
	free(var_path);

	if(sze>max_size) {
		DEBUG_PRN("filename_prefix: insufficient size for storing drive in prefix (%u<%u)", max_size, sze );
		return -1;
	}

	return sze;
}//eo directory_name

ssize_t filename_base( const char * fullpath, char* bname, size_t max_size  )
{
	char * var_path = strdup(fullpath);
	if ( NULL==var_path  ){
		die(-1,"filename_base: allocation failed in filename extraction");
	}
	char *pbase = basename(var_path);
	if( NULL==pbase ) {
		DEBUG_PRN("filename_base: filename extraction failed for %s",fullpath);
		return -1;
	}
	DDEBUG_PRN("filename_base: basename(%s)=[%s] ", fullpath, pbase);
	
	char* pdot = rindex(pbase,'.');
	DDEBUG_PRN("filename_base: rindex(%s)=[%s] ", pbase, pdot);
	if( NULL!= pdot ){
		*pdot = '\0';
	}	

	size_t sze = strlcpy( bname, pbase, max_size);	
	free(var_path);

	if(sze>max_size) {
		DEBUG_PRN("filename_base: insufficient size for basename (%u<%u)", max_size, sze );
		return -1;
	}

	return sze;
	
}//eo filename_extension

ssize_t filename_extension( const char * fullpath, char* extension, size_t max_size  )
{	
	char * var_path = strdup(fullpath);
	if ( NULL==var_path  ){
		die(-1,"filename_base: allocation failed in extension extraction");
	}
	
	char* pdot = rindex(var_path,'.');
	DDEBUG_PRN("filename_extension: rindex(%s)=[%s] ", var_path, pdot);
	if( NULL== pdot ){
		return 0;
	}
	*pdot = '\0';
		
	size_t sze = strlcpy( extension, pdot+1, max_size);	
	free(var_path);

	if(sze>max_size) {
		DEBUG_PRN("filename_base: insufficient size for basename (%u<%u)", max_size, sze );
		return -1;
	}

	return sze;	
}//eo filename_extension

#endif//eo POSIX file manipulations

int file_copy(const char * src_path, const char * dest_path )
{
	char   buffer[1024];
    size_t n;

    FILE* f_from = fopen(src_path,"r");
    if( NULL== f_from ){
    	DEBUG_PRN("file_copy: Failed to open source file '%s'", src_path );
    	return -1;
    }

    FILE* f_to   = fopen(dest_path,"w");
    if( NULL== f_from ){
    	DEBUG_PRN("file_copy: Failed to open destination file '%s'", dest_path );
    	return -1;
    }

    while ( (n = fread(buffer, sizeof(char), sizeof(buffer), f_from)) > 0 )
    {
        if (fwrite( buffer, sizeof(char), n, f_to) != n) {
            DEBUG_PRN("file_copy: write to '%s' failed", dest_path);
        	return -1;
        }
    }//eo foreach K

    fclose(f_from);
    fclose(f_to);

    return 0;
}//eo file_copy


// real command call
static int vcall_command( const char* fmt, va_list args ) 
{
	
	// building the command line
	char cmd[MAX_COMMAND_LEN+1]; // command line to call
   	vsnprintf (cmd, MAX_COMMAND_LEN, fmt, args);
	cmd[MAX_COMMAND_LEN]='\0';

	// calling
	DDEBUG_PRN("> cmd: %s\n", cmd); 

	int res = system(cmd);
	secure_memzero(cmd, MAX_COMMAND_LEN);

	// processing result
	if (res < 0) {
		perror("internal error: external call failed");
		return -1;
	} else {
		if (WIFEXITED(res)) {
			DDEBUG_PRN("raw:%d refined:%d", res, WEXITSTATUS(res)); 
			return WEXITSTATUS(res);
		}
		else return -1;
	}

}//eo vcall_command

int call_command( const char* fmt, ... ) 
{
	va_list args;
	va_start (args, fmt);
	
	int res = vcall_command(fmt,args);

	va_end(args);

	return (res==0);

}//eo call_command


int call_openssl( const char * fmt, ...) 
{

	char format[MAX_COMMAND_LEN+1];  

	va_list args;
	va_start (args, fmt);

	snprintf(format, MAX_COMMAND_LEN, "%s %s", OPENSSL_PATH, fmt);
	format[MAX_COMMAND_LEN]=0;

	// executing
	int res = vcall_command(format, args);

	// cleanup
	secure_memzero(format, MAX_COMMAND_LEN);
	va_end (args);

	return res;

}//eo call_openssl

void _print_debug(const char* prefix, const char* fname, const int lnum, const char *fmt, ... )
{	
	va_list args;
	va_start (args, fmt);

	fprintf( stderr,"%s[%s:%d] ", prefix, fname, lnum);
	vfprintf( stderr, fmt, args);
	fprintf( stderr,"\n");

	va_end(args);
}//eo print_debug

void vwarn( const char * fmt, va_list args ) 
{
	fprintf( stderr,"WARNING: ");
	vfprintf( stderr, fmt, args);
	fprintf( stderr,"\n");
}//eo die

void warn( const char * fmt, ...) 
{
	va_list args;
	va_start (args, fmt);

	vwarn(fmt, args);

	va_end(args);
}//eo die


void die( int code, const char * fmt, ...) 
{

	va_list args;
	va_start (args, fmt);

	fprintf(stderr,"ERROR: ");
	vfprintf( stderr, fmt, args);
	fprintf(stderr,"\n");

	va_end(args);

	exit(code);
}//eo die

ssize_t write_to_file(const char* fname, size_t size, const char * data)
{
	FILE* fp = fopen(fname,"w");
	if( fp == NULL ) {
		printf("Error during opening to write\n");
		return -1;
	}
	ssize_t res = fwrite(data, sizeof(char), size, fp );
	fclose(fp);

	if( res == 0 ) {
		printf("Error during writing file\n");
		return -1;
	} 

	return res;
}//eo write_to_file


ssize_t prompt( const char* message, char * result, size_t max_size ) 
{
	
	result[0]='\0';
 
	size_t n = max_size;
	ssize_t res = 0;

	while( res==0 ) {
		printf("%s: ", message);
		res = getline( &result, &n, stdin );
		if( res < 0 ) { return -1; }
	}
	result[res]='\0';
	strtok(result,"\n");

	//DDEBUG_PRN("input:>%s<\n", result); 

	return strnlen(result,max_size);
}//eo prompt

int strtobool(const char* str, int* bval)
{
	if( strcasecmp(str,"YES") || strcasecmp(str,"TRUE") || strcasecmp(str,"OUI") || strcasecmp(str,"VRAI") ) {
 		*bval =1;
 		return 0;
 	} else if( strcasecmp(str,"NO") || strcasecmp(str,"FALSE") || strcasecmp(str, "NON") || strcasecmp(str, "FAUX") ) {
 		*bval =0;
 		return 0;
 	} else {
 		*bval = -1;
 		return -1;
 	}
}//eo strtobool

int strtoint(const char* str, int* ival)
{
	//TODO
    errno = 0;
    long int v = strtol( str, NULL, 10);
    if( errno != 0 || v>INT_MAX || v<INT_MIN) {
		return -1;
    }        	

    *ival= (int) v;

    return 0;
}//eo strtoint

ssize_t hex_encode(char *out, const size_t max_out, const uint8_t *in, const size_t in_size )
{
	DDEBUG_PRN("hex_encode( out:%p, max_out:%u, in:%p, in_size:%u", out, max_out, in, in_size);

  	size_t  out_size  = 2*in_size+1;
 
  	if( max_out < out_size ){
  		DEBUG_PRN("Output buffer insufficient for the hex encoded data (%u<%u)", max_out, out_size );
  		return -1;
 	}

	secure_memzero(out,out_size);
	for( unsigned i = 0; i<in_size; i++){		
		sprintf(out+i*2, "%02X", in[i]);
  	}
 
	return out_size-1;
}//eo hex_encode


ssize_t hex_decode(uint8_t* out, const size_t max_out, const char *in )
{
	long s;
	int i=0;
	size_t lim = strlen(in);
	if( lim % 2 ){
  		DEBUG_PRN("Invalid size to decode an hex encoded value %u", lim);
  		return -1;
	}

	size_t out_size = lim/2;
	if( max_out < out_size ){
		DEBUG_PRN("Output buffer insufficient for the hex encoded data (%u<%u)", max_out, out_size );
		return -1;
	}

	char hex[3];
	secure_memzero(out,lim);

	for( unsigned idx = 0; idx<lim; idx=idx+2 ){
		memset(hex,0,3);
		memcpy(hex, &in[idx], 2);
		s = strtol(hex,NULL,16);
		out[i]=(char)s;
		i++;
	}
  
  return i;
}//eo hex_decode



void chomp( char * line )
{
	int len = strlen(line);
	if( line[len]=='\n' || line[len]=='\r' ) line[len]='\0';
	len--;
	if( line[len]=='\n' || line[len]=='\r' ) line[len]='\0';
}//eo chomp


ssize_t file_slurp( const char *fname, uint8_t* buffer, const size_t max_size )
{
	FILE *f = fopen(fname, "rb");
	if( NULL == f ){
		DEBUG_PRN("slurp(%s: failed to open file", fname);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	size_t fsize = ftell(f);
	fseek(f, 0, SEEK_SET);  //same as rewind(f);

	if( fsize > max_size ) {
		DEBUG_PRN("slurp(%s): not enough room for the file size (%u>%u)", fname, fsize, max_size );
		return -1;	
	}
		
	size_t r = fread(buffer, fsize, 1, f);
	if( r < 1 ) {
		if( feof(f)) {
			return fsize;
		} else {
			DEBUG_PRN(
				"slurp(%s): error encountered while reading file, %u bytes expected but got %d return", 
				fname, fsize, r 
			);
			return -1;
		}

	}

	if( fclose(f) ) {
		DEBUG_PRN("slurp(%s): error when closing file", fname);
		return -1;
	}
	
	return fsize;
}//eo slurp



//eof

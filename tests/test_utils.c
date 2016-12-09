#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>

#include <CUnit/Basic.h> 

//#define DEEPDEBUG 1

#include "utils.h"



#define ASCII_SAMPLE ( "Maitre renard sur un arbre perche tenait dans son bec un fromage." )

#define ASCII_HEX_ENCODED_SAMPLE (     \
  "4D61697472652072656E6172642073757220756E206172627265207065726368652074656E6169742064616E7320736F6E2062656320756E2066726F6D6167652E" \
  )

#define ASCII_B64_ENCODED_SAMPLE ( \
  "TWFpdHJlIHJlbmFyZCBzdXIgdW4gYXJicmUgcGVyY2hlIHRlbmFpdCBkYW5zIHNvbiBiZWMgdW4gZnJvbWFnZS4=" \
)

#define BIN_SAMPLE ( \
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" \
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\xEF" \
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F" \
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F" \
    "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F" \
    "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F" \
) 

#define BIN_SAMPLE_LEN (96)

#define BIN_HEX_ENCODED_SAMPLE ( \
    "000102030405060708090A0B0C0D0E0F" \
    "101112131415161718191A1B1C1D1EEF" \
    "202122232425262728292A2B2C2D2E2F" \
    "303132333435363738393A3B3C3D3E3F" \
    "404142434445464748494A4B4C4D4E4F" \
    "505152535455565758595A5B5C5D5E5F" \
) 

#define BIN_B64_ENCODED_SAMPLE ( \
"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHu8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f" \
)

#if defined (__WIN32__)
  #define FULLPATH_SAMPLE           ("d:\\tmp\\someplace\\dark\\something.dotty.someext")
  #define FILE_PREFIX               ("d:\\tmp\\someplace\\dark")
  #define DIRECTORY_FULLPATH_SAMPLE ("d:\\tmp\\someplace\\dark")
  #define DIRECTORY_PREFIX          ("d:\\tmp\\someplace")
#else
  #define FULLPATH_SAMPLE           ("/tmp/someplace/dark/something.dotty.someext")
  #define FILE_PREFIX               ("/tmp/someplace/dark")
  #define DIRECTORY_FULLPATH_SAMPLE ("/tmp/someplace/dark")
  #define DIRECTORY_PREFIX          ("/tmp/someplace")
  
#endif

#define FILE_BASE      ("something.dotty")
#define FILE_EXTENSION ("someext")
#define DIRECTORY_BASE ("dark")

typedef ssize_t (*encode_func_ptr) ( char *out,   const size_t max_out, const uint8_t *in, const size_t in_size );
typedef ssize_t (*decode_func_ptr) ( uint8_t* out, const size_t max_out, const char *in );

void do_encoding_test
(
  const char * enc_name, 
  encode_func_ptr do_encode, 
  decode_func_ptr do_decode, 
  const char * raw_ref, 
  const size_t raw_size, 
  const char* encoded_ref   
)
{
    char    buffer_enc[256];
    uint8_t buffer_dec[256];

    memset(buffer_enc, 0, sizeof(buffer_enc));
    memset(buffer_dec, 0, sizeof(buffer_enc));

    size_t encoded_ref_len = strlen(encoded_ref);
    
    DDEBUG_PRN("%s:%s", enc_name, raw_ref);

    ssize_t encoding_result = do_encode( buffer_enc, sizeof(buffer_enc), (uint8_t*)raw_ref, raw_size );
    
    DDEBUG_PRN("%s ref    (%02u):[%s]", enc_name, encoded_ref_len, encoded_ref);
    DDEBUG_PRN("%s encoded(%02d):[%s]", enc_name, encoding_result, buffer_enc);  
    CU_ASSERT_FATAL( encoding_result >= 0 );

    int encoded_invalid = memcmp( buffer_enc, encoded_ref, encoded_ref_len );
    DDEBUG_PRN("memcmp(%u) = %d", encoded_ref_len, encoded_invalid );
    CU_ASSERT_FATAL( encoded_invalid==0  ) ;    


    ssize_t decoding_result = do_decode( buffer_dec, sizeof(buffer_dec), buffer_enc );
    DDEBUG_PRN("%s decoded(%d):[%s]", enc_name, decoding_result, buffer_dec);
    CU_ASSERT_FATAL( decoding_result >=0 );

    

    int decoded_invalid = memcmp( buffer_dec, raw_ref, raw_size);
    DDEBUG_PRN("memcmp(%u) = %d", raw_size, decoded_invalid );
    CU_ASSERT_FATAL( decoded_invalid==0 );
}//en gen_encoding_test


void HexEncode_Test()
{
  do_encoding_test( "Hex/ASCII",  hex_encode, hex_decode, ASCII_SAMPLE, strlen(ASCII_SAMPLE), ASCII_HEX_ENCODED_SAMPLE );
  do_encoding_test( "Hex/Binary", hex_encode, hex_decode, BIN_SAMPLE,   BIN_SAMPLE_LEN,       BIN_HEX_ENCODED_SAMPLE );     

}//eo HexEncode_Test

void Base64Encode_Test()
{
  do_encoding_test( "Base64/ASCII",       base64_encode, base64_decode, ASCII_SAMPLE, strlen(ASCII_SAMPLE), ASCII_B64_ENCODED_SAMPLE );
  do_encoding_test( "Base64/Binary even", base64_encode, base64_decode, BIN_SAMPLE,   BIN_SAMPLE_LEN,       BIN_B64_ENCODED_SAMPLE );     
}//eo Base64Encode_Test

void do_filename_manip_test()
{
    char prefix[MAX_FILE_PATH];
    char bname [MAX_FILE_PATH];
    char ext[32];    

    ssize_t rpfx = filename_prefix( FULLPATH_SAMPLE, prefix, sizeof(prefix) );
    DDEBUG_PRN("prefix(%s)=[%s]",FULLPATH_SAMPLE, prefix);
    CU_ASSERT_FATAL( rpfx >= 0 );
    CU_ASSERT_FATAL( 0 == strcmp( prefix, FILE_PREFIX ) );

    ssize_t rbas = filename_base( FULLPATH_SAMPLE, bname, sizeof(bname) );
    DDEBUG_PRN("basename(%s)=[%s]",FULLPATH_SAMPLE, bname);
    CU_ASSERT_FATAL( rbas >= 0 );
    CU_ASSERT_FATAL( 0 == strcmp( bname, FILE_BASE ) );

    ssize_t rext = filename_extension( FULLPATH_SAMPLE, ext, sizeof(ext) );
    DDEBUG_PRN("extension(%s)=[%s]",FULLPATH_SAMPLE, ext);
    CU_ASSERT_FATAL( 0 == strcmp( ext, FILE_EXTENSION ) );
    CU_ASSERT_FATAL( rext >= 0 );
}

void FilenameManip_Test()
{
  do_filename_manip_test( FULLPATH_SAMPLE, FILE_PREFIX, FILE_BASE, FILE_EXTENSION );
  do_filename_manip_test( FULLPATH_SAMPLE, DIRECTORY_PREFIX, DIRECTORY_BASE,  "" );
    
}//eo FilenameManip_Test

//
//
int main (int argc, char** argv) 
{
 
  CU_pSuite pSuite = NULL;
 
  /* initialize the CUnit test registry */ 
  if (CUE_SUCCESS != CU_initialize_registry())
    return CU_get_error();
 
  /* add a suite to the registry */ 
  pSuite = CU_add_suite("Suite_1", NULL, NULL);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  if (NULL == CU_add_test(pSuite, "Hex encoding test", HexEncode_Test )) {
    CU_cleanup_registry();
    return CU_get_error();
  }
 
  if (NULL == CU_add_test(pSuite, "Base64 encoding test", Base64Encode_Test )) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  if (NULL == CU_add_test(pSuite, "Filename manipulation test", FilenameManip_Test )) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Run all tests using the CUnit Basic interface */ 
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  CU_cleanup_registry();
  return CU_get_error();

}//eo main



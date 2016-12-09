#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <CUnit/Basic.h> 
#include "shamir.h"
#include "utils.h"

#define TEST_SECRET1 (const uint8_t*)("somethingcontinuousandillisiblewhilesecret")
#define TEST_SECRET2 (const uint8_t*)("SomeThingContinuousAndIllisibleWhileSecret")
#define TEST_SECRET3 (const uint8_t*)("\xDE\xAD\xBE\xEF \xDE\xCA\xFB\xAD")
#define TEST_SECRET4 (const uint8_t*)("This is a real secret")
#define TEST_SECRET5 (const uint8_t*)("\x47\x4b\xa5\x7a\x12\xb1\x8e\xea\xa7\x7b\xc1\xe8\x24\xe7\xd5\x3a\xa6\xfa\xf9\x59\xe1\x20\xbc\x32\x73\xe8\x80\xc6\xb8\xb5\x21\xdb\x43\x2e\x3a\xe8\x48\xec\xec\x62")
#define TEST_SECRET5_LEN 40

#define MAX (1024)



void test_shamir_split( const uint8_t* test_secret, size_t sec_len, int chorum, int nb_shares ) 
{
    
    uint8_t   secret[256];
    s_share_t shares[128];
    
    ////////////////////// Splitting
    printf("\nShamir split(%d/%d)", chorum, nb_shares );
    int split_res = do_shamir_split( 
      chorum, nb_shares, 
      test_secret, sec_len, 
      shares 
    );
    printf("=> res:%d\n", split_res );
    CU_ASSERT_FATAL( split_res == 0 );
		printf("Split Ok \n");

    ////////////////////// Recovering
    memset( secret, 0, sizeof(secret) );
    printf("\nShamir recovery (%d/%d)", chorum, nb_shares );
    int recover_res = do_shamir_recovery( chorum, shares, secret, sizeof(secret) );
    printf("=> res:%d\n", recover_res );
    CU_ASSERT_FATAL( recover_res == 0 );

    printf("\nrecovered\n\tC:%s\n\tS:%s\n", test_secret, secret);

    CU_ASSERT_FATAL( memcmp( secret, test_secret, sec_len) == 0 );

}//eo test shamir split

// Basic test for Shamir Sharing
#define BYTESLEN(ustr) strlen((const char*)(ustr))

void ShamirShare_Basic_Test(void) 
{
    test_shamir_split( TEST_SECRET1, BYTESLEN(TEST_SECRET1), 3, 4);
    test_shamir_split( TEST_SECRET2, BYTESLEN(TEST_SECRET2), 3, 4);
  //  test_shamir_split( TEST_SECRET3, 3, 4);
    test_shamir_split( TEST_SECRET4, BYTESLEN(TEST_SECRET4), 3, 4);
    test_shamir_split( TEST_SECRET5, TEST_SECRET5_LEN,       3, 4);

}// eo basic test 


// Multiple iteration for Shamir Sharing for 3 among 5
void ShamirShare_Many3Among5_Test(void) 
{
    for ( unsigned i = 0; i < 10; i++ ) {
        test_shamir_split(TEST_SECRET2, BYTESLEN(TEST_SECRET2), 3, 5);
    }
}// eo ShamirShare_Many3Among5_Test


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
 
   /* add the tests to the suite */ 
   if (NULL == CU_add_test(pSuite, "Basic Test for Shamir Secret Sharing (3 among 4)", ShamirShare_Basic_Test)) {
      CU_cleanup_registry();
      return CU_get_error();
   }
 
   if (NULL == CU_add_test(pSuite, "Test multiple iterations for Shamir secret Sharing (3 among 5)", ShamirShare_Many3Among5_Test)) {
      CU_cleanup_registry();
      return CU_get_error();
   }
 
   /* Run all tests using the CUnit Basic interface */ 
   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();
   CU_cleanup_registry();
   return CU_get_error();
}



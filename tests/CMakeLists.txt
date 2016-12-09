

# Test Shamir Secret Sharing low level functions
add_executable(test_shamir ../src/shamir.c ../src/utils.c ../src/bsd-strlcpy.c ../src/sha3.c ../src/base64.c ../tests/test_shamir.c)
target_link_libraries(test_shamir ${LIBS})
target_include_directories(test_shamir PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../src>)
set_target_properties (test_shamir PROPERTIES LINK_FLAGS -Wl,-lcunit)
add_test (test_shamir ${EXECUTABLE_OUTPUT_PATH}/test_shamir)

# Test support functions 
add_executable(test_utils ../src/utils.c ../src/bsd-strlcpy.c  ../src/base64.c ../src/sha3.c ../tests/test_utils.c)
target_link_libraries(test_utils ${LIBS})
target_include_directories(test_utils PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../src>)
set_target_properties (test_utils PROPERTIES LINK_FLAGS -Wl,-lcunit)
add_test (test_utils ${EXECUTABLE_OUTPUT_PATH}/test_utils)


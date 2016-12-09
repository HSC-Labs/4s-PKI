
cmake_minimum_required (VERSION 3.0)

project (4s)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
#set(RUNTIME_OUTPUT_DIRECTORY  ${PROJECT_SOURCE_DIR}/bin)


enable_testing()


#SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
#SET(BUILD_SHARED_LIBRARIES OFF)
#SET(CMAKE_EXE_LINKER_FLAGS "-static")

# Make sure that CMAKE_BUILD_TYPE is either Debug or Release:
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release
        CACHE STRING "Build type (Debug, Release)" FORCE)
endif ()
if (NOT (CMAKE_BUILD_TYPE STREQUAL "Debug" OR
        CMAKE_BUILD_TYPE STREQUAL "Release"))
    message("${CMAKE_BUILD_TYPE}")
    message(FATAL_ERROR "CMAKE_BUILD_TYPE must be one of: Debug, Release (current value: '${CMAKE_BUILD_TYPE}')")
endif ()


# Flags for GCC or CLang
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_C_FLAGS_DEBUG
        "${CMAKE_C_FLAGS_DEBUG} -Wno-unused-parameter -Wall -pedantic -Wextra -ggdb -lm")
    set(CMAKE_C_FLAGS_RELEASE
        "${CMAKE_C_FLAGS_RELEASE} -Wno-unused-parameter -Wall -std=gnu99 -lm")
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_C_FLAGS_DEBUG
        "${CMAKE_CXX_FLAGS_DEBUG} -Wno-unused-parameter -ggdb")
    set(CMAKE_C_FLAGS_RELEASE
        "${CMAKE_C_FLAGS_RELEASE} -Wno-unused-parameter -std=gnu99")
endif()



# Finding LibUI library
set(LIBUI_DIR "/opt/devel")
find_package(LIBUI REQUIRED)
include_directories(${LIBUI_INCLUDE_DIRS})
set(LIBS ${LIBS} ${LIBUI_LIBRARIES})

# Finding iniparser library
set(LIBINIPARSER_DIR "/opt/devel")
find_package(LIBINIPARSER REQUIRED)
include_directories(${LIBINIPARSER_INCLUDE_DIRS})
set(LIBS ${LIBS} ${LIBINIPARSER_LIBRARIES})

# Finding GMP library
find_package(GMP REQUIRED)
include_directories(${GMP_INCLUDE_DIRS})
set(LIBS ${LIBS} ${GMP_LIBRARIES})

# Finding OpenSSL libraries
find_package(OPENSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})

# Adding source directory
add_subdirectory(src)

# Adding tests directory
add_subdirectory(tests)


############################# Final message
message("\n")
message("Configuration results")
message("---------------------")
message("C compiler: ${CMAKE_C_COMPILER}")
message("Build type: ${CMAKE_BUILD_TYPE}")
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message("C compiler flags: ${CMAKE_C_FLAGS_DEBUG}")
else ()
    message("C compiler flags: ${CMAKE_C_FLAGS_RELEASE}")
endif ()
message("Installation prefix: ${CMAKE_INSTALL_PREFIX}")
message("GMP_INCLUDE_DIRS: ${GMP_INCLUDE_DIRS}")
message("GMP_LIBRARIES: ${GMP_LIBRARIES}")
message("OpenSSL_INCLUDE_DIRS: ${OPENSSL_INCLUDE_DIR}")
message("OpenSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")
message("\n")
message("Libraries: ${LIBS}")
message("Binary path: ${PROJECT_BINARY_PATH}")
message("Executables path: ${EXECUTABLE_OUTPUT_PATH}")
message("------------------\n")




# S4 minimal PKI with a Shamir shared root private key

## Summary

### What is S4 ?

This tool si built to operate a very simple self signed PKI based on OpenSSL functions.

The configuration is provided to sign Sub-CA certificates appropriate 
for Microsoft Certificate Services or others PKI products.

This tool specificity is to use a Shamir Secret Sharing to protect the PKI Root key.

### Why S4 ?

We could no find a tool allowing to simply operate a rootca secured by secret sharing.

Particularly most Shamir Secret Sharing implementations were mostly demonstrators or 
university projects with little practical orientation. 

Our goals are to provide a tool:
 * Usable by non technical users
 * Open and auditable
 * Minimal
 * Portable, at least on Linux+X11 and Ms Windows (OSX should also work but won't be tested)
 * With a graphical interface
 * Independant of an eventual complex secret storage (encrypted USB keys, or otherwise)

The end product should allow a root CA to generate its self signed certificates, to sign sub-CA CSR, revocate sub-CA and emit CRL.

### How to generate rich text versions of this document

This document is encoded in Markdown.

A PDF version can be generated with the `pandoc` tool as follow:

        pandoc README.md -f markdown -o README.pdf

### Other documentations

* See LICENCE.md file for the legal condition of use, distribution, modification of the present program.
* Doxygen can be used to generate project internal documentation  in the `doc` directory using the command: 

        doxygen doxy.conf


## Specifications

### User interface
* Allows to select between *Creation mode* and *Recovery mode*
* *Creation mode* allows to enter
    * Number of participants
    * Minimum Qorum required to authorize operations
    * Filename/Path for each secret
* *Recovery mode* allows to enter
    * Number of secret holder present
    * Filename/Path for each secret
    * in CLI: result is sent to STDOUT
    * in GUI: result is copied to clipboard and optionnaly can be displayed in a text field
* PKI functions:
    * Sign a CSR
    * Revoke a Certificate
    * Emit a CRL

### Main functions

#### Root Key generation
* Inputs
    * destination filename
    * key size
    * encryption passphrase
* Outputs
    * RSA private key as a DER encoded PKCS7, encrypted with AES256 
* Sequence
    1. Generate a safe passphrase with OpenSSL functions
    2. Generate a RSA key using OpenSSL functions
    3. create a Shamir share of the passphrase

#### Shamir Share generation
* Inputs:
    * passphrase to protect
    * number of secrets holders
    * minimum qorum size
* Outputs:
    * array of the secrets
* Sequence
    1. Create a Share of the passphrase for M parties with a N quorum
    3. Erase securely temporary files and buffers containing sensitive informations (particularly passphrase)

#### Key recovery 
* Inputs:
    * array of secrets
    * number of participants
* Output:
    * Rebuilt secret
* Sequence:
    1. Verify the input (number of secrets and their format)
    2. Rebuild passphrase
    3. Verify passphrase format
    4. Purge copies of secrets from memory

## Build instructions

### Generate Makefile 

1. Go to distribution root directory
2. Create a build directory and enter it
        
        mkdir build
        cd build

3. Run cmake

        cmake ..

for "release" mode, or 

       cmake -DCMAKE_BUILD_TYPE=Debug ..

for "debug" mode.

This should generate the apropriate build file for your environment.

### Build Binaries

To build the binaries from the build directory with a Makefile based 
environement (after Makefile generation) simply type:

        make

The binaries will be generated in the `bin` subfolder

### Run the tests

To run the program tests from the build directorywith a Makefile based 
environement (after makefile generation) simply type:

        make
        make test


## Using 4s

4s can be used in two modes:

* `4s-cli` provides a command line interface for 4s operations
* `4s-gui` provides a GUI for more simplicity


### Using 4s command line

#### Syntax

    4s-cli <mode> <mode parameters>

##### Modes

    --help     show the command line use
    --init     initialise a new PKI
    --sign     sign a subca CSR
    --revoke   revoke a subca   

##### Common parameters

* [required] path to the PKI root directory
    
        --rootdir <path>  

* [required] path to a secret. must be specified for each shamir secret

        --secret <path>   

##### Init mode parameters

* [required] minimum number of secrets holders required to authorize operations

        --quorum  <n>         

* [required] number of secrets holders
 
        --nbshares <m>    

* [optional] specifies wether the user should be prompted between secret exports (default:no)

        --paused <yes|no> 


##### Sign mode parameters

* [required] path to the CSR to sign
 
        --csr  <path>    

* [required] path where to save the sub-CA certificate

        --cert <path>    

##### Revoke mode parameters

* [required] path to certificate file to revoke

        --cert <certificate> 

* [required] path where to write CRL

        --crl <path>         

##### Return values

* 0 on success
* non 0 on error

#### Examples

* Creating a new PKI with 5 secrets holders

        4s-cli --init --rootdir /home/pki --subject \"/CN=mypki/OU=it/O=company/C=FR\" --quorum 3 --nbshares 5


* Revocation of a certificate

        4s-cli --revoke --rootdir /home/pki --secret secret1.smr --secret secret2.smr --secret secret3.smr --cert subcacert.pem --crl rootca.crl

* Signature of a sub-ca certificate

        4s-cli --sign --rootdir /home/pki --secret secret1.smr --secret secret3.smr --secret secret5.smr --csr subcacsr.pem


### Using 4s graphical user interface

/TODO/

---
Initial source for Shamir Secret Sharing <https://github.com/mohamed/ShamirSecretSharing>



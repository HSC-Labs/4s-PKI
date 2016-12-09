// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 *
 * \file pki.c
 *
 * \brief Key and certificate management functions
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

//#define DEEPDEBUG 1

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <openssl/rand.h>
#include <errno.h>
#include <gmp.h>

#include "iniparser.h"
#include "utils.h"
#include "pki.h"
#include "openssl_conf.h"
#include "shared_secret.h"

#define ROOT_CERT_FNAME ("root.crt")
#define INI_FILENAME    ("pki.ini")
#define MAX_COMMAND_LINE_SIZE (1024)

#define INI_VAR_SUBJECT     ("pki:subject")
#define INI_VAR_NB_SHARE    ("pki:nb_share")
#define INI_VAR_QUORUM      ("pki:quorum")
#define INI_VAR_NB_EMITTED  ("pki:nb_emitted")
#define INI_VAR_NB_REVOQUED ("pki:nb_revoqued")

#define DEFAULT_HASH_ALGORITHM ("sha256")
#define DEFAULT_CERT_KEY_SIZE  (2048)
#define DEFAULT_CERT_LIFE_LEN  (3650)
#define DEFAULT_CRL_LIFE_LEN   (365)

#define STEP(p,m) if( evt_handlers->on_progress ) { evt_handlers->on_progress( evt_handlers->data, (p), (m) ); }
#define WARN(...) if( evt_handlers->on_warning)   { evt_handlers->on_warning( evt_handlers->data, __VA_ARGS__ ); }



int write_ca_infos( 
	const char * dirname, 
	const char * subject,
	const unsigned nb_holders, 
	const unsigned quorum,  
	const unsigned nb_emitted, 
	const unsigned nb_revoqued 
){

	assert(NULL!=dirname);
	assert(NULL!=subject);	
	assert(nb_holders>2);
	assert(quorum<nb_holders);


	char filename[MAX_FILE_PATH+1];
	snprintf(filename, MAX_FILE_PATH, "%s/%s", dirname, INI_FILENAME );

	const char *ini_fmt = 
		"[pki]\n"          \
		"subject=%s\n"     \
		"nb_emitted=%u\n"  \
		"nb_revoqued=%u\n" \
		"quorum=%u\n"      \
		"nb_share=%u\n";

	FILE * fh_ini = fopen(filename,"w");
	if( NULL  == fh_ini ) {
		DEBUG_PRN("write_ca_infos: error while opening '%s'", filename );
		return -1;
	}
	int res = fprintf( fh_ini, ini_fmt, subject, nb_emitted, nb_revoqued, quorum, nb_holders);
	if( res < 0 ) {
		DEBUG_PRN("write_ca_infos: error while writing to '%s'", filename);
		return -1;
	}

	if( fclose(fh_ini) ) {
		DEBUG_PRN("write_ca_infos: error while closing file '%s'", filename);
		return -1;
	}

	return 0;

}//eo write_ca_infos


int read_ca_infos(
    const char *dirname, 
    char *subject, size_t subject_max, 
	unsigned *pnb_holders, unsigned *pquorum,  
	unsigned *pnb_emitted, unsigned *pnb_revoqued  
) {
	assert(NULL!=dirname);
	assert(NULL!=subject);
	assert(subject_max>1);
	assert(NULL!=pnb_holders);
	assert(NULL!=pquorum);
	assert(NULL!=pnb_revoqued);
	assert(NULL!=pnb_emitted);

	DDEBUG_PRN(
		"read_ca_infos: (dir:'%s',subj:%p, subj_sze:%u, pnb_share:%p, pquorum:%p, pnb_certs:%p, pnb_revoqued;%p)",
						dirname,  subject, subject_max, pnb_holders,  pquorum, pnb_emitted, pnb_revoqued
	);

	char filename[MAX_FILE_PATH+1];
	snprintf(filename, MAX_FILE_PATH, "%s/%s", dirname, INI_FILENAME );

	dictionary * ini = iniparser_load(filename);
	if( NULL  == ini ) {
		DEBUG_PRN("read_ca_infos: failed to load/parse '%s'", filename);
		return 1;
	}

	iniparser_dump(ini, stdout );


	const char * subj = iniparser_getstring(ini, INI_VAR_SUBJECT, NULL);
	DDEBUG_PRN("read_ca_infos: [%s]=%s", INI_VAR_SUBJECT, subj );
	if( NULL == subj ) {
		DEBUG_PRN("read_ca_infos: [%s] configuration variable not found in '%s'", INI_VAR_SUBJECT, filename);
		return 1;
	}	
	size_t rs = strlcpy( subject, subj, subject_max);
	if( rs > subject_max ) {
		DEBUG_PRN("read_ca_infos: subject is too long and getting trucated");
	}
	
	int nb_holders = iniparser_getint(ini, INI_VAR_NB_SHARE, -1 );
	DDEBUG_PRN("read_ca_infos: [%s]=%d", INI_VAR_NB_SHARE, nb_holders );
	if( -1 == nb_holders ){
		DEBUG_PRN("read_ca_infos: [%s] configuration variable not found in '%s'", INI_VAR_NB_SHARE, filename);
		return 1;
	}
	*pnb_holders = nb_holders;
	
	int quorum = iniparser_getint(ini, INI_VAR_QUORUM, -1 );
	DDEBUG_PRN("read_ca_infos: [%s]=%d", INI_VAR_QUORUM, quorum );
	if( -1 == quorum ) {
		DEBUG_PRN("read_ca_infos: [%s] configuration variable not found in '%s'", INI_VAR_QUORUM, filename);
		return 1;
	}
	*pquorum = quorum;
	
	int nb_emitted = iniparser_getint( ini, INI_VAR_NB_EMITTED, -1 );
	DDEBUG_PRN("read_ca_infos: [%s]=%d", INI_VAR_NB_EMITTED, nb_emitted );
	if( -1 == nb_emitted ) {
		DEBUG_PRN("read_ca_infos: [%s] configuration variable not found in '%s'", INI_VAR_NB_EMITTED, filename);
		return 1;
	}
	*pnb_emitted = nb_emitted;

	int nb_revoqued = iniparser_getint( ini, INI_VAR_NB_REVOQUED, -1 );
	DDEBUG_PRN("read_ca_infos: [%s]=%d", INI_VAR_NB_REVOQUED, nb_revoqued );
	if( -1 == nb_revoqued ){ 
		DEBUG_PRN("read_ca_infos: [%s] configuration variable not found in '%s'", INI_VAR_NB_REVOQUED, filename);
		return 1;
	}
	*pnb_revoqued = nb_revoqued;

	iniparser_freedict(ini);

	return 0;
}//eo pki_gen_conf


////
ssize_t gen_pass(char *out, const size_t max_size )
{
	DDEBUG_PRN("gen_pass(out=%p,size=%d) pass_size:%d", out, max_size, PASS_SIZE);

	size_t strength = PASS_SIZE;
	uint8_t pass_bytes[PASS_SIZE+1]; 
	
	int res = RAND_bytes( pass_bytes, strength);
	if( 1 != res ) {
    	warn("Random password generation failed (code:%d)", res);
    	return -1;
	}

	//encode in base64 to the out
	ssize_t result_size =  base64_encode( out, max_size, pass_bytes, strength );
	if( result_size <0 ) {
		DEBUG_PRN("gen_pass: base64 encoding of password failed");
		return -1;
	}

	DEBUG_PRN("gen_pass(%d) => %s", result_size, out );	
	return result_size;
}//eo genpass



static int generate_openssl_config(
	const char    *dir, 
	const char    *crl_distribution_point, 
	const unsigned ca_life_len,
	const unsigned crl_life_len
)
{
	char conf_filename[MAX_FILE_PATH+1];
	secure_memzero(conf_filename,MAX_FILE_PATH+1);
	const char    *hash_algorithm         = DEFAULT_HASH_ALGORITHM;
	const unsigned default_cert_ksize     = DEFAULT_CERT_KEY_SIZE; 

	sprintf( conf_filename, "%s/openssl.conf", dir);
	FILE * fp_out = fopen(conf_filename,"w");	
	if( NULL==fp_out  ) {
		warn("Error encountered opening %s", conf_filename );
		return -1;
	}
	fprintf( fp_out, "# OpenSSL CA configuration\n");
	fprintf( fp_out, "dir=%s\n",              dir );
	fprintf( fp_out, "cdp=%s\n",              crl_distribution_point );
	fprintf( fp_out, "hashalg=%s\n",          hash_algorithm );
	fprintf( fp_out, "defaultcertksize=%u\n", default_cert_ksize );
	fprintf( fp_out, "crllifelen=%u\n",       crl_life_len );
	fprintf( fp_out, "califelen=%u\n",        ca_life_len  );
	fprintf( fp_out, "\n" );
	fprintf( fp_out,"%s", OPENSSL_DEFAULT_CONF );
	fclose( fp_out );
	// TODO check return values

	return 0;
}//eo generate_openssl_config

////
int gen_self_signed( const char *dir, const s_pki_parameters_t *params, const char *password, const unsigned nb_share, const unsigned quorum, struct SS4EventHandlers* evt_handlers )
{
	DDEBUG_PRN("gen_self_signed(dir=\"%s\", params=\"%p\", password=\"%s\", nb_share=%u, quorum=%u, evt_h=%p", dir, params, password, nb_share, quorum, evt_handlers );

	char cmd[MAX_COMMAND_LINE_SIZE];

    STEP( 1, "initializing PKI creation");
	
    STEP( 10, "Building PKI directory tree");
	int dir_create_res = 0;
	dir_create_res &= call_command("mkdir %s/cacert   2>/dev/null", dir);
	dir_create_res &= call_command("mkdir %s/private  2>/dev/null", dir);
	dir_create_res &= call_command("mkdir %s/certs    2>/dev/null", dir);
	dir_create_res &= call_command("mkdir %s/p7       2>/dev/null", dir);
	dir_create_res &= call_command("mkdir %s/crl      2>/dev/null", dir);
	if( dir_create_res ) {
		warn("Error encountered on PKI directories creation.");
		return -1;
	}
 
	/** prepare PKI directory 
	 - serial
	 - cert.idx
	 - cacert/  --> root certificate
	 - certs/   --> certificate output
	 - p7/      --> PKCS#7 certification chain
	 - private/ --> private key
	 - crl/     --> crl output
	***/
    STEP(20, "Initializing certificate counter");
	secure_memzero(cmd,MAX_COMMAND_LINE_SIZE);
	sprintf(cmd,"%s/serial",dir);
	FILE * fp_out = fopen(cmd,"w");
	if( fp_out == NULL ) {
		WARN("Error encountered opening %s", cmd);
		return -1;
	}
	fwrite("01",sizeof(char),3,fp_out);
	fclose(fp_out);

    STEP(30, "Initializing certificate index");
	secure_memzero(cmd,MAX_COMMAND_LINE_SIZE);
	sprintf(cmd,"%s/cert.idx",dir);
	fp_out = fopen(cmd,"w");
	if( fp_out == NULL ) {
		WARN("Error encountered opening %s", cmd);
		return -1;
	}
	fclose(fp_out);

    STEP(40, "Initializing certificate serial numbers registry");
	secure_memzero(cmd,MAX_COMMAND_LINE_SIZE);
	sprintf(cmd,"%s/crl/crl_serial",dir);
	fp_out = fopen(cmd,"w");
	if( fp_out == NULL ) {
		WARN("Error encountered opening %s", cmd);
		return -1;
	}
	fwrite("01",sizeof(char),3,fp_out);
	fclose(fp_out);

    STEP(50, "Generating OpenSSL configuration");
    if( generate_openssl_config(dir,
     	params->cdp_url, 
     	params->ca_life_len, 
     	params->crl_life_len
    ) ) {
    	WARN("failed to creation openssl configuration");
    	return -1;
    }

	/** genkey
		openssl genrsa -aes256 -out $dir/root.key -passout pass:$pass  4096
	***/
    STEP(60, "Creating root private key");
	int err = call_openssl("genrsa -aes256 -out %s/private/root.key -passout pass:%s 4096 ", dir, password);
	if( err ) {
		WARN("Failed to generate RSA keypair");
		return -1;
	}
	
	/** gen x509
	 openssl req -new -x509 -key $dir/root.key -out $dir/root.crt -subj "$subj" -passin pass:$pass
	***/
    STEP(80, "Creating root certificate");
	err = call_openssl("req -new -x509 -extensions v3_ca_root -days 7300 -key %s/private/root.key -out %s/cacert/%s  -subj \"%s\" -config %s/openssl.conf -passin pass:%s", 
		dir, dir, ROOT_CERT_FNAME, params->subject, dir, password);
	if( err ) {
		WARN("Failed to generate Root certificate");
		return -1;
	}

	/** gen CRL
	openssl ca -gencrl -crlexts crl_ext -config ./openssl.conf -crldays 7300 -cert CAcerts/rootCA.pem -keyfile private/rootCA.key -out crl/root.crl
	****/
    STEP(90, "Creating initial CRL");
	err = call_openssl(
		"ca -gencrl -crlexts crl_ext -crldays 7300 -config"
		" %s/openssl.conf -cert %s/cacert/%s              -keyfile %s/private/root.key -out %s/crl/root.crl -passin pass:%s", 
		  dir, dir, ROOT_CERT_FNAME, dir, dir, password );
	if( err ) {
		WARN("Failed to generate Root CRL");
		return -1;
	}

	/** generating PKI configuration file
	****/
	STEP(95,"Writing configuration");
	err = write_ca_infos( dir, params->subject, nb_share, quorum, 0, 0 );
	if( -1 == err ) {		
		WARN("Failed to write configuration file to %s", dir);
		return -1;
	}


    STEP(100, "PKI created");

	return 0;
}//eo gen self signed


//////
int sign_subca(const char *dir, const char *csr_filename, const char * cert_copy, const char *password, struct SS4EventHandlers* evt_handlers )
{
	DDEBUG_PRN("sign_subca(dir=\"%s\", csr=\"%s\", pwd=\"%s\", evt_h=%p", dir, csr_filename, password, evt_handlers );	

	char cert_fpath[MAX_FILE_PATH];
	char dir_output[MAX_FILE_PATH];	
	char base_fname[MAX_FILE_PATH/2];

	secure_memzero( cert_fpath,  sizeof(cert_fpath) );
	secure_memzero( dir_output,  sizeof(dir_output) );
	secure_memzero( base_fname,  sizeof(base_fname) );

	STEP( 10, "Certificate name initialisation");
	if( filename_prefix( csr_filename, dir_output, sizeof(dir_output) ) <0 ) {
		WARN("Failed to extract prefix from CSR filename: %s", csr_filename );
		return -1;
	}

	if( filename_base( csr_filename, base_fname, sizeof(base_fname) ) <0 ) {
		WARN("Failed to extract name from CSR filename: %s", csr_filename );
		return -1;
	}
	snprintf( cert_fpath, sizeof(cert_fpath), "%s/certs/%s.%s", dir,        base_fname, "crt"); //TODO check results	

	STEP( 40, "Signing the CSR");
	int err = call_openssl(
		"ca -config %s/openssl.conf -batch -extensions v3_subca1 -in %s -out %s          -cert %s/cacert/root.crt -keyfile %s/private/root.key -passin pass:%s",
		            dir,                             csr_filename,   cert_fpath,       dir,                       dir,                      password
	);
	if( err ) {
		WARN("Failed to sign the Sub CA csr.");
		return -1;
	}

	if( NULL!=cert_copy && *cert_copy!='\0' ) {
		STEP( 70, "Copying the certificate");
		if( file_copy( cert_fpath, cert_copy ) <0 ) {
			WARN("Failed to copy the resulting certificate from '%s' to '%s'", cert_fpath, cert_copy );
			return -1;
		}
	}

	STEP( 80, "Creation of the PKCS7 chain CA");
	/** Create the PKCS7 Chain CA ***/
	err = call_openssl("crl2pkcs7 -nocrl -certfile %s/cacert/root.crt -out %s/p7/CAs.p7b -certfile %s", dir, dir, cert_fpath);
	if( err ) {
		WARN("Failed to create the pkcs7 of CAs.");
		return -1;
	}

	STEP(100, "sub-CA signature done.")

	return 0;
}//eo sign_subCA


//////////////////
int revoke_subca(const char *dir, const char *cert_filename, const char *password, struct SS4EventHandlers* evt_handlers )
{	
	DDEBUG_PRN("revoke_subca(dir=\"%s\", cert=\"%s\", pwd=\"%s\", evt_h=%p)",dir, cert_filename, password, evt_handlers);

	STEP( 10, "revocating sub-CA");
	int err = call_openssl(
		"ca -config %s/openssl.conf -revoke %s -out %s/crl/crl.idx	-cert %s/cacert/root.crt -keyfile %s/private/root.key -passin pass:%s",
		dir,cert_filename,dir,dir,dir,password
	);
	if( err ) {
		WARN("Failed to revoke the certificate %s",cert_filename);
		return -1;
	}
	return 0;
}

int generate_crl(const char *dir, const char *crl_filename, const char *password, struct SS4EventHandlers* evt_handlers )
{
	DDEBUG_PRN("generate_crl(dir=\"%s\", crl=\"%s\", pwd=\"%s\", evt_h=%p)", dir, crl_filename, password, evt_handlers);

	STEP( 50, "generating the new CRL");
	int err = call_openssl(
		"ca -gencrl -crlexts crl_ext -crldays 7300 -config %s/openssl.conf -cert %s/cacert/root.crt -keyfile %s/private/root.key -out %s -passin pass:%s", 
		dir, dir, dir, crl_filename, password
	);
	if( err ) {
		WARN("Failed to generate CRL");
		return -1;
	}	
	STEP(100, "sub-CA revocation done.")

	return 0;
}//eo revokeSubCA


ssize_t read_ca_cert_infos( const char *dir,  char *buffer, const size_t max_size )
{
	char infofilepath[MAX_FILE_PATH+1];
	char certfilepath[MAX_FILE_PATH+1];

	snprintf( infofilepath, sizeof(infofilepath), "%s/cacert/root.txt", dir );
	snprintf( certfilepath, sizeof(certfilepath), "%s/cacert/%s", dir, ROOT_CERT_FNAME );

	int err = call_openssl(
		"x509 -in %s -noout -text > %s",
		certfilepath, infofilepath
	);
	if( err ) {
		DEBUG_PRN("read_ca_cert_infos: failed to dump certificate description for %s ", certfilepath );
		return -1;
	}	

	ssize_t res = file_slurp(infofilepath, (uint8_t*)buffer,max_size);
	if( res < 0 ) {
		DEBUG_PRN("read_ca_cert_infos: failed to read info file: '%s'", infofilepath );
		return -1;
	}
	buffer[res]='\0';

	return res;
}//eo read ca cert infos



#undef WARN
#undef STEP


/**
 *
 * \file gui_strings.h
 *
 * \brief User interface management declarations
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#if !defined( _S4_GUI_STRINGS_H_ )
#define _S4_GUI_STRINGS_H_

#define DEFAULT_ROOT_SUBJECT         ("/CN=XXX/OU=sub_org/O=org")
#define DEFAULT_ROOT_CDP             ("http://revocation.pki.orgationsation.org/crl/org-pki.crl")
#define DEFAULT_CERT_CONTENT         ("\n\n< PKI root certificate >\n\n") 
#define DEFAULT_NUM                  ("0")
#define DEFAULT_TIMESTAMP            ("01/01/2016 00:00")
#define DEFAULT_PKI_DIR              ("/where to find the PKI")
#define DEFAULT_INPUT_FILE           ("/where to find the file")
#define DEFAULT_SHARE_STATUS         ("Select the Shamir share")
#define DEFAULT_SHARE_LOADED         ("sha3: %s")

#define LABEL_SELECT_ROOT_DIR        ("Select PKI Root directory")
#define LABEL_ROOT_SUBJECT           ("Root certificate subject :")
#define LABEL_ROOT_CDP               ("CRL distribution point :")
#define LABEL_CERT_LIFE_DAYS         ("Certificate life length (in days) :")
#define LABEL_CRL_LIFE_DAYS          ("CRL life length (in days) :")
#define LABEL_ROOT_KEYSIZE           ("RSA root key size (bits):")
#define LABEL_SHARE_COUNT            ("Number of share holders:")
#define LABEL_QUORUM_SIZE            ("quorum size:")

#define LABEL_OP_STATUS              ("Operations status:")
#define LABEL_CERT_FNAME             ("Root certificate (PEM):")
#define LABEL_EXPORT_PROGRESS        ("Share export progress:")
#define LABEL_EXPORT_PROGRESS_UPDT   ("Share export progress: %2u /%2u")

#define LABEL_SUBCA_COUNT            ("Total number of sub-CA:")
#define LABEL_REVOCATIONS_COUNT      ("Number of revoqued sub-CA:")
#define LABEL_LAST_CRL               ("Last CRL emission:")
#define LABEL_PKI_STATUS             ("PKI Status:")


#define LABEL_BTN_CREATE             ("Initialize PKI")
#define LABEL_BTN_LOCK               ("Lock")
#define LABEL_BTN_UNLOCK             ("Unlock")
#define LABEL_BTN_EXPORT_FIRST       ("Export first share")
#define LABEL_BTN_EXPORT_NEXT        ("Export next share")
#define LABEL_BTN_EXPORT_RESET       ("Restart shares export")
#define LABEL_BTN_SEL_CERT           ("Select the certificate")
#define LABEL_BTN_REVOKE             ("Revocate")
#define LABEL_BTN_REKEY              ("Regenerate secret share")
#define LABEL_BTN_SEL_CSR            ("Select the request")
#define LABEL_BTN_SIGN               ("Sign")
#define LABEL_BTN_SHARE_LOAD         ("Load share %u")
#define LABEL_BTN_GEN_CRL            ("Generate CRL")

#define LABEL_GROUP_PKI_PARAMETERS   ("PKI parameters")
#define LABEL_GROUP_SHARE_PARAMETERS ("Shamir Share parameters")
#define LABEL_GROUP_GENERATION       ("PKI generation")
#define LABEL_GROUP_PKI_INFO         ("PKI informations")
#define LABEL_GROUP_SHARE_EXPORT     ("Shamir Share export")
#define LABEL_GROUP_REVOCATION       ("Revoke a sub-CA")
#define LABEL_GROUP_SIGNATURE        ("Sign a sub-CA")
#define LABEL_GROUP_SHARES           ("Shamir shares")
#define LABEL_GROUP_CRL              ("Generate CRL")
#define LABEL_SHARE_LOADED_INIT      ("0/0 shares loaded / pki locked")
#define LABEL_SHARE_LOADED           ("%u/%u shares loaded / pki %s")

#define LABEL_PKI_STATUS_LOCKED      (" - LOCKED - ")
#define LABEL_PKI_STATUS_UNLOCKED    (" - UNLOCKED - ")

#define HASH_SHA256                  ("sha256")
#define HASH_SHA512                  ("sha512")

#endif
//eof

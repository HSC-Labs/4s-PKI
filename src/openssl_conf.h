#define OPENSSL_DEFAULT_CONF \
"[ ca ]\n"                                           \
"default_ca              = CA_default\n"             \
"\n"                                                 \
"[ CA_default ]\n"                                   \
"serial                  = $dir/serial\n"            \
"database                = $dir/cert.idx\n"          \
"new_certs_dir           = $dir/certs/\n"            \
"certificate             = $dir/cacerts/root.crt\n"  \
"private_key             = $dir/private/root.key\n"  \
"default_days            = $califelen \n"            \
"crl                     = $dir/crl/root.crl\n"      \
"crlnumber               = $dir/crl/crl_serial\n"    \
"default_crl_days        = $crllifelen\n"            \
"default_md              = $hashalg\n"               \
"preserve                = no\n"                     \
"email_in_dn             = no\n"                     \
"unique_subject          = no\n"                     \
"nameopt                 = default_ca\n"             \
"certopt                 = default_ca\n"             \
"policy                  = policy_match\n"           \
"copy_extensions         = copy\n"                   \
"\n"                                                 \
"[ policy_match ]\n"                                 \
"countryName             = optional\n"               \
"stateOrProvinceName     = optional\n"               \
"organizationName        = supplied\n"               \
"organizationalUnitName  = optional\n"               \
"commonName              = supplied\n"               \
"emailAddress            = optional\n"               \
"[ req ]\n"                                          \
"default_bits            = $defaultcertksize\n"                   \
"default_keyfile         = key.pem\n"                \
"default_md              = $hashalg\n"               \
"string_mask             = nombstr\n"                \
"distinguished_name      = req_distinguished_name\n" \
"req_extensions          = v3_req\n\n"               \
"\n"                                                 \
"[ req_distinguished_name ]\n"                       \
"0.organizationName          = Organization Name (company)\n"                     \
"organizationalUnitName      = Organizational Unit Name (department, division)\n" \
"emailAddress                = Email Address\n"                                   \
"emailAddress_max            = 80\n"                                              \
"localityName                = Locality Name (city, district)\n"                  \
"stateOrProvinceName         = State or Province Name (full name)\n"              \
"countryName                 = Country Name (2 letter code)\n"                    \
"countryName_min             = 2\n"                                               \
"countryName_max             = 2\n"                                               \
"commonName                  = Common Name (hostname, IP, or your name)\n"        \
"commonName_max              = 64\n"                                              \
"\n"                                                                              \
"[ v3_ca_root ]\n"                                                                \
"basicConstraints            = CA:TRUE, pathlen:1\n"                              \
"keyUsage                    = critical, keyCertSign, cRLSign\n"                  \
"subjectKeyIdentifier        = hash\n"                                            \
"authorityKeyIdentifier      = keyid:always,issuer:always\n\n"                    \
"\n"                                                                              \
"[ v3_subca1 ]\n"                                                                 \
"basicConstraints            = CA:TRUE, pathlen:0\n"                              \
"keyUsage                    = critical, keyCertSign, cRLSign\n"                  \
"subjectKeyIdentifier        = hash\n"                                            \
"authorityKeyIdentifier      = keyid:always,issuer:always\n"                      \
"crlDistributionPoints       = URI:$cdp\n"                                        \
"\n"                                                                              \
"[ v3_ca_host ]\n"                                                                \
"basicConstraints            = CA:TRUE, pathlen:0\n"                              \
"keyUsage                    = critical, keyCertSign, cRLSign\n"                  \
"subjectKeyIdentifier        = hash\n"                                            \
"authorityKeyIdentifier      = keyid:always,issuer:always\n"                      \
"crlDistributionPoints       = URI:$cdp\n"                                        \
"\n"                                                                              \
"[ v3_SSL_server ]\n"                                                             \
"basicConstraints          = CA:FALSE\n"                                          \
"subjectKeyIdentifier      = hash\n"                                              \
"keyUsage                  = critical, digitalSignature, keyEncipherment \n"      \
"extendedKeyUsage          = critical, serverAuth\n"                              \
"authorityKeyIdentifier    = keyid:always,issuer:always\n"                        \
"crlDistributionPoints     = URI:$cdp\n"                                          \
"subjectAltNames           = copy\n"                                              \
"\n"                                                                              \
"[ v3_req ]\n"                                                                    \
"basicConstraints          = CA:FALSE\n"                                          \
"subjectKeyIdentifier      = hash\n"                                              \
"\n"                                                                              \
"[ crl_ext ]\n"                                                                   \
"authorityKeyIdentifier = keyid:always,issuer:always\n" 
 

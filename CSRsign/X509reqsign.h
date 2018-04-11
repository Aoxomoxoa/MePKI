#pragma once

#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ossl_typ.h>

X509_REQ * read_from_disk(const char *filepath);
EVP_PKEY * read_ca_pkey(const char *filepath_to_pkey_ca);
#pragma once

#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ossl_typ.h>

X509_REQ * read_from_disk(const char *filepath);
EVP_PKEY * read_ca_pkey(const char *filepath_to_pkey_ca);
int request_signing(X509_REQ *certificate_request, X509 * certificate, EVP_PKEY *pkey, int days, const EVP_MD *(*EVP_sha)());
bool write_to_disk(X509 *x509);
void print_x509_req(X509_REQ* x509_req);
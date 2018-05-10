#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <cstring>
#include <time.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ossl_typ.h>
#include <openssl/applink.c>

#include "X509reqsign.h"

const int DAYS_DEFAULT = 365;

bool write_to_disk(EVP_PKEY *pkey, X509 *x509)
{
	/* Open the PEM file for writing the key to disk. */
	FILE *pkey_file = fopen("private.key", "wb");
	if (!pkey_file)
	{
		std::cerr << "[error]   Unable to open \"private.key\" for writing." << std::endl;
		return false;
	}

	/* Write the key to disk. */
	bool ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(pkey_file);

	if (!ret)
	{
		std::cerr << "[error]   Unable to write private key to disk." << std::endl;
		return false;
	}

	std::cout << "[success] Private key have been written to file" << std::endl;

	/* Open the PEM file for writing the certificate to disk. */
	FILE *x509_file = fopen("x509.cert", "wb");
	if (!x509_file)
	{
		std::cerr << "[error]   Unable to open \"cert.pem\" for writing." << std::endl;
		return false;
	}

	/* Write the certificate to disk. */
	ret = PEM_write_X509(x509_file, x509);
	fclose(x509_file);

	if (!ret)
	{
		std::cerr << "[error]   Unable to write certificate to disk." << std::endl;
		return false;
	}
	return true;
}

void parse_arguments(int &sha, int &days, int argc, char **argv)
{
	for (int i = 0; i < argc; ++i)
	{
		if (strcmp(argv[i], "--days") == 0)
			days = atoi(argv[i + 1]);
		else if (strcmp(argv[i], "--sha") == 0)
			sha = atoi(argv[i + 1]);
	}
	if (days <= 0)
	{
		std::cerr << "[warn]    days argument is invalid. Using default - " << DAYS_DEFAULT << " days" << std::endl;
		days = DAYS_DEFAULT;
	}
}


int main(int argc, char ** argv)
{
	X509 * cert_from_CSR = X509_new();
	int cert_from_CSR_bytes=0;
	int sha = 0;
	int days = 0;
	parse_arguments(sha, days, argc, argv);

	const EVP_MD *(*sha_structures[5])() = { EVP_sha1, EVP_sha224, EVP_sha256, EVP_sha384, EVP_sha512 };
	int sha_structures_index = 0;

	switch (sha)
	{
	case 1: sha_structures_index = 0; break;
	case 224: sha_structures_index = 1; break;
	case 256: sha_structures_index = 2; break;
	case 384: sha_structures_index = 3; break;
	case 512: sha_structures_index = 4; break;
	default:
		std::cerr << "[warn]    sha argument is invalid. Using default - sha1" << std::endl;
		sha_structures_index = 0;
	}

	//Read CSR from disk
	X509_REQ * CSR_for_cert = read_from_disk("request.csr");

		//Read PrivateKey from disk
	EVP_PKEY * CA_PrivateKey = read_ca_pkey("private.key");

	//sign CSR
	cert_from_CSR_bytes = request_signing(CSR_for_cert, cert_from_CSR, CA_PrivateKey, days, sha_structures[sha_structures_index]);

	return 0;
}
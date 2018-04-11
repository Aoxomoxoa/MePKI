#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <cstring>
#include <time.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ossl_typ.h>
#include <openssl/applink.c>

#include "X509reqsign.h"

const int BITS_DEFAULT = 512;
const int YEARS_DEFAULT = 1;

bool write_to_disk(EVP_PKEY *pkey, X509 *x509)
{
	/* Open the PEM file for writing the key to disk. */
	FILE *pkey_file = fopen("private.key", "wb");
	if (!pkey_file)
	{
		std::cerr << "Unable to open \"private.key\" for writing." << std::endl;
		return false;
	}

	/* Write the key to disk. */
	bool ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(pkey_file);

	if (!ret)
	{
		std::cerr << "Unable to write private key to disk." << std::endl;
		return false;
	}

	std::cout << "Private key have been written to file" << std::endl;

	/* Open the PEM file for writing the certificate to disk. */
	FILE *x509_file = fopen("x509.cert", "wb");
	if (!x509_file)
	{
		std::cerr << "Unable to open \"cert.pem\" for writing." << std::endl;
		return false;
	}

	/* Write the certificate to disk. */
	ret = PEM_write_X509(x509_file, x509);
	fclose(x509_file);

	if (!ret)
	{
		std::cerr << "Unable to write certificate to disk." << std::endl;
		return false;
	}
	return true;
}

void parse_argumenrs(int &bits, int &years, int &sha, int argc, char **argv)
{
	for (int i = 0; i < argc; ++i)
	{
		if (strcmp(argv[i], "--bits") == 0)
			bits = atoi(argv[i + 1]);
		else if (strcmp(argv[i], "--years") == 0)
			years = atoi(argv[i + 1]);
		else if (strcmp(argv[i], "--sha") == 0)
			sha = atoi(argv[i + 1]);
	}
	if (bits <= 0)
	{
		std::cerr << "bits argument is invalid. Using default" << std::endl;
		bits = BITS_DEFAULT;
	}
	if (years <= 0)
	{
		std::cerr << "years argument is invalid. Using default" << std::endl;
		years = YEARS_DEFAULT;
	}
}


int main(int argc, char ** argv)
{
	int bits = BITS_DEFAULT;
	int years = YEARS_DEFAULT;
	int sha = 0;
	parse_argumenrs(bits, years, sha, argc, argv);

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
		std::cerr << "sha argument is invalid. Using sha1" << std::endl;
		sha_structures_index = 0;
	}

	/* Write the private key and certificate out to disk. */
	/*std::cout << "Writing key and certificate to disk..." << std::endl;

	bool ret = write_to_disk(pkey, x509);
	EVP_PKEY_free(pkey);
	X509_free(x509);

	if (ret)
		std::cout << "Success!" << std::endl;
	else
		return 1;
		*/
	X509_REQ * cert_CSR = read_from_disk("E:\\project\\test\\test\\request.csr");

	if (!cert_CSR)
	{
		std::cout << "Error in reading CSR from disk";
		return 1;
	}
	std::cout << "CSR is have been read successful" << std::endl;

	EVP_PKEY * CA_PrivateKey = read_ca_pkey("E:\\project\\test\\test\\private.key");

	if (!CA_PrivateKey)
	{
		std::cout << "Error in reading Private key from disk";
		return 1;
	}

	std::cout << "Private Key is have been read successful" << std::endl;
	return 0;
}
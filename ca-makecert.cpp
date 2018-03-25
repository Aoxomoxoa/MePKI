#include <iostream>
#include <cstring>
#include <time.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ossl_typ.h>
#include <openssl/applink.c>


const int BITS_DEFAULT = 512;
const int YEARS_DEFAULT = 1;

/* Generates RSA key. */
EVP_PKEY * generate_RSA_key(int bits)
{
	/* Allocate memory for the EVP_PKEY structure. */
	EVP_PKEY *pkey = EVP_PKEY_new();
	if (!pkey)
	{
		std::cerr << "Unable to create EVP_PKEY structure." << std::endl;
		return NULL;
	}

	/* Generate the RSA key and assign it to pkey. */
	RSA *rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	if (!EVP_PKEY_assign_RSA(pkey, rsa))
	{
		std::cerr << "Unable to generate " << bits << "-bit RSA key." << std::endl;
		EVP_PKEY_free(pkey);
		return NULL;
	}

	/* The key has been generated, return it. */
	return pkey;
}

/* Generates a self-signed x509 certificate. */
X509 * generate_x509(EVP_PKEY *pkey, int years, const EVP_MD *(*EVP_sha)())
{
	/* Allocate memory for the X509 structure. */

	std::cout << "Start generating certificate for " << years << " years" << std::endl;

	X509 *x509 = X509_new();
	if (!x509)
	{
		std::cerr << "Unable to create X509 structure." << std::endl;
		return NULL;
	}

	/* Generate random number for serial Number */
	srand(time(NULL));
	int random_value = rand();

	/* Set the serial number. */
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

	/* This certificate is valid from now until exactly one year from now. */
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L * years);

	/* Set the public key for our certificate. */
	X509_set_pubkey(x509, pkey);

	/* We want to copy the subject name to the issuer name. */
	X509_NAME *name = X509_get_subject_name(x509);

	/* Set the country code and common name. */
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"RU", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"MEPHI", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"RomanKyarimov", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char *)"Moscow, Kashira Highway, 31", -1, -1, 0);

	/* Now set the issuer name. */
	X509_set_issuer_name(x509, name);

	/* Actually sign the certificate with our key. */
	if (!X509_sign(x509, pkey, EVP_sha()))
	{
		std::cerr << "Error signing certificate." << std::endl;
		X509_free(x509);
		return NULL;
	}
	std::cout << "Certificate signed succesfully" << std::endl;
	return x509;
}

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

	std::cout << "Private key have written to file" << std::endl;

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

	/* Generate the key. */
	std::cout << "Generating RSA key..." << std::endl;

	EVP_PKEY *pkey = generate_RSA_key(bits);
	if (!pkey)
		return 1;

	/* Generate the certificate. */
	std::cout << "Generating x509 certificate..." << std::endl;

	X509 *x509 = generate_x509(pkey, years, sha_structures[sha_structures_index]);
	if (!x509)
	{
		EVP_PKEY_free(pkey);
		return 1;
	}

	/* Write the private key and certificate out to disk. */
	std::cout << "Writing key and certificate to disk..." << std::endl;

	bool ret = write_to_disk(pkey, x509);
	EVP_PKEY_free(pkey);
	X509_free(x509);

	if (ret)
	{
		std::cout << "Success!" << std::endl;
		return 0;
	}
	return 1;
}

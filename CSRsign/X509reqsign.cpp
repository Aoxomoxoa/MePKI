#include "X509reqsign.h"

X509_REQ * read_from_disk(const char *filepath)
{
	/* Open the csr file for reading. */
	X509_REQ *cert_req;
	FILE *csr_file = fopen(filepath, "r");

	if (!csr_file)
	{
		std::cerr << "Unable to open csr file for reading." << std::endl;
		return NULL;
	}

	cert_req = PEM_read_X509_REQ(csr_file, NULL, 0, NULL);
	fclose(csr_file);
	if (!cert_req)
	{
		std::cerr << "Unable request from disk." << std::endl;
		return NULL;
	}

	return cert_req;
	
}

EVP_PKEY * read_ca_pkey(const char *filepath_to_pkey_ca)
{
	EVP_PKEY *pkey_ca;
	FILE *pkey_ca_file = fopen(filepath_to_pkey_ca, "r");

	if (!pkey_ca_file)
	{
		std::cerr << "Unable to open CA private key file for reading." << std::endl;
		return NULL;
	}
	/*RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u);
	Интересный вариант с структурой RSA, возвращает ошибку, если ключ другого типа, но при этом X509_sign
	использует всё же EVP_PKEY
	*/
	pkey_ca = PEM_read_PrivateKey(pkey_ca_file, NULL, 0, NULL);
	fclose(pkey_ca_file);
	if (!pkey_ca)
	{
		std::cerr << "ERROR in reading pkey from file." << std::endl;
		return NULL;
	}
	return pkey_ca;
}
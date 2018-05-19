#include "X509reqsign.h"
#include <string>
#include <fstream>

void print_x509_req(X509_REQ* x509_req)
{
	BIO * bio_out = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(bio_out, x509_req);
	BUF_MEM *bio_buf;
	BIO_get_mem_ptr(bio_out, &bio_buf);
	auto pem = std::string(bio_buf->data, bio_buf->length);
	BIO_free(bio_out);
	std::cout << pem << std::endl;
}


X509_REQ * read_from_disk(const char *filepath)
{
	/* Open the csr file for reading. */
	X509_REQ *cert_req;
	FILE *csr_file = fopen(filepath, "r");

	if (!csr_file)
	{
		std::cerr << "[error]   Unable to open csr file for reading." << std::endl;
		return NULL;
	}

	cert_req = PEM_read_X509_REQ(csr_file, NULL, 0, NULL);
	fclose(csr_file);
	if (!cert_req)
	{
		std::cerr << "[error]   Unable request from disk." << std::endl;
		return NULL;
	}
	std::cout << "[success] CSR have been read successful" << std::endl;
	
	return cert_req;
	
}

EVP_PKEY * read_ca_pkey(const char *filepath_to_pkey_ca)
{
	EVP_PKEY *pkey_ca;
	FILE *pkey_ca_file = fopen(filepath_to_pkey_ca, "r");

	if (!pkey_ca_file)
	{
		std::cerr << "[error]   Unable to open CA private key file for reading." << std::endl;
		return NULL;
	}
	/*RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u);
	���������� ������� � ���������� RSA, ���������� ������, ���� ���� ������� ����, �� ��� ���� X509_sign
	���������� �� �� EVP_PKEY
	*/
	pkey_ca = PEM_read_PrivateKey(pkey_ca_file, NULL, 0, NULL);
	fclose(pkey_ca_file);
	if (!pkey_ca)
	{
		std::cerr << "[error]   ERROR in reading pkey from file." << std::endl;
		return NULL;
	}
	std::cout << "[success] Private Key have been read successful" << std::endl;
	return pkey_ca;
}

bool write_to_disk(X509 *x509)
{
	/* Open the PEM file for writing the key to disk. */
	FILE *x509_file = fopen("cert.pem", "wb");
	if (!x509_file)
	{
		std::cerr << "[error]   Unable to open \"cert.pem\" for writing." << std::endl;
		return false;
	}

	/* Write the certificate to disk. */
	bool ret = PEM_write_X509(x509_file, x509);
	fclose(x509_file);

	if (!ret)
	{
		std::cerr << "[error]   Unable to write certificate to disk." << std::endl;
		return false;
	}
	return true;
}

int request_signing(X509_REQ *certificate_request, X509 * certificate, EVP_PKEY *pkey, int days, const EVP_MD *(*EVP_sha)())
{
	int bytes;
	int Snumber;
	bool serial_is_unique = true;
	srand(time(NULL));
	int random_value;
	std::ifstream CA_DB_file;
	std::string line_with_Snumber;
	CA_DB_file.open("CA_DB");
	/*check for CA_DB*/
	if (!CA_DB_file) {
		std::cout << "[error]   Unable to open CA_DB file";
	}
	/*check if this number is unique*/
	do
	{
		random_value = rand();

		while (std::getline(CA_DB_file, line_with_Snumber))
		{
				Snumber = std::stoi(line_with_Snumber);
				if (Snumber == random_value)
				{
					serial_is_unique = false;
					break;
				}
			}
	CA_DB_file.seekg(0, CA_DB_file.beg);
	} while (!serial_is_unique);	CA_DB_file.close();
	//write new serial number in file
	std::ofstream CA_DB_file_for_W;
	CA_DB_file_for_W.open("CA_DB", std::ios_base::app);
	CA_DB_file_for_W << random_value << std::endl;
	CA_DB_file_for_W.close();
	
	std::cout << "[info]    Start generating certificate from CSR" << std::endl;
	if (X509_REQ_sign(certificate_request, pkey, EVP_sha()) == 0)
	{
		std::cerr << "[error]   Error signing CSR." << std::endl;
		return 0;
	}
	bytes = X509_REQ_sign(certificate_request, pkey, EVP_sha());
	std::cout << "[success] CSR is signed" << std::endl;
	
	certificate = X509_REQ_to_X509(certificate_request, days, pkey);
	
	if (X509_sign(certificate, pkey, EVP_sha()) == 0)
	{
		std::cerr << "[error]   Error while generating cerificate." << std::endl;
		return 0;
	}
	bytes = X509_sign(certificate, pkey, EVP_sha());
	std::cout << "[success] Certificate is successfuly generated" << std::endl;
	/* Set the serial number. */
	ASN1_INTEGER_set(X509_get_serialNumber(certificate), random_value);
	bool ret = write_to_disk(certificate);
	return bytes;
}

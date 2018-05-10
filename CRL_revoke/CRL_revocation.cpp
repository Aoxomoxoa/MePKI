#include "crlrvk.h"

X509 * read_from_disk(const char *filepath)
{
	/* Open the csr file for reading. */
	X509 *cert_req;
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
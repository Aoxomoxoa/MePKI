#include "crlrvk.h"
#include <string>
#include <fstream>

X509 * read_from_disk(const char *filepath)
{
	/* Open the cert file for reading. */
	X509 *cert;
	FILE *cert_file = fopen(filepath, "r");

	if (!cert_file)
	{
		std::cerr << "[error]   Unable to open cert file for reading." << std::endl;
		return NULL;
	}

	cert = PEM_read_X509(cert_file, NULL, 0, NULL);
	fclose(cert_file);

	std::cout << "[success] Cert file have been read successful" << std::endl;
	return cert;

}
void parse_arguments(int &rev_type, int &certSerial, bool &isRevoke, bool &isVerify, int argc, char **argv)
{
	std::string certFile;
	const char* certFile_filepath = "cert.pem";
	X509 *cert;

	for (int i = 0; i < argc; ++i)
	{
		// if revoke. 
		if (strcmp(argv[i], "--revoke") == 0)
		{
			//check for wrong entry
			if ((argc == 1) || (argc == 2) || (argc == 3) || (argc > 4))
			{
				std::cout << "Usage: --revoke <rev_type> <cert_filename>" << std::endl;
				return;
			}
			rev_type = atoi(argv[i + 1]);
			certFile = argv[i + 2];
			certFile_filepath = certFile.c_str();
			cert = read_from_disk(certFile_filepath);
			if (cert == NULL)
			{
				std::cerr << "[error]   Unable to open cert file with filename " << certFile_filepath << std::endl;
				return;
			}
			isRevoke = true;
			/*
			X509_get_serialNumber returns type ASN1_INTEGER, 
			when ASN1_INTEGER_get return value ASN1_INTEGER in int
			*/
			certSerial = ASN1_INTEGER_get(X509_get_serialNumber(cert));
		}

		// if verify
		if (strcmp(argv[i], "--verify") == 0)
		{
			if ((argc == 2) || (argc > 3))
			{
				std::cout << "Usage: --verify <cert_filename>" << std::endl;
				return;
			}
			certFile = argv[i + 1];
			certFile_filepath = certFile.c_str();
			cert = read_from_disk(certFile_filepath);
			if (cert == NULL)
			{
				std::cerr << "[error]   Unable to open cert file with filename " << certFile_filepath << std::endl;
				return;
			}
			isVerify = true;
			certSerial = ASN1_INTEGER_get(X509_get_serialNumber(cert));
		}
			
	}
	if ((rev_type > 3) || (rev_type <0))
	{
		std::cerr << "[warn]    revocation type code is invalid. Using 0" << std::endl;
		rev_type = 0;
	}
}
void do_revoke(int &rev_type, int &certSerial)
{
	std::ofstream CRL_DB_W;
	std::ifstream CRL_DB_R;
	//open CRL database for writing
	CRL_DB_W.open("CRL_DB", std::ios_base::app);
	//check if database file exists
	if (!CRL_DB_W) {
		std::cout << "[error]   Unable to open CRL_DB file";
		return;
	}
	//open CRL database for reading
	CRL_DB_R.open("CRL_DB");
	/*
	check if certificate with this serial nubmer is already revoked
	This is a bit tricky. I read CRL_DB_R in certSerial_str line with delimiter 'space' and then the rest of it with delimiter '/n'
	i.e. line: 452 1
	read till 'space' → 452
	read the rest till /n → 1 
	*/
	for (std::string certSerial_str, rev_reason_str;
		std::getline(CRL_DB_R, certSerial_str, ' ') && std::getline(CRL_DB_R, rev_reason_str);
		)
	{
		if (certSerial == std::stoi(certSerial_str))
		{
			std::cout << "[info]    Certificate with number " << certSerial << " is already revoked. For additional information call --verify" << std::endl;
			return;
		}
	}
	CRL_DB_W << certSerial << " " << rev_type << std::endl;
	std::cout << "[success] Certificate with number " << certSerial << " have been revoked by reason " << rev_type << std::endl;
	CRL_DB_W.close();
}
void do_verify(int &certSerial)
{
	bool cert_is_revoked = false;
	std::ifstream CRL_DB_R;
	int rev_reason=-1;
	CRL_DB_R.open("CRL_DB");
	if (!CRL_DB_R)
	{
		std::cout << "[error]   Unable to open CRL_DB file";
		return;
	}
	for (std::string certSerial_str, rev_reason_str;
			std::getline(CRL_DB_R, certSerial_str, ' ') && std::getline(CRL_DB_R, rev_reason_str);
			)
	{
		if (certSerial == std::stoi(certSerial_str))
		{
			cert_is_revoked = true;
			std::cout << "[info]    Certificate with serial number " << certSerial_str << " is revoked";
			rev_reason = stoi(rev_reason_str);
			switch (rev_reason)
			{
			case 0:
				std::cout << ", but there is no additional information about revocation reason" << std::endl;
				break;
			case 1:
				std::cout << " because certificate is outdated" << std::endl;
				break;
			case 2:
				std::cout << " because certificate key is compromised" << std::endl;
				break;
			case 3:
				std::cout << " because CA key is compromised" << std::endl;
				break;
			default:
				std::cout << std::endl << "[error]   wrong revokation reason code" << std::endl;
				break;
			}
		}
	}
	if (!cert_is_revoked)
		std::cout << "[info]    Certificate with serial number " << certSerial << " is valid" << std::endl;

}
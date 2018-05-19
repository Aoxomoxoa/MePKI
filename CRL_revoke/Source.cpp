#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <cstring>
#include <time.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ossl_typ.h>
#include <openssl/applink.c>

#include "crlrvk.h"

int main(int argc, char ** argv)
{
	int rev_type = 0;
	int certSerial = 0;
	bool isRevoke = false;
	bool isVerify = false;
	parse_arguments(rev_type, certSerial, isRevoke, isVerify, argc, argv);
	if (isRevoke)
		do_revoke(rev_type, certSerial);
	if (isVerify)
		do_verify(certSerial);
	if ((!isRevoke) && (!isVerify))
	{
		std::cout << "The input values are not full. Input parameter can be --revoke or --verify." << std::endl;
		std::cout << "Type one of them without arguments to see form." << std::endl;
		std::cout << "Revocation type code can be" << std::endl;
		std::cout << "0, No additional information" << std::endl;
		std::cout << "1, Value is cert is outdated" << std::endl;
		std::cout << "2, Value is cert key is compromised" << std::endl;
		std::cout << "3, Value is CA key is compromised" << std::endl;
	}
	return 0;
}
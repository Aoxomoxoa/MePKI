#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

int create_socket(char[], BIO *);

int main() {

// init all structures
  char            dest_url[128];
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  X509_NAME       *certname = NULL;
  X509_NAME     *certissuer = NULL;
  ASN1_TIME      *notBefore = NULL;
  ASN1_TIME       *notAfter = NULL;

// init all variables
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int server = 0;
  int ret, i, res;
  long is_valid;

// load some functional abilities
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

// init input and output buffers
  certbio = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  if(SSL_library_init() < 0)
    BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");

// set connection method
  method = SSLv23_client_method();

  if ( (ctx = SSL_CTX_new(method)) == NULL)
    BIO_printf(outbio, "Unable to create a new SSL context structure.\n");
 
// load certificate chain 
  res = SSL_CTX_load_verify_locations(ctx, "chain.pem", NULL);

  if (res == 0) printf("Chain file is not found\n");

// do not use the SSLv2 protocol
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

  ssl = SSL_new(ctx);

  printf("Enter destination url (format: https://example.com): \n");
  scanf("%s", dest_url);

// create socket for connection
  server = create_socket(dest_url, outbio);
  if(server != 0)
    BIO_printf(outbio, "--Successfully made the TCP connection to:-- \n %s.\n", dest_url);

// set the file descriptor as the input/output facility for the TLS/SSL
  SSL_set_fd(ssl, server);

  if ( SSL_connect(ssl) != 1 )
    BIO_printf(outbio, "Error: Could not build a SSL session to: \n %s.\n", dest_url);
  else
    BIO_printf(outbio, "--Successfully enabled SSL/TLS session to:-- \n %s.\n", dest_url);

// get the X509 certificate of the peer
  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL)
    BIO_printf(outbio, "Error: Could not get a certificate from: \n %s.\n", dest_url);
  else
    BIO_printf(outbio, "--Retrieved the server's certificate from:-- \n %s.\n", dest_url);
 
 if (cert)
    X509_free(cert);

/*
  returns the result of the verification:
  0  - cert is OK;
  18 - self-signed cert;
  20 - cert is not trusted
*/
  is_valid = SSL_get_verify_result(ssl);
  switch(is_valid)   
  {
    case '0':
      printf("Code 0 - certificate is valid"); 
    case '18':
      printf("Code 18 - self-signed certificate");   
    default :
      printf("Code 20 - certificate is not trusted");  
  }  

// get all certificate data
  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);
  certissuer = X509_get_issuer_name(cert);

  notBefore = X509_getm_notBefore(cert);
  notAfter = X509_getm_notAfter(cert);

// display all certificate data
  BIO_printf(outbio, "--Displaying the certificate subject data:--\n");
  X509_NAME_print_ex(outbio, certname, 0, 0);
  BIO_printf(outbio, "\n");

  BIO_printf(outbio, "--Displaying the certificate issuer data:--\n");
  X509_NAME_print_ex(outbio, certissuer, 0, 0);
  BIO_printf(outbio, "\n");

  BIO_printf(outbio, "--Displaying the certificate notBefore data:--\n");
  ASN1_STRING_print_ex(outbio, notBefore, ASN1_STRFLGS_ESC_QUOTE);
  BIO_printf(outbio, "\n");

  BIO_printf(outbio, "--Displaying the certificate notAfter data:--\n");
  ASN1_STRING_print_ex(outbio, notAfter, ASN1_STRFLGS_ESC_QUOTE);
  BIO_printf(outbio, "\n");

// free memory after usage
  SSL_free(ssl);
  shutdown(server, 2);
  SSL_CTX_free(ctx);
  BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
  return(0);
}

// function to parse url and create socket
int create_socket(char url_str[], BIO *out) {
  int sockfd;
  char hostname[256] = "";
  char    portnum[6] = "443";
  char      proto[6] = "";
  char      *tmp_ptr = NULL;
  int           port;
  struct hostent *host;
  struct sockaddr_in dest_addr;

  if(url_str[strlen(url_str)] == '/')
    url_str[strlen(url_str)] = '\0';

  strncpy(proto, url_str, (strchr(url_str, ':')-url_str));

  strncpy(hostname, strstr(url_str, "://")+3, sizeof(hostname));

  if(strchr(hostname, ':')) {
    tmp_ptr = strchr(hostname, ':');
    /* the last : starts the port number, if avail, i.e. 8443 */
    strncpy(portnum, tmp_ptr+1,  sizeof(portnum));
    *tmp_ptr = '\0';
  }

  port = atoi(portnum);

  if ( (host = gethostbyname(hostname)) == NULL ) {
    BIO_printf(out, "Error: Cannot resolve hostname %s.\n",  hostname);
    abort();
  }

  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

  memset(&(dest_addr.sin_zero), '\0', 8);

  tmp_ptr = inet_ntoa(dest_addr.sin_addr);

  if ( connect(sockfd, (struct sockaddr *) &dest_addr,
                              sizeof(struct sockaddr)) == -1 ) {
    BIO_printf(out, "Error: Cannot connect to host %s [%s] on port %d.\n",
             hostname, tmp_ptr, port);
  }

  return sockfd;
}
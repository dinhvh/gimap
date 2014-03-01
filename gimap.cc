#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

int main(int argc, char* argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: gimap username@gmail.com password\n");
    exit(EXIT_FAILURE);
  }

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;  // AF_UNSPEC
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  struct addrinfo* info;
  int result = getaddrinfo("imap.gmail.com", "993", &hints, &info);
  if (result != 0) {
    fprintf(stderr, "getaddrinfo failed!\n");
    exit(EXIT_FAILURE);
  }

  int sockfd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
  if (sockfd == -1) {
    fprintf(stderr, "Error creating socket!\n");
    exit(EXIT_FAILURE);
  }

  if (connect(sockfd, info->ai_addr, info->ai_addrlen) == -1) {
    fprintf(stderr, "Socket connect error!\n");
    exit(EXIT_FAILURE);
  } else {
    printf("%s\n", "TCP Socket connected!");
  }

  freeaddrinfo(info);

  SSL_library_init();
  SSL_load_error_strings();

  SSL_CTX* ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  SSL* ssl = SSL_new(ssl_ctx);
  result = SSL_set_fd(ssl, sockfd);
  if (result == 0) {
    fprintf(stderr, "Operation failed!\n");
    exit(EXIT_FAILURE);
  }

  result = SSL_connect(ssl);
  if (result == 1) {
    printf("TLS/SSL connection has been established.\n");
  }

  // Reading SSL_connect answer.
  const int kMaxLine = 4096;
  char reply[kMaxLine + 1];
  ssize_t bytes_read = SSL_read(ssl, reply, sizeof(reply));
  if (bytes_read < 0) {
    int err = SSL_get_error(ssl, bytes_read);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "SSL_read failed: %d\n", err);
  }
  reply[bytes_read] = '\0';
  fprintf(stdout, "%s", reply);

  // Sending login command.
  char msg[kMaxLine + 1];
  snprintf(msg, sizeof(msg), "1 LOGIN %s %s\r\n", argv[1], argv[2]);
  SSL_write(ssl, msg, strlen(msg));

  // Reading login command.
  bytes_read = SSL_read(ssl, reply, sizeof(reply));
  if (bytes_read < 0) {
    int err = SSL_get_error(ssl, bytes_read);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "SSL_read failed: %d\n", err);
  }
  reply[bytes_read] = '\0';
  fprintf(stdout, "%s", reply);


  // Sending select command.
  snprintf(msg, sizeof(msg), "2 SELECT INBOX\r\n");
  SSL_write(ssl, msg, strlen(msg));

  // Reading select command.
  bytes_read = SSL_read(ssl, reply, sizeof(reply));
  if (bytes_read < 0) {
    int err = SSL_get_error(ssl, bytes_read);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "SSL_read failed: %d\n", err);
  }
  reply[bytes_read] = '\0';
  fprintf(stdout, "%s", reply);


//   snprintf(sendline, 1024, "3 FETCH 5 UID\r\n");
//   SSL_write(ssl, sendline, strlen(sendline));
//
//   bytes_read = SSL_read(ssl, sendline, 1024);
//   sendline[n] = '\0';
//   fprintf(stderr, "%s", sendline);


  // Sending logout command.
  snprintf(msg, sizeof(msg), "4 logout\r\n");
  SSL_write(ssl, msg, strlen(msg));

  // Reading logout command.
  bytes_read = SSL_read(ssl, reply, sizeof(reply));
  reply[bytes_read] = '\0';
  fprintf(stdout, "%s", reply);

  close(sockfd);

  return 0;
}

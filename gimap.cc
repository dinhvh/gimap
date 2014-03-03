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

  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd == -1) {
    fprintf(stderr, "Error creating socket!\n");
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
    // close sockfd - dinhviethoa
    exit(EXIT_FAILURE);
  }

  result = connect(sockfd, info->ai_addr, info->ai_addrlen);
  if (result == -1) {
    fprintf(stderr, "Unable to connect to gmail server!\n");
    // free info - dinhviethoa
    // close sockfd - dinhviethoa
    exit(EXIT_FAILURE);
  } else {
    printf("%s\n", "TCP Socket connected!");
  }

  freeaddrinfo(info);

  SSL_library_init();
  SSL_load_error_strings();

  SSL_CTX* ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if (!ssl_ctx) {
    // close sockfd - dinhviethoa
    fprintf(stderr, "Unable to create SSL context!\n");
    exit(EXIT_FAILURE);
  }

  SSL* ssl = SSL_new(ssl_ctx);

  SSL_set_fd(ssl, sockfd);

  result = SSL_connect(ssl);
  if (result != 1) {
    // free ssl context - dinhviethoa
    // close sockfd - dinhviethoa
    fprintf(stderr, "The TLS/SSL handshake was not successful!\n");
    exit(EXIT_FAILURE);
  }

  // Reading SSL_connect answer.
  const int kMaxLine = 4096;
  char reply[kMaxLine + 1];
  ssize_t bytes_read = SSL_read(ssl, reply, sizeof(reply));
  if (bytes_read < 0) {
    // free ssl context - dinhviethoa
    // close sockfd - dinhviethoa
    int err = SSL_get_error(ssl, bytes_read);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "SSL_read failed: %d\n", err);
  }
  reply[bytes_read] = '\0';
  fprintf(stdout, "%s", reply);
  
  // (1) You should parse the buffer and read more data if needed - dinhviethoa
  // something like:
  // int parseok = 0;
  // buffer read_data = buffer_new();
  // while (!parseok) {
  //   ssize_t bytes_read = SSL_read(ssl, reply, sizeof(reply));
  //   buffer_append(read_data);
  //   parseok = parse(read_data);
  // }

  // Sending login command.
  char msg[kMaxLine + 1];
  // Here, LOGIN should at least send quoted string.
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
  // same as (1) here - dinhviethoa.

  // Sending select command.
  snprintf(msg, sizeof(msg), "2 SELECT INBOX\r\n");
  SSL_write(ssl, msg, strlen(msg));

  // Reading select command.
  // same as (1) here - dinhviethoa.
  bytes_read = SSL_read(ssl, reply, sizeof(reply));
  if (bytes_read < 0) {
    // cleanup properly - dinhviethoa.
    int err = SSL_get_error(ssl, bytes_read);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "SSL_read failed: %d\n", err);
  }
  reply[bytes_read] = '\0';
  fprintf(stdout, "%s", reply);


  // Sending logout command.
  snprintf(msg, sizeof(msg), "4 logout\r\n");
  SSL_write(ssl, msg, strlen(msg));

  // Reading logout command.
  // same as (1) here - dinhviethoa.
  bytes_read = SSL_read(ssl, reply, sizeof(reply));
  reply[bytes_read] = '\0';
  fprintf(stdout, "%s", reply);

  SSL_shutdown(ssl);

  SSL_CTX_free(ssl_ctx);
  SSL_free(ssl);

  // Shutdown socket for both read and write.
  shutdown(sockfd, SHUT_RDWR);
  close(sockfd);

  return 0;
}

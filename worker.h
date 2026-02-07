#ifndef _WORKER_H_
#define _WORKER_H_

__attribute__((noreturn))
void worker_start(int connfd, int server_fd,EVP_PKEY *pkey,
  X509 *server_cert,
  X509 *ca_cert);

#endif /* !defined(_WORKER_H_) */

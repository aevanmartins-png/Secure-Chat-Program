#ifndef _API_H_
#define _API_H_

#define API_MAX_CLIENT_MSG_LEN 2048
#define API_MAX_SERVER_MSG_LEN 2048 + 128
#include <openssl/ssl.h>

struct api_msg {
  char data[API_MAX_SERVER_MSG_LEN];
  size_t len; 
};


struct api_state {
  int fd;
  /* TODO add required fields */
  SSL *ssl;
  int use_tls;
};


int api_recv(struct api_state *state, struct api_msg *msg);
void api_recv_free(struct api_msg *msg);

int api_send(struct api_state *state, const char *msg);

void api_state_free(struct api_state *state);
void api_state_init(struct api_state *state, int fd);

/* TODO add API calls to send messages to perform client-server interactions */

#endif /* defined(_API_H_) */

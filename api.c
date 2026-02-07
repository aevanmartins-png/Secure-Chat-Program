#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "api.h"

/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(struct api_state *state, struct api_msg *msg) {

  assert(state);
  assert(msg);
  char buf[API_MAX_CLIENT_MSG_LEN];
  
  ssize_t r;
  if (state -> use_tls){
    r = SSL_read(state->ssl, buf, sizeof(buf)-1);
  } else {
    r = read(state->fd,buf, sizeof(buf)-1);
  } 
  
  if(r < 0) {
    perror("error: api_recv read failed");
    return -1;
  }

  if(r == 0) {
    /* connection closed */
    return 0;
  }

  if( r > API_MAX_CLIENT_MSG_LEN){
    perror("error: message over maximum character limit");
    return 0;
  }

  buf[r] = '\0';  // Null-terminate the received data
  strncpy(msg->data, buf, sizeof(msg->data));
  msg->len = strlen(buf);
 
  return 1;
}


/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg) {
  /* TODO clean up state allocated for msg */
}


int api_send( struct api_state *state, const char *msg){
  
  assert(state);
  
  if(state->use_tls){
    if(SSL_write(state->ssl, msg, strlen(msg)) <=0){
      perror("error: SSL_write failed to send message");
      return -1;
    }
  else{
    if(write(state -> fd, msg, strlen(msg)) < 0){
      perror("error: api_send failed to send message");
      return -1;
    }
  }
  
  return 0;
  


}



/**
 * @brief         Frees api_state context
 * @param state   Initialized API state to be cleaned up
 */
void api_state_free(struct api_state *state) {

  assert(state);

  /* TODO clean up API state */
}



/**
 * @brief         Initializes api_state context
 * @param state   API state to be initialized
 * @param fd      File descriptor of connection socket
 */
void api_state_init(struct api_state *state, int fd) {

  assert(state);

  /* initialize to zero */
  memset(state, 0, sizeof(*state));

  /* store connection socket */
  state->fd = fd;

  /* TODO initialize API state */
}

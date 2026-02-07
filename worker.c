#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <ctype.h>

#include "api.h"
#include "util.h"
#include "worker.h"

struct worker_state {
  struct api_state api;
  int eof;
  int server_fd;  /* server <-> worker bidirectional notification channel */
  int server_eof;
  long long last_sent_msg;
  long long logged_in_user_id;
  char current_username[64];
  
  EVP_PKEY *server_privatekey;
  X509 *server_cert;
  X509 *ca_cert;
  X509 *client_cert;
  sqlite3 *db; 
  SSL_CTX *ssl_ctx;
  SSL *ssl;
};

int db_table_exists(sqlite3 *db, const char *table_name) {
    const char *sql =
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;";

    sqlite3_stmt *table_check_stmt = NULL; 

    int sqlite_status = sqlite3_prepare_v2(db, sql, -1, &table_check_stmt, NULL);
    if (sqlite_status != SQLITE_OK) {
        return -1; 
    }

    sqlite3_bind_text(table_check_stmt, 1, table_name, -1, SQLITE_TRANSIENT);

    int exists = (sqlite3_step(table_check_stmt) == SQLITE_ROW);

    sqlite3_finalize(table_check_stmt);
    return exists;
}

static int init_db(sqlite3 *db){
  int sqliteStatus;
  if (!db_table_exists(db, "messages")) {
    const char *create_table_sql = "CREATE TABLE messages ("
                                        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
                                        "user TEXT DEFAULT 'unknown',"
                                        "message TEXT NOT NULL);";

        sqliteStatus = sqlite3_exec(db, create_table_sql, 0, 0, 0);
        if (sqliteStatus != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
            return -1;
        }
  }

  if (!db_table_exists(db, "users")) {
    const char *create_table_sql = "CREATE TABLE users ("
                                        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                        "online INTEGER NOT NULL DEFAULT 0,"
                                        "username TEXT NOT NULL UNIQUE,"
                                        "password_hash TEXT NOT NULL);";

        sqliteStatus = sqlite3_exec(db, create_table_sql, 0, 0, 0);
        if (sqliteStatus != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
            return -1;
        }
  }
  sqliteStatus = sqlite3_exec(db, "UPDATE users SET online = 0;", 0, 0, 0);
    if (sqliteStatus != SQLITE_OK) {
        fprintf(stderr, "SQL error (reset online): %s\n", sqlite3_errmsg(db));
        return -1;
    }
  return 0;
}

static int readMessageHistory(struct worker_state *state){
  const char *sql =
        "SELECT id, "
        "       strftime('%Y-%m-%d %H:%M:%S', timestamp), "
        "       user, "
        "       message "
        "FROM messages "
        "ORDER BY id ASC;";
  sqlite3_stmt *read_stmt = NULL; 

    int sqlite_status = sqlite3_prepare_v2(state->db, sql, -1, &read_stmt, NULL);
    if (sqlite_status != SQLITE_OK) {
        return -1; 
    }

  char buf[API_MAX_SERVER_MSG_LEN];
  while (sqlite3_step(read_stmt) == SQLITE_ROW) {
      int id = sqlite3_column_int(read_stmt, 0);
      const unsigned char *timestamp = sqlite3_column_text(read_stmt, 1);
      const unsigned char *user = sqlite3_column_text(read_stmt, 2);
      const unsigned char *message = sqlite3_column_text(read_stmt, 3);

      int n = snprintf(buf, sizeof(buf), " %s <%s>: %s\n",
                       timestamp,
                       user,
                       message);
      if (n < 0 || n >= sizeof(buf)) {
          sqlite3_finalize(read_stmt);
          return -1; 
      }

      if (SSL_write(state->ssl, buf, n) < 0) {
          sqlite3_finalize(read_stmt);
          return -1; 
      }
      state->last_sent_msg = id;
      
  }
  sqlite3_finalize(read_stmt);

  return 0;

}
bool is_valid_username(const char *username) {
    if (username == NULL) return false;

    size_t len = strlen(username);
    if (len < 8 || len > 20) {
        return false;
    }

    if (!isalpha((unsigned char)username[0])) {
        return false;
    }

    for (size_t i = 1; i < len; ++i) {
        unsigned char c = (unsigned char)username[i];
        if (!isalnum(c) && c != '_' && c != '-') {
            return false;
        }
    }

    return true;
}

bool is_valid_password(const char *password) {
    if (password == NULL) return false;

    size_t len = strlen(password);
    if (len < 16 || len > 64) {
        return false;
    }

    bool has_lower = false;
    bool has_upper = false;
    bool has_digit = false;

    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)password[i];

        if (isspace(c) || iscntrl(c)) {
            return false;
        }

        if (islower(c)) {
        has_lower = true;
        }

        if (isupper(c)) {
            has_upper = true;
        }

        if (isdigit(c)) {
            has_digit = true;
        }
    }

    if (!has_lower || !has_upper || !has_digit) {
        return false;
    }

    return true;
}

bool is_valid_certificate(struct worker_state *state, X509 *certificate){

  EVP_PKEY *ca_pubkey = X509_get_pubkey(state->ca_cert);
  if(!ca_pubkey){
    perror("error: couldn't retrieve public key from cert");
    return false;
  }

  if (!X509_verify(certificate, ca_pubkey)){
    perror("error: certificate validation failed");
    return false;
  }

  return true;

}

static int handle_register(struct worker_state *state, const char *username, const char *password, X509 *client_cert){
  
  
  const char *sql =
        "SELECT id FROM users WHERE username = ?";
  sqlite3_stmt *read_stmt = NULL;
    int sqlite_status = sqlite3_prepare_v2(state->db, sql, -1, &read_stmt, NULL);
    if (sqlite_status != SQLITE_OK) {
        return -1; 
    }

    sqlite3_bind_text(read_stmt, 1, username, -1, SQLITE_TRANSIENT);
  int step = sqlite3_step(read_stmt);

  if (step == SQLITE_ROW) {
      api_send(&state->api, "user already exists\n");
      sqlite3_finalize(read_stmt);
      return 0;
  }

  if (step != SQLITE_DONE) {
      fprintf(stderr, "DB error in SELECT: %s\n", sqlite3_errmsg(state->db));
      sqlite3_finalize(read_stmt);
      api_send(&state->api, "error when checking if the user already exists \n");
      return -1;
  }

  else{
    sqlite3_finalize(read_stmt);
  }
  const char *insert_sql = "INSERT INTO users(username, password_hash) VALUES(?, ?);";
  sqlite3_stmt *insert_stmt = NULL;
  sqlite_status = sqlite3_prepare_v2(state->db, insert_sql, -1, &insert_stmt, NULL);
  if (sqlite_status != SQLITE_OK) {
      return -1; 
  }
  sqlite3_bind_text(insert_stmt, 1, username, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(insert_stmt, 2, password, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(insert_stmt) != SQLITE_DONE) {
    fprintf(stderr, "DB insert error: %s\n", sqlite3_errmsg(state->db));
    sqlite3_finalize(insert_stmt);
    api_send(&state->api, "error: failed to register\n");
    return -1;
  }
  sqlite3_finalize(insert_stmt);
  sqlite3_int64 new_id = sqlite3_last_insert_rowid(state->db);
  state->logged_in_user_id = new_id;
  strncpy(state->current_username, username, sizeof(state->current_username) - 1);
  state->current_username[sizeof(state->current_username) - 1] = '\0';
  sqlite3_stmt *update_stmt = NULL;
  int update_status = sqlite3_prepare_v2(state->db, "UPDATE users SET online = 1 WHERE id = ?;", -1, &update_stmt, NULL);
  if (update_status != SQLITE_OK) {
      sqlite3_finalize(read_stmt);
      api_send(&state->api, "error: when updating the logged user in the db \n");
      return -1;
  }    
  sqlite3_bind_int(update_stmt, 1, new_id);

  int step2 = sqlite3_step(update_stmt);
  sqlite3_finalize(update_stmt);
  sqlite3_finalize(read_stmt);

  if (step2 != SQLITE_DONE) {
      api_send(&state->api, "error: failed to mark user online\n");
      return -1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestInit(ctx, EVP_sha256());

  const int SALT_LEN = 16;
  unsigned char salt[SALT_LEN];
  RAND_bytes(salt, SALT_LEN);

  unsigned char hash[32];

  //Uses slow hash to defend against brute force attacks
  int r = PKCS5_PBKDF2_HMAC(password, strlen(password),
                            salt, SALT_LEN,
                            10000,EVP_sha256(),
                            sizeof(hash), hash);

  if(r == 0){
    perror("error: couldnt generate hash");
    return -1;
  }

  api_send(&state->api, "registration successful\n");
  return 0;

}
static int handle_login(struct worker_state *state, const char *username, const char *password){
  const char *sql =
      "SELECT id, password_hash FROM users WHERE username = ?";
  sqlite3_stmt *read_stmt = NULL;
  int sqlite_status = sqlite3_prepare_v2(state->db, sql, -1, &read_stmt, NULL);
  if (sqlite_status != SQLITE_OK) {
      return -1; 
  }

  sqlite3_bind_text(read_stmt, 1, username, -1, SQLITE_TRANSIENT);
  int step = sqlite3_step(read_stmt);

  if (step == SQLITE_ROW) {
    int user_id = sqlite3_column_int(read_stmt, 0);
    const unsigned char *stored_pwd = sqlite3_column_text(read_stmt, 1);
    
    if (strcmp((const char *)stored_pwd, password) != 0) {
        sqlite3_finalize(read_stmt);
        api_send(&state->api, "wrong pwd\n");
        return 0;
    }

    state->logged_in_user_id = user_id;
    strncpy(state->current_username, username, sizeof(state->current_username) - 1);
    state->current_username[sizeof(state->current_username) - 1] = '\0';
    
    sqlite3_stmt *update_stmt = NULL;
    int update_status = sqlite3_prepare_v2(state->db, "UPDATE users SET online = 1 WHERE id = ?;", -1, &update_stmt, NULL);
    if (update_status != SQLITE_OK) {
        sqlite3_finalize(read_stmt);
        api_send(&state->api, "error: when updating the logged user in the db \n");
        return -1;
    }    
    sqlite3_bind_int(update_stmt, 1, user_id);

    int step2 = sqlite3_step(update_stmt);
    sqlite3_finalize(update_stmt);
    sqlite3_finalize(read_stmt);

    if (step2 != SQLITE_DONE) {
        api_send(&state->api, "error: failed to mark user online\n");
        return -1;
    }
    api_send(&state->api, "login successful\n");
    return 0;
  }

  else if (step == SQLITE_DONE) {
      api_send(&state->api, "Your username does not exist  \n");
      sqlite3_finalize(read_stmt);
      return 0;
  }

  else{
    fprintf(stderr, "DB error in SELECT: %s\n", sqlite3_errmsg(state->db));
    api_send(&state->api, "error when checking if the user already exists \n");
    sqlite3_finalize(read_stmt);
    return -1;
  }
}
static int handle_users(struct worker_state *state){
  if(state->logged_in_user_id == 0){
    api_send(&state->api, "error: you must be logged in to see online users\n");
    return 0;
  }
    const char *sql =
        "SELECT username FROM users WHERE online = 1;";
    sqlite3_stmt *read_stmt = NULL;
    int sqlite_status = sqlite3_prepare_v2(state->db, sql, -1, &read_stmt, NULL);
    if (sqlite_status != SQLITE_OK) {
      fprintf(stderr, "DB error in INSERT prepare: %s\n", sqlite3_errmsg(state->db));
      sqlite3_finalize(read_stmt);
      api_send(&state->api, "error: when getting the logged in users  \n");
      return -1;
    }

    int step = sqlite3_step(read_stmt);

    if (step == SQLITE_DONE) {
      api_send(&state->api, "no users online\n");
      sqlite3_finalize(read_stmt);
      return 0;
    }

    if (step != SQLITE_ROW) {
      fprintf(stderr, "DB error in /users step: %s\n", sqlite3_errmsg(state->db));
      sqlite3_finalize(read_stmt);
      api_send(&state->api, "error: internal error (/users)\n");
      return -1;
    }

    api_send(&state->api, "online users:\n");
    while(step == SQLITE_ROW){
      const unsigned char *username = sqlite3_column_text(read_stmt, 0);
      char buf[API_MAX_SERVER_MSG_LEN];
      snprintf(buf, sizeof(buf), " - %s\n", (const char *)username);
      api_send(&state->api, buf);
      step = sqlite3_step(read_stmt);
    }
    sqlite3_finalize(read_stmt);
      
    return 0;
  }
  /**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
  const char *sql =
        "SELECT id, "
        "       strftime('%Y-%m-%d %H:%M:%S', timestamp), "
        "       user, "
        "       message "
        "FROM messages "
        "where id > ? "
        "ORDER BY id ASC;";
  sqlite3_stmt *read_stmt = NULL;
    int sqlite_status = sqlite3_prepare_v2(state->db, sql, -1, &read_stmt, NULL);
    if (sqlite_status != SQLITE_OK) {
        return -1; 
    }

    sqlite3_bind_int64(read_stmt, 1, state->last_sent_msg);
  char buf[API_MAX_SERVER_MSG_LEN];
  while (sqlite3_step(read_stmt) == SQLITE_ROW) {
      int id = sqlite3_column_int(read_stmt, 0);
      const unsigned char *timestamp = sqlite3_column_text(read_stmt, 1);
      const unsigned char *user = sqlite3_column_text(read_stmt, 2);
      const unsigned char *message = sqlite3_column_text(read_stmt, 3);

      int n = snprintf(buf, sizeof(buf), " %s <%s>: %s\n",
                       timestamp,
                       user,
                       message);
      if (n < 0 || n >= sizeof(buf)) {
          sqlite3_finalize(read_stmt);
          return -1; 
      }

      if (SSL_write(state->ssl, buf, n) < 0) {
          sqlite3_finalize(read_stmt);
          return -1; 
      }
      state->last_sent_msg = id;
      
  }
  sqlite3_finalize(read_stmt);
  return 0;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
/* TODO call this function to notify other workers through server */
__attribute__((unused))
static int notify_workers(struct worker_state *state) {
  char buf = 0;
  ssize_t r;

  /* we only need to send something to notify the other workers,
   * data does not matter
   */
  r = write(state->server_fd, &buf, sizeof(buf));
  if (r < 0 && errno != EPIPE) {
    perror("error: write of server_fd failed");
    return -1;
  }
  return 0;
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(
  struct worker_state *state,
  const struct api_msg *msg) {

  const char *line = msg->data;

  if (strncmp(line, "/register", 9) == 0 &&
      (line[9] == '\0' || line[9] == ' ' || line[9] == '\t')) {
        char buf[API_MAX_SERVER_MSG_LEN];

        strncpy(buf, line, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        char *saveptr = NULL;
        strtok_r(buf, " \t", &saveptr);
        char *username = strtok_r(NULL, " \t", &saveptr);
        char *password = strtok_r(NULL, " \t", &saveptr);
        char *cert_str = strtok_r(NULL, " \t", &saveptr);

        BIO *bio = BIO_new_mem_buf(cert_str,strlen(cert_str));
        X509 *tmp_cert = PEM_read_bio_X509(bio,NULL,NULL,NULL);
        BIO_free(bio);

        if (!username || !password) {
          fprintf(stderr, "Error: missing username or password\n");
          api_send(&state->api, "error: missing username or password\n");
          return 0;
        } 
        if(!tmp_cert){
          fprintf(stderr, "Error: invalid certificate format\n");
          api_send(&state->api, "error: invalid certificate format\n");
          return 0;
        }
        if (!is_valid_username(username)) {
            fprintf(stderr, "Error: invalid username\n");
            api_send(&state->api, "error: invalid username\n");
            return 0;
        }
         if (!is_valid_password(password)) {
            fprintf(stderr, "Error: invalid password\n");
            api_send(&state->api, "error: invalid password\n");
            return 0;
         }
         if(!is_valid_certificate(state,tmp_cert)){
            X509_free(tmp_cert);
            fprintf(stderr, "Error: invalid certificate\n");
            api_send(&state->api, "error: invalid certificate");
         }

          return handle_register(state, username,password, tmp_cert);


    }

    if (strncmp(line, "/login", 6) == 0 &&
      (line[6] == '\0' || line[6] == ' ' || line[6] == '\t')) {
        char buf[API_MAX_SERVER_MSG_LEN];

        strncpy(buf, line, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        char *saveptr = NULL;
        strtok_r(buf, " \t", &saveptr);
        char *username = strtok_r(NULL, " \t", &saveptr);
        char *password = strtok_r(NULL, " \t", &saveptr);
        if (!username || !password) {
          fprintf(stderr, "Error: missing username or password\n");
          api_send(&state->api, "error: missing username or password\n");
        } else {
          return handle_login(state, username,password);
        }
    } 
    if (strncmp(line, "/users", 6) == 0 &&
      (line[6] == '\0' || line[6] == ' ' || line[6] == '\t')) {
        return handle_users(state);
    }
    if(state->logged_in_user_id == 0){
      api_send(&state->api, "error: you must be logged in\n");
      return 0;
    } 
    const char *sql = "INSERT INTO messages(user, message) VALUES(?, ?);";

    sqlite3_stmt *insert_stmt = NULL;
    sqlite3_prepare_v2(state->db, sql, strlen(sql), &insert_stmt, NULL);
    sqlite3_bind_text(insert_stmt, 1, state->current_username,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert_stmt, 2, msg->data, -1, SQLITE_TRANSIENT);//use input validation to prevent sql injection !!!!!
    int step_status = sqlite3_step(insert_stmt);
    if (step_status != SQLITE_DONE) {
      sqlite3_finalize(insert_stmt);
      return -1;
    }
    sqlite3_finalize(insert_stmt);

    notify_workers(state);
    return 0;
}

 




/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state *state) {
  struct api_msg msg;
  int r, success = 1;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(&state->api, &msg);
  if (r < 0) return -1;
  if (r == 0) {
    state->eof = 1;
    return 0;
  }

  /* execute request */
  if (execute_request(state, &msg) != 0) {
    success = 0;
  }

  /* clean up state associated with the message */
  api_recv_free(&msg);

  return success ? 0 : -1;
}

static int handle_s2w_read(struct worker_state *state) {
  char buf[256];
  ssize_t r;

  /* notification from the server that the workers must notify their clients
   * about new messages; these notifications are idempotent so the number
   * does not actually matter, nor does the data sent over the pipe
   */
  errno = 0;
  r = read(state->server_fd, buf, sizeof(buf));
  if (r < 0) {
    perror("error: read server_fd failed");
    return -1;
  }
  if (r == 0) {
    state->server_eof = 1;
    return 0;
  }

  /* notify our client */
  if (handle_s2w_notification(state) != 0) return -1;

  return 0;
}

/**
 * @brief Registers for: client request events, server notification
 *        events. In case of a client request, it processes the
 *        request and sends a response to client. In case of a server
 *        notification it notifies the client of all newly received
 *        messages.
 *
 */
static int handle_incoming(struct worker_state *state) {
  int fdmax, r, success = 1;
  fd_set readfds;

  assert(state);

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  /* wake on incoming messages from client */
  FD_SET(state->api.fd, &readfds);
  /* wake on incoming server notifications */
  if (!state->server_eof) FD_SET(state->server_fd, &readfds);
  fdmax = max(state->api.fd, state->server_fd);

  /* wait for at least one to become ready */
  r = select(fdmax+1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  /* TODO once you implement encryption you may need to call ssl_has_data
   * here due to buffering (see ssl-nonblock example)
   */
   if (state->api.use_tls && SSL_has_pending(state->ssl)){
    if (handle_client_request(state) !=0) success =0;
   }
  
  if (FD_ISSET(state->api.fd, &readfds)) {
    if (handle_client_request(state) != 0) success = 0;
  }
  if (FD_ISSET(state->server_fd, &readfds)) {
    if (handle_s2w_read(state) != 0) success = 0;
  }
  return success ? 0 : -1;
}

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param server_fd    File descriptor for socket to communicate
 *                     between server and worker
 */
static int worker_state_init(
  struct worker_state *state,
  int connfd,
  int server_fd, 
  EVP_PKEY *pkey,
  X509 *server_cert,
  X509 *ca_cert) {

  /* initialize */
  memset(state, 0, sizeof(*state));
  state->server_fd = server_fd;

  state->server_privatekey = pkey;
  state->server_cert = server_cert;
  state->ca_cert = ca_cert;
  
  /* set up API state */
  api_state_init(&state->api, connfd);

  /* TODO any additional worker state initialization */
  int sqlite_status = sqlite3_open("chat.db", &state->db);
  if (sqlite_status != SQLITE_OK) {
      fprintf(stderr, "error when opening database: %s\n",
              state->db ? sqlite3_errmsg(state->db) : "no handle");
      if (state->db) {
          sqlite3_close(state->db);
          state->db = NULL;
      }
      return -1;
  }

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  state->ssl_ctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_use_certificate(state->ssl_ctx, server_cert);
  SSL_CTX_use_PrivateKey(state->ssl_ctx, pkey);
  SSL_CTX_check_private_key(state->ssl_ctx);

  SSL_CTX_set_verify(state->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
  SSL_CTX_load_verify_locations(state->ssl_ctx, "serverkeys/ca-cert.pem", NULL);

  state->ssl = SSL_new(state->ssl_ctx);
  SSL_set_fd(state->ssl, state->api.fd);
  if (SSL_accept(state->ssl) <= 0){
    ERR_print_errors_fp(stderr);
    return -1;
  }

  state-> api.ssl = state->ssl;
  state->api.use_tls = 1;

  //maybe handle case of failures for both at the bottom here 
  init_db(state->db);
  readMessageHistory(state); 

  return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(
  struct worker_state *state) {
  /* TODO any additional worker state cleanup */
  if (state->logged_in_user_id != 0){
    const char *update_sql = "UPDATE users SET online = 0 WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(state->db, update_sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {

        sqlite3_bind_int(stmt, 1, state->logged_in_user_id);

        rc = sqlite3_step(stmt);

    }

    sqlite3_finalize(stmt);
  }

  if (state->db) {
      sqlite3_close(state->db);
      state->db = NULL;
  }
  
  /* clean up API state */
  api_state_free(&state->api);

  SSL_shutdown(state->ssl);
  SSL_free(state->ssl);
  SSL_CTX_free(state->ssl_ctx);

  /* close file descriptors */
  close(state->server_fd);
  close(state->api.fd);
}

/**
 * @brief              Worker entry point. Called by the server when a
 *                     worker is spawned.
 * @param connfd       File descriptor for connection socket
 * @param server_fd    File descriptor for socket to communicate
 *                     between server and worker
 */
__attribute__((noreturn))
void worker_start(
  int connfd,
  int server_fd,
  EVP_PKEY *pkey,
  X509 *server_cert,
  X509 *ca_cert) {

  struct worker_state state;
  int success = 1;

  
  /* initialize worker state */
  if (worker_state_init(&state, connfd, server_fd, pkey,server_cert, ca_cert) != 0) {
    goto cleanup;
  }
  /* TODO any additional worker initialization */
  setvbuf(stdout, NULL, _IONBF, 0);



  /* handle for incoming requests */
  while (!state.eof) {
    if (handle_incoming(&state) != 0) {
      success = 0;
      break;
    }
  }

cleanup:
  /* cleanup worker */
  /* TODO any additional worker cleanup */
  worker_state_free(&state);

  exit(success ? 0 : 1);
  }



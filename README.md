# Secure-programming

# Deadline A
Basic Chat Functionality
## client.c
Here we handle the different commands , for now we only handle /exit and whenever another one is written we tel the user that this is the wrong command. When CTRL + D is pressed or "/exit" is written we set the state of the end of file to 1 so that the while loops stops running and the cleanup is triggered. While this state is in 0 we continue handling incoming messages/ commands.

The client reads at most API_MAX_CLIENT_MSG_LEN bytes per line; public messages exceeding this limit are rejected with error: maximum message limit exceeded. Network send/recv errors are reported via perror() and then the client exits cleanly, while invalid or unknown commands produce a single-line error and the client continues running.

## worker.c/worker.h
Here we handle requests from the client and the server. Messages sent by client are stored on a file and the server is notified of any new messages. The worker listens for notifications from the server and sends any new messages to the client.

Deadline A Changes
We added an variable that keeps track of the last read line by the client so previous messages aren't resent.

Implemented the handle_srw_notification function that sends any new messages to client when a server notification is recieved by opening the messages file and jumping to lines with new messages.

Implemented the notify_workers function which sends an empty message to the server to notify that a client has sent a message.

Implemented the execute_request function which writes a users message along with a timestamp to a file, will later be changed to a database.


## api.c/api.h
api_recv can receive and store the  message from the sender. The message has a maximum length. api_send can send the message and gives an error message “error: api_send failed to send message” if it’s not possible.

# Deadline B
Secure Program Design

## Cryptography Overview
An overview of each type of message exchanged between client and server,
including whether cryptography is applied and how.

We use **two layers of protection**:

### Transport layer

All client–server communication runs over **TLS 1.3** (OpenSSL):

- Encrypts traffic.
- Detects tampering.
- Uses a **CA-signed certificate** to identify the server.

### Application layer (per-user keys)

On top of TLS, each user has an **RSA public/private key pair**:

- **Private key**: stored locally, encrypted with the user’s password.
- **Public key**: shared via the server so clients can look up each other’s keys.
- **Private messages**:
  - Encrypted with the recipient’s public key (end-to-end).
  - Signed with the sender’s private key.
- The server can verify signatures but only sees ciphertext for private messages.

## Which Messages Are Protected (and How)

All messages go **inside TLS 1.3** (encrypted in transit, integrity-checked).

### Client → Server

- **`/register <user> <pass>`**  
  Create account.  
  **Protection:** TLS only.

- **`/login <user> <pass>`**  
  Log in, bind connection to user.  
  **Protection:** TLS only.

- **`<text>`** — public message  
  Broadcast to all users.  
  **Protection:** TLS (optionally signed, not end-to-end; server sees plaintext).

- **`@user <text>`** — private message  
  Direct/private chat.  
  **Protection:** TLS + end-to-end encryption + signature (server stores/forwards ciphertext only).

- **`/users`** — list online users  
  **Protection:** TLS only.

- **`/exit`** — quit  
  **Protection:** TLS only.

- **`/passwd <old> <new>`** (optional)  
  Change password.  
  **Protection:** TLS only.

- **`/whoami`, `/ping`** (optional)  
  Helper commands.  
  **Protection:** TLS only.

### Server → Client

All responses are sent **inside TLS**.

- **Registration result (`ok` / `error`)** — TLS only.  
- **Login result (`ok` / `error`)** — TLS only.  

- **History replay**  
  - Public messages: plaintext at app layer, inside TLS.  
  - Private messages: ciphertext only; client decrypts locally.

- **Public delivery (broadcast messages)**  
  Plaintext at app layer, inside TLS.

- **Private delivery (direct messages)**  
  Ciphertext only; client decrypts and checks signature.

- **Users list (reply to `/users`)** — TLS only.  
- **Errors / notices** — TLS only.

## Key Distribution Overview
An overview of your approach to key distribution

We will use an asymmetric approach to key distribution. We will use RSA encryption in OpenSSL to secure all our communication. That means that there is a public and private key. First we generate a large number m between 1024-4096 bits. Then we calculate the public key e and private key d so that (n^e)^d=n (mod m) for any n. Alice and Bob both have their own public and private key. If Alice wants to send a message to Bob then she can derive the public key from a trusted third party that can verify Bob's identity. She computes Ee(m) and sends it to Bob. Bob can decrypt the message by computing Ed(Ee(m))=m. The messages will also have padding to lessen the amount of information that can be retained. 

## Security Requirements Overview
An explanation of how this addresses the requirements in Section 7

Our program will use:
1. Certificates recieved from a trusted third party
2. Encrypted commmunication for client server communications
3. End to end encryption for private messages

### Mallory cannot get information about private messages for which they are not either the sender or the intended recipient.

Mallory would not be able to access information about private messages because they will be end to end encrypted.
This prevents mallory from getting private message information because:
- Private messages will never be stored as plaintext on the server's database
- Only sender and intended recipient can decrypt the message using their private keys.
- All client-server communciations will be encrypted


### Mallory cannot send messages on behalf of another user.

To ensure that mallory can not send messages on behalf of another user we will sign each message with the users private key. The server will then verify the signature using the users public key. Since only the user has access to the private key this will ensure that any message sent from a user will be from that user.

### Mallory cannot modify messages sent by other users.

Mallory won't be able to modify any messages because users messages will be encrypted with the users signature and if the message is unmodified the server will recognize the signature as being invalid. This will ensure that the messages sent by the user will be unmodified when recieved by other users.

### Mallory cannot find out users’ passwords, private keys, or private messages.

- Mallory wont be able to find out user's passwords because password is only used to encrypt the users private key and is never stored anywhere. This will ensure that once a user creates a password it can never be recovered.
- Mallory wont be able to access a users private key because it will be encrypted using the users password, since only the user knows their password there will be no other way to decrypt it and gain access to the key. Additionaly users private keys will only be stored locally and never be sebent to the server.
- Mallory wont be able to access private messages because they will only be stored as cipher text, encrypted using the recipients public key, which only the recipient will be able to decrypt.
- Mallory can't get access to the passwords that are easy to guess becuase the password will be combined with salt before encrypting to make a salted hash. This will ensure that making a rainbow table is unfeasible.

### Conservative and Secure Design principals:
In order to ensure we meet the following Security requirements we will use Conservative and Secure design principals discussed in the lectures.
- Mallory cannot use the client or server programs to achieve privilege escalation on the systems they are running on.
- Mallory cannot leak or corrupt data in the client or server programs.
- Mallory cannot crash the client or server programs.
- The programs must never expose any information from the systems they run on, beyond what is required for the program to meet the requirements in the assignments.
- The programs must be unable to modify any files except for chat.db and the contents of the clientkeys and serverkeys directories, or any operating system settings, even if Mallory attempts to force it to do so.

#### Principals we plan on implementing:
- All user input will be properly sanitized as early as possible, checking that inputs are reasonable and within bounds. 
- All messages will have their lengths validated. All variables and states will be cleaned after use.
- Use safe functions when handling strings like snprintf
- Use asserts in the program.
- Check return value of functions for errors and properly handle them.
- When accessing databases we will use prepared statements or stored procedures.
- Always initialize pointers to avoid use after free attacks
- Server never runs on sudo
- SQLite is configured with sqlite3_busy_timeout to prevent corruption during concurrent writes by multiple workers.
- To prevent against a malicious server, every message will be signed with a clients private key, which the server will not have access to.
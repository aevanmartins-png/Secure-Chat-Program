# SecChat framework

This directory contains a starting point for building your secure chat program,
as well as a minimal test suite and a script to package your code
for submission. Existing files clearly mark with TODO where you are expected
to add code, but you are also allowed to alter other parts if needed.
We generally recommend to make such changes only where needed.
Below, we provide an overview of the relevant files.

## group.txt

Add this file to specify your group members and workload distribution.
It will be parsed automatically, so follow the format in the assignment exactly.
This is the only file allowed to contain any personal information.
No names, e-mail addresses, student numbers, VUNet IDs, etc. may be mentioned
in any other files.

## README.md

Add this file to provide the documentation required in the assignment.

## package.sh

Use this script to package your assignment before submission.
It performs basic tests to prevent submissions that are obviously
incomplete or incorrect.

## test/test.py

Use this script as a starting point to test your program. It builds and invokes
your server and client binaries a number of times and minimally verifies
the output. You should make sure you pass these tests, but just passing
the tests does not guarantee a good grade. You are encouraged to build better
tests yourself, following the guidance in the course material.

To test your program, go to the directory where your Makefile is and run:
`python3 test/test.py .`

## Makefile

This is the build system of your application. If you add source files,
you must list them here to include them in the build.
The Makefile also prepares the `clientkeys`, `serverkeys`, and `ttpkeys`
directories with all keys that must be generated before the program is used.

## client.c

This is the main program for the client. The core of the client is a loop
to handle incoming input from either stdin or the socket that connects it
to the server.

## server.c

This is the main program for the server. The core of the server is a loop
that waits for incoming connections or notifications from its workers.
This file does not handle chat data, whenever there is an incoming connection
it creates a worker process for that connection.

## worker.c/worker.h

This is where the actual server logic is. It handles incoming commands for
one connection, which corresponds to a single client. Any incoming messages
are stored in the database, and other workers are notified that they may
have work to do.

## api.c/api.h

The API handles the network protocol used by the client and server
to communicate with each other.

## ui.c/ui.h

The UI handles user input and output in the client.

## util.c/util.h

This file offers miscellaneous utility functions shared between
multiple source files.

## ttp.sh

You can use this script to implement the Trusted Third Party (TTP)
using OpenSSL commands. For convenience, we pretend that the TTP is
a separate server that we share a trusted communication channel with.
The TTP may generate keys, certificates, etc., but is not intended
to relay messages, keys, or certificates between server and client or
between client instances.

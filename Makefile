.PHONY: all clean generate_keys
.DEFAULT_GOAL := all

# ---------- file specification and configuration options ----------

# TODO specify all source files for the server here
SERVERSRC = server.c api.c util.c worker.c

# TODO specify all source files for the client here
CLIENTSRC = client.c api.c ui.c util.c

# TODO specify all key files that must be generated for the TTP here
# (all in the ttpkeys subdirectory)
TTPKEYS = ttpkeys/ca-key.pem ttpkeys/ca-cert.pem

# EXAMPLE:
#
# TTPKEYS = ttpkeys/ca-key.pem ttpkeys/ca-cert.pem

# TODO specify all key files that must be generated for the server here
# (all in the serverkeys subdirectory)
SERVERKEYS = serverkeys/server-key.pem serverkeys/server-cert.pem serverkeys/ca-cert

# TODO specify all key files that must be generated for the client here
# (all in the clientkeys subdirectory)
CLIENTKEYS = clientkeys/ca-cert.pem

# Specify compiler flags here
CFLAGS+=-g -Wall -Werror -UDEBUG
CFLAGS+=$(shell pkg-config --cflags openssl 2>/dev/null)
# Specify linker flags here
LDFLAGS+=-g $(shell pkg-config --libs-only-L openssl 2>/dev/null)


# Specify linker flags here
LDFLAGS+=-g $(shell pkg-config --libs-only-L openssl 2>/dev/null)

# Specify libraries to link to here (these should be sufficient)
LDLIBS=-lsqlite3 -lcrypto -lssl



# ---------- rules to build key files ----------

# TODO add rules to build the key files here. Note that, if one key file
# requires another to be built, you must specify it as a dependency.
# Make sure you use a tab character for indentation of build rules,
# spaces will not work

# EXAMPLE:
#
$(TTPKEYS):
	./ttp.sh create-ca
$(SERVERKEYS):
	./ttp.sh create-server



# ---------- there is usually no need to modify below this line ----------

# Generate object file lists from source files
CLIENTOBJ = $(CLIENTSRC:.c=.o)
SERVEROBJ = $(SERVERSRC:.c=.o)

# 'make all' builds everything
all: client server generate_keys

# 'make clean' removes everything that was built
clean:
	rm -f server client *.o *.d chat.db
	rm -rf serverkeys clientkeys ttpkeys

# boilerplate for key generation (the actual work is done in the code you add)
generate_keys: $(TTPKEYS) $(SERVERKEYS) $(CLIENTKEYS)

# generate the necessary directories
$(TTPKEYS): ttpkeys

ttpkeys:
	mkdir -p ttpkeys

$(SERVERKEYS): serverkeys

serverkeys:
	mkdir -p serverkeys

$(CLIENTKEYS): clientkeys

clientkeys:
	mkdir -p clientkeys

# link the binaries
client: $(CLIENTOBJ)
	$(CC) $(LDFLAGS) -o $@ $(CLIENTOBJ) $(LDLIBS)

server: $(SERVEROBJ)
	$(CC) $(LDFLAGS) -o $@ $(SERVEROBJ) $(LDLIBS)

# rule to compile object files from C files, while generating a dependency file
# that is used to recompile it if any of the included headers changes
%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# include generated dependency files into the Makefile
DEPS = $(CLIENTSRC:.c=.d) $(SERVERSRC:.c=.d)
-include $(DEPS)

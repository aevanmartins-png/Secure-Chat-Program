#!/bin/sh

set -e
  
mkdir -p ttpkeys
mkdir -p serverkeys
mkdir -p clientkeys

# Creates Certificate authority key and certificate
if [ "$1" = "create-ca" ]; then
    echo "Generating CA key and certificate"

    openssl genrsa -out ttpkeys/ca-key.pem 2048
    echo "CA private key generated"

    openssl req -new -x509 -key "ttpkeys/ca-key.pem" -out ttpkeys/ca-cert.pem  \
                -nodes -subj "/C=NL/ST=Noord-Holland/L=Amsterdam/O=SecChat/OU=CA/CN=SecChat-CA"


    cp "ttpkeys/ca-cert.pem" "serverkeys/"
    cp "ttpkeys/ca-cert.pem" "clientkeys/"
    echo "CA certificate generated"
    exit 0

fi

if [ "$1" = "create-server" ]; then

    echo "Generating server key and certificate..."

    #Generate Server Key
    openssl genrsa -out serverkeys/server-key.pem 2048

    echo "Server private key generated"
    
    #Create and sign server certificate
    openssl req -new -key serverkeys/server-key.pem -out serverkeys/server-csr.pem
    openssl x509 -req -CA ttpkeys/ca-cert.pem -CAkey ttpkeys/ca-key.pem \
    -CAcreateserial -in serverkeys/server-csr.pem -out serverkeys/server-cert.pem

    echo "Server certificate generated"

    rm serverkeys/server-csr.pem
    exit 0
fi

if [ "$1" = "create-user" ]; then

    USER="$2"

    #Generate client key
    openssl genrsa -out clientkeys/$USER-key.pem

    #Generate client certificate
    openssl req -new -key clientkeys/$USER-key.pem -out clientkeys/$USER-csr.pem
    openssl x509 -req -CA ttpkeys/ca-cert.pem -CAkey ttpkeys/ca-key.pem \
    -CAcreateserial -in clientkeys/$USER-csr.pem -out clientkeys/$USER-cert.pem

    rm clientkeys/$USER-csr.pem   

    exit 0


fi



exit 1




# TODO implement trusted third party here, using OpenSSL command line tools

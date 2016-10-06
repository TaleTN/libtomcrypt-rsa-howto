#!/bin/bash
openssl rsa -inform DER -in private_key.der -outform PEM -out private_key.pem
openssl rsa -inform DER -in private_key.der -pubout -outform PEM -out public_key.pem

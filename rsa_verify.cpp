/* Copyright (C) 2015-2023 Theo Niessink <theo@taletn.com>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include <stdio.h>
#include <string.h>

#include <tomcrypt.h>
#include "error.h"

#define MAX_RSA_SIZE 4096 // bits

int main(int argc, char** argv)
{
	// Usage: rsa_verify "<message>" <signature file> <public key file>
	const char* msg = ARGV(1);
	const char* signature = ARGV(2);
	const char* public_key = ARGV(3);

	ltc_mp = ltm_desc;

	// Read public key.
	FILE* f = fopen(public_key, "rb");
	if (!f) return error(CRYPT_FILE_NOTFOUND);
	unsigned char buf[MAX_RSA_SIZE * 100 / 512]; // guesstimate
	unsigned long buflen = (unsigned long)fread(buf, 1, sizeof(buf), f);
	fclose(f);
	if (!buflen) return error(CRYPT_ERROR);

	// Import DER key.
	rsa_key key;
	int err = rsa_import(buf, buflen, &key);
	if (err != CRYPT_OK) return error(err);

	// Read signature.
	f = fopen(signature, "r");
	if (!f) return error(CRYPT_FILE_NOTFOUND, &key);
	buflen = (unsigned long)fread(buf, 1, sizeof(buf), f);
	fclose(f);
	if (!buflen) return error(CRYPT_ERROR, &key);

	// Decode signature.
	unsigned char sig[MAX_RSA_SIZE / 8];
	unsigned long siglen = sizeof(sig);
	err = base64_decode((const char*)buf, buflen, sig, &siglen);
	if (err != CRYPT_OK) return error(err, &key);

	// Register hash algorithm.
	const ltc_hash_descriptor& hash_desc = sha512_desc;
	const int hash_idx = register_hash(&hash_desc);
	if (hash_idx < 0) return error(CRYPT_INVALID_HASH, &key);

	// Hash message.
	unsigned char hash[64];
	hash_state md;
	hash_desc.init(&md);
	hash_desc.process(&md, (const unsigned char*)msg, (unsigned long)strlen(msg));
	hash_desc.done(&md, hash);

	// Define padding scheme.
	const int padding = LTC_PKCS_1_V1_5;
	const unsigned long saltlen = 0;

	// Verify signature.
	int stat = 0;
	err = rsa_verify_hash_ex(sig, siglen, hash, hash_desc.hashsize, padding, hash_idx, saltlen, &stat, &key);
	rsa_free(&key);
	if (err != CRYPT_OK) return error(err);
	if (!stat) return error("Invalid signature");

	return error(CRYPT_OK, stdout);
}

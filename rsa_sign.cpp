/* Copyright (C) 2015 Theo Niessink <theo@taletn.com>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include <stdio.h>
#include <string.h>

#include <tomcrypt.h>
#include "error.h"

int main(int argc, char** argv)
{
	// Usage: rsa_sign "<message>" <private key file>
	const char* msg = ARGV(1);
	const char* private_key = ARGV(2);

	ltc_mp = ltm_desc;

	// Read private key.
	FILE* f = fopen(private_key, "rb");
	if (!f) return error(CRYPT_FILE_NOTFOUND);
	unsigned char buf[MAX_RSA_SIZE * 5 / 8]; // guesstimate
	unsigned long buflen = (unsigned long)fread(buf, 1, sizeof(buf), f);
	fclose(f);
	if (!buflen) return error(CRYPT_ERROR);

	// Import DER key.
	rsa_key key;
	int err = rsa_import(buf, buflen, &key);
	if (err != CRYPT_OK) return error(err);

	// Register hash algorithm.
	const ltc_hash_descriptor& hash_desc = sha512_desc;
	const int hash_idx = register_hash(&hash_desc);
	if (hash_idx < 0) return error(CRYPT_INVALID_HASH, &key);

	// Hash message.
	unsigned char hash[MAXBLOCKSIZE];
	hash_state md;
	hash_desc.init(&md);
	hash_desc.process(&md, (const unsigned char*)msg, (unsigned long)strlen(msg));
	hash_desc.done(&md, hash);

	// Define padding scheme.
	const int padding = LTC_PKCS_1_V1_5;
	const unsigned long saltlen = 0;

	// Register PRNG algorithm (PSS only).
	const int prng_idx = padding == LTC_PKCS_1_PSS ? register_prng(&sprng_desc) : 0;
	if (prng_idx < 0) return error(CRYPT_INVALID_PRNG, &key);

	// Sign hash.
	unsigned char sig[MAX_RSA_SIZE / 8];
	unsigned long siglen = sizeof(sig);
	err = rsa_sign_hash_ex(hash, hash_desc.hashsize, sig, &siglen, padding, NULL, prng_idx, hash_idx, saltlen, &key);
	if (err != CRYPT_OK) return error(err, &key);
	rsa_free(&key);

	// Encode signature.
	buflen = sizeof(buf);
	base64_encode(sig, siglen, buf, &buflen);
	for (int i = 0, n = buflen; i < n; ++i)
	{
		putchar(buf[i]);
		if ((i & 63) == 63) putchar('\n');
	}
	if (buflen & 63) putchar('\n');

	return 0;
}

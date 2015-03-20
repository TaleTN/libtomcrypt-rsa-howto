/* Copyright (C) 2015 Theo Niessink <theo@taletn.com>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include <stdio.h>

#include <tomcrypt.h>
#include "error.h"

int main(int argc, char** argv)
{
	// Usage: rsa_make_key <private key file> <public key file>
	const char* private_key = ARGV(1);
	const char* public_key = ARGV(2);

	ltc_mp = ltm_desc;

	// Register PRNG algorithm.
	const int prng_idx = register_prng(&sprng_desc);
	if (prng_idx < 0) return error(CRYPT_INVALID_PRNG);

	// Generate key.
	rsa_key key;
	const int bitsize = 2048;
	int err = rsa_make_key(NULL, prng_idx, bitsize/8, 65537, &key);
	if (err != CRYPT_OK) return error(err);

	// Export private key.
	unsigned char out[bitsize * 5 / 8]; // guesstimate
	unsigned long outlen = sizeof(out);
	err = rsa_export(out, &outlen, PK_PRIVATE, &key);
	if (err != CRYPT_OK) return error(err, &key);

	// Save private key.
	FILE* f = fopen(private_key, "wb");
	if (!f) return error(CRYPT_FILE_NOTFOUND, &key);
	outlen = (unsigned long)fwrite(out, 1, outlen, f);
	fclose(f);
	if (!outlen) return error(CRYPT_ERROR, &key);

	// Export public key.
	outlen = sizeof(out);
	err = rsa_export(out, &outlen, PK_PUBLIC, &key);
	if (err != CRYPT_OK) return error(err, &key);

	// Save public key.
	f = fopen(public_key, "wb");
	if (!f) return error(CRYPT_FILE_NOTFOUND, &key);
	outlen = (unsigned long)fwrite(out, 1, outlen, f);
	fclose(f);
	if (!outlen) return error(CRYPT_ERROR, &key);

	rsa_free(&key);
	return 0;
}

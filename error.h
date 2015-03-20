/* Copyright (C) 2015 Theo Niessink <theo@taletn.com>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#define ARGV(i) (argc > (i) ? argv[i] : "")

int error(const char* str, int err = CRYPT_ERROR, FILE* stream = stderr)
{
	fprintf(stream, "%s\n", str);
	return err;
}

int error(int err, rsa_key *key, FILE* stream = stderr)
{
	if (key) rsa_free(key);
	return error(error_to_string(err), err, stream);
}

int error(int err, FILE* stream = stderr)
{
	return error(err, NULL, stream);
}

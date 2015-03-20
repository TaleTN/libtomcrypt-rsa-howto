/* Copyright (C) 2015 Theo Niessink <theo@taletn.com>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include <stdio.h>

#define ARGV(i) (argc > (i) ? argv[i] : "")

int error(const char* str, int err = 1, FILE* stream = stderr)
{
	fprintf(stream, "%s\n", str);
	return err;
}

int main(int argc, char** argv)
{
	// Usage: dertoh <public key file> [<array name>] > <C header file>
	const char* public_key = ARGV(1);
	const char* array_name = ARGV(2);

	FILE* f = fopen(public_key, "rb");
	if (!f) return error("File not found");
	unsigned char buf[400]; // 2048 bits
	int len = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	if (!len) return error("Read error");

	if (*array_name) printf("const unsigned char %s[%d] =\n{\n", array_name, len);
	for (int i = 0; i < len;)
	{
		if (i % 12) putchar(' '); else
		{
			if (i > 0) putchar('\n');
			if (*array_name) putchar('\t');
		}
		printf("0x%02x", buf[i++]);
		putchar(i < len ? ',' : '\n');
	}
	if (*array_name) printf("};\n");

	return 0;
}

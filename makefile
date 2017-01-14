# Copyright (C) 2015-2017 Theo Niessink <theo@taletn.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the LICENSE file for more details.

CFLAGS = -O2 -fno-stack-protector -DNDEBUG -Wall

LTM_OBJECTS = \
libtommath/bncore.o \
libtommath/bn_mp_init.o \
libtommath/bn_mp_clear.o \
libtommath/bn_mp_exch.o \
libtommath/bn_mp_grow.o \
libtommath/bn_mp_clamp.o \
libtommath/bn_mp_zero.o \
libtommath/bn_mp_set.o \
libtommath/bn_mp_set_int.o \
libtommath/bn_mp_init_size.o \
libtommath/bn_mp_copy.o \
libtommath/bn_mp_init_copy.o \
libtommath/bn_mp_abs.o \
libtommath/bn_mp_neg.o \
libtommath/bn_mp_cmp_mag.o \
libtommath/bn_mp_cmp.o \
libtommath/bn_mp_cmp_d.o \
libtommath/bn_mp_rshd.o \
libtommath/bn_mp_lshd.o \
libtommath/bn_mp_mod_2d.o \
libtommath/bn_mp_div_2d.o \
libtommath/bn_mp_mul_2d.o \
libtommath/bn_mp_div_2.o \
libtommath/bn_mp_mul_2.o \
libtommath/bn_s_mp_add.o \
libtommath/bn_s_mp_sub.o \
libtommath/bn_fast_s_mp_mul_digs.o \
libtommath/bn_s_mp_mul_digs.o \
libtommath/bn_fast_s_mp_mul_high_digs.o \
libtommath/bn_s_mp_mul_high_digs.o \
libtommath/bn_fast_s_mp_sqr.o \
libtommath/bn_s_mp_sqr.o \
libtommath/bn_mp_add.o \
libtommath/bn_mp_sub.o \
libtommath/bn_mp_karatsuba_mul.o \
libtommath/bn_mp_mul.o \
libtommath/bn_mp_karatsuba_sqr.o \
libtommath/bn_mp_sqr.o \
libtommath/bn_mp_div.o \
libtommath/bn_mp_mod.o \
libtommath/bn_mp_add_d.o \
libtommath/bn_mp_sub_d.o \
libtommath/bn_mp_mul_d.o \
libtommath/bn_mp_div_d.o \
libtommath/bn_mp_mod_d.o \
libtommath/bn_mp_addmod.o \
libtommath/bn_mp_submod.o \
libtommath/bn_mp_mulmod.o \
libtommath/bn_mp_sqrmod.o \
libtommath/bn_mp_gcd.o \
libtommath/bn_mp_lcm.o \
libtommath/bn_fast_mp_invmod.o \
libtommath/bn_mp_invmod.o \
libtommath/bn_mp_reduce.o \
libtommath/bn_mp_montgomery_setup.o \
libtommath/bn_fast_mp_montgomery_reduce.o \
libtommath/bn_mp_montgomery_reduce.o \
libtommath/bn_mp_exptmod_fast.o \
libtommath/bn_mp_exptmod.o \
libtommath/bn_mp_2expt.o \
libtommath/bn_reverse.o \
libtommath/bn_mp_count_bits.o \
libtommath/bn_mp_read_unsigned_bin.o \
libtommath/bn_mp_to_unsigned_bin.o \
libtommath/bn_mp_unsigned_bin_size.o \
libtommath/bn_mp_rand.o \
libtommath/bn_mp_montgomery_calc_normalization.o \
libtommath/bn_mp_prime_is_divisible.o \
libtommath/bn_prime_tab.o \
libtommath/bn_mp_prime_miller_rabin.o \
libtommath/bn_mp_prime_is_prime.o \
libtommath/bn_mp_dr_reduce.o \
libtommath/bn_mp_dr_is_modulus.o \
libtommath/bn_mp_dr_setup.o \
libtommath/bn_mp_reduce_setup.o \
libtommath/bn_mp_toom_mul.o \
libtommath/bn_mp_toom_sqr.o \
libtommath/bn_mp_div_3.o \
libtommath/bn_s_mp_exptmod.o \
libtommath/bn_mp_reduce_2k.o \
libtommath/bn_mp_reduce_is_2k.o \
libtommath/bn_mp_reduce_2k_setup.o \
libtommath/bn_mp_reduce_2k_l.o \
libtommath/bn_mp_reduce_is_2k_l.o \
libtommath/bn_mp_reduce_2k_setup_l.o \
libtommath/bn_mp_radix_smap.o \
libtommath/bn_mp_read_radix.o \
libtommath/bn_mp_toradix.o \
libtommath/bn_mp_cnt_lsb.o \
libtommath/bn_mp_init_multi.o \
libtommath/bn_mp_clear_multi.o \
libtommath/bn_mp_get_int.o \
libtommath/bn_mp_invmod_slow.o

LTM_HEADERS = \
libtommath/tommath.h \
libtommath/tommath_class.h \
libtommath/tommath_private.h \
libtommath/tommath_superclass.h

LTC_OBJECTS = \
libtomcrypt/src/hashes/md2.o \
libtomcrypt/src/hashes/md5.o \
libtomcrypt/src/hashes/sha1.o \
libtomcrypt/src/hashes/sha2/sha256.o \
libtomcrypt/src/hashes/sha2/sha512.o \
libtomcrypt/src/math/ltm_desc.o \
libtomcrypt/src/math/multi.o \
libtomcrypt/src/math/rand_prime.o \
libtomcrypt/src/misc/base64/base64_decode.o \
libtomcrypt/src/misc/base64/base64_encode.o \
libtomcrypt/src/misc/crypt/crypt_argchk.o \
libtomcrypt/src/misc/crypt/crypt_hash_descriptor.o \
libtomcrypt/src/misc/crypt/crypt_hash_is_valid.o \
libtomcrypt/src/misc/crypt/crypt_ltc_mp_descriptor.o \
libtomcrypt/src/misc/crypt/crypt_prng_descriptor.o \
libtomcrypt/src/misc/crypt/crypt_prng_is_valid.o \
libtomcrypt/src/misc/crypt/crypt_register_hash.o \
libtomcrypt/src/misc/crypt/crypt_register_prng.o \
libtomcrypt/src/misc/error_to_string.o \
libtomcrypt/src/misc/pk_get_oid.o \
libtomcrypt/src/misc/zeromem.o \
libtomcrypt/src/pk/asn1/der/bit/der_decode_bit_string.o \
libtomcrypt/src/pk/asn1/der/bit/der_encode_bit_string.o \
libtomcrypt/src/pk/asn1/der/bit/der_decode_raw_bit_string.o \
libtomcrypt/src/pk/asn1/der/bit/der_encode_raw_bit_string.o \
libtomcrypt/src/pk/asn1/der/bit/der_length_bit_string.o \
libtomcrypt/src/pk/asn1/der/boolean/der_decode_boolean.o \
libtomcrypt/src/pk/asn1/der/boolean/der_encode_boolean.o \
libtomcrypt/src/pk/asn1/der/boolean/der_length_boolean.o \
libtomcrypt/src/pk/asn1/der/choice/der_decode_choice.o \
libtomcrypt/src/pk/asn1/der/ia5/der_decode_ia5_string.o \
libtomcrypt/src/pk/asn1/der/ia5/der_encode_ia5_string.o \
libtomcrypt/src/pk/asn1/der/ia5/der_length_ia5_string.o \
libtomcrypt/src/pk/asn1/der/integer/der_decode_integer.o \
libtomcrypt/src/pk/asn1/der/integer/der_encode_integer.o \
libtomcrypt/src/pk/asn1/der/integer/der_length_integer.o \
libtomcrypt/src/pk/asn1/der/object_identifier/der_decode_object_identifier.o \
libtomcrypt/src/pk/asn1/der/object_identifier/der_encode_object_identifier.o \
libtomcrypt/src/pk/asn1/der/object_identifier/der_length_object_identifier.o \
libtomcrypt/src/pk/asn1/der/octet/der_decode_octet_string.o \
libtomcrypt/src/pk/asn1/der/octet/der_encode_octet_string.o \
libtomcrypt/src/pk/asn1/der/octet/der_length_octet_string.o \
libtomcrypt/src/pk/asn1/der/printable_string/der_decode_printable_string.o \
libtomcrypt/src/pk/asn1/der/printable_string/der_encode_printable_string.o \
libtomcrypt/src/pk/asn1/der/printable_string/der_length_printable_string.o \
libtomcrypt/src/pk/asn1/der/sequence/der_decode_sequence_ex.o \
libtomcrypt/src/pk/asn1/der/sequence/der_decode_sequence_multi.o \
libtomcrypt/src/pk/asn1/der/sequence/der_decode_subject_public_key_info.o \
libtomcrypt/src/pk/asn1/der/sequence/der_encode_sequence_ex.o \
libtomcrypt/src/pk/asn1/der/sequence/der_encode_sequence_multi.o \
libtomcrypt/src/pk/asn1/der/sequence/der_encode_subject_public_key_info.o \
libtomcrypt/src/pk/asn1/der/sequence/der_length_sequence.o \
libtomcrypt/src/pk/asn1/der/set/der_encode_set.o \
libtomcrypt/src/pk/asn1/der/set/der_encode_setof.o \
libtomcrypt/src/pk/asn1/der/short_integer/der_decode_short_integer.o \
libtomcrypt/src/pk/asn1/der/short_integer/der_encode_short_integer.o \
libtomcrypt/src/pk/asn1/der/short_integer/der_length_short_integer.o \
libtomcrypt/src/pk/asn1/der/utctime/der_decode_utctime.o \
libtomcrypt/src/pk/asn1/der/utctime/der_encode_utctime.o \
libtomcrypt/src/pk/asn1/der/utctime/der_length_utctime.o \
libtomcrypt/src/pk/asn1/der/utf8/der_decode_utf8_string.o \
libtomcrypt/src/pk/asn1/der/utf8/der_encode_utf8_string.o \
libtomcrypt/src/pk/asn1/der/utf8/der_length_utf8_string.o \
libtomcrypt/src/pk/ecc/ltc_ecc_map.o \
libtomcrypt/src/pk/ecc/ltc_ecc_mul2add.o \
libtomcrypt/src/pk/ecc/ltc_ecc_mulmod.o \
libtomcrypt/src/pk/ecc/ltc_ecc_points.o \
libtomcrypt/src/pk/ecc/ltc_ecc_projective_add_point.o \
libtomcrypt/src/pk/ecc/ltc_ecc_projective_dbl_point.o \
libtomcrypt/src/pk/pkcs1/pkcs_1_mgf1.o \
libtomcrypt/src/pk/pkcs1/pkcs_1_pss_decode.o \
libtomcrypt/src/pk/pkcs1/pkcs_1_pss_encode.o \
libtomcrypt/src/pk/pkcs1/pkcs_1_v1_5_decode.o \
libtomcrypt/src/pk/pkcs1/pkcs_1_v1_5_encode.o \
libtomcrypt/src/pk/rsa/rsa_export.o \
libtomcrypt/src/pk/rsa/rsa_exptmod.o \
libtomcrypt/src/pk/rsa/rsa_free.o \
libtomcrypt/src/pk/rsa/rsa_import.o \
libtomcrypt/src/pk/rsa/rsa_make_key.o \
libtomcrypt/src/pk/rsa/rsa_sign_hash.o \
libtomcrypt/src/pk/rsa/rsa_verify_hash.o \
libtomcrypt/src/prngs/rng_get_bytes.o \
libtomcrypt/src/prngs/sprng.o

LTC_HEADERS = \
libtomcrypt/src/headers/tomcrypt_cfg.h \
libtomcrypt/src/headers/tomcrypt_mac.h \
libtomcrypt/src/headers/tomcrypt_macros.h \
libtomcrypt/src/headers/tomcrypt_custom.h \
libtomcrypt/src/headers/tomcrypt_argchk.h \
libtomcrypt/src/headers/tomcrypt_cipher.h \
libtomcrypt/src/headers/tomcrypt_pk.h \
libtomcrypt/src/headers/tomcrypt_hash.h \
libtomcrypt/src/headers/tomcrypt_math.h \
libtomcrypt/src/headers/tomcrypt_misc.h \
libtomcrypt/src/headers/tomcrypt.h \
libtomcrypt/src/headers/tomcrypt_pkcs.h \
libtomcrypt/src/headers/tomcrypt_prng.h \
libtomcrypt/src/hashes/sha2/sha224.c \
libtomcrypt/src/hashes/sha2/sha384.c

default: libtommath libtomcrypt

libtommath/%.o: libtommath/%.c
	$(CC) $(CFLAGS) -I./libtommath -o $@ -c $<

libtommath: $(LTM_OBJECTS)

LTC_CFLAGS = $(CFLAGS) -Ilibtomcrypt/src/headers -Ilibtommath -DLTC_SOURCE -DLTM_DESC -o $@

libtomcrypt/%.o: libtomcrypt/%.c
	$(CC) $(LTC_CFLAGS) -c $<

#ciphers come in two flavours... enc+dec and enc
libtomcrypt/src/ciphers/aes/aes_enc.o: libtomcrypt/src/ciphers/aes/aes.c libtomcrypt/src/ciphers/aes/aes_tab.c
	$(CC) $(LTC_CFLAGS) -DENCRYPT_ONLY -c libtomcrypt/src/ciphers/aes/aes.c

libtomcrypt: $(LTC_OBJECTS)

CXXFLAGS = $(CFLAGS) -fno-rtti -Ilibtomcrypt/src/headers -DLTM_DESC
LT_OBJECTS = $(LTM_OBJECTS) $(LTC_OBJECTS)

rsa_make_key: rsa_make_key.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LT_OBJECTS)

key: rsa_make_key
	./rsa_make_key private_key.der public_key.der

rsa_sign: rsa_sign.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LT_OBJECTS)

sign: rsa_sign
	./rsa_sign "hello, world" private_key.der > signature.txt
	@cat signature.txt

rsa_verify: rsa_verify.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LT_OBJECTS)

verify: rsa_verify
	./rsa_verify "hello, world" signature.txt public_key.der

test: sign verify

.PHONY: dertoh
dertoh: dertoh.cpp
	$(CXX) $(CFLAGS) -o $@ $^
	./dertoh public_key.der public_key > public_key.h

clean:
	rm -f `find . -type f | grep "[.]o" | xargs`
	rm -f rsa_make_key rsa_sign rsa_verify dertoh private_key.der public_key.der signature.txt

patch:
	git apply --whitespace=fix patches/0001-der-fixes-and-additions.patch
	git apply --whitespace=fix patches/0002-dsa-fix-compiler-warning.patch
	git apply --whitespace=fix patches/0003-ecc-fix-compiler-warnings.patch
	git apply --whitespace=fix patches/0004-include-stddef.h-per-default.patch
	git apply --whitespace=fix patches/0005-der_encode_setof-fix-compiler-warning-when-compiling.patch
	git apply --whitespace=fix patches/0006-fix-clang-compiler-warnings.patch
	git apply --whitespace=fix patches/0007-only-use-ulong32-or-ulong64-in-the-macros.patch
	git apply --whitespace=fix patches/0008-adjust-inline-asm-requiring-constants.patch

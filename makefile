# Copyright (C) 2015-2023 Theo Niessink <theo@taletn.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the LICENSE file for more details.

CFLAGS = -O2 -fno-stack-protector -DNDEBUG -Wall

LTM_OBJECTS = \
libtommath/mp_2expt.o \
libtommath/mp_abs.o \
libtommath/mp_add.o \
libtommath/mp_add_d.o \
libtommath/mp_addmod.o \
libtommath/mp_and.o \
libtommath/mp_clamp.o \
libtommath/mp_clear.o \
libtommath/mp_clear_multi.o \
libtommath/mp_cmp.o \
libtommath/mp_cmp_d.o \
libtommath/mp_cmp_mag.o \
libtommath/mp_cnt_lsb.o \
libtommath/mp_complement.o \
libtommath/mp_copy.o \
libtommath/mp_count_bits.o \
libtommath/mp_cutoffs.o \
libtommath/mp_div.o \
libtommath/mp_div_2.o \
libtommath/mp_div_2d.o \
libtommath/mp_div_d.o \
libtommath/mp_dr_is_modulus.o \
libtommath/mp_dr_reduce.o \
libtommath/mp_dr_setup.o \
libtommath/mp_error_to_string.o \
libtommath/mp_exch.o \
libtommath/mp_expt_n.o \
libtommath/mp_exptmod.o \
libtommath/mp_exteuclid.o \
libtommath/mp_fread.o \
libtommath/mp_from_sbin.o \
libtommath/mp_from_ubin.o \
libtommath/mp_fwrite.o \
libtommath/mp_gcd.o \
libtommath/mp_get_double.o \
libtommath/mp_get_i32.o \
libtommath/mp_get_i64.o \
libtommath/mp_get_l.o \
libtommath/mp_get_mag_u32.o \
libtommath/mp_get_mag_u64.o \
libtommath/mp_get_mag_ul.o \
libtommath/mp_grow.o \
libtommath/mp_hash.o \
libtommath/mp_init.o \
libtommath/mp_init_copy.o \
libtommath/mp_init_i32.o \
libtommath/mp_init_i64.o \
libtommath/mp_init_l.o \
libtommath/mp_init_multi.o \
libtommath/mp_init_set.o \
libtommath/mp_init_size.o \
libtommath/mp_init_u32.o \
libtommath/mp_init_u64.o \
libtommath/mp_init_ul.o \
libtommath/mp_invmod.o \
libtommath/mp_is_square.o \
libtommath/mp_kronecker.o \
libtommath/mp_lcm.o \
libtommath/mp_log.o \
libtommath/mp_log_n.o \
libtommath/mp_lshd.o \
libtommath/mp_mod.o \
libtommath/mp_mod_2d.o \
libtommath/mp_montgomery_calc_normalization.o \
libtommath/mp_montgomery_reduce.o \
libtommath/mp_montgomery_setup.o \
libtommath/mp_mul.o \
libtommath/mp_mul_2.o \
libtommath/mp_mul_2d.o \
libtommath/mp_mul_d.o \
libtommath/mp_mulmod.o \
libtommath/mp_neg.o \
libtommath/mp_or.o \
libtommath/mp_pack.o \
libtommath/mp_pack_count.o \
libtommath/mp_prime_fermat.o \
libtommath/mp_prime_frobenius_underwood.o \
libtommath/mp_prime_is_prime.o \
libtommath/mp_prime_miller_rabin.o \
libtommath/mp_prime_next_prime.o \
libtommath/mp_prime_rabin_miller_trials.o \
libtommath/mp_prime_rand.o \
libtommath/mp_prime_strong_lucas_selfridge.o \
libtommath/mp_radix_size.o \
libtommath/mp_radix_size_overestimate.o \
libtommath/mp_rand.o \
libtommath/mp_rand_source.o \
libtommath/mp_read_radix.o \
libtommath/mp_reduce.o \
libtommath/mp_reduce_2k.o \
libtommath/mp_reduce_2k_l.o \
libtommath/mp_reduce_2k_setup.o \
libtommath/mp_reduce_2k_setup_l.o \
libtommath/mp_reduce_is_2k.o \
libtommath/mp_reduce_is_2k_l.o \
libtommath/mp_reduce_setup.o \
libtommath/mp_root_n.o \
libtommath/mp_rshd.o \
libtommath/mp_sbin_size.o \
libtommath/mp_set.o \
libtommath/mp_set_double.o \
libtommath/mp_set_i32.o \
libtommath/mp_set_i64.o \
libtommath/mp_set_l.o \
libtommath/mp_set_u32.o \
libtommath/mp_set_u64.o \
libtommath/mp_set_ul.o \
libtommath/mp_shrink.o \
libtommath/mp_signed_rsh.o \
libtommath/mp_sqrmod.o \
libtommath/mp_sqrt.o \
libtommath/mp_sqrtmod_prime.o \
libtommath/mp_sub.o \
libtommath/mp_sub_d.o \
libtommath/mp_submod.o \
libtommath/mp_to_radix.o \
libtommath/mp_to_sbin.o \
libtommath/mp_to_ubin.o \
libtommath/mp_ubin_size.o \
libtommath/mp_unpack.o \
libtommath/mp_xor.o \
libtommath/mp_zero.o \
libtommath/s_mp_add.o \
libtommath/s_mp_copy_digs.o \
libtommath/s_mp_div_3.o \
libtommath/s_mp_div_recursive.o \
libtommath/s_mp_div_school.o \
libtommath/s_mp_div_small.o \
libtommath/s_mp_exptmod.o \
libtommath/s_mp_exptmod_fast.o \
libtommath/s_mp_fp_log.o \
libtommath/s_mp_fp_log_d.o \
libtommath/s_mp_get_bit.o \
libtommath/s_mp_invmod.o \
libtommath/s_mp_invmod_odd.o \
libtommath/s_mp_log_2expt.o \
libtommath/s_mp_montgomery_reduce_comba.o \
libtommath/s_mp_mul.o \
libtommath/s_mp_mul_balance.o \
libtommath/s_mp_mul_comba.o \
libtommath/s_mp_mul_high.o \
libtommath/s_mp_mul_high_comba.o \
libtommath/s_mp_mul_karatsuba.o \
libtommath/s_mp_mul_toom.o \
libtommath/s_mp_prime_is_divisible.o \
libtommath/s_mp_prime_tab.o \
libtommath/s_mp_radix_map.o \
libtommath/s_mp_radix_size_overestimate.o \
libtommath/s_mp_rand_platform.o \
libtommath/s_mp_sqr.o \
libtommath/s_mp_sqr_comba.o \
libtommath/s_mp_sqr_karatsuba.o \
libtommath/s_mp_sqr_toom.o \
libtommath/s_mp_sub.o \
libtommath/s_mp_zero_buf.o \
libtommath/s_mp_zero_digs.o

LTM_HEADERS = \
libtommath/tommath.h \
libtommath/tommath_class.h \
libtommath/tommath_cutoffs.h \
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
libtomcrypt/src/misc/compare_testvector.o \
libtomcrypt/src/misc/crypt/crypt_argchk.o \
libtomcrypt/src/misc/crypt/crypt_hash_descriptor.o \
libtomcrypt/src/misc/crypt/crypt_hash_is_valid.o \
libtomcrypt/src/misc/crypt/crypt_ltc_mp_descriptor.o \
libtomcrypt/src/misc/crypt/crypt_prng_descriptor.o \
libtomcrypt/src/misc/crypt/crypt_prng_is_valid.o \
libtomcrypt/src/misc/crypt/crypt_register_hash.o \
libtomcrypt/src/misc/crypt/crypt_register_prng.o \
libtomcrypt/src/misc/error_to_string.o \
libtomcrypt/src/misc/mem_neq.o \
libtomcrypt/src/misc/zeromem.o \
libtomcrypt/src/pk/asn1/der/bit/der_decode_bit_string.o \
libtomcrypt/src/pk/asn1/der/bit/der_decode_raw_bit_string.o \
libtomcrypt/src/pk/asn1/der/bit/der_encode_bit_string.o \
libtomcrypt/src/pk/asn1/der/bit/der_encode_raw_bit_string.o \
libtomcrypt/src/pk/asn1/der/bit/der_length_bit_string.o \
libtomcrypt/src/pk/asn1/der/boolean/der_decode_boolean.o \
libtomcrypt/src/pk/asn1/der/boolean/der_encode_boolean.o \
libtomcrypt/src/pk/asn1/der/boolean/der_length_boolean.o \
libtomcrypt/src/pk/asn1/der/choice/der_decode_choice.o \
libtomcrypt/src/pk/asn1/der/custom_type/der_decode_custom_type.o \
libtomcrypt/src/pk/asn1/der/custom_type/der_encode_custom_type.o \
libtomcrypt/src/pk/asn1/der/custom_type/der_length_custom_type.o \
libtomcrypt/src/pk/asn1/der/general/der_asn1_maps.o \
libtomcrypt/src/pk/asn1/der/general/der_decode_asn1_identifier.o \
libtomcrypt/src/pk/asn1/der/general/der_decode_asn1_length.o \
libtomcrypt/src/pk/asn1/der/general/der_encode_asn1_identifier.o \
libtomcrypt/src/pk/asn1/der/general/der_encode_asn1_length.o \
libtomcrypt/src/pk/asn1/der/general/der_length_asn1_identifier.o \
libtomcrypt/src/pk/asn1/der/general/der_length_asn1_length.o \
libtomcrypt/src/pk/asn1/der/generalizedtime/der_decode_generalizedtime.o \
libtomcrypt/src/pk/asn1/der/generalizedtime/der_encode_generalizedtime.o \
libtomcrypt/src/pk/asn1/der/generalizedtime/der_length_generalizedtime.o \
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
libtomcrypt/src/pk/asn1/der/sequence/der_encode_sequence_ex.o \
libtomcrypt/src/pk/asn1/der/sequence/der_encode_sequence_multi.o \
libtomcrypt/src/pk/asn1/der/sequence/der_length_sequence.o \
libtomcrypt/src/pk/asn1/der/set/der_encode_set.o \
libtomcrypt/src/pk/asn1/der/set/der_encode_setof.o \
libtomcrypt/src/pk/asn1/der/short_integer/der_decode_short_integer.o \
libtomcrypt/src/pk/asn1/der/short_integer/der_encode_short_integer.o \
libtomcrypt/src/pk/asn1/der/short_integer/der_length_short_integer.o \
libtomcrypt/src/pk/asn1/der/teletex_string/der_decode_teletex_string.o \
libtomcrypt/src/pk/asn1/der/teletex_string/der_length_teletex_string.o \
libtomcrypt/src/pk/asn1/der/utctime/der_decode_utctime.o \
libtomcrypt/src/pk/asn1/der/utctime/der_encode_utctime.o \
libtomcrypt/src/pk/asn1/der/utctime/der_length_utctime.o \
libtomcrypt/src/pk/asn1/der/utf8/der_decode_utf8_string.o \
libtomcrypt/src/pk/asn1/der/utf8/der_encode_utf8_string.o \
libtomcrypt/src/pk/asn1/der/utf8/der_length_utf8_string.o \
libtomcrypt/src/pk/asn1/oid/pk_get_oid.o \
libtomcrypt/src/pk/asn1/oid/pk_oid_cmp.o \
libtomcrypt/src/pk/asn1/oid/pk_oid_str.o \
libtomcrypt/src/pk/asn1/x509/x509_decode_subject_public_key_info.o \
libtomcrypt/src/pk/asn1/x509/x509_encode_subject_public_key_info.o \
libtomcrypt/src/pk/ecc/ltc_ecc_is_point_at_infinity.o \
libtomcrypt/src/pk/ecc/ltc_ecc_map.o \
libtomcrypt/src/pk/ecc/ltc_ecc_mul2add.o \
libtomcrypt/src/pk/ecc/ltc_ecc_mulmod.o \
libtomcrypt/src/pk/ecc/ltc_ecc_mulmod_timing.o \
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
libtomcrypt/src/pk/rsa/rsa_import.o \
libtomcrypt/src/pk/rsa/rsa_key.o \
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
libtomcrypt/src/headers/tomcrypt_private.h \
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

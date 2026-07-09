/**
 * \file    test_cipher_suite_4.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for cipher suite 4.
 * 
 * \copyright Copyright (c) 2026
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Cipher suite 4 header: */
#include "edhoc_cipher_suite_4.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* EDHOC headers: */
#include <edhoc_crypto.h>
#include <edhoc_values.h>
#include <edhoc_macros.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Compact25519 crypto headers: */
#include <compact_x25519.h>
#include <compact_ed25519.h>

/* Module defines ---------------------------------------------------------- */
#define INPUT_TO_SIGN_LEN ((size_t)128)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct edhoc_keys *edhoc_keys;
static const struct edhoc_crypto *edhoc_crypto;
static const struct edhoc_cipher_suite *edhoc_suite;

static int ret = EDHOC_ERROR_GENERIC_ERROR;

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(cipher_suite_4);

TEST_SETUP(cipher_suite_4)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
	edhoc_keys = edhoc_cipher_suite_4_get_keys();
	edhoc_crypto = edhoc_cipher_suite_4_get_crypto();
	edhoc_suite = edhoc_cipher_suite_4_get_suite();
}

TEST_TEAR_DOWN(cipher_suite_4)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_4, suite_parameters)
{
	/* Cipher suite 4 (RFC 9528, IANA EDHOC Cipher Suites registry):
	 * https://www.iana.org/assignments/edhoc/edhoc.xhtml
	 *   AEAD      = ChaCha20/Poly1305 (key 32, tag 16, iv 12)
	 *   hash      = SHA-256 (32)
	 *   MAC (static DH) = 16
	 *   ECDH      = X25519 (32)
	 *   signature = EdDSA / Ed25519 (64)
	 */
	TEST_ASSERT_EQUAL(4, edhoc_suite->value);
	TEST_ASSERT_EQUAL(32, edhoc_suite->aead_key_length);
	TEST_ASSERT_EQUAL(16, edhoc_suite->aead_tag_length);
	TEST_ASSERT_EQUAL(12, edhoc_suite->aead_iv_length);
	TEST_ASSERT_EQUAL(32, edhoc_suite->hash_length);
	TEST_ASSERT_EQUAL(16, edhoc_suite->mac_length);
	TEST_ASSERT_EQUAL(32, edhoc_suite->ecc_key_length);
	TEST_ASSERT_EQUAL(64, edhoc_suite->ecc_sign_length);
}

TEST(cipher_suite_4, eddsa)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const uint8_t priv_key[ED25519_PRIVATE_KEY_SIZE] = {
		0xef, 0x14, 0x0f, 0xf9, 0x00, 0xb0, 0xab, 0x03,
		0xf0, 0xc0, 0x8d, 0x87, 0x9c, 0xbb, 0xd4, 0xb3,
		0x1e, 0xa7, 0x1e, 0x6e, 0x7e, 0xe7, 0xff, 0xcb,
		0x7e, 0x79, 0x55, 0x77, 0x7a, 0x33, 0x27, 0x99,

		0xa1, 0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85, 0x4a,
		0xd1, 0x2a, 0x0c, 0x1a, 0x35, 0x4e, 0x41, 0x8a,
		0xac, 0xe3, 0x3a, 0xa0, 0xf2, 0xc6, 0x62, 0xc0,
		0x0b, 0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93, 0x59,
	};

	const uint8_t pub_key[] = {
		0xa1, 0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85, 0x4a,
		0xd1, 0x2a, 0x0c, 0x1a, 0x35, 0x4e, 0x41, 0x8a,
		0xac, 0xe3, 0x3a, 0xa0, 0xf2, 0xc6, 0x62, 0xc0,
		0x0b, 0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93, 0x59,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->ecc_key_length, ARRAY_SIZE(pub_key));

	/* Random input for signature. */
	uint8_t input[INPUT_TO_SIGN_LEN] = { 0 };
	ret = psa_generate_random(input, ARRAY_SIZE(input));
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	size_t sign_len = 0;
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));

	/* Generate signature. */
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_SIGNATURE, priv_key,
				     ARRAY_SIZE(priv_key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->signature(NULL, &key_id, input, ARRAY_SIZE(input),
				      sign, ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL((size_t)edhoc_suite->ecc_sign_length, sign_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_VERIFY, pub_key,
				     ARRAY_SIZE(pub_key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Verify signature. */
	ret = edhoc_crypto->verify(NULL, &key_id, input, ARRAY_SIZE(input),
				   sign, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_4, ecdh)
{
	psa_key_id_t key_id_a = PSA_KEY_HANDLE_INIT;
	psa_key_id_t key_id_b = PSA_KEY_HANDLE_INIT;

	/* Alice ECDH key pair. */
	size_t priv_key_len_a = 0;
	uint8_t priv_key_a[edhoc_suite->ecc_key_length];
	memset(priv_key_a, 0, sizeof(priv_key_a));

	size_t pub_key_len_a = 0;
	uint8_t pub_key_a[edhoc_suite->ecc_key_length];
	memset(pub_key_a, 0, sizeof(pub_key_a));

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_MAKE_KEY_PAIR, NULL, 0,
				     &key_id_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->make_key_pair(NULL, &key_id_a, priv_key_a,
					  ARRAY_SIZE(priv_key_a),
					  &priv_key_len_a, pub_key_a,
					  ARRAY_SIZE(pub_key_a),
					  &pub_key_len_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(priv_key_a), priv_key_len_a);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(pub_key_a), pub_key_len_a);

	ret = edhoc_keys->destroy_key(NULL, &key_id_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Bob ECDH key pair. */
	size_t priv_key_len_b = 0;
	uint8_t priv_key_b[edhoc_suite->ecc_key_length];
	memset(priv_key_b, 0, sizeof(priv_key_b));

	size_t pub_key_len_b = 0;
	uint8_t pub_key_b[edhoc_suite->ecc_key_length];
	memset(pub_key_b, 0, sizeof(pub_key_b));

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_MAKE_KEY_PAIR, NULL, 0,
				     &key_id_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->make_key_pair(NULL, &key_id_b, priv_key_b,
					  ARRAY_SIZE(priv_key_b),
					  &priv_key_len_b, pub_key_b,
					  ARRAY_SIZE(pub_key_b),
					  &pub_key_len_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(priv_key_b), priv_key_len_b);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(pub_key_b), pub_key_len_b);

	ret = edhoc_keys->destroy_key(NULL, &key_id_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Shared secret for Alice. */
	size_t shr_sec_len_a = 0;
	uint8_t shr_sec_a[edhoc_suite->ecc_key_length];
	memset(shr_sec_a, 0, sizeof(shr_sec_a));

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_KEY_AGREEMENT, priv_key_a,
				     priv_key_len_a, &key_id_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->key_agreement(NULL, &key_id_a, pub_key_b,
					  pub_key_len_b, shr_sec_a,
					  ARRAY_SIZE(shr_sec_a),
					  &shr_sec_len_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(shr_sec_a), shr_sec_len_a);

	ret = edhoc_keys->destroy_key(NULL, &key_id_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Shared secret for Bob. */
	size_t shr_sec_len_b = 0;
	uint8_t shr_sec_b[edhoc_suite->ecc_key_length];
	memset(shr_sec_b, 0, sizeof(shr_sec_b));

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_KEY_AGREEMENT, priv_key_b,
				     priv_key_len_b, &key_id_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->key_agreement(NULL, &key_id_b, pub_key_a,
					  pub_key_len_a, shr_sec_b,
					  ARRAY_SIZE(shr_sec_b),
					  &shr_sec_len_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(shr_sec_b), shr_sec_len_b);

	ret = edhoc_keys->destroy_key(NULL, &key_id_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Compare if Alice and Bob has the same shared secrets. */
	TEST_ASSERT_EQUAL(shr_sec_len_a, shr_sec_len_b);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(shr_sec_a, shr_sec_b, shr_sec_len_a);
}

TEST(cipher_suite_4, hkdf)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	/* Known-answer test taken from RFC 5869, Appendix A.1 (Test Case 1),
	 * HMAC-SHA-256:
	 * https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.1
	 */
	const uint8_t ikm[] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	};

	const uint8_t salt[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	};

	const uint8_t info[] = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
	};

	const size_t L = 42;

	const uint8_t prk[] = {
		0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
		0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
		0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
		0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
	};

	const uint8_t okm[] = {
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90,
		0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d,
		0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d,
		0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
		0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
	};

	/* HKDF extract part. */
	size_t comp_prk_len = 0;
	uint8_t comp_prk[edhoc_suite->hash_length];
	memset(comp_prk, 0, sizeof(comp_prk));

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_EXTRACT, ikm,
				     ARRAY_SIZE(ikm), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->extract(NULL, &key_id, salt, ARRAY_SIZE(salt),
				    comp_prk, ARRAY_SIZE(comp_prk),
				    &comp_prk_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(comp_prk), comp_prk_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(comp_prk_len, ARRAY_SIZE(prk));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(comp_prk, prk, comp_prk_len);

	/* HKDF expand part. */
	uint8_t comp_okm[L];
	memset(comp_okm, 0, sizeof(comp_okm));

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_EXPAND, comp_prk,
				     ARRAY_SIZE(comp_prk), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->expand(NULL, &key_id, info, ARRAY_SIZE(info),
				   comp_okm, ARRAY_SIZE(comp_okm));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(comp_okm, okm, ARRAY_SIZE(okm));
}

TEST(cipher_suite_4, aead)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	/* AEAD key, iv and aad. */
	const uint8_t key[] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_key_length, ARRAY_SIZE(key));
	const uint8_t iv[] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 0,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_iv_length, ARRAY_SIZE(iv));
	const uint8_t aad[4] = {
		0,
		1,
		2,
		3,
	};

	/* AEAD encryption. */
	const uint8_t ptxt[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_ENCRYPT, key,
				     ARRAY_SIZE(key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	size_t ctxt_len = 0;
	uint8_t ctxt[ARRAY_SIZE(ptxt) + edhoc_suite->aead_tag_length];
	memset(ctxt, 0, sizeof(ctxt));
	ret = edhoc_crypto->encrypt(NULL, &key_id, iv, ARRAY_SIZE(iv), aad,
				    ARRAY_SIZE(aad), ptxt, ARRAY_SIZE(ptxt),
				    ctxt, ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ctxt), ctxt_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* AEAD decryption. */
	size_t dec_ctxt_len = 0;
	uint8_t dec_ctxt[ARRAY_SIZE(ptxt)] = { 0 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_DECRYPT, key,
				     ARRAY_SIZE(key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->decrypt(NULL, &key_id, iv, ARRAY_SIZE(iv), aad,
				    ARRAY_SIZE(aad), ctxt, ctxt_len, dec_ctxt,
				    ARRAY_SIZE(dec_ctxt), &dec_ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ptxt), dec_ctxt_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Verify if plaintext is equal to decrypted ciphertext. */
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ptxt, dec_ctxt, ARRAY_SIZE(ptxt));
}

TEST(cipher_suite_4, aead_rfc8439_kat)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	/* Known-answer test taken from RFC 8439, Section 2.8.2
	 * ("Example and Test Vector for AEAD_CHACHA20_POLY1305"):
	 * https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
	 */
	const uint8_t key[] = {
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_key_length, ARRAY_SIZE(key));

	/* 96-bit nonce = constant (32 bits) || IV (64 bits). */
	const uint8_t nonce[] = {
		0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
		0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_iv_length, ARRAY_SIZE(nonce));

	const uint8_t aad[] = {
		0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
		0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	};

	/* Plaintext: "Ladies and Gentlemen of the class of '99: If I could
	 * offer you only one tip for the future, sunscreen would be it." */
	const uint8_t ptxt[] = {
		0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64,
		0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e,
		0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
		0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
		0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75,
		0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
		0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
		0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
		0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65,
		0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65,
		0x20, 0x69, 0x74, 0x2e,
	};

	const uint8_t exp_ctxt[] = {
		0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86,
		0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51,
		0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
		0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
		0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71,
		0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
		0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
		0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
		0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
		0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0,
		0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce,
		0xc6, 0x4b, 0x61, 0x16,
	};

	const uint8_t exp_tag[] = {
		0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
		0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_tag_length, ARRAY_SIZE(exp_tag));

	/* AEAD encryption must reproduce the RFC 8439 ciphertext and tag. */
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_ENCRYPT, key,
				     ARRAY_SIZE(key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	size_t ctxt_len = 0;
	uint8_t ctxt[ARRAY_SIZE(ptxt) + edhoc_suite->aead_tag_length];
	memset(ctxt, 0, sizeof(ctxt));
	ret = edhoc_crypto->encrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				    aad, ARRAY_SIZE(aad), ptxt,
				    ARRAY_SIZE(ptxt), ctxt, ARRAY_SIZE(ctxt),
				    &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(exp_ctxt) + ARRAY_SIZE(exp_tag), ctxt_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(exp_ctxt, ctxt, ARRAY_SIZE(exp_ctxt));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(exp_tag, &ctxt[ARRAY_SIZE(exp_ctxt)],
				      ARRAY_SIZE(exp_tag));

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* AEAD decryption of the RFC 8439 ciphertext must recover plaintext. */
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_DECRYPT, key,
				     ARRAY_SIZE(key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	size_t dec_len = 0;
	uint8_t dec[ARRAY_SIZE(ptxt)] = { 0 };
	ret = edhoc_crypto->decrypt(NULL, &key_id, nonce, ARRAY_SIZE(nonce),
				    aad, ARRAY_SIZE(aad), ctxt, ctxt_len, dec,
				    ARRAY_SIZE(dec), &dec_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ptxt), dec_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ptxt, dec, ARRAY_SIZE(ptxt));

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_4, hash)
{
	/* Known-answer test: SHA-256("abc") from NIST FIPS 180-4.
	 * NIST CSRC published example:
	 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
	 */
	const uint8_t input[] = { 0x61, 0x62, 0x63 };

	const uint8_t exp_hash[] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->hash_length, ARRAY_SIZE(exp_hash));

	/* Hashing operation. */
	size_t hash_len = 0;
	uint8_t hash[edhoc_suite->hash_length];
	memset(hash, 0, sizeof(hash));

	ret = edhoc_crypto->hash(NULL, input, ARRAY_SIZE(input), hash,
				 ARRAY_SIZE(hash), &hash_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(hash), hash_len);

	/* Verify if hashes are equals. */
	TEST_ASSERT_EQUAL_UINT8_ARRAY(hash, exp_hash, ARRAY_SIZE(exp_hash));
}

TEST_GROUP_RUNNER(cipher_suite_4)
{
	RUN_TEST_CASE(cipher_suite_4, suite_parameters);
	RUN_TEST_CASE(cipher_suite_4, eddsa);
	RUN_TEST_CASE(cipher_suite_4, ecdh);
	RUN_TEST_CASE(cipher_suite_4, hkdf);
	RUN_TEST_CASE(cipher_suite_4, aead);
	RUN_TEST_CASE(cipher_suite_4, aead_rfc8439_kat);
	RUN_TEST_CASE(cipher_suite_4, hash);
}

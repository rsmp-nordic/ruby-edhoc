#include "ruby.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <psa/crypto.h>
#include <mbedtls/psa_util.h>

#define EDHOC_ALLOW_PRIVATE_ACCESS
#include <edhoc.h>
#include <edhoc_cipher_suite_0.h>
#include "../../vendor/libedhoc/tests/include/test_vector_x5chain_sign_keys_suite_0.h"

/* Compile libedhoc's suite-0 helper into this native extension. */
#include "../../vendor/libedhoc/helpers/src/edhoc_cipher_suite_0.c"

#define EDHOC_RUBY_MAX_MESSAGE 2048

static VALUE mEdhoc;
static VALUE mNative;
static VALUE cSuite0Session;
static VALUE eEdhocError;

struct suite0_session {
	struct edhoc_context ctx;
	enum edhoc_role role;
	bool initialized;
	uint8_t *private_key;
	size_t private_key_len;
	uint8_t *credential;
	size_t credential_len;
	uint8_t *peer_public_key;
	size_t peer_public_key_len;
	uint8_t *peer_credential;
	size_t peer_credential_len;
};

static const struct edhoc_crypto suite0_crypto = {
	.make_key_pair = edhoc_cipher_suite_0_make_key_pair,
	.key_agreement = edhoc_cipher_suite_0_key_agreement,
	.signature = edhoc_cipher_suite_0_signature,
	.verify = edhoc_cipher_suite_0_verify,
	.extract = edhoc_cipher_suite_0_extract,
	.expand = edhoc_cipher_suite_0_expand,
	.encrypt = edhoc_cipher_suite_0_encrypt,
	.decrypt = edhoc_cipher_suite_0_decrypt,
	.hash = edhoc_cipher_suite_0_hash,
};

static void raise_edhoc_error(const char *operation, int code)
{
	rb_raise(eEdhocError, "%s failed with libedhoc error %d", operation, code);
}

static uint8_t *copy_bytes(VALUE value, size_t *length)
{
	StringValue(value);
	*length = RSTRING_LEN(value);
	if (*length == 0)
		rb_raise(rb_eArgError, "byte string must not be empty");

	uint8_t *copy = malloc(*length);
	if (copy == NULL)
		rb_raise(rb_eNoMemError, "failed to allocate byte string");

	memcpy(copy, RSTRING_PTR(value), *length);
	return copy;
}

static int auth_cred_fetch(void *user_ctx, struct edhoc_auth_creds *auth_cred)
{
	struct suite0_session *session = user_ctx;

	if (session == NULL || auth_cred == NULL)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 1;
	auth_cred->x509_chain.cert[0] = session->credential;
	auth_cred->x509_chain.cert_len[0] = session->credential_len;

	int res = edhoc_cipher_suite_0_key_import(
		NULL,
		EDHOC_KT_SIGNATURE,
		session->private_key,
		session->private_key_len,
		auth_cred->priv_key_id
	);

	return res == EDHOC_SUCCESS ? EDHOC_SUCCESS : EDHOC_ERROR_CREDENTIALS_FAILURE;
}

static int auth_cred_verify(void *user_ctx, struct edhoc_auth_creds *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len)
{
	struct suite0_session *session = user_ctx;

	if (session == NULL || auth_cred == NULL || pub_key == NULL || pub_key_len == NULL)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (auth_cred->label != EDHOC_COSE_HEADER_X509_CHAIN)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (auth_cred->x509_chain.nr_of_certs != 1)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (auth_cred->x509_chain.cert_len[0] != session->peer_credential_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (memcmp(auth_cred->x509_chain.cert[0], session->peer_credential,
		   session->peer_credential_len) != 0)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	*pub_key = session->peer_public_key;
	*pub_key_len = session->peer_public_key_len;

	return EDHOC_SUCCESS;
}

static const struct edhoc_credentials suite0_credentials = {
	.fetch = auth_cred_fetch,
	.verify = auth_cred_verify,
};

static void suite0_session_free(void *ptr)
{
	struct suite0_session *session = ptr;
	if (session == NULL)
		return;

	if (session->initialized)
		edhoc_context_deinit(&session->ctx);

	free(session->private_key);
	free(session->credential);
	free(session->peer_public_key);
	free(session->peer_credential);
	free(session);
}

static size_t suite0_session_size(const void *ptr)
{
	(void)ptr;
	return sizeof(struct suite0_session);
}

static const rb_data_type_t suite0_session_type = {
	"Edhoc::Native::Suite0Session",
	{ 0, suite0_session_free, suite0_session_size },
	0, 0, RUBY_TYPED_FREE_IMMEDIATELY
};

static VALUE suite0_session_alloc(VALUE klass)
{
	struct suite0_session *session = calloc(1, sizeof(struct suite0_session));
	if (session == NULL)
		rb_raise(rb_eNoMemError, "failed to allocate EDHOC session");

	return TypedData_Wrap_Struct(klass, &suite0_session_type, session);
}

static struct suite0_session *get_session(VALUE self)
{
	struct suite0_session *session;
	TypedData_Get_Struct(self, struct suite0_session, &suite0_session_type, session);
	if (session == NULL || !session->initialized)
		rb_raise(eEdhocError, "EDHOC session is not initialized");
	return session;
}

static struct edhoc_connection_id parse_connection_id(VALUE value)
{
	struct edhoc_connection_id cid;
	memset(&cid, 0, sizeof(cid));

	if (RB_INTEGER_TYPE_P(value)) {
		long id = NUM2LONG(value);
		if (id < -24 || id > 23)
			rb_raise(rb_eArgError, "integer connection id must fit EDHOC one-byte integer range");
		cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
		cid.int_value = (int8_t)id;
		return cid;
	}

	StringValue(value);
	if (RSTRING_LEN(value) == 0)
		rb_raise(rb_eArgError, "byte-string connection id must not be empty");
	if ((size_t)RSTRING_LEN(value) > sizeof(cid.bstr_value))
		rb_raise(rb_eArgError, "byte-string connection id is too long");

	cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
	cid.bstr_length = RSTRING_LEN(value);
	memcpy(cid.bstr_value, RSTRING_PTR(value), cid.bstr_length);
	return cid;
}

static VALUE suite0_session_initialize(VALUE self, VALUE role_value,
				       VALUE private_key, VALUE credential,
				       VALUE peer_public_key, VALUE peer_credential,
				       VALUE connection_id_value)
{
	struct suite0_session *session;
	TypedData_Get_Struct(self, struct suite0_session, &suite0_session_type, session);

	const char *role = StringValueCStr(role_value);
	if (strcmp(role, "initiator") == 0) {
		session->role = EDHOC_INITIATOR;
	} else if (strcmp(role, "responder") == 0) {
		session->role = EDHOC_RESPONDER;
	} else {
		rb_raise(rb_eArgError, "role must be initiator or responder");
	}

	session->private_key = copy_bytes(private_key, &session->private_key_len);
	session->credential = copy_bytes(credential, &session->credential_len);
	session->peer_public_key = copy_bytes(peer_public_key, &session->peer_public_key_len);
	session->peer_credential = copy_bytes(peer_credential, &session->peer_credential_len);

	if (session->private_key_len != 64)
		rb_raise(rb_eArgError, "suite 0 Ed25519 private key must be 64 bytes");
	if (session->peer_public_key_len != 32)
		rb_raise(rb_eArgError, "suite 0 Ed25519 peer public key must be 32 bytes");

	int ret = psa_crypto_init();
	if (ret != PSA_SUCCESS)
		rb_raise(eEdhocError, "psa_crypto_init failed with code %d", ret);

	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	const struct edhoc_cipher_suite cipher_suites[] = {
		*edhoc_cipher_suite_0_get_suite(),
	};
	struct edhoc_connection_id connection_id = parse_connection_id(connection_id_value);

	ret = edhoc_context_init(&session->ctx);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_context_init", ret);
	session->initialized = true;

	ret = edhoc_set_methods(&session->ctx, methods, 1);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_set_methods", ret);

	ret = edhoc_set_cipher_suites(&session->ctx, cipher_suites, 1);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_set_cipher_suites", ret);

	ret = edhoc_set_connection_id(&session->ctx, &connection_id);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_set_connection_id", ret);

	ret = edhoc_set_user_context(&session->ctx, session);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_set_user_context", ret);

	ret = edhoc_bind_keys(&session->ctx, edhoc_cipher_suite_0_get_keys());
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_bind_keys", ret);

	ret = edhoc_bind_crypto(&session->ctx, &suite0_crypto);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_bind_crypto", ret);

	ret = edhoc_bind_credentials(&session->ctx, &suite0_credentials);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_bind_credentials", ret);

	return self;
}

static VALUE compose_to_string(struct suite0_session *session, const char *name,
			       int (*fn)(struct edhoc_context *, uint8_t *, size_t, size_t *))
{
	uint8_t buffer[EDHOC_RUBY_MAX_MESSAGE];
	size_t length = 0;
	int ret = fn(&session->ctx, buffer, sizeof(buffer), &length);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error(name, ret);
	return rb_str_new((const char *)buffer, length);
}

static VALUE suite0_compose_message1(VALUE self)
{
	return compose_to_string(get_session(self), "edhoc_message_1_compose", edhoc_message_1_compose);
}

static VALUE suite0_compose_message2(VALUE self)
{
	return compose_to_string(get_session(self), "edhoc_message_2_compose", edhoc_message_2_compose);
}

static VALUE suite0_compose_message3(VALUE self)
{
	return compose_to_string(get_session(self), "edhoc_message_3_compose", edhoc_message_3_compose);
}

static VALUE process_message(struct suite0_session *session, VALUE message, const char *name,
			     int (*fn)(struct edhoc_context *, const uint8_t *, size_t))
{
	StringValue(message);
	int ret = fn(&session->ctx, (const uint8_t *)RSTRING_PTR(message), RSTRING_LEN(message));
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error(name, ret);
	return Qtrue;
}

static VALUE suite0_process_message1(VALUE self, VALUE message)
{
	return process_message(get_session(self), message, "edhoc_message_1_process", edhoc_message_1_process);
}

static VALUE suite0_process_message2(VALUE self, VALUE message)
{
	return process_message(get_session(self), message, "edhoc_message_2_process", edhoc_message_2_process);
}

static VALUE suite0_process_message3(VALUE self, VALUE message)
{
	return process_message(get_session(self), message, "edhoc_message_3_process", edhoc_message_3_process);
}

static VALUE suite0_export_prk(VALUE self, VALUE label_value, VALUE length_value)
{
	struct suite0_session *session = get_session(self);
	size_t label = NUM2SIZET(label_value);
	size_t length = NUM2SIZET(length_value);

	if (length == 0 || length > 1024)
		rb_raise(rb_eArgError, "export length must be between 1 and 1024 bytes");

	uint8_t *buffer = malloc(length);
	if (buffer == NULL)
		rb_raise(rb_eNoMemError, "failed to allocate exporter buffer");

	int ret = edhoc_export_prk_exporter(&session->ctx, label, buffer, length);
	if (ret != EDHOC_SUCCESS) {
		free(buffer);
		raise_edhoc_error("edhoc_export_prk_exporter", ret);
	}

	VALUE result = rb_str_new((const char *)buffer, length);
	free(buffer);
	return result;
}

static VALUE native_library_version(VALUE self)
{
	(void)self;
	VALUE hash = rb_hash_new();
	rb_hash_aset(hash, ID2SYM(rb_intern("libedhoc_api_major")), INT2NUM(EDHOC_API_VERSION_MAJOR));
	rb_hash_aset(hash, ID2SYM(rb_intern("libedhoc_api_minor")), INT2NUM(EDHOC_API_VERSION_MINOR));
	return hash;
}

static VALUE native_suite0_profile(VALUE self)
{
	(void)self;
	const struct edhoc_cipher_suite *suite = edhoc_cipher_suite_0_get_suite();
	VALUE hash = rb_hash_new();
	rb_hash_aset(hash, ID2SYM(rb_intern("method")), INT2NUM(0));
	rb_hash_aset(hash, ID2SYM(rb_intern("cipher_suite")), INT2NUM(suite->value));
	rb_hash_aset(hash, ID2SYM(rb_intern("ecdh")), rb_str_new_cstr("X25519"));
	rb_hash_aset(hash, ID2SYM(rb_intern("signature")), rb_str_new_cstr("Ed25519/EdDSA"));
	rb_hash_aset(hash, ID2SYM(rb_intern("hash")), rb_str_new_cstr("SHA-256"));
	rb_hash_aset(hash, ID2SYM(rb_intern("aead")), rb_str_new_cstr("AES-CCM-16-64-128"));
	rb_hash_aset(hash, ID2SYM(rb_intern("aead_key_length")), SIZET2NUM(suite->aead_key_length));
	rb_hash_aset(hash, ID2SYM(rb_intern("aead_tag_length")), SIZET2NUM(suite->aead_tag_length));
	rb_hash_aset(hash, ID2SYM(rb_intern("aead_iv_length")), SIZET2NUM(suite->aead_iv_length));
	rb_hash_aset(hash, ID2SYM(rb_intern("hash_length")), SIZET2NUM(suite->hash_length));
	rb_hash_aset(hash, ID2SYM(rb_intern("ecc_key_length")), SIZET2NUM(suite->ecc_key_length));
	rb_hash_aset(hash, ID2SYM(rb_intern("signature_length")), SIZET2NUM(suite->ecc_sign_length));
	return hash;
}

static VALUE native_suite0_test_vector(VALUE self)
{
	(void)self;
	VALUE hash = rb_hash_new();
	rb_hash_aset(hash, ID2SYM(rb_intern("initiator_private_key")),
		     rb_str_new((const char *)SK_I, ARRAY_SIZE(SK_I)));
	rb_hash_aset(hash, ID2SYM(rb_intern("initiator_public_key")),
		     rb_str_new((const char *)PK_I, ARRAY_SIZE(PK_I)));
	rb_hash_aset(hash, ID2SYM(rb_intern("initiator_credential")),
		     rb_str_new((const char *)CRED_I, ARRAY_SIZE(CRED_I)));
	rb_hash_aset(hash, ID2SYM(rb_intern("responder_private_key")),
		     rb_str_new((const char *)SK_R, ARRAY_SIZE(SK_R)));
	rb_hash_aset(hash, ID2SYM(rb_intern("responder_public_key")),
		     rb_str_new((const char *)PK_R, ARRAY_SIZE(PK_R)));
	rb_hash_aset(hash, ID2SYM(rb_intern("responder_credential")),
		     rb_str_new((const char *)CRED_R, ARRAY_SIZE(CRED_R)));
	return hash;
}

void Init_edhoc_native(void)
{
	mEdhoc = rb_define_module("Edhoc");
	eEdhocError = rb_define_class_under(mEdhoc, "NativeError", rb_eStandardError);
	mNative = rb_define_module_under(mEdhoc, "Native");

	rb_define_singleton_method(mNative, "library_version", native_library_version, 0);
	rb_define_singleton_method(mNative, "suite0_profile", native_suite0_profile, 0);
	rb_define_singleton_method(mNative, "suite0_test_vector", native_suite0_test_vector, 0);

	cSuite0Session = rb_define_class_under(mNative, "Suite0Session", rb_cObject);
	rb_define_alloc_func(cSuite0Session, suite0_session_alloc);
	rb_define_method(cSuite0Session, "initialize", suite0_session_initialize, 6);
	rb_define_method(cSuite0Session, "compose_message1", suite0_compose_message1, 0);
	rb_define_method(cSuite0Session, "process_message1", suite0_process_message1, 1);
	rb_define_method(cSuite0Session, "compose_message2", suite0_compose_message2, 0);
	rb_define_method(cSuite0Session, "process_message2", suite0_process_message2, 1);
	rb_define_method(cSuite0Session, "compose_message3", suite0_compose_message3, 0);
	rb_define_method(cSuite0Session, "process_message3", suite0_process_message3, 1);
	rb_define_method(cSuite0Session, "export_prk", suite0_export_prk, 2);
}

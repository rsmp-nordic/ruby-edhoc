#include "ruby.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <edhoc/edhoc.h>
#include <psa/crypto.h>

#define EDHOC_RUBY_MAX_MESSAGE 2048
#define EDHOC_RUBY_MAX_EXPORT 1024

enum suite_credential_format {
	SUITE_CREDENTIAL_X509_CHAIN,
	SUITE_CREDENTIAL_KID_CBOR,
};

static VALUE mEdhoc;
static VALUE mNative;
static VALUE cSuite0Session;
static VALUE cSuite4Session;
static VALUE eEdhocError;
static VALUE eEdhocNativeError;
static VALUE eEdhocBadStateError;
static VALUE eEdhocCborError;
static VALUE eEdhocCryptoError;
static VALUE eEdhocCredentialsError;
static VALUE eEdhocKeyExchangeError;
static VALUE eEdhocMessageError;

struct suite_peer {
	char *id;
	size_t id_len;
	uint8_t *public_key;
	size_t public_key_len;
	uint8_t *credential;
	size_t credential_len;
	uint8_t *kid;
	size_t kid_len;
};

struct suite_session {
	struct edhoc_context *ctx;
	size_t ctx_size;
	bool context_initialized;
	enum edhoc_role role;
	enum edhoc_cipher_suite_id suite_id;
	psa_key_id_t authentication_key_id;
	bool authentication_key_imported;
	uint8_t *credential;
	size_t credential_len;
	uint8_t *kid;
	size_t kid_len;
	enum suite_credential_format credential_format;
	struct suite_peer *peers;
	size_t peers_len;
	size_t matched_peer_index;
	bool matched_peer;
	uint8_t *untrusted_credential;
	size_t untrusted_credential_len;
};

struct parsed_connection_id {
	uint8_t bytes[CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID];
	struct edhoc_buffer buffer;
};

_Static_assert(sizeof(psa_key_id_t) <= CONFIG_LIBEDHOC_KEY_ID_LEN,
	       "libedhoc key handles must fit a PSA key identifier");

static void platform_zeroize(void *buffer, size_t length)
{
	volatile uint8_t *cursor = buffer;

	while (length-- > 0)
		*cursor++ = 0;
}

static const struct edhoc_platform platform = {
	.zeroize = platform_zeroize,
};

static const char *edhoc_error_name(int code)
{
	switch (code) {
	case EDHOC_ERROR_GENERIC_ERROR:
		return "generic_error";
	case EDHOC_ERROR_NOT_SUPPORTED:
		return "not_supported";
	case EDHOC_ERROR_NOT_PERMITTED:
		return "not_permitted";
	case EDHOC_ERROR_BUFFER_TOO_SMALL:
		return "buffer_too_small";
	case EDHOC_ERROR_BAD_STATE:
		return "bad_state";
	case EDHOC_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case EDHOC_ERROR_NOT_ENOUGH_MEMORY:
		return "not_enough_memory";
	case EDHOC_ERROR_CBOR_FAILURE:
		return "cbor_failure";
	case EDHOC_ERROR_CRYPTO_FAILURE:
		return "crypto_failure";
	case EDHOC_ERROR_CREDENTIALS_FAILURE:
		return "credentials_failure";
	case EDHOC_ERROR_EAD_COMPOSE_FAILURE:
		return "ead_compose_failure";
	case EDHOC_ERROR_EAD_PROCESS_FAILURE:
		return "ead_process_failure";
	case EDHOC_ERROR_MSG_1_PROCESS_FAILURE:
		return "message_1_process_failure";
	case EDHOC_ERROR_MSG_2_PROCESS_FAILURE:
		return "message_2_process_failure";
	case EDHOC_ERROR_MSG_3_PROCESS_FAILURE:
		return "message_3_process_failure";
	case EDHOC_ERROR_MSG_4_PROCESS_FAILURE:
		return "message_4_process_failure";
	case EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE:
		return "ephemeral_key_exchange_failure";
	case EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE:
		return "transcript_hash_failure";
	case EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE:
		return "pseudorandom_key_failure";
	case EDHOC_ERROR_INVALID_SIGN_OR_MAC_2:
		return "invalid_sign_or_mac_2";
	case EDHOC_ERROR_INVALID_SIGN_OR_MAC_3:
		return "invalid_sign_or_mac_3";
	default:
		return "unknown";
	}
}

static VALUE edhoc_exception_class(int code)
{
	switch (code) {
	case EDHOC_ERROR_BAD_STATE:
		return eEdhocBadStateError;
	case EDHOC_ERROR_CBOR_FAILURE:
		return eEdhocCborError;
	case EDHOC_ERROR_CRYPTO_FAILURE:
	case EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE:
	case EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE:
	case EDHOC_ERROR_INVALID_SIGN_OR_MAC_2:
	case EDHOC_ERROR_INVALID_SIGN_OR_MAC_3:
		return eEdhocCryptoError;
	case EDHOC_ERROR_CREDENTIALS_FAILURE:
		return eEdhocCredentialsError;
	case EDHOC_ERROR_MSG_1_PROCESS_FAILURE:
	case EDHOC_ERROR_MSG_2_PROCESS_FAILURE:
	case EDHOC_ERROR_MSG_3_PROCESS_FAILURE:
	case EDHOC_ERROR_MSG_4_PROCESS_FAILURE:
		return eEdhocMessageError;
	case EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE:
		return eEdhocKeyExchangeError;
	default:
		return eEdhocNativeError;
	}
}

_Noreturn static void raise_edhoc_error(const char *operation, int code)
{
	rb_raise(edhoc_exception_class(code),
		 "%s failed with libedhoc error %s (%d)", operation,
		 edhoc_error_name(code), code);
}

static uint8_t *copy_bytes(VALUE value, size_t *length)
{
	uint8_t *copy;

	StringValue(value);
	*length = (size_t)RSTRING_LEN(value);
	if (*length == 0)
		rb_raise(rb_eArgError, "byte string must not be empty");

	copy = malloc(*length);
	if (copy == NULL)
		rb_raise(rb_eNoMemError, "failed to allocate byte string");

	memcpy(copy, RSTRING_PTR(value), *length);
	return copy;
}

static uint8_t *copy_optional_bytes(VALUE value, size_t *length)
{
	if (NIL_P(value)) {
		*length = 0;
		return NULL;
	}

	return copy_bytes(value, length);
}

static char *copy_optional_string(VALUE value, size_t *length)
{
	char *copy;

	if (NIL_P(value)) {
		*length = 0;
		return NULL;
	}

	StringValue(value);
	*length = (size_t)RSTRING_LEN(value);
	if (*length == 0)
		rb_raise(rb_eArgError, "peer id must not be empty");

	copy = malloc(*length);
	if (copy == NULL)
		rb_raise(rb_eNoMemError, "failed to allocate peer id");

	memcpy(copy, RSTRING_PTR(value), *length);
	return copy;
}

static void session_set_untrusted_credential(struct suite_session *session,
					     const uint8_t *credential,
					     size_t credential_len)
{
	free(session->untrusted_credential);
	session->untrusted_credential = NULL;
	session->untrusted_credential_len = 0;

	if (credential == NULL || credential_len == 0)
		return;

	session->untrusted_credential = malloc(credential_len);
	if (session->untrusted_credential == NULL)
		return;

	memcpy(session->untrusted_credential, credential, credential_len);
	session->untrusted_credential_len = credential_len;
}

static void peer_dispose(struct suite_peer *peer)
{
	if (peer == NULL)
		return;

	free(peer->id);
	free(peer->public_key);
	free(peer->credential);
	free(peer->kid);
	memset(peer, 0, sizeof(*peer));
}

static void session_dispose_peers(struct suite_session *session)
{
	if (session->peers == NULL)
		return;

	for (size_t i = 0; i < session->peers_len; ++i)
		peer_dispose(&session->peers[i]);

	free(session->peers);
	session->peers = NULL;
	session->peers_len = 0;
	session->matched_peer_index = 0;
	session->matched_peer = false;
}

static void validate_public_key_length(size_t length)
{
	if (length != 32)
		rb_raise(rb_eArgError,
			 "Ed25519 peer public key must be exactly 32 bytes");
}

static void validate_kid_length(size_t length)
{
	if (length == 0 || length > EDHOC_CREDENTIAL_KID_MAX_LEN)
		rb_raise(rb_eArgError, "credential kid must be 1..%d bytes",
			 EDHOC_CREDENTIAL_KID_MAX_LEN);
}

static void parse_single_peer(struct suite_session *session, VALUE public_key,
			      VALUE credential, VALUE kid)
{
	session->peers = calloc(1, sizeof(*session->peers));
	if (session->peers == NULL)
		rb_raise(rb_eNoMemError, "failed to allocate EDHOC peer");

	session->peers_len = 1;
	session->peers[0].public_key =
		copy_bytes(public_key, &session->peers[0].public_key_len);
	session->peers[0].credential =
		copy_bytes(credential, &session->peers[0].credential_len);
	session->peers[0].kid =
		copy_optional_bytes(kid, &session->peers[0].kid_len);
	validate_public_key_length(session->peers[0].public_key_len);
	if (session->peers[0].kid != NULL)
		validate_kid_length(session->peers[0].kid_len);
}

static void parse_peer_tuple(struct suite_peer *peer, VALUE tuple)
{
	Check_Type(tuple, T_ARRAY);
	if (RARRAY_LEN(tuple) != 3 && RARRAY_LEN(tuple) != 4)
		rb_raise(rb_eArgError,
			 "peer tuple must be [id, public_key, credential] or "
			 "[id, public_key, credential, kid]");

	peer->id = copy_optional_string(rb_ary_entry(tuple, 0), &peer->id_len);
	peer->public_key =
		copy_bytes(rb_ary_entry(tuple, 1), &peer->public_key_len);
	peer->credential =
		copy_bytes(rb_ary_entry(tuple, 2), &peer->credential_len);
	if (RARRAY_LEN(tuple) == 4)
		peer->kid =
			copy_optional_bytes(rb_ary_entry(tuple, 3), &peer->kid_len);

	validate_public_key_length(peer->public_key_len);
	if (peer->kid != NULL)
		validate_kid_length(peer->kid_len);
}

static void parse_peers(struct suite_session *session, VALUE peers_value)
{
	Check_Type(peers_value, T_ARRAY);
	if (RARRAY_LEN(peers_value) == 0)
		rb_raise(rb_eArgError, "at least one peer is required");

	session->peers_len = (size_t)RARRAY_LEN(peers_value);
	session->peers = calloc(session->peers_len, sizeof(*session->peers));
	if (session->peers == NULL)
		rb_raise(rb_eNoMemError, "failed to allocate EDHOC peers");

	for (size_t i = 0; i < session->peers_len; ++i)
		parse_peer_tuple(&session->peers[i],
				 rb_ary_entry(peers_value, (long)i));
}

static enum suite_credential_format parse_credential_format(VALUE value)
{
	const char *format = StringValueCStr(value);

	if (strcmp(format, "x509_chain") == 0)
		return SUITE_CREDENTIAL_X509_CHAIN;
	if (strcmp(format, "kid_cbor") == 0)
		return SUITE_CREDENTIAL_KID_CBOR;

	rb_raise(rb_eArgError,
		 "credential_format must be x509_chain or kid_cbor");
}

static void validate_credential_settings(struct suite_session *session)
{
	if (session->credential_format == SUITE_CREDENTIAL_X509_CHAIN)
		return;

	validate_kid_length(session->kid_len);
	for (size_t i = 0; i < session->peers_len; ++i) {
		if (session->peers[i].kid == NULL)
			rb_raise(rb_eArgError,
				 "peer kid is required for kid_cbor credentials");
		validate_kid_length(session->peers[i].kid_len);
	}
}

static int validate_call_context(const struct suite_session *session,
				 const struct edhoc_call_context *call_context)
{
	if (call_context == NULL || call_context->role != session->role ||
	    call_context->method != EDHOC_METHOD_0 ||
	    call_context->selected_cipher_suite != (int32_t)session->suite_id)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

static int credential_select_local(
	void *user_context, const struct edhoc_call_context *call_context,
	struct edhoc_credential_selected *selected)
{
	struct suite_session *session = user_context;

	if (session == NULL || selected == NULL)
		return EDHOC_ERROR_INVALID_ARGUMENT;
	if (validate_call_context(session, call_context) != EDHOC_SUCCESS)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	memset(selected, 0, sizeof(*selected));
	memcpy(selected->private_key_id, &session->authentication_key_id,
	       sizeof(session->authentication_key_id));

	if (session->credential_format == SUITE_CREDENTIAL_KID_CBOR) {
		selected->label = EDHOC_COSE_HEADER_KID;
		selected->kid.identifier.value = session->kid;
		selected->kid.identifier.length = session->kid_len;
		selected->kid.credential.value = session->credential;
		selected->kid.credential.length = session->credential_len;
		selected->kid.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
	} else {
		selected->label = EDHOC_COSE_HEADER_X509_CHAIN;
		selected->x509_chain.count = 1;
		selected->x509_chain.certificate[0].value = session->credential;
		selected->x509_chain.certificate[0].length =
			session->credential_len;
	}

	return EDHOC_SUCCESS;
}

static int authenticate_kid_peer(
	struct suite_session *session,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	if (received->label != EDHOC_COSE_HEADER_KID)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	for (size_t i = 0; i < session->peers_len; ++i) {
		const struct suite_peer *peer = &session->peers[i];

		if (peer->kid_len != received->kid.identifier.length)
			continue;
		if (memcmp(peer->kid, received->kid.identifier.value,
			   peer->kid_len) != 0)
			continue;

		trusted->credential.value = peer->credential;
		trusted->credential.length = peer->credential_len;
		trusted->format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
		trusted->public_key.value = peer->public_key;
		trusted->public_key.length = peer->public_key_len;
		session->matched_peer_index = i;
		session->matched_peer = true;
		session_set_untrusted_credential(session, NULL, 0);
		return EDHOC_SUCCESS;
	}

	return EDHOC_ERROR_CREDENTIALS_FAILURE;
}

static int authenticate_x509_peer(
	struct suite_session *session,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	const struct edhoc_buffer *certificate;

	if (received->label != EDHOC_COSE_HEADER_X509_CHAIN ||
	    received->x509_chain.count != 1)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	certificate = &received->x509_chain.certificate[0];
	session_set_untrusted_credential(session, certificate->value,
				 certificate->length);

	for (size_t i = 0; i < session->peers_len; ++i) {
		const struct suite_peer *peer = &session->peers[i];

		if (certificate->length != peer->credential_len)
			continue;
		if (memcmp(certificate->value, peer->credential,
			   peer->credential_len) != 0)
			continue;

		trusted->credential = *certificate;
		trusted->format = EDHOC_CREDENTIAL_FORMAT_RAW;
		trusted->public_key.value = peer->public_key;
		trusted->public_key.length = peer->public_key_len;
		session->matched_peer_index = i;
		session->matched_peer = true;
		session_set_untrusted_credential(session, NULL, 0);
		return EDHOC_SUCCESS;
	}

	return EDHOC_ERROR_CREDENTIALS_FAILURE;
}

static int credential_authenticate_peer(
	void *user_context, const struct edhoc_call_context *call_context,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	struct suite_session *session = user_context;

	if (session == NULL || received == NULL || trusted == NULL)
		return EDHOC_ERROR_INVALID_ARGUMENT;
	if (validate_call_context(session, call_context) != EDHOC_SUCCESS)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	memset(trusted, 0, sizeof(*trusted));
	if (session->credential_format == SUITE_CREDENTIAL_KID_CBOR)
		return authenticate_kid_peer(session, received, trusted);

	return authenticate_x509_peer(session, received, trusted);
}

static const struct edhoc_credentials credentials = {
	.select_local = credential_select_local,
	.authenticate_peer = credential_authenticate_peer,
};

static void session_dispose(struct suite_session *session)
{
	if (session == NULL)
		return;

	if (session->context_initialized) {
		(void)edhoc_context_deinit(session->ctx);
		session->context_initialized = false;
	}

	if (session->ctx != NULL) {
		platform_zeroize(session->ctx, session->ctx_size);
		free(session->ctx);
		session->ctx = NULL;
		session->ctx_size = 0;
	}

	if (session->authentication_key_imported) {
		(void)psa_destroy_key(session->authentication_key_id);
		session->authentication_key_id = PSA_KEY_ID_NULL;
		session->authentication_key_imported = false;
	}

	free(session->credential);
	session->credential = NULL;
	session->credential_len = 0;
	free(session->kid);
	session->kid = NULL;
	session->kid_len = 0;
	free(session->untrusted_credential);
	session->untrusted_credential = NULL;
	session->untrusted_credential_len = 0;
	session_dispose_peers(session);
}

static void session_free(void *ptr)
{
	struct suite_session *session = ptr;

	if (session == NULL)
		return;

	session_dispose(session);
	platform_zeroize(session, sizeof(*session));
	free(session);
}

static size_t session_size(const void *ptr)
{
	const struct suite_session *session = ptr;
	size_t size = sizeof(*session);

	if (session != NULL)
		size += session->ctx_size;
	return size;
}

static const rb_data_type_t session_type = {
	"Edhoc::Native::Session",
	{ 0, session_free, session_size },
	0, 0, RUBY_TYPED_FREE_IMMEDIATELY
};

static VALUE session_alloc(VALUE klass)
{
	struct suite_session *session = calloc(1, sizeof(*session));

	if (session == NULL)
		rb_raise(rb_eNoMemError, "failed to allocate EDHOC session");

	return TypedData_Wrap_Struct(klass, &session_type, session);
}

static struct suite_session *get_session(VALUE self)
{
	struct suite_session *session;

	TypedData_Get_Struct(self, struct suite_session, &session_type, session);
	if (session == NULL || !session->context_initialized)
		rb_raise(eEdhocBadStateError, "EDHOC session is not initialized");

	return session;
}

static struct parsed_connection_id parse_connection_id(VALUE value)
{
	struct parsed_connection_id parsed = { 0 };

	if (RB_INTEGER_TYPE_P(value)) {
		long id = NUM2LONG(value);

		if (id < -24 || id > 23)
			rb_raise(rb_eArgError,
				 "integer connection id must fit the EDHOC compact "
				 "integer range");
		parsed.bytes[0] =
			id >= 0 ? (uint8_t)id : (uint8_t)(0x20 | (-1 - id));
		parsed.buffer.value = parsed.bytes;
		parsed.buffer.length = 1;
		return parsed;
	}

	StringValue(value);
	if ((size_t)RSTRING_LEN(value) > sizeof(parsed.bytes))
		rb_raise(rb_eArgError, "byte-string connection id is too long");

	parsed.buffer.length = (size_t)RSTRING_LEN(value);
	if (parsed.buffer.length > 0)
		memcpy(parsed.bytes, RSTRING_PTR(value), parsed.buffer.length);
	parsed.buffer.value = parsed.bytes;
	return parsed;
}

static void import_authentication_key(struct suite_session *session,
				      VALUE private_key)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	StringValue(private_key);
	if (RSTRING_LEN(private_key) != 64)
		rb_raise(rb_eArgError,
			 "Ed25519 private key must be exactly 64 bytes");

	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
	status = psa_import_key(&attributes,
				(const uint8_t *)RSTRING_PTR(private_key),
				(size_t)RSTRING_LEN(private_key),
				&session->authentication_key_id);
	psa_reset_key_attributes(&attributes);

	if (status != PSA_SUCCESS)
		rb_raise(eEdhocCryptoError,
			 "psa_import_key failed with code %d", (int)status);

	session->authentication_key_imported = true;
}

static VALUE suite_session_initialize(int argc, VALUE *argv, VALUE self,
				      enum edhoc_cipher_suite_id suite_id)
{
	VALUE role_value;
	VALUE private_key;
	VALUE credential;
	VALUE credential_format_value;
	VALUE kid_value;
	VALUE peer_public_key;
	VALUE peer_credential;
	VALUE peer_kid;
	VALUE peers_value;
	VALUE connection_id_value;
	struct suite_session *session;
	const struct edhoc_cipher_suite *suite;
	const struct edhoc_crypto *crypto;
	struct parsed_connection_id connection_id;
	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	int ret;

	TypedData_Get_Struct(self, struct suite_session, &session_type, session);

	if (argc == 6) {
		role_value = argv[0];
		private_key = argv[1];
		credential = argv[2];
		credential_format_value = rb_str_new_cstr("x509_chain");
		kid_value = Qnil;
		peer_public_key = argv[3];
		peer_credential = argv[4];
		peer_kid = Qnil;
		connection_id_value = argv[5];
		peers_value = Qnil;
	} else if (argc == 5) {
		role_value = argv[0];
		private_key = argv[1];
		credential = argv[2];
		credential_format_value = rb_str_new_cstr("x509_chain");
		kid_value = Qnil;
		peers_value = argv[3];
		connection_id_value = argv[4];
		peer_public_key = Qnil;
		peer_credential = Qnil;
		peer_kid = Qnil;
	} else if (argc == 9) {
		role_value = argv[0];
		private_key = argv[1];
		credential = argv[2];
		credential_format_value = argv[3];
		kid_value = argv[4];
		peer_public_key = argv[5];
		peer_credential = argv[6];
		peer_kid = argv[7];
		connection_id_value = argv[8];
		peers_value = Qnil;
	} else if (argc == 7) {
		role_value = argv[0];
		private_key = argv[1];
		credential = argv[2];
		credential_format_value = argv[3];
		kid_value = argv[4];
		peers_value = argv[5];
		connection_id_value = argv[6];
		peer_public_key = Qnil;
		peer_credential = Qnil;
		peer_kid = Qnil;
	} else {
		rb_raise(rb_eArgError,
			 "wrong number of arguments (given %d, expected 5, 6, 7, "
			 "or 9)", argc);
	}

	const char *role = StringValueCStr(role_value);
	if (strcmp(role, "initiator") == 0)
		session->role = EDHOC_ROLE_INITIATOR;
	else if (strcmp(role, "responder") == 0)
		session->role = EDHOC_ROLE_RESPONDER;
	else
		rb_raise(rb_eArgError, "role must be initiator or responder");

	session->suite_id = suite_id;
	session->credential =
		copy_bytes(credential, &session->credential_len);
	session->credential_format =
		parse_credential_format(credential_format_value);
	session->kid = copy_optional_bytes(kid_value, &session->kid_len);
	if (NIL_P(peers_value))
		parse_single_peer(session, peer_public_key, peer_credential,
				  peer_kid);
	else
		parse_peers(session, peers_value);
	validate_credential_settings(session);
	connection_id = parse_connection_id(connection_id_value);

	ret = psa_crypto_init();
	if (ret != PSA_SUCCESS)
		rb_raise(eEdhocCryptoError,
			 "psa_crypto_init failed with code %d", ret);
	import_authentication_key(session, private_key);

	suite = edhoc_cipher_suite_get_params(suite_id);
	crypto = edhoc_cipher_suite_get_crypto(suite_id);
	if (suite == NULL || crypto == NULL)
		rb_raise(eEdhocNativeError,
			 "libedhoc cipher suite %d is not available", (int)suite_id);

	session->ctx_size = edhoc_context_size();
	session->ctx = calloc(1, session->ctx_size);
	if (session->ctx == NULL)
		rb_raise(rb_eNoMemError, "failed to allocate libedhoc context");

	ret = edhoc_context_init(session->ctx);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_context_init", ret);
	session->context_initialized = true;

	ret = edhoc_set_methods(session->ctx, methods, 1);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_set_methods", ret);
	ret = edhoc_set_cipher_suites(session->ctx, suite, 1);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_set_cipher_suites", ret);
	ret = edhoc_set_connection_id(session->ctx, &connection_id.buffer);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_set_connection_id", ret);
	ret = edhoc_set_user_context(session->ctx, session);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_set_user_context", ret);
	ret = edhoc_bind_crypto(session->ctx, crypto);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_bind_crypto", ret);
	ret = edhoc_bind_platform(session->ctx, &platform);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_bind_platform", ret);
	ret = edhoc_bind_credentials(session->ctx, &credentials);
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error("edhoc_bind_credentials", ret);

	return self;
}

static VALUE suite0_session_initialize(int argc, VALUE *argv, VALUE self)
{
	return suite_session_initialize(argc, argv, self, EDHOC_CIPHER_SUITE_0);
}

static VALUE suite4_session_initialize(int argc, VALUE *argv, VALUE self)
{
	return suite_session_initialize(argc, argv, self, EDHOC_CIPHER_SUITE_4);
}

static VALUE compose_to_string(
	struct suite_session *session, const char *name,
	int (*fn)(struct edhoc_context *, uint8_t *, size_t, size_t *))
{
	uint8_t buffer[EDHOC_RUBY_MAX_MESSAGE];
	size_t length = 0;
	int ret = fn(session->ctx, buffer, sizeof(buffer), &length);

	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error(name, ret);
	return rb_str_new((const char *)buffer, (long)length);
}

static VALUE session_compose_message1(VALUE self)
{
	return compose_to_string(get_session(self), "edhoc_message_1_compose",
				 edhoc_message_1_compose);
}

static VALUE session_compose_message2(VALUE self)
{
	return compose_to_string(get_session(self), "edhoc_message_2_compose",
				 edhoc_message_2_compose);
}

static VALUE session_compose_message3(VALUE self)
{
	return compose_to_string(get_session(self), "edhoc_message_3_compose",
				 edhoc_message_3_compose);
}

static VALUE process_message(
	struct suite_session *session, VALUE message, const char *name,
	int (*fn)(struct edhoc_context *, const uint8_t *, size_t))
{
	int ret;

	StringValue(message);
	ret = fn(session->ctx, (const uint8_t *)RSTRING_PTR(message),
		 (size_t)RSTRING_LEN(message));
	if (ret != EDHOC_SUCCESS)
		raise_edhoc_error(name, ret);
	return Qtrue;
}

static VALUE session_process_message1(VALUE self, VALUE message)
{
	return process_message(get_session(self), message,
			       "edhoc_message_1_process",
			       edhoc_message_1_process);
}

static VALUE session_process_message2(VALUE self, VALUE message)
{
	return process_message(get_session(self), message,
			       "edhoc_message_2_process",
			       edhoc_message_2_process);
}

static VALUE session_process_message3(VALUE self, VALUE message)
{
	return process_message(get_session(self), message,
			       "edhoc_message_3_process",
			       edhoc_message_3_process);
}

static VALUE export_prk(struct suite_session *session, VALUE label_value,
			VALUE context_value, VALUE length_value)
{
	const uint8_t *context = NULL;
	size_t context_length = 0;
	size_t label = NUM2SIZET(label_value);
	size_t length = NUM2SIZET(length_value);
	uint8_t *buffer;
	VALUE result;
	int ret;

	if (!NIL_P(context_value)) {
		StringValue(context_value);
		context_length = (size_t)RSTRING_LEN(context_value);
		if (context_length > 0)
			context = (const uint8_t *)RSTRING_PTR(context_value);
	}

	if (length == 0 || length > EDHOC_RUBY_MAX_EXPORT)
		rb_raise(rb_eArgError,
			 "export length must be between 1 and %d bytes",
			 EDHOC_RUBY_MAX_EXPORT);

	buffer = malloc(length);
	if (buffer == NULL)
		rb_raise(rb_eNoMemError, "failed to allocate exporter buffer");

	ret = edhoc_export_raw(session->ctx, label, context, context_length,
			       buffer, length);
	if (ret != EDHOC_SUCCESS) {
		platform_zeroize(buffer, length);
		free(buffer);
		raise_edhoc_error("edhoc_export_raw", ret);
	}

	result = rb_str_new((const char *)buffer, (long)length);
	platform_zeroize(buffer, length);
	free(buffer);
	return result;
}

static VALUE session_export_prk(VALUE self, VALUE label_value,
				VALUE length_value)
{
	return export_prk(get_session(self), label_value, Qnil, length_value);
}

static VALUE session_export_prk_with_context(VALUE self, VALUE label_value,
					     VALUE context_value,
					     VALUE length_value)
{
	return export_prk(get_session(self), label_value, context_value,
			  length_value);
}

static VALUE session_close(VALUE self)
{
	struct suite_session *session;

	TypedData_Get_Struct(self, struct suite_session, &session_type, session);
	session_dispose(session);
	return Qnil;
}

static VALUE session_matched_peer_id(VALUE self)
{
	struct suite_session *session = get_session(self);
	struct suite_peer *peer;

	if (!session->matched_peer)
		return Qnil;
	peer = &session->peers[session->matched_peer_index];
	if (peer->id == NULL)
		return Qnil;

	return rb_str_new(peer->id, (long)peer->id_len);
}

static VALUE session_untrusted_credential(VALUE self)
{
	struct suite_session *session = get_session(self);

	if (session->untrusted_credential == NULL ||
	    session->untrusted_credential_len == 0)
		return Qnil;

	return rb_str_new((const char *)session->untrusted_credential,
			  (long)session->untrusted_credential_len);
}

static VALUE native_library_version(VALUE self)
{
	VALUE hash = rb_hash_new();

	(void)self;
	rb_hash_aset(hash, ID2SYM(rb_intern("libedhoc_api_major")),
		      INT2NUM(EDHOC_API_VERSION_MAJOR));
	rb_hash_aset(hash, ID2SYM(rb_intern("libedhoc_api_minor")),
		      INT2NUM(EDHOC_API_VERSION_MINOR));
	rb_hash_aset(hash, ID2SYM(rb_intern("libedhoc_api_patch")),
		      INT2NUM(EDHOC_API_VERSION_PATCH));
	return hash;
}

static VALUE suite_profile_hash(const struct edhoc_cipher_suite *suite,
				const char *aead)
{
	VALUE hash = rb_hash_new();

	rb_hash_aset(hash, ID2SYM(rb_intern("method")), INT2NUM(0));
	rb_hash_aset(hash, ID2SYM(rb_intern("cipher_suite")),
		      INT2NUM(suite->value));
	rb_hash_aset(hash, ID2SYM(rb_intern("ecdh")),
		      rb_str_new_cstr("X25519"));
	rb_hash_aset(hash, ID2SYM(rb_intern("signature")),
		      rb_str_new_cstr("Ed25519/EdDSA"));
	rb_hash_aset(hash, ID2SYM(rb_intern("hash")),
		      rb_str_new_cstr("SHA-256"));
	rb_hash_aset(hash, ID2SYM(rb_intern("aead")), rb_str_new_cstr(aead));
	rb_hash_aset(hash, ID2SYM(rb_intern("aead_key_length")),
		      SIZET2NUM(suite->aead_key_length));
	rb_hash_aset(hash, ID2SYM(rb_intern("aead_tag_length")),
		      SIZET2NUM(suite->aead_tag_length));
	rb_hash_aset(hash, ID2SYM(rb_intern("aead_iv_length")),
		      SIZET2NUM(suite->aead_iv_length));
	rb_hash_aset(hash, ID2SYM(rb_intern("hash_length")),
		      SIZET2NUM(suite->hash_length));
	rb_hash_aset(hash, ID2SYM(rb_intern("ecc_key_length")),
		      SIZET2NUM(suite->kem_encapsulation_key_length));
	rb_hash_aset(hash, ID2SYM(rb_intern("signature_length")),
		      SIZET2NUM(suite->sign_length));
	return hash;
}

static VALUE native_suite0_profile(VALUE self)
{
	(void)self;
	return suite_profile_hash(
		edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_0),
		"AES-CCM-16-64-128");
}

static VALUE native_suite4_profile(VALUE self)
{
	(void)self;
	return suite_profile_hash(
		edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_4),
		"ChaCha20-Poly1305");
}

static void define_session_methods(VALUE klass)
{
	rb_define_alloc_func(klass, session_alloc);
	rb_define_method(klass, "compose_message1", session_compose_message1, 0);
	rb_define_method(klass, "process_message1", session_process_message1, 1);
	rb_define_method(klass, "compose_message2", session_compose_message2, 0);
	rb_define_method(klass, "process_message2", session_process_message2, 1);
	rb_define_method(klass, "compose_message3", session_compose_message3, 0);
	rb_define_method(klass, "process_message3", session_process_message3, 1);
	rb_define_method(klass, "export_prk", session_export_prk, 2);
	rb_define_method(klass, "export_prk_with_context",
			 session_export_prk_with_context, 3);
	rb_define_method(klass, "matched_peer_id", session_matched_peer_id, 0);
	rb_define_method(klass, "untrusted_credential",
			 session_untrusted_credential, 0);
	rb_define_method(klass, "close", session_close, 0);
}

void Init_edhoc_native(void)
{
	mEdhoc = rb_define_module("Edhoc");
	eEdhocError = rb_const_get(mEdhoc, rb_intern("Error"));
	eEdhocNativeError =
		rb_define_class_under(mEdhoc, "NativeError", eEdhocError);
	eEdhocBadStateError = rb_define_class_under(
		mEdhoc, "BadStateError", eEdhocNativeError);
	eEdhocCborError =
		rb_define_class_under(mEdhoc, "CborError", eEdhocNativeError);
	eEdhocCryptoError =
		rb_define_class_under(mEdhoc, "CryptoError", eEdhocNativeError);
	eEdhocCredentialsError = rb_define_class_under(
		mEdhoc, "CredentialsError", eEdhocNativeError);
	eEdhocKeyExchangeError = rb_define_class_under(
		mEdhoc, "KeyExchangeError", eEdhocCryptoError);
	eEdhocMessageError =
		rb_define_class_under(mEdhoc, "MessageError", eEdhocNativeError);
	mNative = rb_define_module_under(mEdhoc, "Native");

	rb_define_singleton_method(mNative, "library_version",
				   native_library_version, 0);
	rb_define_singleton_method(mNative, "suite0_profile",
				   native_suite0_profile, 0);
	rb_define_singleton_method(mNative, "suite4_profile",
				   native_suite4_profile, 0);

	cSuite0Session =
		rb_define_class_under(mNative, "Suite0Session", rb_cObject);
	define_session_methods(cSuite0Session);
	rb_define_method(cSuite0Session, "initialize", suite0_session_initialize,
			 -1);

	cSuite4Session =
		rb_define_class_under(mNative, "Suite4Session", rb_cObject);
	define_session_methods(cSuite4Session);
	rb_define_method(cSuite4Session, "initialize", suite4_session_initialize,
			 -1);
}

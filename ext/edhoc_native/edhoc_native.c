#include "ruby.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <edhoc/edhoc.h>
#include <psa/crypto.h>

#define RUBY_EDHOC_MAX_EXPORT (1024U * 1024U)

static VALUE mEdhoc;
static VALUE mNative;
static VALUE cSession;
static VALUE eNativeError;
static VALUE eBadStateError;
static VALUE eInvalidArgumentError;
static VALUE eNotSupportedError;
static VALUE eNotPermittedError;
static VALUE eBufferTooSmallError;
static VALUE eNativeMemoryError;
static VALUE eCborError;
static VALUE eCryptoError;
static VALUE eCredentialsError;
static VALUE eEadError;
static VALUE eKeyExchangeError;
static VALUE eMessageError;

static ID id_native_select_local;
static ID id_native_authenticate_peer;
static ID id_native_ead_compose;
static ID id_native_ead_process;

enum ruby_edhoc_state {
	RUBY_EDHOC_NEW,
	RUBY_EDHOC_WAIT_MESSAGE_2,
	RUBY_EDHOC_RECEIVED_MESSAGE_1,
	RUBY_EDHOC_VERIFIED_MESSAGE_2,
	RUBY_EDHOC_WAIT_MESSAGE_3,
	RUBY_EDHOC_COMPLETED,
	RUBY_EDHOC_PERSISTED,
	RUBY_EDHOC_ABORTED,
	RUBY_EDHOC_CLOSED,
};

struct ruby_edhoc_session {
	struct edhoc_context *context;
	size_t context_size;
	bool initialized;
	enum edhoc_role role;
	enum ruby_edhoc_state state;
	enum edhoc_method methods[CONFIG_LIBEDHOC_MAX_NR_OF_METHODS];
	size_t method_count;
	struct edhoc_cipher_suite suites[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	size_t suite_count;
	int32_t selected_method;
	int32_t selected_suite;
	bool parameters_selected;
	size_t max_message_size;
	psa_key_id_t authentication_key;
	bool authentication_key_imported;
	VALUE credentials;
	VALUE ead;
	VALUE pending_exception;
	VALUE callback_roots;
	VALUE peer_id;
	VALUE last_operation;
	int last_native_error;
	int protocol_error;
	bool has_protocol_error;
	int32_t local_suites[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	size_t local_suite_count;
	int32_t peer_suites[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	size_t peer_suite_count;
};

struct parsed_connection_id {
	uint8_t bytes[CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID];
	struct edhoc_buffer buffer;
};

struct protected_call {
	VALUE receiver;
	ID method;
	int argc;
	VALUE argv[2];
};

_Static_assert(sizeof(psa_key_id_t) <= CONFIG_LIBEDHOC_KEY_ID_LEN,
	       "PSA key handles must fit libedhoc key identifiers");

static void secure_zero(void *buffer, size_t length)
{
	volatile uint8_t *cursor = buffer;
	while (length-- > 0)
		*cursor++ = 0;
}

static const struct edhoc_platform platform = {
	.zeroize = secure_zero,
};

static VALUE symbol(const char *name)
{
	return ID2SYM(rb_intern(name));
}

static VALUE hash_get(VALUE hash, const char *name)
{
	return rb_hash_aref(hash, symbol(name));
}

static void hash_set(VALUE hash, const char *name, VALUE value)
{
	rb_hash_aset(hash, symbol(name), value);
}

static struct edhoc_buffer ruby_buffer(VALUE value)
{
	StringValue(value);
	return (struct edhoc_buffer){
		.value = (const uint8_t *)RSTRING_PTR(value),
		.length = (size_t)RSTRING_LEN(value),
	};
}

static VALUE protected_funcall(VALUE opaque)
{
	struct protected_call *call = (struct protected_call *)opaque;
	return rb_funcallv(call->receiver, call->method, call->argc, call->argv);
}

static VALUE call_ruby(struct ruby_edhoc_session *session, VALUE receiver,
		       ID method, int argc, VALUE *argv)
{
	struct protected_call call = {
		.receiver = receiver,
		.method = method,
		.argc = argc,
	};
	int state = 0;

	for (int i = 0; i < argc; i++)
		call.argv[i] = argv[i];
	VALUE result = rb_protect(protected_funcall, (VALUE)&call, &state);
	if (state != 0) {
		session->pending_exception = rb_errinfo();
		rb_set_errinfo(Qnil);
		return Qnil;
	}
	return result;
}

static bool authentication_is_static(enum edhoc_method method,
				     enum edhoc_role role)
{
	switch (method) {
	case EDHOC_METHOD_0:
		return false;
	case EDHOC_METHOD_1:
		return role == EDHOC_ROLE_RESPONDER;
	case EDHOC_METHOD_2:
		return role == EDHOC_ROLE_INITIATOR;
	case EDHOC_METHOD_3:
		return true;
	default:
		return false;
	}
}

static VALUE context_hash(const struct edhoc_call_context *context,
			  bool peer_credential, bool ead)
{
	VALUE hash = rb_hash_new();
	enum edhoc_role credential_role = context->role;
	if (peer_credential)
		credential_role = context->role == EDHOC_ROLE_INITIATOR ?
				  EDHOC_ROLE_RESPONDER : EDHOC_ROLE_INITIATOR;

	hash_set(hash, "role", context->role == EDHOC_ROLE_INITIATOR ?
				 symbol("initiator") : symbol("responder"));
	hash_set(hash, "method", INT2NUM(context->method));
	hash_set(hash, "cipher_suite", INT2NUM(context->selected_cipher_suite));
	hash_set(hash, "message", INT2NUM((int)context->message + 1));
	if (!ead) {
		hash_set(hash, "authentication",
			 authentication_is_static(context->method, credential_role) ?
			 symbol("static_dh") : symbol("signature"));
	}
	return hash;
}

static int import_authentication_key(struct ruby_edhoc_session *session,
				     VALUE bytes, bool static_dh)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;
	int32_t suite = session->selected_suite;

	StringValue(bytes);
	if (session->authentication_key_imported) {
		psa_destroy_key(session->authentication_key);
		session->authentication_key_imported = false;
	}

	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	if (!static_dh && (suite == 0 || suite == 4)) {
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
	} else if (suite == 0 || suite == 4) {
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
		psa_set_key_type(&attributes,
			PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
		psa_set_key_bits(&attributes, 255);
	} else {
		size_t bits = suite == 2 ? 256 : 384;
		psa_set_key_type(&attributes,
			PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attributes, bits);
		if (static_dh) {
			psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
			psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
		} else {
			psa_algorithm_t hash = suite == 2 ? PSA_ALG_SHA_256 : PSA_ALG_SHA_384;
			psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
			psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(hash));
		}
	}

	status = psa_import_key(&attributes,
				(const uint8_t *)RSTRING_PTR(bytes),
				(size_t)RSTRING_LEN(bytes),
				&session->authentication_key);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS)
		return EDHOC_ERROR_CRYPTO_FAILURE;
	session->authentication_key_imported = true;
	return EDHOC_SUCCESS;
}

static bool symbol_is(VALUE value, const char *name)
{
	return SYMBOL_P(value) && SYM2ID(value) == rb_intern(name);
}

static int credentials_select_local(
	void *user_context, const struct edhoc_call_context *call_context,
	struct edhoc_credential_selected *selected)
{
	struct ruby_edhoc_session *session = user_context;
	memset(selected, 0, sizeof(*selected));
	VALUE args[] = { context_hash(call_context, false, false) };
	VALUE result = call_ruby(session, session->credentials,
				 id_native_select_local, 1, args);
	if (!NIL_P(session->pending_exception))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	Check_Type(result, T_HASH);
	rb_ary_push(session->callback_roots, result);

	session->selected_method = (int32_t)call_context->method;
	session->selected_suite = call_context->selected_cipher_suite;
	session->parameters_selected = true;
	VALUE private_key = hash_get(result, "private_key");
	bool static_dh = authentication_is_static(call_context->method,
						 call_context->role);
	int ret = import_authentication_key(session, private_key, static_dh);
	if (ret != EDHOC_SUCCESS)
		return ret;
	memcpy(selected->private_key_id, &session->authentication_key,
	       sizeof(session->authentication_key));

	VALUE kind = hash_get(result, "kind");
	if (symbol_is(kind, "kid")) {
		selected->label = EDHOC_COSE_HEADER_KID;
		selected->kid.identifier = ruby_buffer(hash_get(result, "identifier"));
		selected->kid.credential = ruby_buffer(hash_get(result, "credential"));
		selected->kid.format = symbol_is(hash_get(result, "format"), "cbor") ?
			EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED : EDHOC_CREDENTIAL_FORMAT_RAW;
	} else if (symbol_is(kind, "x5chain")) {
		VALUE certificates = hash_get(result, "certificates");
		Check_Type(certificates, T_ARRAY);
		long count = RARRAY_LEN(certificates);
		if (count < 1 || count > EDHOC_CREDENTIAL_X5CHAIN_CAPACITY)
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		selected->label = EDHOC_COSE_HEADER_X509_CHAIN;
		selected->x509_chain.count = (size_t)count;
		for (long i = 0; i < count; i++)
			selected->x509_chain.certificate[i] =
				ruby_buffer(rb_ary_entry(certificates, i));
	} else if (symbol_is(kind, "x5t")) {
		VALUE algorithm = hash_get(result, "algorithm");
		selected->label = EDHOC_COSE_HEADER_X509_HASH;
		if (RB_INTEGER_TYPE_P(algorithm)) {
			selected->x509_hash.algorithm.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
			selected->x509_hash.algorithm.integer = NUM2INT(algorithm);
		} else {
			selected->x509_hash.algorithm.encode_type = EDHOC_ENCODE_TYPE_STRING;
			selected->x509_hash.algorithm.string = ruby_buffer(algorithm);
		}
		selected->x509_hash.fingerprint = ruby_buffer(hash_get(result, "fingerprint"));
		selected->x509_hash.certificate = ruby_buffer(hash_get(result, "certificate"));
	} else {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}
	return EDHOC_SUCCESS;
}

static VALUE received_credential_hash(
	const struct edhoc_credential_received *received)
{
	VALUE hash = rb_hash_new();
	if (received->label == EDHOC_COSE_HEADER_KID) {
		hash_set(hash, "kind", symbol("kid"));
		hash_set(hash, "identifier",
			rb_str_new((const char *)received->kid.identifier.value,
				   (long)received->kid.identifier.length));
	} else if (received->label == EDHOC_COSE_HEADER_X509_CHAIN) {
		VALUE certificates = rb_ary_new_capa((long)received->x509_chain.count);
		hash_set(hash, "kind", symbol("x5chain"));
		for (size_t i = 0; i < received->x509_chain.count; i++) {
			struct edhoc_buffer certificate = received->x509_chain.certificate[i];
			rb_ary_push(certificates,
				rb_str_new((const char *)certificate.value,
					   (long)certificate.length));
		}
		hash_set(hash, "certificates", certificates);
	} else {
		hash_set(hash, "kind", symbol("x5t"));
		if (received->x509_hash.algorithm.encode_type == EDHOC_ENCODE_TYPE_INTEGER) {
			hash_set(hash, "algorithm",
				 INT2NUM(received->x509_hash.algorithm.integer));
		} else {
			struct edhoc_buffer algorithm = received->x509_hash.algorithm.string;
			hash_set(hash, "algorithm",
				rb_str_new((const char *)algorithm.value,
					   (long)algorithm.length));
		}
		hash_set(hash, "fingerprint",
			rb_str_new((const char *)received->x509_hash.fingerprint.value,
				   (long)received->x509_hash.fingerprint.length));
	}
	return hash;
}

static int credentials_authenticate_peer(
	void *user_context, const struct edhoc_call_context *call_context,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	struct ruby_edhoc_session *session = user_context;
	memset(trusted, 0, sizeof(*trusted));
	VALUE args[] = {
		context_hash(call_context, true, false),
		received_credential_hash(received),
	};
	VALUE result = call_ruby(session, session->credentials,
				 id_native_authenticate_peer, 2, args);
	if (!NIL_P(session->pending_exception) || NIL_P(result))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	Check_Type(result, T_HASH);
	rb_ary_push(session->callback_roots, result);

	session->selected_method = (int32_t)call_context->method;
	session->selected_suite = call_context->selected_cipher_suite;
	session->parameters_selected = true;
	trusted->credential = ruby_buffer(hash_get(result, "credential"));
	trusted->format = symbol_is(hash_get(result, "format"), "cbor") ?
		EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED : EDHOC_CREDENTIAL_FORMAT_RAW;
	trusted->public_key = ruby_buffer(hash_get(result, "public_key"));
	session->peer_id = hash_get(result, "peer_id");
	return EDHOC_SUCCESS;
}

static const struct edhoc_credentials credentials = {
	.select_local = credentials_select_local,
	.authenticate_peer = credentials_authenticate_peer,
};

static int ead_compose(void *user_context,
		       const struct edhoc_call_context *call_context,
		       struct edhoc_ead_token *tokens, size_t token_size,
		       size_t *token_count)
{
	struct ruby_edhoc_session *session = user_context;
	VALUE args[] = { context_hash(call_context, false, true) };
	VALUE result = call_ruby(session, session->ead, id_native_ead_compose, 1, args);
	if (!NIL_P(session->pending_exception))
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	Check_Type(result, T_ARRAY);
	long count = RARRAY_LEN(result);
	if (count < 0 || (size_t)count > token_size)
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	rb_ary_push(session->callback_roots, result);
	static const uint8_t empty_value = 0;
	for (long i = 0; i < count; i++) {
		VALUE tuple = rb_ary_entry(result, i);
		Check_Type(tuple, T_ARRAY);
		tokens[i].label = NUM2INT(rb_ary_entry(tuple, 0));
		VALUE value = rb_ary_entry(tuple, 1);
		if (NIL_P(value)) {
			tokens[i].value.value = NULL;
			tokens[i].value.length = 0;
		} else {
			tokens[i].value = ruby_buffer(value);
			if (tokens[i].value.length == 0)
				tokens[i].value.value = &empty_value;
		}
	}
	*token_count = (size_t)count;
	return EDHOC_SUCCESS;
}

static int ead_process(void *user_context,
		       const struct edhoc_call_context *call_context,
		       const struct edhoc_ead_token *tokens, size_t token_count)
{
	struct ruby_edhoc_session *session = user_context;
	VALUE encoded = rb_ary_new_capa((long)token_count);
	for (size_t i = 0; i < token_count; i++) {
		VALUE tuple = rb_ary_new_capa(2);
		rb_ary_push(tuple, INT2NUM(tokens[i].label));
		if (tokens[i].value.value == NULL)
			rb_ary_push(tuple, Qnil);
		else
			rb_ary_push(tuple,
				rb_str_new((const char *)tokens[i].value.value,
					   (long)tokens[i].value.length));
		rb_ary_push(encoded, tuple);
	}
	VALUE args[] = { context_hash(call_context, false, true), encoded };
	call_ruby(session, session->ead, id_native_ead_process, 2, args);
	return NIL_P(session->pending_exception) ? EDHOC_SUCCESS :
		EDHOC_ERROR_EAD_PROCESS_FAILURE;
}

static const struct edhoc_ead ead = {
	.compose = ead_compose,
	.process = ead_process,
};

static const char *error_name(int code)
{
	switch (code) {
	case EDHOC_ERROR_GENERIC_ERROR: return "generic_error";
	case EDHOC_ERROR_NOT_SUPPORTED: return "not_supported";
	case EDHOC_ERROR_NOT_PERMITTED: return "not_permitted";
	case EDHOC_ERROR_BUFFER_TOO_SMALL: return "buffer_too_small";
	case EDHOC_ERROR_BAD_STATE: return "bad_state";
	case EDHOC_ERROR_INVALID_ARGUMENT: return "invalid_argument";
	case EDHOC_ERROR_NOT_ENOUGH_MEMORY: return "not_enough_memory";
	case EDHOC_ERROR_CBOR_FAILURE: return "cbor_failure";
	case EDHOC_ERROR_CRYPTO_FAILURE: return "crypto_failure";
	case EDHOC_ERROR_CREDENTIALS_FAILURE: return "credentials_failure";
	case EDHOC_ERROR_EAD_COMPOSE_FAILURE: return "ead_compose_failure";
	case EDHOC_ERROR_EAD_PROCESS_FAILURE: return "ead_process_failure";
	case EDHOC_ERROR_MSG_1_PROCESS_FAILURE: return "message_1_process_failure";
	case EDHOC_ERROR_MSG_2_PROCESS_FAILURE: return "message_2_process_failure";
	case EDHOC_ERROR_MSG_3_PROCESS_FAILURE: return "message_3_process_failure";
	case EDHOC_ERROR_MSG_4_PROCESS_FAILURE: return "message_4_process_failure";
	case EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE: return "ephemeral_key_exchange_failure";
	case EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE: return "transcript_hash_failure";
	case EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE: return "pseudorandom_key_failure";
	case EDHOC_ERROR_INVALID_SIGN_OR_MAC_2: return "invalid_sign_or_mac_2";
	case EDHOC_ERROR_INVALID_SIGN_OR_MAC_3: return "invalid_sign_or_mac_3";
	default: return "unknown";
	}
}

static VALUE exception_class(int code)
{
	switch (code) {
	case EDHOC_ERROR_BAD_STATE: return eBadStateError;
	case EDHOC_ERROR_INVALID_ARGUMENT: return eInvalidArgumentError;
	case EDHOC_ERROR_NOT_SUPPORTED: return eNotSupportedError;
	case EDHOC_ERROR_NOT_PERMITTED: return eNotPermittedError;
	case EDHOC_ERROR_BUFFER_TOO_SMALL: return eBufferTooSmallError;
	case EDHOC_ERROR_NOT_ENOUGH_MEMORY: return eNativeMemoryError;
	case EDHOC_ERROR_CBOR_FAILURE: return eCborError;
	case EDHOC_ERROR_CRYPTO_FAILURE:
	case EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE:
	case EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE:
	case EDHOC_ERROR_INVALID_SIGN_OR_MAC_2:
	case EDHOC_ERROR_INVALID_SIGN_OR_MAC_3: return eCryptoError;
	case EDHOC_ERROR_CREDENTIALS_FAILURE: return eCredentialsError;
	case EDHOC_ERROR_EAD_COMPOSE_FAILURE:
	case EDHOC_ERROR_EAD_PROCESS_FAILURE: return eEadError;
	case EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE: return eKeyExchangeError;
	case EDHOC_ERROR_MSG_1_PROCESS_FAILURE:
	case EDHOC_ERROR_MSG_2_PROCESS_FAILURE:
	case EDHOC_ERROR_MSG_3_PROCESS_FAILURE:
	case EDHOC_ERROR_MSG_4_PROCESS_FAILURE: return eMessageError;
	default: return eNativeError;
	}
}

static VALUE int_array(const int32_t *items, size_t count)
{
	VALUE array = rb_ary_new_capa((long)count);
	for (size_t i = 0; i < count; i++)
		rb_ary_push(array, INT2NUM(items[i]));
	return array;
}

static _Noreturn void raise_native_error(const char *operation, int code)
{
	VALUE message = rb_sprintf("%s failed with libedhoc error %s (%d)",
				   operation, error_name(code), code);
	VALUE exception = rb_exc_new_str(exception_class(code), message);
	rb_ivar_set(exception, rb_intern("@operation"), symbol(operation));
	rb_ivar_set(exception, rb_intern("@code"), symbol(error_name(code)));
	rb_ivar_set(exception, rb_intern("@code_number"), INT2NUM(code));
	rb_ivar_set(exception, rb_intern("@protocol_code"), Qnil);
	rb_ivar_set(exception, rb_intern("@local_cipher_suites"), rb_ary_new());
	rb_ivar_set(exception, rb_intern("@peer_cipher_suites"), rb_ary_new());
	rb_exc_raise(exception);
}

static void record_error(struct ruby_edhoc_session *session, int code)
{
	session->last_native_error = code;
	session->has_protocol_error = false;
	session->local_suite_count = 0;
	session->peer_suite_count = 0;
	enum edhoc_error_code protocol;
	if (edhoc_error_get_code(session->context, &protocol) == EDHOC_SUCCESS &&
	    protocol != EDHOC_ERROR_CODE_SUCCESS) {
		session->protocol_error = (int)protocol;
		session->has_protocol_error = true;
		if (protocol == EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
			edhoc_error_get_cipher_suites(
				session->context, session->local_suites,
				CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES,
				&session->local_suite_count, session->peer_suites,
				CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES,
				&session->peer_suite_count);
		}
	}
}

static _Noreturn void raise_session_error(struct ruby_edhoc_session *session,
					 const char *operation, int code)
{
	record_error(session, code);
	if (session->authentication_key_imported) {
		psa_destroy_key(session->authentication_key);
		session->authentication_key_imported = false;
	}
	if (!NIL_P(session->pending_exception)) {
		VALUE exception = session->pending_exception;
		session->pending_exception = Qnil;
		rb_exc_raise(exception);
	}

	VALUE message = rb_sprintf("%s failed with libedhoc error %s (%d)",
				   operation, error_name(code), code);
	VALUE exception = rb_exc_new_str(exception_class(code), message);
	rb_ivar_set(exception, rb_intern("@operation"), symbol(operation));
	rb_ivar_set(exception, rb_intern("@code"), symbol(error_name(code)));
	rb_ivar_set(exception, rb_intern("@code_number"), INT2NUM(code));
	rb_ivar_set(exception, rb_intern("@protocol_code"),
		    session->has_protocol_error ? INT2NUM(session->protocol_error) : Qnil);
	rb_ivar_set(exception, rb_intern("@local_cipher_suites"),
		    int_array(session->local_suites, session->local_suite_count));
	rb_ivar_set(exception, rb_intern("@peer_cipher_suites"),
		    int_array(session->peer_suites, session->peer_suite_count));
	rb_exc_raise(exception);
}

static void session_mark(void *pointer)
{
	struct ruby_edhoc_session *session = pointer;
	if (session == NULL)
		return;
	rb_gc_mark_movable(session->credentials);
	rb_gc_mark_movable(session->ead);
	rb_gc_mark_movable(session->pending_exception);
	rb_gc_mark_movable(session->callback_roots);
	rb_gc_mark_movable(session->peer_id);
	rb_gc_mark_movable(session->last_operation);
}

static void session_compact(void *pointer)
{
	struct ruby_edhoc_session *session = pointer;
	if (session == NULL)
		return;
	session->credentials = rb_gc_location(session->credentials);
	session->ead = rb_gc_location(session->ead);
	session->pending_exception = rb_gc_location(session->pending_exception);
	session->callback_roots = rb_gc_location(session->callback_roots);
	session->peer_id = rb_gc_location(session->peer_id);
	session->last_operation = rb_gc_location(session->last_operation);
}

static void session_release(struct ruby_edhoc_session *session)
{
	if (session->authentication_key_imported) {
		psa_destroy_key(session->authentication_key);
		session->authentication_key_imported = false;
	}
	if (session->initialized) {
		edhoc_context_deinit(session->context);
		session->initialized = false;
	}
	if (session->context != NULL) {
		secure_zero(session->context, session->context_size);
		free(session->context);
		session->context = NULL;
	}
}

static void session_free(void *pointer)
{
	struct ruby_edhoc_session *session = pointer;
	if (session == NULL)
		return;
	session_release(session);
	secure_zero(session, sizeof(*session));
	free(session);
}

static size_t session_memsize(const void *pointer)
{
	const struct ruby_edhoc_session *session = pointer;
	return session == NULL ? 0 : sizeof(*session) + session->context_size;
}

static const rb_data_type_t session_type = {
	.wrap_struct_name = "Edhoc::Native::Session",
	.function = {
		.dmark = session_mark,
		.dfree = session_free,
		.dsize = session_memsize,
		.dcompact = session_compact,
	},
	.flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

static VALUE session_alloc(VALUE klass)
{
	struct ruby_edhoc_session *session = calloc(1, sizeof(*session));
	if (session == NULL)
		rb_memerror();
	session->credentials = Qnil;
	session->ead = Qnil;
	session->pending_exception = Qnil;
	session->callback_roots = rb_ary_new();
	session->peer_id = Qnil;
	session->last_operation = Qnil;
	return TypedData_Wrap_Struct(klass, &session_type, session);
}

static struct ruby_edhoc_session *get_session(VALUE self)
{
	struct ruby_edhoc_session *session;
	TypedData_Get_Struct(self, struct ruby_edhoc_session, &session_type, session);
	if (session == NULL || !session->initialized || session->state == RUBY_EDHOC_CLOSED)
		rb_raise(eBadStateError, "EDHOC session is closed or uninitialized");
	return session;
}

static struct parsed_connection_id parse_connection_id(VALUE value)
{
	struct parsed_connection_id parsed = { 0 };
	if (RB_INTEGER_TYPE_P(value)) {
		long id = NUM2LONG(value);
		if (id < -24 || id > 23)
			rb_raise(rb_eArgError, "integer connection ID must be between -24 and 23");
		parsed.bytes[0] = id >= 0 ? (uint8_t)id : (uint8_t)(0x20 | (-1 - id));
		parsed.buffer.value = parsed.bytes;
		parsed.buffer.length = 1;
		return parsed;
	}
	StringValue(value);
	if ((size_t)RSTRING_LEN(value) > sizeof(parsed.bytes))
		rb_raise(rb_eArgError, "connection ID is too long");
	parsed.buffer.length = (size_t)RSTRING_LEN(value);
	memcpy(parsed.bytes, RSTRING_PTR(value), parsed.buffer.length);
	parsed.buffer.value = parsed.bytes;
	return parsed;
}

static enum edhoc_role parse_role(VALUE value)
{
	if (symbol_is(value, "initiator"))
		return EDHOC_ROLE_INITIATOR;
	if (symbol_is(value, "responder"))
		return EDHOC_ROLE_RESPONDER;
	rb_raise(rb_eArgError, "role must be :initiator or :responder");
}

static VALUE session_initialize(VALUE self, VALUE role_value, VALUE methods_value,
				VALUE suites_value, VALUE connection_id_value,
				VALUE credentials_value, VALUE ead_value,
				VALUE max_message_size_value)
{
	struct ruby_edhoc_session *session;
	TypedData_Get_Struct(self, struct ruby_edhoc_session, &session_type, session);
	session->role = parse_role(role_value);
	session->credentials = credentials_value;
	session->ead = ead_value;
	session->max_message_size = NUM2SIZET(max_message_size_value);
	if (session->max_message_size == 0)
		rb_raise(rb_eArgError, "max message size must be positive");

	Check_Type(methods_value, T_ARRAY);
	long method_count = RARRAY_LEN(methods_value);
	if (method_count < 1 || method_count > CONFIG_LIBEDHOC_MAX_NR_OF_METHODS)
		rb_raise(rb_eArgError, "invalid method count");
	session->method_count = (size_t)method_count;
	for (long i = 0; i < method_count; i++)
		session->methods[i] = (enum edhoc_method)NUM2INT(rb_ary_entry(methods_value, i));

	Check_Type(suites_value, T_ARRAY);
	long suite_count = RARRAY_LEN(suites_value);
	if (suite_count < 1 || suite_count > CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES)
		rb_raise(rb_eArgError, "invalid cipher suite count");
	session->suite_count = (size_t)suite_count;
	for (long i = 0; i < suite_count; i++) {
		int id = NUM2INT(rb_ary_entry(suites_value, suite_count - i - 1));
		const struct edhoc_cipher_suite *suite =
			edhoc_cipher_suite_get_params((enum edhoc_cipher_suite_id)id);
		if (suite == NULL)
			rb_raise(rb_eArgError, "cipher suite %d is unavailable", id);
		session->suites[i] = *suite;
	}
	session->selected_suite = session->suites[session->suite_count - 1].value;
	session->selected_method = (int32_t)session->methods[0];

	psa_status_t psa_status = psa_crypto_init();
	if (psa_status != PSA_SUCCESS)
		rb_raise(eCryptoError, "psa_crypto_init failed with code %d", (int)psa_status);

	session->context_size = edhoc_context_size();
	session->context = calloc(1, session->context_size);
	if (session->context == NULL)
		rb_memerror();
	int ret = edhoc_context_init(session->context);
	if (ret != EDHOC_SUCCESS)
		raise_session_error(session, "edhoc_context_init", ret);
	session->initialized = true;
	struct parsed_connection_id connection_id = parse_connection_id(connection_id_value);
	ret = edhoc_set_methods(session->context, session->methods, session->method_count);
	if (ret == EDHOC_SUCCESS)
		ret = edhoc_set_cipher_suites(session->context, session->suites, session->suite_count);
	if (ret == EDHOC_SUCCESS)
		ret = edhoc_set_connection_id(session->context, &connection_id.buffer);
	if (ret == EDHOC_SUCCESS)
		ret = edhoc_set_user_context(session->context, session);
	const struct edhoc_crypto *crypto = edhoc_cipher_suite_get_crypto(
		(enum edhoc_cipher_suite_id)session->selected_suite);
	if (ret == EDHOC_SUCCESS && crypto == NULL)
		ret = EDHOC_ERROR_NOT_SUPPORTED;
	if (ret == EDHOC_SUCCESS)
		ret = edhoc_bind_crypto(session->context, crypto);
	if (ret == EDHOC_SUCCESS)
		ret = edhoc_bind_platform(session->context, &platform);
	if (ret == EDHOC_SUCCESS)
		ret = edhoc_bind_credentials(session->context, &credentials);
	if (ret == EDHOC_SUCCESS && !NIL_P(session->ead))
		ret = edhoc_bind_ead(session->context, &ead);
	if (ret != EDHOC_SUCCESS)
		raise_session_error(session, "initialize", ret);
	session->state = RUBY_EDHOC_NEW;
	return self;
}

static bool cbor_integer(const uint8_t *data, size_t length, size_t *offset,
			 int32_t *value)
{
	if (*offset >= length)
		return false;
	uint8_t first = data[(*offset)++];
	uint8_t major = first >> 5;
	uint8_t additional = first & 0x1f;
	uint32_t number;
	if (additional < 24) {
		number = additional;
	} else if (additional == 24 && *offset < length) {
		number = data[(*offset)++];
	} else {
		return false;
	}
	if (major == 0)
		*value = (int32_t)number;
	else if (major == 1)
		*value = -(int32_t)number - 1;
	else
		return false;
	return true;
}

static bool parse_message_1_selection(const uint8_t *data, size_t length,
				      int32_t *method, int32_t *suite)
{
	size_t offset = 0;
	if (!cbor_integer(data, length, &offset, method) || offset >= length)
		return false;
	uint8_t first = data[offset];
	if ((first >> 5) != 4)
		return cbor_integer(data, length, &offset, suite);
	offset++;
	size_t count = first & 0x1f;
	if (count < 2 || count > CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES)
		return false;
	for (size_t i = 0; i < count; i++) {
		if (!cbor_integer(data, length, &offset, suite))
			return false;
	}
	return true;
}

static bool supports_suite(struct ruby_edhoc_session *session, int32_t selected)
{
	for (size_t i = 0; i < session->suite_count; i++)
		if (session->suites[i].value == selected)
			return true;
	return false;
}

static void prepare_operation(struct ruby_edhoc_session *session,
			      const char *operation)
{
	session->last_operation = symbol(operation);
	session->callback_roots = rb_ary_new();
	session->pending_exception = Qnil;
}

static void finish_operation(struct ruby_edhoc_session *session,
			     const char *operation, int ret,
			     enum ruby_edhoc_state success_state)
{
	session->callback_roots = rb_ary_new();
	if (ret != EDHOC_SUCCESS) {
		session->state = RUBY_EDHOC_ABORTED;
		raise_session_error(session, operation, ret);
	}
	if (!NIL_P(session->pending_exception)) {
		VALUE exception = session->pending_exception;
		session->pending_exception = Qnil;
		session->state = RUBY_EDHOC_ABORTED;
		rb_exc_raise(exception);
	}
	session->state = success_state;
	session->last_native_error = EDHOC_SUCCESS;
	session->has_protocol_error = false;
}

static void require_state(struct ruby_edhoc_session *session,
			  enum edhoc_role role, enum ruby_edhoc_state state,
			  const char *operation)
{
	if (session->role != role || session->state != state)
		rb_raise(eBadStateError, "%s is invalid for this role or session state", operation);
}

static VALUE compose_message(VALUE self, const char *name,
			     enum edhoc_role role, enum ruby_edhoc_state required,
			     enum ruby_edhoc_state success,
			     int (*compose)(struct edhoc_context *, uint8_t *, size_t, size_t *))
{
	struct ruby_edhoc_session *session = get_session(self);
	require_state(session, role, required, name);
	prepare_operation(session, name);
	uint8_t *buffer = calloc(1, session->max_message_size);
	if (buffer == NULL)
		rb_memerror();
	size_t length = 0;
	int ret = compose(session->context, buffer, session->max_message_size, &length);
	VALUE output = Qnil;
	if (ret == EDHOC_SUCCESS)
		output = rb_str_new((const char *)buffer, (long)length);
	secure_zero(buffer, session->max_message_size);
	free(buffer);
	finish_operation(session, name, ret, success);
	return output;
}

static VALUE process_message(VALUE self, VALUE message, const char *name,
			     enum edhoc_role role, enum ruby_edhoc_state required,
			     enum ruby_edhoc_state success,
			     int (*process)(struct edhoc_context *, const uint8_t *, size_t))
{
	struct ruby_edhoc_session *session = get_session(self);
	require_state(session, role, required, name);
	StringValue(message);
	if ((size_t)RSTRING_LEN(message) > session->max_message_size)
		rb_raise(rb_eArgError, "message exceeds max_message_size");
	prepare_operation(session, name);
	int ret = process(session->context, (const uint8_t *)RSTRING_PTR(message),
			  (size_t)RSTRING_LEN(message));
	finish_operation(session, name, ret, success);
	return Qnil;
}

static VALUE session_compose_message_1(VALUE self)
{
	VALUE output = compose_message(self, "compose_message1", EDHOC_ROLE_INITIATOR,
		RUBY_EDHOC_NEW, RUBY_EDHOC_WAIT_MESSAGE_2, edhoc_message_1_compose);
	get_session(self)->parameters_selected = true;
	return output;
}

static VALUE session_process_message_1(VALUE self, VALUE message)
{
	struct ruby_edhoc_session *session = get_session(self);
	require_state(session, EDHOC_ROLE_RESPONDER, RUBY_EDHOC_NEW,
		      "process_message1");
	StringValue(message);
	int32_t method, selected;
	if (parse_message_1_selection((const uint8_t *)RSTRING_PTR(message),
				      (size_t)RSTRING_LEN(message), &method, &selected)) {
		session->selected_method = method;
		session->selected_suite = selected;
		if (supports_suite(session, selected)) {
			const struct edhoc_crypto *crypto = edhoc_cipher_suite_get_crypto(
				(enum edhoc_cipher_suite_id)selected);
			if (crypto != NULL) {
				int bind = edhoc_bind_crypto(session->context, crypto);
				if (bind != EDHOC_SUCCESS)
					raise_session_error(session, "bind_selected_crypto", bind);
			}
		}
	}
	VALUE output = process_message(self, message, "process_message1", EDHOC_ROLE_RESPONDER,
		RUBY_EDHOC_NEW, RUBY_EDHOC_RECEIVED_MESSAGE_1, edhoc_message_1_process);
	session->parameters_selected = true;
	return output;
}

static VALUE session_compose_message_2(VALUE self)
{
	return compose_message(self, "compose_message2", EDHOC_ROLE_RESPONDER,
		RUBY_EDHOC_RECEIVED_MESSAGE_1, RUBY_EDHOC_WAIT_MESSAGE_3,
		edhoc_message_2_compose);
}

static VALUE session_process_message_2(VALUE self, VALUE message)
{
	return process_message(self, message, "process_message2", EDHOC_ROLE_INITIATOR,
		RUBY_EDHOC_WAIT_MESSAGE_2, RUBY_EDHOC_VERIFIED_MESSAGE_2,
		edhoc_message_2_process);
}

static VALUE session_compose_message_3(VALUE self)
{
	return compose_message(self, "compose_message3", EDHOC_ROLE_INITIATOR,
		RUBY_EDHOC_VERIFIED_MESSAGE_2, RUBY_EDHOC_COMPLETED,
		edhoc_message_3_compose);
}

static VALUE session_process_message_3(VALUE self, VALUE message)
{
	return process_message(self, message, "process_message3", EDHOC_ROLE_RESPONDER,
		RUBY_EDHOC_WAIT_MESSAGE_3, RUBY_EDHOC_COMPLETED,
		edhoc_message_3_process);
}

static VALUE session_compose_message_4(VALUE self)
{
	return compose_message(self, "compose_message4", EDHOC_ROLE_RESPONDER,
		RUBY_EDHOC_COMPLETED, RUBY_EDHOC_PERSISTED, edhoc_message_4_compose);
}

static VALUE session_process_message_4(VALUE self, VALUE message)
{
	return process_message(self, message, "process_message4", EDHOC_ROLE_INITIATOR,
		RUBY_EDHOC_COMPLETED, RUBY_EDHOC_PERSISTED, edhoc_message_4_process);
}

static VALUE session_export(VALUE self, VALUE label, VALUE context, VALUE length_value)
{
	struct ruby_edhoc_session *session = get_session(self);
	StringValue(context);
	size_t length = NUM2SIZET(length_value);
	if (length == 0 || length > RUBY_EDHOC_MAX_EXPORT)
		rb_raise(rb_eArgError, "export length must be between 1 and 1048576");
	prepare_operation(session, "export");
	uint8_t *secret = calloc(1, length);
	if (secret == NULL)
		rb_memerror();
	int ret = edhoc_export_raw(session->context, NUM2SIZET(label),
		(const uint8_t *)RSTRING_PTR(context), (size_t)RSTRING_LEN(context),
		secret, length);
	VALUE output = ret == EDHOC_SUCCESS ? rb_str_new((const char *)secret, (long)length) : Qnil;
	secure_zero(secret, length);
	free(secret);
	finish_operation(session, "export", ret, session->state);
	return output;
}

static VALUE session_key_update(VALUE self, VALUE context)
{
	struct ruby_edhoc_session *session = get_session(self);
	StringValue(context);
	prepare_operation(session, "key_update");
	int ret = edhoc_export_key_update(session->context,
		(const uint8_t *)RSTRING_PTR(context), (size_t)RSTRING_LEN(context));
	finish_operation(session, "key_update", ret, session->state);
	return Qnil;
}

static VALUE session_export_oscore(VALUE self, VALUE secret_length_value,
				   VALUE salt_length_value)
{
	struct ruby_edhoc_session *session = get_session(self);
	size_t secret_length = NUM2SIZET(secret_length_value);
	size_t salt_length = NUM2SIZET(salt_length_value);
	if (secret_length == 0 || salt_length == 0 ||
	    secret_length > RUBY_EDHOC_MAX_EXPORT || salt_length > RUBY_EDHOC_MAX_EXPORT)
		rb_raise(rb_eArgError, "invalid OSCORE secret or salt length");
	uint8_t *secret = calloc(1, secret_length);
	uint8_t *salt = calloc(1, salt_length);
	uint8_t sender[CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID] = { 0 };
	uint8_t recipient[CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID] = { 0 };
	if (secret == NULL || salt == NULL) {
		free(secret);
		free(salt);
		rb_memerror();
	}
	size_t sender_length = 0, recipient_length = 0;
	prepare_operation(session, "export_oscore_context");
	int ret = edhoc_export_oscore_context_raw(
		session->context, secret, secret_length, salt, salt_length,
		sender, sizeof(sender), &sender_length, recipient, sizeof(recipient),
		&recipient_length);
	VALUE output = Qnil;
	if (ret == EDHOC_SUCCESS) {
		output = rb_hash_new();
		hash_set(output, "master_secret", rb_str_new((char *)secret, (long)secret_length));
		hash_set(output, "master_salt", rb_str_new((char *)salt, (long)salt_length));
		hash_set(output, "sender_id", rb_str_new((char *)sender, (long)sender_length));
		hash_set(output, "recipient_id", rb_str_new((char *)recipient, (long)recipient_length));
	}
	secure_zero(secret, secret_length);
	secure_zero(salt, salt_length);
	secure_zero(sender, sizeof(sender));
	secure_zero(recipient, sizeof(recipient));
	free(secret);
	free(salt);
	finish_operation(session, "export_oscore_context", ret, session->state);
	return output;
}

static VALUE state_symbol(enum ruby_edhoc_state state)
{
	static const char *names[] = {
		"new", "waiting_for_message2", "received_message1", "verified_message2",
		"waiting_for_message3", "completed", "persisted", "aborted", "closed"
	};
	return symbol(names[state]);
}

static VALUE session_state(VALUE self)
{
	struct ruby_edhoc_session *session;
	TypedData_Get_Struct(self, struct ruby_edhoc_session, &session_type, session);
	return state_symbol(session->state);
}

static VALUE session_selected_method(VALUE self)
{
	struct ruby_edhoc_session *session = get_session(self);
	return session->parameters_selected ? INT2NUM(session->selected_method) : Qnil;
}

static VALUE session_selected_suite(VALUE self)
{
	struct ruby_edhoc_session *session = get_session(self);
	return session->parameters_selected ? INT2NUM(session->selected_suite) : Qnil;
}

static VALUE session_protocol_error(VALUE self)
{
	struct ruby_edhoc_session *session = get_session(self);
	return session->has_protocol_error ? INT2NUM(session->protocol_error) : Qnil;
}

static VALUE session_local_suites(VALUE self)
{
	struct ruby_edhoc_session *session = get_session(self);
	if (session->local_suite_count > 0)
		return int_array(session->local_suites, session->local_suite_count);
	VALUE result = rb_ary_new_capa((long)session->suite_count);
	for (size_t i = 0; i < session->suite_count; i++)
		rb_ary_push(result, INT2NUM(session->suites[i].value));
	return result;
}

static VALUE session_error_text(VALUE self)
{
	(void)self;
	return Qnil;
}

static VALUE session_peer_id(VALUE self)
{
	return get_session(self)->peer_id;
}

static VALUE session_closed(VALUE self)
{
	struct ruby_edhoc_session *session;
	TypedData_Get_Struct(self, struct ruby_edhoc_session, &session_type, session);
	return session->state == RUBY_EDHOC_CLOSED ? Qtrue : Qfalse;
}

static VALUE session_close(VALUE self)
{
	struct ruby_edhoc_session *session;
	TypedData_Get_Struct(self, struct ruby_edhoc_session, &session_type, session);
	if (session->state != RUBY_EDHOC_CLOSED) {
		session_release(session);
		session->state = RUBY_EDHOC_CLOSED;
	}
	return Qnil;
}

static VALUE session_diagnostics(VALUE self)
{
	struct ruby_edhoc_session *session;
	TypedData_Get_Struct(self, struct ruby_edhoc_session, &session_type, session);
	VALUE result = rb_hash_new();
	hash_set(result, "state", state_symbol(session->state));
	hash_set(result, "selected_method", session->parameters_selected ? INT2NUM(session->selected_method) : Qnil);
	hash_set(result, "selected_cipher_suite", session->parameters_selected ? INT2NUM(session->selected_suite) : Qnil);
	VALUE local = rb_ary_new_capa((long)session->suite_count);
	for (size_t i = 0; i < session->suite_count; i++)
		rb_ary_push(local, INT2NUM(session->suites[i].value));
	hash_set(result, "local_cipher_suites", local);
	hash_set(result, "peer_cipher_suites", int_array(session->peer_suites, session->peer_suite_count));
	hash_set(result, "last_operation", session->last_operation);
	hash_set(result, "native_error_code", session->last_native_error == EDHOC_SUCCESS ? Qnil : INT2NUM(session->last_native_error));
	hash_set(result, "protocol_error_code", session->has_protocol_error ? INT2NUM(session->protocol_error) : Qnil);
	hash_set(result, "peer_id", session->peer_id);
	hash_set(result, "closed", session->state == RUBY_EDHOC_CLOSED ? Qtrue : Qfalse);
	return result;
}

static VALUE native_error_compose(VALUE module, VALUE code_value, VALUE text_value,
				  VALUE suites_value)
{
	(void)module;
	enum edhoc_error_code code = (enum edhoc_error_code)NUM2INT(code_value);
	struct edhoc_error_info info = { 0 };
	int32_t suites[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	if (code == EDHOC_ERROR_CODE_UNSPECIFIED_ERROR) {
		StringValue(text_value);
		info.text_string = RSTRING_PTR(text_value);
		info.entries_length = (size_t)RSTRING_LEN(text_value);
		info.entries_size = info.entries_length;
	} else if (code == EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
		Check_Type(suites_value, T_ARRAY);
		long count = RARRAY_LEN(suites_value);
		if (count < 1 || count > CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES)
			rb_raise(rb_eArgError, "invalid cipher suite count");
		for (long i = 0; i < count; i++)
			suites[i] = NUM2INT(rb_ary_entry(suites_value, i));
		info.cipher_suites = suites;
		info.entries_length = (size_t)count;
		info.entries_size = (size_t)count;
	}
	size_t capacity = 65536, length = 0;
	uint8_t *buffer = calloc(1, capacity);
	if (buffer == NULL)
		rb_memerror();
	int ret = edhoc_message_error_compose(buffer, capacity, &length, code, &info);
	VALUE output = ret == EDHOC_SUCCESS ? rb_str_new((char *)buffer, (long)length) : Qnil;
	secure_zero(buffer, capacity);
	free(buffer);
	if (ret != EDHOC_SUCCESS)
		raise_native_error("error_message_compose", ret);
	return output;
}

static VALUE native_error_parse(VALUE module, VALUE message)
{
	(void)module;
	StringValue(message);
	enum edhoc_error_code code;
	union {
		char text[65536];
		int32_t suites[65536];
	} storage = { 0 };
	struct edhoc_error_info info = {
		.text_string = storage.text,
		.entries_size = 65536,
	};
	int ret = edhoc_message_error_process((const uint8_t *)RSTRING_PTR(message),
		(size_t)RSTRING_LEN(message), &code, &info);
	if (ret != EDHOC_SUCCESS)
		raise_native_error("error_message_parse", ret);
	VALUE result = rb_hash_new();
	hash_set(result, "code", INT2NUM(code));
	if (code == EDHOC_ERROR_CODE_UNSPECIFIED_ERROR)
		hash_set(result, "text", rb_str_new(storage.text, (long)info.entries_length));
	if (code == EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE)
		hash_set(result, "cipher_suites", int_array(storage.suites, info.entries_length));
	secure_zero(&storage, sizeof(storage));
	return result;
}

static VALUE native_coap_prepend_flow(VALUE module, VALUE message)
{
	(void)module;
	StringValue(message);
	size_t capacity = (size_t)RSTRING_LEN(message) + 1;
	uint8_t *buffer = malloc(capacity);
	if (buffer == NULL)
		rb_memerror();
	struct edhoc_coap_prepended_fields fields = { .buffer = buffer, .capacity = capacity };
	int ret = edhoc_coap_prepend_flow(&fields);
	if (ret == EDHOC_SUCCESS) {
		memcpy(buffer + fields.length, RSTRING_PTR(message), (size_t)RSTRING_LEN(message));
		fields.length += (size_t)RSTRING_LEN(message);
	}
	VALUE output = ret == EDHOC_SUCCESS ? rb_str_new((char *)buffer, (long)fields.length) : Qnil;
	free(buffer);
	if (ret != EDHOC_SUCCESS)
		raise_native_error("coap_prepend_flow", ret);
	return output;
}

static VALUE native_coap_extract_flow(VALUE module, VALUE payload)
{
	(void)module;
	StringValue(payload);
	struct edhoc_coap_extracted_fields fields = {
		.buffer = (const uint8_t *)RSTRING_PTR(payload),
		.length = (size_t)RSTRING_LEN(payload),
	};
	int ret = edhoc_coap_extract_flow_info(&fields);
	if (ret != EDHOC_SUCCESS)
		raise_native_error("coap_extract_flow", ret);
	VALUE result = rb_hash_new();
	hash_set(result, "forward", fields.is_forward_flow ? Qtrue : Qfalse);
	hash_set(result, "reverse", fields.is_reverse_flow ? Qtrue : Qfalse);
	hash_set(result, "message", rb_str_substr(payload, (long)fields.consumed,
					  RSTRING_LEN(payload) - (long)fields.consumed));
	return result;
}

static VALUE native_coap_prepend_connection_id(VALUE module, VALUE message,
					VALUE connection_id_value)
{
	(void)module;
	StringValue(message);
	struct parsed_connection_id connection_id = parse_connection_id(connection_id_value);
	size_t capacity = (size_t)RSTRING_LEN(message) + connection_id.buffer.length + 9;
	uint8_t *buffer = malloc(capacity);
	if (buffer == NULL)
		rb_memerror();
	struct edhoc_coap_prepended_fields fields = { .buffer = buffer, .capacity = capacity };
	int ret = edhoc_coap_prepend_connection_id(&fields, &connection_id.buffer);
	if (ret == EDHOC_SUCCESS) {
		memcpy(buffer + fields.length, RSTRING_PTR(message), (size_t)RSTRING_LEN(message));
		fields.length += (size_t)RSTRING_LEN(message);
	}
	VALUE output = ret == EDHOC_SUCCESS ? rb_str_new((char *)buffer, (long)fields.length) : Qnil;
	free(buffer);
	if (ret != EDHOC_SUCCESS)
		raise_native_error("coap_prepend_connection_id", ret);
	return output;
}

static VALUE native_coap_extract_connection_id(VALUE module, VALUE payload)
{
	(void)module;
	StringValue(payload);
	struct edhoc_coap_extracted_fields fields = {
		.buffer = (const uint8_t *)RSTRING_PTR(payload),
		.length = (size_t)RSTRING_LEN(payload),
	};
	int ret = edhoc_coap_extract_connection_id(&fields);
	if (ret != EDHOC_SUCCESS)
		raise_native_error("coap_extract_connection_id", ret);
	VALUE result = rb_hash_new();
	hash_set(result, "connection_id",
		rb_str_new((const char *)fields.connection_id.value,
			   (long)fields.connection_id.length));
	hash_set(result, "message", rb_str_substr(payload, (long)fields.consumed,
					  RSTRING_LEN(payload) - (long)fields.consumed));
	return result;
}

static VALUE native_coap_connection_id_equal(VALUE module, VALUE left, VALUE right)
{
	(void)module;
	struct parsed_connection_id first = parse_connection_id(left);
	struct parsed_connection_id second = parse_connection_id(right);
	return edhoc_coap_connection_id_equal(&first.buffer, &second.buffer) ? Qtrue : Qfalse;
}

static VALUE native_profile(VALUE module)
{
	(void)module;
	return rb_str_new_cstr("built-in-crypto");
}

static VALUE native_library_version(VALUE module)
{
	(void)module;
	return rb_sprintf("%d.%d.%d", EDHOC_API_VERSION_MAJOR,
			 EDHOC_API_VERSION_MINOR, EDHOC_API_VERSION_PATCH);
}

void Init_edhoc_native(void)
{
	mEdhoc = rb_define_module("Edhoc");
	mNative = rb_define_module_under(mEdhoc, "Native");
	eNativeError = rb_const_get(mEdhoc, rb_intern("NativeError"));
	eBadStateError = rb_const_get(mEdhoc, rb_intern("BadStateError"));
	eInvalidArgumentError = rb_const_get(mEdhoc, rb_intern("InvalidArgumentError"));
	eNotSupportedError = rb_const_get(mEdhoc, rb_intern("NotSupportedError"));
	eNotPermittedError = rb_const_get(mEdhoc, rb_intern("NotPermittedError"));
	eBufferTooSmallError = rb_const_get(mEdhoc, rb_intern("BufferTooSmallError"));
	eNativeMemoryError = rb_const_get(mEdhoc, rb_intern("NativeMemoryError"));
	eCborError = rb_const_get(mEdhoc, rb_intern("CborError"));
	eCryptoError = rb_const_get(mEdhoc, rb_intern("CryptoError"));
	eCredentialsError = rb_const_get(mEdhoc, rb_intern("CredentialsError"));
	eEadError = rb_const_get(mEdhoc, rb_intern("EadError"));
	eKeyExchangeError = rb_const_get(mEdhoc, rb_intern("KeyExchangeError"));
	eMessageError = rb_const_get(mEdhoc, rb_intern("MessageError"));
	id_native_select_local = rb_intern("__native_select_local");
	id_native_authenticate_peer = rb_intern("__native_authenticate_peer");
	id_native_ead_compose = rb_intern("__native_compose");
	id_native_ead_process = rb_intern("__native_process");

	cSession = rb_define_class_under(mNative, "Session", rb_cObject);
	rb_define_alloc_func(cSession, session_alloc);
	rb_define_method(cSession, "initialize", session_initialize, 7);
	rb_define_method(cSession, "compose_message1", session_compose_message_1, 0);
	rb_define_method(cSession, "process_message1", session_process_message_1, 1);
	rb_define_method(cSession, "compose_message2", session_compose_message_2, 0);
	rb_define_method(cSession, "process_message2", session_process_message_2, 1);
	rb_define_method(cSession, "compose_message3", session_compose_message_3, 0);
	rb_define_method(cSession, "process_message3", session_process_message_3, 1);
	rb_define_method(cSession, "compose_message4", session_compose_message_4, 0);
	rb_define_method(cSession, "process_message4", session_process_message_4, 1);
	rb_define_method(cSession, "export", session_export, 3);
	rb_define_method(cSession, "key_update", session_key_update, 1);
	rb_define_method(cSession, "export_oscore_context", session_export_oscore, 2);
	rb_define_method(cSession, "state", session_state, 0);
	rb_define_method(cSession, "selected_method", session_selected_method, 0);
	rb_define_method(cSession, "selected_cipher_suite", session_selected_suite, 0);
	rb_define_method(cSession, "protocol_error_code", session_protocol_error, 0);
	rb_define_method(cSession, "local_cipher_suites", session_local_suites, 0);
	rb_define_method(cSession, "error_text", session_error_text, 0);
	rb_define_method(cSession, "peer_id", session_peer_id, 0);
	rb_define_method(cSession, "closed?", session_closed, 0);
	rb_define_method(cSession, "close", session_close, 0);
	rb_define_method(cSession, "diagnostics", session_diagnostics, 0);

	rb_define_singleton_method(mNative, "error_message_compose", native_error_compose, 3);
	rb_define_singleton_method(mNative, "error_message_parse", native_error_parse, 1);
	rb_define_singleton_method(mNative, "coap_prepend_flow", native_coap_prepend_flow, 1);
	rb_define_singleton_method(mNative, "coap_extract_flow", native_coap_extract_flow, 1);
	rb_define_singleton_method(mNative, "coap_prepend_connection_id", native_coap_prepend_connection_id, 2);
	rb_define_singleton_method(mNative, "coap_extract_connection_id", native_coap_extract_connection_id, 1);
	rb_define_singleton_method(mNative, "coap_connection_id_equal", native_coap_connection_id_equal, 2);
	rb_define_singleton_method(mNative, "profile", native_profile, 0);
	rb_define_singleton_method(mNative, "library_version", native_library_version, 0);
}

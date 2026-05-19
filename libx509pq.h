/* libx509pq - shared declarations
 * Written by Rob Stradling
 * Copyright (C) 2015-2020 Sectigo Limited
 *
 * Licensed under the GNU GPL v3 or later. See the LICENSE file or
 * libx509pq.c for the full notice.
 */

#ifndef LIBX509PQ_H
#define LIBX509PQ_H

#include "c.h"
#include "postgres.h"
#include "plpgsql.h"	/* _PG_init() */
#include "funcapi.h"
#include "fmgr.h"
#include "access/htup_details.h"
#include "utils/timestamp.h"
#include "utils/builtins.h"

#include <string.h>
#include <time.h>

#include "openssl/asn1.h"
#include "openssl/asn1t.h"
#include "openssl/bn.h"
#include "openssl/engine.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/objects.h"
#include "openssl/ocsp.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#define MAX_OIDSTRING_LENGTH   80


/* -- OpenSSL version compatibility shims --------------------------------- */

#if OPENSSL_VERSION_NUMBER < 0x10100000L	/* < 1.1.0 */
	#define ASN1_STRING_get0_data		ASN1_STRING_data
	#define SIGNATURE_ALGORITHM		X509_ALGOR
	#define SIGNATURE_BIT_STRING		ASN1_BIT_STRING
	#define X509_get0_extensions(x)		(x)->cert_info->extensions
	#define X509_get0_notAfter		X509_get_notAfter
	#define X509_get0_notBefore		X509_get_notBefore
	#define X509_get0_tbs_sigalg(x)		(x)->cert_info->signature

	#define EVP_PKEY_get0_RSA(evp_pkey)	((evp_pkey)->pkey.rsa)
	static inline void RSA_get0_key(
		const RSA* r,
		const BIGNUM** n,
		const BIGNUM** e,
		const BIGNUM** d
	)
	{
		if (n != NULL)
			*n = r->n;
		if (e != NULL)
			*e = r->e;
		if (d != NULL)
			*d = r->d;
	}
#else						/* >= 1.1.0 */
	#define SIGNATURE_ALGORITHM		const X509_ALGOR
	#define SIGNATURE_BIT_STRING		const ASN1_BIT_STRING
#endif

#if OPENSSL_VERSION_NUMBER < 0x10002000L	/* < 1.0.2 */
	#define X509_get_signature_nid(x)	(x)->sig_alg->algorithm
	#define X509_GET_SIGNATURE(psig, x)	(*(psig)) = (x)->signature
	#define X509_GET_SIGALGNID(palg, x)	(*(palg)) = (x)->sig_alg

	static inline int i2d_re_X509_tbs(
		X509* x,
		unsigned char** pp
	)
	{
		x->cert_info->enc.modified = 1;
		return i2d_X509_CINF(x->cert_info, pp);
	}
#else						/* >= 1.0.2 */
	#define X509_GET_SIGNATURE(psig, x)	X509_get0_signature(psig, NULL, x)
	#define X509_GET_SIGALGNID(palg, x)	X509_get0_signature(NULL, palg, x)
#endif


/* -- Old draft Basic Constraints extension (used by SGC cross-certs) ----- */

typedef struct BASIC_CONSTRAINTS_OLD_st {
	ASN1_BIT_STRING* subjtype;
	ASN1_INTEGER* pathlen;
} BASIC_CONSTRAINTS_OLD;

DECLARE_ASN1_FUNCTIONS(BASIC_CONSTRAINTS_OLD)

#define CERT_CA_SUBJECT_FLAG		0x80
#define CERT_END_ENTITY_SUBJECT_FLAG	0x40

/* Defined in extensions.c; ext_nid is patched in _PG_init() (libx509pq.c). */
extern X509V3_EXT_METHOD v3_bcOld;


/* -- Shared globals defined in libx509pq.c ------------------------------- */

extern char g_error[];

/* Human-readable name for an OpenSSL hash NID, or NULL if not recognised. */
extern const char* hash_alg_name(int nid);

/* Human-readable name for an OpenSSL public-key NID, or NULL if not
  recognised. */
extern const char* pkey_alg_name(int nid);

/* Parse a Time (UTCTime or GeneralizedTime) into a struct tm.
  Returns 1 on success, 0 on error. */
extern int ASN1_TIME_parse(
	const ASN1_TIME* const v_asn1Time,
	struct tm* const v_time
);


/* -- ROCA fingerprint table init/teardown (defined in crypto.c) ---------- */

#define ROCA_PRINTS_LENGTH	17
extern void rocacheck_init(void);
extern void rocacheck_cleanup(void);


/* -- Shared inline helpers ----------------------------------------------- */

/* Allocate a PostgreSQL text* and copy "len" bytes from "src" into it. */
static inline text* text_from_cstring_len(
	const void* src,
	size_t len
)
{
	text* t_text = palloc(len + VARHDRSZ);
	SET_VARSIZE(t_text, len + VARHDRSZ);
	memcpy((void*)VARDATA(t_text), src, len);
	return t_text;
}

/* Allocate a PostgreSQL bytea* and copy "len" bytes from "src" into it. */
static inline bytea* bytea_from_buffer(
	const void* src,
	size_t len
)
{
	bytea* t_bytea = palloc(len + VARHDRSZ);
	SET_VARSIZE(t_bytea, len + VARHDRSZ);
	memcpy((void*)VARDATA(t_bytea), src, len);
	return t_bytea;
}

/* Build a PostgreSQL text* from the contents of a memory BIO, then free
  the BIO. */
static inline text* text_from_bio(
	BIO* t_bio
)
{
	char* t_string = NULL;
	long t_size = BIO_get_mem_data(t_bio, &t_string);
	text* t_text = text_from_cstring_len(t_string, t_size);
	BIO_free(t_bio);
	return t_text;
}


/* -- Shared function-style macros ---------------------------------------- */

/* Decode the bytea function argument at index "argno" into an X509*.
  Returns NULL from the surrounding function if the argument is SQL NULL.
  Sets the supplied X509** to NULL if decoding fails. */
#define X509_FROM_BYTEA_ARG(x509_out, argno)                            \
	do {                                                            \
		bytea* _b;                                              \
		const unsigned char* _p;                                \
		if (PG_ARGISNULL(argno))                                \
			PG_RETURN_NULL();                               \
		_b = PG_GETARG_BYTEA_PP(argno);                         \
		_p = (const unsigned char*)VARDATA_ANY(_b);             \
		(x509_out) = d2i_X509(                                  \
			NULL, &_p, VARSIZE_ANY_EXHDR(_b)                \
		);                                                      \
	} while (0)

/* SRF-friendly variant: sets the supplied X509** to NULL if the argument
  is SQL NULL (instead of returning), so the SRF firstcall setup can
  continue (e.g. to restore the memory context) and the per-call loop
  will naturally return zero rows. Also sets X509** to NULL if decoding
  fails. */
#define X509_FROM_BYTEA_ARG_OR_NULL(x509_out, argno)                    \
	do {                                                            \
		if (PG_ARGISNULL(argno))                                \
			(x509_out) = NULL;                              \
		else {                                                  \
			bytea* _b = PG_GETARG_BYTEA_PP(argno);          \
			const unsigned char* _p =                       \
				(const unsigned char*)VARDATA_ANY(_b);  \
			(x509_out) = d2i_X509(                          \
				NULL, &_p, VARSIZE_ANY_EXHDR(_b)        \
			);                                              \
		}                                                       \
	} while (0)

/* Shorthand for the V1-calling-convention prologue every SQL-callable
  function needs. Expands to PG_FUNCTION_INFO_V1(name); Datum name(...).
  The function body follows in the usual { ... } block. */
#define PG_FN(name)                                                     \
	PG_FUNCTION_INFO_V1(name);                                      \
	Datum name(PG_FUNCTION_ARGS)

/* SRF firstcall boilerplate: enters the multi-call memory context and
  allocates a zero-initialised per-call context struct. Use only inside an
  `if (SRF_IS_FIRSTCALL()) { ... }` block. Requires `t_funcCtx` to be
  declared in the enclosing function; sets it and the supplied ctx_var
  pointer. Must be paired with SRF_FIRSTCALL_END() before leaving the
  block. */
#define SRF_FIRSTCALL_BEGIN(ctx_type, ctx_var)                          \
	MemoryContext _oldMemCtx;                                       \
	t_funcCtx = SRF_FIRSTCALL_INIT();                               \
	_oldMemCtx = MemoryContextSwitchTo(                             \
		t_funcCtx->multi_call_memory_ctx                        \
	);                                                              \
	t_funcCtx->user_fctx = (ctx_var) = palloc0(sizeof(ctx_type))

/* Restore the memory context entered by SRF_FIRSTCALL_BEGIN. */
#define SRF_FIRSTCALL_END()                                             \
	MemoryContextSwitchTo(_oldMemCtx)


#endif /* LIBX509PQ_H */

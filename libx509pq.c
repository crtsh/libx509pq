/* libx509pq - a certificate parsing library for PostgreSQL
 * Written by Rob Stradling
 * Copyright (C) 2015-2020 Sectigo Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * This translation unit holds the module lifecycle (_PG_init/_PG_fini),
 * shared globals (g_error), the algorithm-name lookup
 * tables, the ASN.1 time parsers, the trivial per-field accessors that
 * don't fit elsewhere (notBefore/notAfter/serialNumber/print), plus
 * URL encode/decode and the OpenSSL-version helper.
 *
 * The rest of the extension is split across:
 *   - name.c        - Name accessors (issuer/subject/CN/attribute SRFs).
 *   - extensions.c  - X.509 v3 extension accessors (EKU, policies, AIA,
 *                     CRL DP, SAN, AKI/SKI, basicConstraints, ...).
 *   - crypto.c      - Public-key, signature, verify, ROCA, close-primes.
 *   - basic_info.c  - x509_basic_info single-row composite accessor.
 *   - libx509pq.h   - Shared types, macros, and inline helpers.
 */

#include "libx509pq.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif


/* Human-readable name for an OpenSSL hash NID, or NULL if not
  recognised. NIDs are small non-contiguous integer constants, so the
  compiler typically turns this into a jump table or binary search. */
const char* hash_alg_name(int nid)
{
	switch (nid) {
		case NID_md2:			return "MD2";
		case NID_md4:			return "MD4";
		case NID_md5:			return "MD5";
		case NID_sha:			return "SHA";
		case NID_sha1:			return "SHA-1";
		case NID_sha224:		return "SHA-224";
		case NID_sha256:		return "SHA-256";
		case NID_sha384:		return "SHA-384";
		case NID_sha512:		return "SHA-512";
		case NID_ripemd160:		return "RIPEMD-160";
		case NID_mdc2:			return "MDC-2";
		case NID_id_GostR3411_94:	return "GOST R 34.11-94";
		default:			return NULL;
	}
}

/* Human-readable name for an OpenSSL public-key NID, or NULL if not
  recognised. */
const char* pkey_alg_name(int nid)
{
	switch (nid) {
		case NID_rsaEncryption:
		case NID_rsa:			return "RSA";
		case NID_dsa:
		case NID_dsa_2:			return "DSA";
		case NID_X9_62_id_ecPublicKey:	return "ECDSA";
		case NID_id_GostR3410_94:	return "GOST R 34.10-94";
		case NID_id_GostR3410_94_cc:	return "GOST 34.10-94 Cryptocom";
		case NID_id_GostR3410_2001:	return "GOST R 34.10-2001";
		case NID_id_GostR3410_2001_cc:	return "GOST 34.10-2001 Cryptocom";
		default:			return NULL;
	}
}


/* Sentinel text returned by the legacy scalar accessors when the
  certificate cannot be parsed.  Externed via libx509pq.h. */
char g_error[] = "ERROR!";

#if OPENSSL_VERSION_NUMBER < 0x30000000L
/* Process-global state initialised once in _PG_init() and torn down in
  _PG_fini(). PostgreSQL spawns a separate OS process per backend and a
  backend is single-threaded, so no locking is required around these
  globals: each backend has its own private copy, and within a backend
  only one SQL function executes at a time. Do NOT add lazy
  (re)initialisation from SQL-callable functions; _PG_init() is the sole
  initialisation point. */
static ENGINE* g_gostEngine = NULL;
#endif


/******************************************************************************
 * _PG_init()                                                                 *
 ******************************************************************************/
void _PG_init(void)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	/* We need MD2 to verify old MD2/RSA certificate signatures, but
	  OpenSSL_add_all_digests() no longer enables MD2 by default */
	OpenSSL_add_all_digests();
#ifndef OPENSSL_NO_MD2
	EVP_add_digest(EVP_md2());
#endif

	ERR_load_crypto_strings();
#endif

	/* Define the OID for the draft Basic Constraints extension. The
	  v3_bcOld struct itself lives in extensions.c. */
	v3_bcOld.ext_nid = OBJ_create(
		"2.5.29.10", "bCold",
		"draft-ietf-pkix-ipki-part1-01 Basic Constraints"
	);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	/* Load all built-in engines */
	ENGINE_load_builtin_engines();

	/* Enable the GOST engine */
	g_gostEngine = ENGINE_by_id("gost");
	if (g_gostEngine && ENGINE_init(g_gostEngine))
		ENGINE_set_default(g_gostEngine, ENGINE_METHOD_ALL);
#else
	/* OpenSSL 3.0+ replaced ENGINEs with the provider API.
	   GOST support requires a GOST provider to be installed
	   and configured (e.g. via openssl.cnf). */
	OSSL_PROVIDER_load(NULL, "default");
#endif

	rocacheck_init();
}


/******************************************************************************
 * _PG_fini()                                                                 *
 *                                                                            *
 * NB: PostgreSQL never unloads loaded modules - see the comment above        *
 * internal_load_library() in src/backend/utils/fmgr/dfmgr.c ("There is       *
 * presently no way to unload a dynamically loaded file") - and modern PG     *
 * does not even dlsym() this symbol. So this function is effectively dead    *
 * code today; it is retained for documentation of intent and in case a       *
 * future PG version starts honouring it. The OS reclaims process memory      *
 * and OpenSSL ENGINE refcounts at backend exit either way, so the absence    *
 * of these cleanups is not a leak in any meaningful sense.                   *
 ******************************************************************************/
extern void _PG_fini(void);
void _PG_fini(void)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (g_gostEngine) {
		ENGINE_finish(g_gostEngine);
		ENGINE_free(g_gostEngine);
	}
	ENGINE_cleanup();
	EVP_cleanup();
	OBJ_cleanup();
	ERR_free_strings();
#endif

	rocacheck_cleanup();
}


/******************************************************************************
 * ASN1_GENERALIZEDTIME_parse()                                               *
 *   Parse a GeneralizedTime value into a "struct tm".                        *
 *                                                                            *
 * IN:	v_asn1GeneralizedTime - an OpenSSL GeneralizedTime object.            *
 * 	v_time - the "struct tm" object to populate.                          *
 *                                                                            *
 * OUT:	v_time - the "struct tm" object, populated.                           *
 *                                                                            *
 * Returns:	1 = Successful; 0 = An error occurred.                        *
 ******************************************************************************/
static int ASN1_GENERALIZEDTIME_parse(
	const ASN1_GENERALIZEDTIME* const v_asn1GeneralizedTime,
	struct tm* const v_time
)
{
	char *t_data;
	int i;

	i = ASN1_STRING_length(v_asn1GeneralizedTime);
	t_data = (char*)ASN1_STRING_get0_data(v_asn1GeneralizedTime);

	if (i < 12)
		goto label_error;

	for (i = 0; i < 12; i++)
		if ((t_data[i] > '9') || (t_data[i] < '0'))
			goto label_error;

	v_time->tm_year = (
		((t_data[0] - '0') * 1000) + ((t_data[1] - '0') * 100)
		+ ((t_data[2] - '0') * 10) + (t_data[3] - '0')
	) - 1900;

	v_time->tm_mon = (t_data[4] - '0') * 10 + (t_data[5] - '0');
	if ((v_time->tm_mon > 12) || (v_time->tm_mon < 1))
		goto label_error;
	v_time->tm_mon--;

	v_time->tm_mday = (t_data[6] - '0') * 10 + (t_data[7] - '0');

	v_time->tm_hour = (t_data[8] - '0') * 10 + (t_data[9] - '0');

	v_time->tm_min = (t_data[10] - '0') * 10 + (t_data[11] - '0');

	if ((t_data[12] >= '0') && (t_data[12] <= '9')
			&& (t_data[13] >= '0') && (t_data[13] <= '9'))
		v_time->tm_sec = (t_data[12] - '0') * 10 + (t_data[13] - '0');
	else
		v_time->tm_sec = 0;

	return 1;

label_error:
	return 0;
}


/******************************************************************************
 * ASN1_UTCTIME_parse()                                                       *
 *   Parse a UTCTime value into a "struct tm".                                *
 *                                                                            *
 * IN:	v_asn1GeneralizedTime - an OpenSSL UTCTime object.                    *
 * 	v_time - the "struct tm" object to populate.                          *
 *                                                                            *
 * OUT:	v_time - the "struct tm" object, populated.                           *
 *                                                                            *
 * Returns:	1 = Successful; 0 = An error occurred.                        *
 ******************************************************************************/
static int ASN1_UTCTIME_parse(
	const ASN1_UTCTIME* const v_asn1UTCTime,
	struct tm* const v_time
)
{
	char* t_data;
	int i;

	i = ASN1_STRING_length(v_asn1UTCTime);
	t_data = (char*)ASN1_STRING_get0_data(v_asn1UTCTime);

	if (i < 10)
		goto label_error;

	for (i = 0; i < 10; i++)
		if ((t_data[i] > '9') || (t_data[i] < '0'))
			goto label_error;

	v_time->tm_year = (t_data[0] - '0') * 10 + (t_data[1] - '0');
	if (v_time->tm_year < 50)
		v_time->tm_year += 100;

	v_time->tm_mon = (t_data[2] - '0') * 10 + (t_data[3] - '0');
	if ((v_time->tm_mon > 12) || (v_time->tm_mon < 1))
		goto label_error;
	v_time->tm_mon--;

	v_time->tm_mday = (t_data[4] - '0') * 10 + (t_data[5] - '0');

	v_time->tm_hour = (t_data[6] - '0') * 10 + (t_data[7] - '0');

	v_time->tm_min = (t_data[8] - '0') * 10 + (t_data[9] - '0');

	if ((t_data[10] >= '0') && (t_data[10] <= '9')
			&& (t_data[11] >= '0') && (t_data[11] <= '9'))
		v_time->tm_sec = (t_data[10] - '0') * 10 + (t_data[11] - '0');
	else
		v_time->tm_sec = 0;

	return 1;

label_error:
	return 0;
}


/******************************************************************************
 * ASN1_TIME_parse()                                                          *
 *   Parse a Time (UTCTime or GeneralizedTime) into a struct tm. Externed     *
 *   via libx509pq.h so basic_info.c can share this implementation.           *
 ******************************************************************************/
int ASN1_TIME_parse(
	const ASN1_TIME* const v_asn1Time,
	struct tm* const v_time
)
{
	if (ASN1_STRING_type(v_asn1Time) == V_ASN1_UTCTIME)
		return ASN1_UTCTIME_parse(v_asn1Time, v_time);
	else if (ASN1_STRING_type(v_asn1Time) == V_ASN1_GENERALIZEDTIME)
		return ASN1_GENERALIZEDTIME_parse(v_asn1Time, v_time);
	return 0;
}

/******************************************************************************
 * x509_notafter()                                                            *
 ******************************************************************************/
PG_FN(x509_notafter)
{
	X509* t_x509 = NULL;
	Timestamp t_timestamp = 0;
	struct tm t_time;
	int t_iResult;

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (!t_x509)
		PG_RETURN_NULL();

	t_iResult = ASN1_TIME_parse(X509_get0_notAfter(t_x509), &t_time);

	X509_free(t_x509);

	if (!t_iResult)
		PG_RETURN_NULL();

	t_timestamp = (timegm(&t_time) - 946684800) * USECS_PER_SEC;

	PG_RETURN_TIMESTAMP(t_timestamp);
}


/******************************************************************************
 * x509_notbefore()                                                           *
 ******************************************************************************/
PG_FN(x509_notbefore)
{
	X509* t_x509 = NULL;
	Timestamp t_timestamp = 0;
	struct tm t_time;
	int t_iResult;

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (!t_x509)
		PG_RETURN_NULL();

	t_iResult = ASN1_TIME_parse(X509_get0_notBefore(t_x509), &t_time);

	X509_free(t_x509);

	if (!t_iResult)
		PG_RETURN_NULL();

	t_timestamp = (timegm(&t_time) - 946684800) * USECS_PER_SEC;

	PG_RETURN_TIMESTAMP(t_timestamp);
}


/******************************************************************************
 * x509_serialnumber()                                                        *
 ******************************************************************************/
PG_FN(x509_serialnumber)
{
	X509* t_x509 = NULL;
	ASN1_INTEGER* t_asn1Integer;
	bytea* t_serialNumber = NULL;
	unsigned char* t_pointer = NULL;
	int t_size;

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (!t_x509)
		PG_RETURN_NULL();

	t_asn1Integer = X509_get_serialNumber(t_x509);
	t_size = i2d_ASN1_INTEGER(t_asn1Integer, NULL);
	if ((t_size < 0) || (t_size > 129))	/* Maximum 1 length octet */
		PG_RETURN_NULL();
	t_serialNumber = palloc(VARHDRSZ + t_size - 2);
	t_pointer = (unsigned char*)t_serialNumber + VARHDRSZ - 2;
	/* The tag octet and length octet are decoded into the last 2 bytes of
	  the VARHDRSZ section... */
	(void)i2d_ASN1_INTEGER(t_asn1Integer, &t_pointer);
	/* ...and then overwritten */
	SET_VARSIZE(t_serialNumber, VARHDRSZ + t_size - 2);

	X509_free(t_x509);

	PG_RETURN_BYTEA_P(t_serialNumber);
}


/******************************************************************************
 * x509_print()                                                               *
 ******************************************************************************/
PG_FN(x509_print)
{
	X509* t_x509 = NULL;
	text* t_text = NULL;

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (!t_x509)
		t_text = text_from_cstring_len(g_error, strlen(g_error));
	else {
		/* Create a memory BIO and tell it to make sure that it clears
		  up all its memory when we close it later */
		BIO* t_bio = BIO_new(BIO_s_mem());
		(void)BIO_set_close(t_bio, BIO_CLOSE);

		/* "Print" the certificate */
		(void)X509_print_ex(
			t_bio, t_x509,
			PG_ARGISNULL(1) ? (ASN1_STRFLGS_DUMP_DER
						| ASN1_STRFLGS_DUMP_UNKNOWN
						| ASN1_STRFLGS_ESC_CTRL
						| ASN1_STRFLGS_UTF8_CONVERT
						| XN_FLAG_DN_REV
						| XN_FLAG_FN_ALIGN
						| XN_FLAG_FN_LN
						| XN_FLAG_SEP_MULTILINE
						| XN_FLAG_SPC_EQ)
					: PG_GETARG_INT32(1),
			PG_ARGISNULL(2) ? 0 : PG_GETARG_INT32(2)
		);

		/* Build the return text from the BIO contents */
		t_text = text_from_bio(t_bio);

		X509_free(t_x509);
	}

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * ocspresponse_print()                                                       *
 ******************************************************************************/
PG_FN(ocspresponse_print)
{
	OCSP_RESPONSE* t_ocspResponse = NULL;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_PP(0);
	t_pointer = (unsigned char*)VARDATA_ANY(t_bytea);
	t_ocspResponse = d2i_OCSP_RESPONSE(
		NULL, &t_pointer, VARSIZE_ANY_EXHDR(t_bytea)
	);
	if (!t_ocspResponse)
		t_text = text_from_cstring_len(g_error, strlen(g_error));
	else {
		/* Create a memory BIO and tell it to make sure that it clears
		  up all its memory when we close it later */
		BIO* t_bio = BIO_new(BIO_s_mem());
		(void)BIO_set_close(t_bio, BIO_CLOSE);

		/* "Print" the OCSP response */
		(void)OCSP_RESPONSE_print(
			t_bio, t_ocspResponse,
			PG_ARGISNULL(1) ? 0 : PG_GETARG_INT32(2)
		);

		/* Build the return text from the BIO contents */
		t_text = text_from_bio(t_bio);

		OCSP_RESPONSE_free(t_ocspResponse);
	}

	PG_RETURN_TEXT_P(t_text);
}




/* URL Encoding - characters to not encode:
 * 33 (!)
 * 39-42 ('()*)
 * 45-46 (-.)
 * 48-57 (0-9)
 * 65-90 (A-Z)
 * 95 (_)
 * 97-122 (a-z)
 * 126 (~)
 */

static int chars_to_not_encode[] = {
	0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,
	0,0,0,1,0,0,0,0,0,1,
	1,1,1,0,0,1,1,0,1,1,
	1,1,1,1,1,1,1,1,0,0,
	0,0,0,0,0,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,
	1,0,0,0,0,1,0,1,1,1,
	1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,
	1,1,1,0,0,0,1,0
};

/******************************************************************************
 * urlencode()                                                                *
 *   Adapted from https://github.com/pramsey/pgsql-http/blob/master/http.c    *
 ******************************************************************************/
PG_FN(urlencode)
{
	text *txt = PG_GETARG_TEXT_P(0); /* Declare strict, so no test for NULL input */
	size_t txt_size = VARSIZE(txt) - VARHDRSZ;
	char *str_in, *str_out, *ptr;
	int i;

	/* Point into the string */
	str_in = (char*)txt + VARHDRSZ;

	/* Prepare the output string */
	str_out = palloc(txt_size * 4);
	ptr = str_out;

	for (i = 0; i < txt_size; i++) {
		unsigned char c = str_in[i];

		/* Break on NULL */
		if (c == '\0')
			break;

		/* Replace ' ' with '+' */
		if (c == ' ')
		{
			*ptr++ = '+';
			continue;
		}

		/* Pass basic characters through */
		if ((c < 127) && chars_to_not_encode[c]) {
			*ptr++ = str_in[i];
			continue;
		}

		/* Encode the remaining chars */
		if (snprintf(ptr, 4, "%%%02X", c) < 0)
			PG_RETURN_NULL();

		/* Move pointer forward */
		ptr += 3;
	}
	*ptr = '\0';

	PG_RETURN_TEXT_P(cstring_to_text(str_out));
}


/******************************************************************************
 * urldecode()                                                                *
 ******************************************************************************/
PG_FN(urldecode)
{
	text *txt = PG_GETARG_TEXT_P(0); /* Declare strict, so no test for NULL input */
	size_t txt_size = VARSIZE(txt) - VARHDRSZ;
	char *str_in, *str_out, *ptr;
	int i, rv;

	/* Point into the string */
	str_in = (char*)txt + VARHDRSZ;

	/* Prepare the output string */
	str_out = palloc(txt_size);
	ptr = str_out;

	for (i = 0; i < txt_size; i++) {
		/* Break on NULL */
		if (str_in[i] == '\0')
			break;

		/* Replace '+' with ' ' */
		if (str_in[i] == '+') {
			*ptr++ = ' ';
			continue;
		}

		/* Pass unencoded characters through */
		if (str_in[i] != '%') {
			*ptr++ = str_in[i];
			continue;
		}

		/* Decode the remaining chars */
		rv = sscanf(str_in + i, "%%%02X", (unsigned int*)ptr);
		if (rv < 0)
			PG_RETURN_NULL();

		/* Move pointer forward */
		ptr++;
		i += 2;
	}
	*ptr = '\0';

	PG_RETURN_TEXT_P(cstring_to_text(str_out));
}


/******************************************************************************
 * x509pq_opensslVersion()                                                    *
 ******************************************************************************/
PG_FN(x509pq_opensslversion)
{
	const char* t_version = SSLeay_version(SSLEAY_VERSION);
	PG_RETURN_TEXT_P(text_from_cstring_len(t_version, strlen(t_version)));
}

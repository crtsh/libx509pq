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
 */

#include "c.h"
#include "postgres.h"
#include "plpgsql.h"	/* _PG_init() */
#include "funcapi.h"
#include "fmgr.h"
#include "access/htup_details.h"
#include "utils/timestamp.h"
#include "utils/builtins.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

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


#if OPENSSL_VERSION_NUMBER < 0x10100000L	/* < 1.1.0 */
	#define ASN1_STRING_get0_data		ASN1_STRING_data
	#define SIGNATURE_ALGORITHM		X509_ALGOR
	#define SIGNATURE_BIT_STRING		ASN1_BIT_STRING
	#define X509_get0_extensions(x)		(x)->cert_info->extensions
	#define X509_get0_notAfter		X509_get_notAfter
	#define X509_get0_notBefore		X509_get_notBefore
	#define X509_get0_tbs_sigalg(x)		(x)->cert_info->signature

	#define EVP_PKEY_get0_RSA(evp_pkey)	((evp_pkey)->pkey.rsa)
	static void RSA_get0_key(
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

	static int i2d_re_X509_tbs(
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


/* Define the old draft Basic Constraints extension, which is supported by
  CryptoAPI and used in the SGC cross-certs.
  See http://tools.ietf.org/html/draft-ietf-pkix-ipki-part1-01 */
typedef struct BASIC_CONSTRAINTS_OLD_st {
	ASN1_BIT_STRING* subjtype;
	ASN1_INTEGER* pathlen;
} BASIC_CONSTRAINTS_OLD;

DECLARE_ASN1_FUNCTIONS(BASIC_CONSTRAINTS_OLD)

static X509V3_EXT_METHOD v3_bcOld = {
	NID_undef, 0,
	ASN1_ITEM_ref(BASIC_CONSTRAINTS_OLD),
	0, 0, 0, 0,
	0, 0,
	NULL/*(X509V3_EXT_I2V)i2v_BASIC_CONSTRAINTS*/,
	NULL/*(X509V3_EXT_V2I)v2i_BASIC_CONSTRAINTS*/,
	NULL, NULL,
	NULL
};

ASN1_SEQUENCE(BASIC_CONSTRAINTS_OLD) = {
	ASN1_OPT(BASIC_CONSTRAINTS_OLD, subjtype, ASN1_BIT_STRING),
	ASN1_OPT(BASIC_CONSTRAINTS_OLD, pathlen, ASN1_INTEGER)
} ASN1_SEQUENCE_END(BASIC_CONSTRAINTS_OLD)

IMPLEMENT_ASN1_FUNCTIONS(BASIC_CONSTRAINTS_OLD)

#define CERT_CA_SUBJECT_FLAG		0x80
#define CERT_END_ENTITY_SUBJECT_FLAG	0x40


/* The old "Root SGC Authority" certificate is treated by CryptoAPI as a CA
  certificate even though it doesn't contain a Basic Constraints extension.
  We need to special case this certificate.  We'll identify it by its
  signature */
static const unsigned char g_rootSGCAuthority_sig[] = {
	0x2b, 0x02, 0x2b, 0x37, 0x66, 0xa5, 0xd1, 0x8c, 0x3e, 0x20, 0x08, 0x1a,
	0x0c, 0xb7, 0xf5, 0x63, 0xcb, 0xc6, 0xdd, 0x9b, 0x62, 0x52, 0x32, 0xbc,
	0x33, 0x74, 0x7a, 0xde, 0xb0, 0x80, 0x05, 0xfa, 0xe5, 0xb5, 0xe4, 0xf7,
	0xf1, 0xd7, 0xa0, 0x95, 0x5c, 0x6c, 0x05, 0x9b, 0x2f, 0x03, 0x4b, 0xb7,
	0x8a, 0x95, 0x0e, 0xb0, 0x06, 0x80, 0xa0, 0x2a, 0x1b, 0xa4, 0x09, 0x58,
	0xbd, 0x87, 0xd4, 0x38, 0x44, 0xb4, 0x71, 0x7b, 0xfb, 0x74, 0xa2, 0x89,
	0x48, 0xe6, 0x5f, 0xab, 0x9a, 0xa4, 0x0a, 0x38, 0xcc, 0x57, 0xa1, 0x14,
	0x2c, 0x5c, 0xee, 0xc2, 0x13, 0x81, 0x00, 0xc3, 0x2d, 0xb1, 0x70, 0xde,
	0x9f, 0xb1, 0x70, 0x43, 0x7e, 0x22, 0xa0, 0x77, 0x96, 0xc8, 0xdf, 0x99,
	0xdc, 0xa6, 0x4e, 0xb3, 0xb5, 0x74, 0x34, 0x13, 0x12, 0x24, 0xa2, 0x6b,
	0x95, 0x80, 0xcf, 0xaa, 0x4a, 0x68, 0xb1, 0x77, 0x27, 0x98, 0xef, 0xaa,
	0x62, 0xd3, 0x22, 0x81, 0x33, 0x2b, 0x12, 0x50, 0xef, 0x16, 0x86, 0xe6,
	0x9a, 0x5a, 0x73, 0x89, 0x6d, 0x83, 0xf2, 0x08, 0xa3, 0x13, 0xab, 0x05,
	0xd5, 0x6e, 0x68, 0xf6, 0x90, 0xa4, 0x4a, 0x9f, 0x7c, 0x4c, 0x5d, 0x8f,
	0x58, 0xf3, 0x11, 0x4c, 0xc7, 0x08, 0x51, 0xea, 0x76, 0xd1, 0xb5, 0x55,
	0x32, 0x3f, 0xff, 0x67, 0xef, 0x35, 0x8c, 0x89, 0xd3, 0xc6, 0x75, 0x15,
	0x68, 0x9f, 0x67, 0x46, 0x9c, 0x94, 0x41, 0xf5, 0x76, 0x51, 0x86, 0xac,
	0x91, 0x75, 0xec, 0xb6, 0xf7, 0x00, 0x40, 0x5b, 0xfe, 0x61, 0xd8, 0x33,
	0x2d, 0x37, 0x65, 0x8b, 0x94, 0xd9, 0x97, 0x21, 0x15, 0x2c, 0x13, 0x49,
	0xff, 0xde, 0xb7, 0x83, 0xd9, 0xae, 0xc4, 0xce, 0x24, 0xb2, 0x50, 0xdf,
	0x75, 0x14, 0x12, 0x8c, 0x46, 0xa4, 0xac, 0xef, 0x4c, 0x72, 0x00, 0x00,
	0xe1, 0x4c, 0x8e, 0xee
};

/* Algorithm names */
typedef struct tAlgorithm {
	int m_nid;
	char* m_name;
} tAlgorithm;

/* Hash Algorithm Names */
static const tAlgorithm g_hashAlgorithms[] = {
	{ NID_md2, "MD2" },
	{ NID_md4, "MD4" },
	{ NID_md5, "MD5" },
	{ NID_sha, "SHA" },
	{ NID_sha1, "SHA-1" },
	{ NID_sha224, "SHA-224" },
	{ NID_sha256, "SHA-256" },
	{ NID_sha384, "SHA-384" },
	{ NID_sha512, "SHA-512" },
	{ NID_ripemd160, "RIPEMD-160" },
	{ NID_mdc2, "MDC-2" },
	{ NID_id_GostR3411_94, "GOST R 34.11-94" }
};

/* Public Key Algorithm Names */
static const tAlgorithm g_pkeyAlgorithms[] = {
	{ NID_rsaEncryption, "RSA" },
	{ NID_rsa, "RSA" },
	{ NID_dsa, "DSA" },
	{ NID_dsa_2, "DSA" },
	{ NID_X9_62_id_ecPublicKey, "ECDSA" },
	{ NID_id_GostR3410_94, "GOST R 34.10-94" },
	{ NID_id_GostR3410_94_cc, "GOST 34.10-94 Cryptocom" },
	{ NID_id_GostR3410_2001, "GOST R 34.10-2001" },
	{ NID_id_GostR3410_2001_cc, "GOST 34.10-2001 Cryptocom" }
};


static char g_error[] = "ERROR!";

static ENGINE* g_gostEngine = NULL;


#define ROCA_PRINTS_LENGTH	17
static unsigned char g_primes[ROCA_PRINTS_LENGTH] = {
	11, 13, 17, 19, 37, 53, 61, 71, 73, 79, 97, 103, 107, 109, 127, 151, 157
};
BIGNUM* g_prints[ROCA_PRINTS_LENGTH];

/******************************************************************************
 * rocacheck_init()                                                           *
 ******************************************************************************/
static void rocacheck_init()
{
	memset(g_prints, '\0', sizeof(BIGNUM*) * ROCA_PRINTS_LENGTH);
	(void)BN_dec2bn(&g_prints[0], "1026");
	(void)BN_dec2bn(&g_prints[1], "5658");
	(void)BN_dec2bn(&g_prints[2], "107286");
	(void)BN_dec2bn(&g_prints[3], "199410");
	(void)BN_dec2bn(&g_prints[4], "67109890");
	(void)BN_dec2bn(&g_prints[5], "5310023542746834");
	(void)BN_dec2bn(&g_prints[6], "1455791217086302986");
	(void)BN_dec2bn(&g_prints[7], "20052041432995567486");
	(void)BN_dec2bn(&g_prints[8], "6041388139249378920330");
	(void)BN_dec2bn(&g_prints[9], "207530445072488465666");
	(void)BN_dec2bn(&g_prints[10], "79228162521181866724264247298");
	(void)BN_dec2bn(&g_prints[11], "1760368345969468176824550810518");
	(void)BN_dec2bn(&g_prints[12], "50079290986288516948354744811034");
	(void)BN_dec2bn(&g_prints[13], "473022961816146413042658758988474");
	(void)BN_dec2bn(&g_prints[14], "144390480366845522447407333004847678774");
	(void)BN_dec2bn(&g_prints[15], "1800793591454480341970779146165214289059119882");
	(void)BN_dec2bn(&g_prints[16], "126304807362733370595828809000324029340048915994");
}

/******************************************************************************
 * rocacheck_cleanup()                                                        *
 ******************************************************************************/
static void rocacheck_cleanup()
{
	int i;
	for (i = 0; i < ROCA_PRINTS_LENGTH; i++)
		BN_free(g_prints[i]);
}


/******************************************************************************
 * _PG_init()                                                                 *
 ******************************************************************************/
void _PG_init(void)
{
	/* We need MD2 to verify old MD2/RSA certificate signatures, but
	  OpenSSL_add_all_digests() no longer enables MD2 by default */
	OpenSSL_add_all_digests();
#ifndef OPENSSL_NO_MD2
	EVP_add_digest(EVP_md2());
#endif

	ERR_load_crypto_strings();

	/* Define the OID for the draft Basic Constraints extension */
	v3_bcOld.ext_nid = OBJ_create(
		"2.5.29.10", "bCold",
		"draft-ietf-pkix-ipki-part1-01 Basic Constraints"
	);

	/* Load all built-in engines */
	ENGINE_load_builtin_engines();

	/* Enable the GOST engine */
	g_gostEngine = ENGINE_by_id("gost");
	if (g_gostEngine && ENGINE_init(g_gostEngine))
		ENGINE_set_default(g_gostEngine, ENGINE_METHOD_ALL);

	rocacheck_init();
}


/******************************************************************************
 * _PG_fini()                                                                 *
 ******************************************************************************/
extern void _PG_fini(void);
void _PG_fini(void)
{
	if (g_gostEngine) {
		ENGINE_finish(g_gostEngine);
		ENGINE_free(g_gostEngine);
	}
	ENGINE_cleanup();
	EVP_cleanup();
	OBJ_cleanup();
	ERR_free_strings();

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

	i = v_asn1GeneralizedTime->length;
	t_data = (char*)v_asn1GeneralizedTime->data;

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

	i = v_asn1UTCTime->length;
	t_data = (char*)v_asn1UTCTime->data;

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
 *   Parse a Time (from X.509 AuthenticationFramework) value into a           *
 * "struct tm".                                                               *
 *                                                                            *
 * IN:	v_asn1Time - a Time object.                                           *
 * 	v_time - the "struct tm" object to populate.                          *
 *                                                                            *
 * OUT:	v_time - the "struct tm" object, populated.                           *
 *                                                                            *
 * Returns:	1 = Successful; 0 = An error occurred.                        *
 ******************************************************************************/
static int ASN1_TIME_parse(
	const ASN1_TIME* const v_asn1Time,
	struct tm* const v_time
)
{
	if (v_asn1Time->type == V_ASN1_UTCTIME)
		return ASN1_UTCTIME_parse(v_asn1Time, v_time);
	else if (v_asn1Time->type == V_ASN1_GENERALIZEDTIME)
		return ASN1_GENERALIZEDTIME_parse(v_asn1Time, v_time);
	return 0;
}


/******************************************************************************
 * x509_issuername()                                                          *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_issuername);
Datum x509_issuername(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	BIO* t_bio;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;
	char* t_string = NULL;
	long t_size;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509) {
		t_text = palloc(strlen(g_error) + VARHDRSZ);
		SET_VARSIZE(t_text, strlen(g_error) + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), g_error, strlen(g_error));
	}
	else {
		/* Create a memory BIO and tell it to make sure that it clears
		  up all its memory when we close it later */
		t_bio = BIO_new(BIO_s_mem());
		(void)BIO_set_close(t_bio, BIO_CLOSE);
		/* Express the certificate's Issuer Name as a one-line
		  string */
		(void)X509_NAME_print_ex(
			t_bio, X509_get_issuer_name(t_x509), 0,
			PG_ARGISNULL(1) ? ((ASN1_STRFLGS_RFC2253
							| ASN1_STRFLGS_ESC_QUOTE
							| XN_FLAG_SEP_CPLUS_SPC
							| XN_FLAG_FN_SN)
						& ~ASN1_STRFLGS_ESC_MSB)
					: PG_GETARG_INT32(1)
		);

		/* Get a pointer to the Issuer Name string and its size */
		t_size = BIO_get_mem_data(t_bio, &t_string);

		/* Copy the Issuer Name string to the return parameter */
		t_text = palloc(t_size + VARHDRSZ);
		SET_VARSIZE(t_text, t_size + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), t_string, t_size);

		/* Free stuff */
		BIO_free(t_bio);
		X509_free(t_x509);
	}

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_keyalgorithm()                                                        *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_keyalgorithm);
Datum x509_keyalgorithm(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;
	char* t_string = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		goto label_error;

	/* Extract the Public Key from this Certificate */
	t_publicKey = X509_get_pubkey(t_x509);
	if (!t_publicKey)
		goto label_error;

	/* Get the name of the algorithm used by this key */
	switch (EVP_PKEY_id(t_publicKey)) {
		case EVP_PKEY_RSA: case EVP_PKEY_RSA2:
			t_string = "RSA";
			break;
		case EVP_PKEY_DSA: case EVP_PKEY_DSA1:
		case EVP_PKEY_DSA2: case EVP_PKEY_DSA3:
		case EVP_PKEY_DSA4:
			t_string = "DSA";
			break;
		case EVP_PKEY_DH:
			t_string = "DH";
			break;
		case EVP_PKEY_EC:
			t_string = "EC";
			break;
		case EVP_PKEY_NONE:
			t_string = "NONE";
			break;
		default:
			goto label_error;
	}

	t_text = palloc(strlen(t_string) + VARHDRSZ);
	SET_VARSIZE(t_text, strlen(t_string) + VARHDRSZ);
	memcpy((void*)VARDATA(t_text), t_string, strlen(t_string));

	goto label_return;

label_error:
	t_text = palloc(strlen(g_error) + VARHDRSZ);
	SET_VARSIZE(t_text, strlen(g_error) + VARHDRSZ);
	memcpy((void*)VARDATA(t_text), g_error, strlen(g_error));

label_return:
	if (t_publicKey)
		EVP_PKEY_free(t_publicKey);
	if (t_x509)
		X509_free(t_x509);

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_keysize()                                                             *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_keysize);
Datum x509_keysize(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	bytea* t_bytea = NULL;
	int32 t_int32 = -1;
	const unsigned char* t_pointer = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (t_x509) {
		t_publicKey = X509_get_pubkey(t_x509);
		if (t_publicKey) {
			t_int32 = EVP_PKEY_bits(t_publicKey);
			EVP_PKEY_free(t_publicKey);
		}
		X509_free(t_x509);
	}

	PG_RETURN_INT32(t_int32);
}


/******************************************************************************
 * x509_notafter()                                                            *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_notafter);
Datum x509_notafter(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	bytea* t_bytea = NULL;
	Timestamp t_timestamp = 0;
	struct tm t_time;
	int t_iResult;
	const unsigned char* t_pointer = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
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
PG_FUNCTION_INFO_V1(x509_notbefore);
Datum x509_notbefore(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	bytea* t_bytea = NULL;
	Timestamp t_timestamp = 0;
	struct tm t_time;
	int t_iResult;
	const unsigned char* t_pointer = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
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
 * x509_publickeymd5()                                                        *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_publickeymd5);
Datum x509_publickeymd5(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	bytea* t_bytea = NULL;
	bytea* t_publicKeyMD5 = NULL;
	const unsigned char* t_pointer = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		goto label_error;

	t_publicKey = X509_get_pubkey(t_x509);
	if (!t_publicKey)
		goto label_error;

	t_publicKeyMD5 = palloc(VARHDRSZ + 16);
	SET_VARSIZE(t_publicKeyMD5, VARHDRSZ + 16);

	if (!X509_pubkey_digest(t_x509, EVP_md5(),
				(unsigned char*)t_publicKeyMD5 + VARHDRSZ,
				NULL))
		goto label_error;

	EVP_PKEY_free(t_publicKey);
	X509_free(t_x509);

	PG_RETURN_BYTEA_P(t_publicKeyMD5);

label_error:
	if (t_publicKey)
		EVP_PKEY_free(t_publicKey);
	if (t_x509)
		X509_free(t_x509);

	PG_RETURN_NULL();
}


/******************************************************************************
 * x509_publickey()                                                           *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_publickey);
Datum x509_publickey(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	bytea* t_bytea = NULL;
	bytea* t_derPublicKey = NULL;
	const unsigned char* t_pointer = NULL;
	unsigned char* t_pointer2 = NULL;
	int t_derPublicKey_size;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		goto label_error;

	t_publicKey = X509_get_pubkey(t_x509);
	if (!t_publicKey)
		goto label_error;

	t_derPublicKey_size = i2d_PUBKEY(t_publicKey, NULL);
	if (t_derPublicKey_size < 0)
		goto label_error;

	t_derPublicKey = palloc(VARHDRSZ + t_derPublicKey_size);
	SET_VARSIZE(t_derPublicKey, VARHDRSZ + t_derPublicKey_size);

	t_pointer2 = (unsigned char*)VARDATA(t_derPublicKey);
	if (i2d_PUBKEY(t_publicKey, &t_pointer2) < 0)
		goto label_error;

	EVP_PKEY_free(t_publicKey);
	X509_free(t_x509);

	PG_RETURN_BYTEA_P(t_derPublicKey);

label_error:
	if (t_publicKey)
		EVP_PKEY_free(t_publicKey);
	if (t_x509)
		X509_free(t_x509);

	PG_RETURN_NULL();
}


/******************************************************************************
 * x509_rsamodulus()                                                          *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_rsamodulus);
Datum x509_rsamodulus(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	const BIGNUM* t_modulus = NULL;
	bytea* t_bytea = NULL;
	bytea* t_derModulus = NULL;
	const unsigned char* t_pointer = NULL;
	int t_derModulus_size;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		goto label_error;

	t_publicKey = X509_get_pubkey(t_x509);
	if (!t_publicKey || (EVP_PKEY_id(t_publicKey) != EVP_PKEY_RSA))
		goto label_error;

	RSA_get0_key(EVP_PKEY_get0_RSA(t_publicKey), &t_modulus, NULL, NULL);
	t_derModulus_size = BN_num_bytes(t_modulus);
	t_derModulus = palloc(VARHDRSZ + t_derModulus_size);
	SET_VARSIZE(t_derModulus, VARHDRSZ + t_derModulus_size);
	if (BN_bn2bin(t_modulus, (unsigned char*)VARDATA(t_derModulus)) != t_derModulus_size)
		goto label_error;

	EVP_PKEY_free(t_publicKey);
	X509_free(t_x509);

	PG_RETURN_BYTEA_P(t_derModulus);

label_error:
	if (t_publicKey)
		EVP_PKEY_free(t_publicKey);
	if (t_x509)
		X509_free(t_x509);

	PG_RETURN_NULL();
}


/******************************************************************************
 * x509_serialnumber()                                                        *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_serialnumber);
Datum x509_serialnumber(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	ASN1_INTEGER* t_asn1Integer;
	bytea* t_bytea = NULL;
	bytea* t_serialNumber = NULL;
	unsigned char* t_pointer = NULL;
	int t_size;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(
		NULL, (const unsigned char**)&t_pointer,
		VARSIZE(t_bytea) - VARHDRSZ
	);
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
 * x509_signaturehashalgorithm()                                              *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_signaturehashalgorithm);
Datum x509_signaturehashalgorithm(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	SIGNATURE_ALGORITHM* t_sigAlg;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;
	char* t_string = g_error;
	int t_iResult;
	int t_sigAlgNID;
	int t_sigHashAlgNID;
	int t_sigKeyAlgNID;
	int l_algNo;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		goto label_return;

	/* Get the names of the algorithms used to generate the signature */
	X509_GET_SIGALGNID(&t_sigAlg, t_x509);
	t_sigAlgNID = OBJ_obj2nid(t_sigAlg->algorithm);
	t_iResult = OBJ_find_sigid_algs(
		t_sigAlgNID, &t_sigHashAlgNID, &t_sigKeyAlgNID
	);
	if (!t_iResult)
		goto label_return;

	/* Get the signature's hash algorithm name */
	for (l_algNo = 0; l_algNo < (sizeof(g_hashAlgorithms)
					/ sizeof(tAlgorithm)); l_algNo++)
		if (g_hashAlgorithms[l_algNo].m_nid == t_sigHashAlgNID) {
			t_string = g_hashAlgorithms[l_algNo].m_name;
			break;
		}

label_return:
	t_text = palloc(strlen(t_string) + VARHDRSZ);
	SET_VARSIZE(t_text, strlen(t_string) + VARHDRSZ);
	memcpy((void*)VARDATA(t_text), t_string, strlen(t_string));

	if (t_x509)
		X509_free(t_x509);

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_signaturekeyalgorithm()                                               *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_signaturekeyalgorithm);
Datum x509_signaturekeyalgorithm(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	SIGNATURE_ALGORITHM* t_sigAlg;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;
	char* t_string = g_error;
	int t_iResult;
	int t_sigAlgNID;
	int t_sigHashAlgNID;
	int t_sigKeyAlgNID;
	int l_algNo;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		goto label_return;

	/* Get the names of the algorithms used to generate the signature */
	X509_GET_SIGALGNID(&t_sigAlg, t_x509);
	t_sigAlgNID = OBJ_obj2nid(t_sigAlg->algorithm);
	t_iResult = OBJ_find_sigid_algs(
		t_sigAlgNID, &t_sigHashAlgNID, &t_sigKeyAlgNID
	);
	if (!t_iResult)
		goto label_return;

	/* Get the signature's key algorithm name */
	for (l_algNo = 0; l_algNo < (sizeof(g_pkeyAlgorithms)
					/ sizeof(tAlgorithm)); l_algNo++)
		if (g_pkeyAlgorithms[l_algNo].m_nid == t_sigKeyAlgNID) {
			t_string = g_pkeyAlgorithms[l_algNo].m_name;
			break;
		}

label_return:
	t_text = palloc(strlen(t_string) + VARHDRSZ);
	SET_VARSIZE(t_text, strlen(t_string) + VARHDRSZ);
	memcpy((void*)VARDATA(t_text), t_string, strlen(t_string));

	if (t_x509)
		X509_free(t_x509);

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_subjectname()                                                         *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_subjectname);
Datum x509_subjectname(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	BIO* t_bio;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;
	char* t_string = NULL;
	long t_size;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509) {
		t_text = palloc(strlen(g_error) + VARHDRSZ);
		SET_VARSIZE(t_text, strlen(g_error) + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), g_error, strlen(g_error));
	}
	else {
		/* Create a memory BIO and tell it to make sure that it clears
		  up all its memory when we close it later */
		t_bio = BIO_new(BIO_s_mem());
		(void)BIO_set_close(t_bio, BIO_CLOSE);
		/* Express the certificate's Subject Name as a one-line
		  string */
		(void)X509_NAME_print_ex(
			t_bio, X509_get_subject_name(t_x509), 0,
			PG_ARGISNULL(1) ? ((ASN1_STRFLGS_RFC2253
							| ASN1_STRFLGS_ESC_QUOTE
							| XN_FLAG_SEP_CPLUS_SPC
							| XN_FLAG_FN_SN)
						& ~ASN1_STRFLGS_ESC_MSB)
					: PG_GETARG_INT32(1)
		);

		/* Get a pointer to the Subject Name string and its size */
		t_size = BIO_get_mem_data(t_bio, &t_string);

		/* Copy the Subject Name string to the return parameter */
		t_text = palloc(t_size + VARHDRSZ);
		SET_VARSIZE(t_text, t_size + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), t_string, t_size);

		/* Free stuff */
		BIO_free(t_bio);
		X509_free(t_x509);
	}

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_name()                                                                *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_name);
Datum x509_name(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	X509_NAME* t_x509Name = NULL;
	bytea* t_bytea = NULL;
	bytea* t_derName = NULL;
	const unsigned char* t_pointer = NULL;
	unsigned char* t_pointer2 = NULL;
	int t_derName_size;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		goto label_error;

	t_x509Name = PG_GETARG_BOOL(1) ? X509_get_subject_name(t_x509)
					: X509_get_issuer_name(t_x509);
	if (!t_x509Name)
		goto label_error;

	t_derName_size = i2d_X509_NAME(t_x509Name, NULL);
	if (t_derName_size < 0)
		goto label_error;

	t_derName = palloc(VARHDRSZ + t_derName_size);
	SET_VARSIZE(t_derName, VARHDRSZ + t_derName_size);

	t_pointer2 = (unsigned char*)VARDATA(t_derName);
	if (i2d_X509_NAME(t_x509Name, &t_pointer2) < 0)
		goto label_error;

	X509_free(t_x509);

	PG_RETURN_BYTEA_P(t_derName);

label_error:
	if (t_x509)
		X509_free(t_x509);

	PG_RETURN_NULL();
}


/******************************************************************************
 * x509_name_print()                                                                *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_name_print);
Datum x509_name_print(
	PG_FUNCTION_ARGS
)
{
	X509_NAME* t_x509Name = NULL;
	BIO* t_bio;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;
	char* t_string = NULL;
	long t_size;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509Name = d2i_X509_NAME(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509Name) {
		t_text = palloc(strlen(g_error) + VARHDRSZ);
		SET_VARSIZE(t_text, strlen(g_error) + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), g_error, strlen(g_error));
	}
	else {
		/* Create a memory BIO and tell it to make sure that it clears
		  up all its memory when we close it later */
		t_bio = BIO_new(BIO_s_mem());
		(void)BIO_set_close(t_bio, BIO_CLOSE);
		/* Express the Name as a one-line string */
		(void)X509_NAME_print_ex(
			t_bio, t_x509Name, 0,
			PG_ARGISNULL(1) ? ((ASN1_STRFLGS_RFC2253
							| ASN1_STRFLGS_ESC_QUOTE
							| XN_FLAG_SEP_CPLUS_SPC
							| XN_FLAG_FN_SN)
						& ~ASN1_STRFLGS_ESC_MSB)
					: PG_GETARG_INT32(1)
		);

		/* Get a pointer to the Name string and its size */
		t_size = BIO_get_mem_data(t_bio, &t_string);

		/* Copy the Name string to the return parameter */
		t_text = palloc(t_size + VARHDRSZ);
		SET_VARSIZE(t_text, t_size + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), t_string, t_size);

		/* Free stuff */
		BIO_free(t_bio);
		X509_NAME_free(t_x509Name);
	}

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_commonname()                                                          *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_commonname);
Datum x509_commonname(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	X509_NAME_ENTRY* t_nameEntry;
	ASN1_STRING* t_asn1String;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;
	unsigned char* t_utf8String = NULL;
	int t_lastPos = -1;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509) {
		t_text = palloc(strlen(g_error) + VARHDRSZ);
		SET_VARSIZE(t_text, strlen(g_error) + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), g_error, strlen(g_error));
	}
	else {
		t_lastPos = X509_NAME_get_index_by_NID(
			X509_get_subject_name(t_x509), NID_commonName, t_lastPos
		);
		if (t_lastPos == -1) {
			X509_free(t_x509);
			PG_RETURN_NULL();
		}
		else {
			t_nameEntry = X509_NAME_get_entry(
				X509_get_subject_name(t_x509), t_lastPos
			);
			t_asn1String = X509_NAME_ENTRY_get_data(t_nameEntry);
			(void)ASN1_STRING_to_UTF8(&t_utf8String, t_asn1String);
			if (t_utf8String) {
				t_text = palloc(
					strlen((char*)t_utf8String) + VARHDRSZ
				);
				SET_VARSIZE(
					t_text,
					strlen((char*)t_utf8String) + VARHDRSZ
				);
				memcpy(
					(void*)VARDATA(t_text), t_utf8String,
					strlen((char*)t_utf8String)
				);
				OPENSSL_free(t_utf8String);
			}
		}
		X509_free(t_x509);
	}

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_subjectkeyidentifier()                                                *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_subjectkeyidentifier);
Datum x509_subjectkeyidentifier(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	ASN1_OCTET_STRING* t_asn1OctetString;
	bytea* t_bytea = NULL;
	bytea* t_subjectKeyIdentifier = NULL;
	unsigned char* t_pointer = NULL;
	int t_size;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(
		NULL, (const unsigned char**)&t_pointer,
		VARSIZE(t_bytea) - VARHDRSZ
	);
	if (!t_x509)
		PG_RETURN_NULL();

	t_asn1OctetString = X509_get_ext_d2i(
		t_x509, NID_subject_key_identifier, NULL, NULL
	);
	if (!t_asn1OctetString) {
		X509_free(t_x509);
		PG_RETURN_NULL();
	}

	t_size = ASN1_STRING_length(t_asn1OctetString);
	t_subjectKeyIdentifier = palloc(VARHDRSZ + t_size);
	t_pointer = (unsigned char*)t_subjectKeyIdentifier + VARHDRSZ;
	memcpy(t_pointer, ASN1_STRING_get0_data(t_asn1OctetString), t_size);
	SET_VARSIZE(t_subjectKeyIdentifier, VARHDRSZ + t_size);

	ASN1_OCTET_STRING_free(t_asn1OctetString);
	X509_free(t_x509);

	PG_RETURN_BYTEA_P(t_subjectKeyIdentifier);
}


/******************************************************************************
 * x509_authoritykeyid()                                                      *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_authoritykeyid);
Datum x509_authoritykeyid(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	AUTHORITY_KEYID* t_authorityKeyIdentifier;
	bytea* t_bytea = NULL;
	bytea* t_keyid = NULL;
	unsigned char* t_pointer = NULL;
	int t_size;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(
		NULL, (const unsigned char**)&t_pointer,
		VARSIZE(t_bytea) - VARHDRSZ
	);
	if (!t_x509)
		PG_RETURN_NULL();

	t_authorityKeyIdentifier = X509_get_ext_d2i(
		t_x509, NID_authority_key_identifier, NULL, NULL
	);
	if (!t_authorityKeyIdentifier || !t_authorityKeyIdentifier->keyid) {
		X509_free(t_x509);
		PG_RETURN_NULL();
	}

	t_size = ASN1_STRING_length(t_authorityKeyIdentifier->keyid);
	t_keyid = palloc(VARHDRSZ + t_size);
	t_pointer = (unsigned char*)t_keyid + VARHDRSZ;
	memcpy(t_pointer, ASN1_STRING_get0_data(t_authorityKeyIdentifier->keyid), t_size);
	SET_VARSIZE(t_keyid, VARHDRSZ + t_size);

	AUTHORITY_KEYID_free(t_authorityKeyIdentifier);
	X509_free(t_x509);

	PG_RETURN_BYTEA_P(t_keyid);
}


typedef struct tExtKeyUsageCtx_st{
	EXTENDED_KEY_USAGE* m_extKeyUsages;
	int m_index;
} tExtKeyUsageCtx;


/******************************************************************************
 * x509_extkeyusages()                                                        *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_extkeyusages);
Datum x509_extkeyusages(
	PG_FUNCTION_ARGS
)
{
	ASN1_OBJECT* t_ekuOID;
	tExtKeyUsageCtx* t_extKeyUsageCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;
		MemoryContext t_oldMemoryCtx;
		bytea* t_bytea = NULL;
		const unsigned char* t_pointer = NULL;

		/* Create a function context for cross-call persistence */
		t_funcCtx = SRF_FIRSTCALL_INIT();
		/* Switch to memory context appropriate for multiple function
		  calls */
		t_oldMemoryCtx = MemoryContextSwitchTo(
			t_funcCtx->multi_call_memory_ctx
		);

		/* Allocate memory for our user-defined structure and initialize
		  it */
		t_funcCtx->user_fctx = t_extKeyUsageCtx
					= palloc(sizeof(tExtKeyUsageCtx));
		memset(t_extKeyUsageCtx, '\0', sizeof(tExtKeyUsageCtx));

		/* One-time setup code */
		if (!PG_ARGISNULL(0)) {
			t_bytea = PG_GETARG_BYTEA_P(0);
			t_pointer = (unsigned char*)VARDATA(t_bytea);
			t_x509 = d2i_X509(
				NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ
			);
		}
		if (t_x509) {
			t_extKeyUsageCtx->m_extKeyUsages = X509_get_ext_d2i(
				t_x509, NID_ext_key_usage, NULL, NULL
			);
			X509_free(t_x509);
		}

		MemoryContextSwitchTo(t_oldMemoryCtx);
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_extKeyUsageCtx = t_funcCtx->user_fctx;

	if (t_extKeyUsageCtx->m_extKeyUsages) {
		while (t_extKeyUsageCtx->m_index < sk_ASN1_OBJECT_num(
					t_extKeyUsageCtx->m_extKeyUsages)) {
			t_ekuOID = sk_ASN1_OBJECT_value(
				t_extKeyUsageCtx->m_extKeyUsages,
				t_extKeyUsageCtx->m_index++
			);

			text* t_text = palloc(MAX_OIDSTRING_LENGTH + VARHDRSZ);

			(void)OBJ_obj2txt(
				VARDATA(t_text), MAX_OIDSTRING_LENGTH, t_ekuOID, 
				PG_GETARG_BOOL(1) ? 1 : 0
			);

			SET_VARSIZE(t_text, strlen(VARDATA(t_text)) + VARHDRSZ);

			SRF_RETURN_NEXT(
				t_funcCtx, PointerGetDatum(t_text)
			);
		}
		EXTENDED_KEY_USAGE_free(t_extKeyUsageCtx->m_extKeyUsages);
	}

	SRF_RETURN_DONE(t_funcCtx);
}


/******************************************************************************
 * x509_isekupermitted()                                                      *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_isekupermitted);
Datum x509_isekupermitted(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	EXTENDED_KEY_USAGE* t_extendedKeyUsage;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;
	char* t_ekuOID = NULL;
	char t_ekuOID2[MAX_OIDSTRING_LENGTH];
	int l_indexNo;
	bool t_bResult = false;

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (t_x509) {
		t_text = PG_GETARG_TEXT_P(1);
		t_ekuOID = calloc(VARSIZE(t_text) - VARHDRSZ + 1, 1);
		if (t_ekuOID) {
			strncpy(
				t_ekuOID, VARDATA(t_text),
				VARSIZE(t_text) - VARHDRSZ
			);
			if (!strcmp(t_ekuOID, "2.5.29.37.0")) {
				t_bResult = true;
				goto label_done;
			}

			t_extendedKeyUsage = X509_get_ext_d2i(
				t_x509, NID_ext_key_usage, NULL, NULL
			);
			if (!t_extendedKeyUsage) {
				t_bResult = true;
				goto label_done;
			}
			for (l_indexNo = 0; l_indexNo < sk_ASN1_OBJECT_num(
							t_extendedKeyUsage
						); l_indexNo++) {
				memset(t_ekuOID2, '\0', MAX_OIDSTRING_LENGTH);
				(void)OBJ_obj2txt(
					t_ekuOID2, MAX_OIDSTRING_LENGTH,
					sk_ASN1_OBJECT_value(
						t_extendedKeyUsage, l_indexNo
					), 1
				);
				if ((!strcmp(t_ekuOID, t_ekuOID2))
						|| (!strcmp(t_ekuOID2,
							"2.5.29.37.0"))) {
					t_bResult = true;
					break;
				}
			}
			EXTENDED_KEY_USAGE_free(t_extendedKeyUsage);
		}

	label_done:
		if (t_ekuOID)
			free(t_ekuOID);
		X509_free(t_x509);
	}

	PG_RETURN_BOOL(t_bResult);
}


typedef struct tCertPoliciesCtx_st{
	CERTIFICATEPOLICIES* m_certPolicies;
	int m_index;
} tCertPoliciesCtx;


/******************************************************************************
 * x509_certpolicies()                                                        *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_certpolicies);
Datum x509_certpolicies(
	PG_FUNCTION_ARGS
)
{
	POLICYINFO* t_policyInfo;
	tCertPoliciesCtx* t_certPoliciesCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;
		MemoryContext t_oldMemoryCtx;
		bytea* t_bytea = NULL;
		const unsigned char* t_pointer = NULL;

		/* Create a function context for cross-call persistence */
		t_funcCtx = SRF_FIRSTCALL_INIT();
		/* Switch to memory context appropriate for multiple function
		  calls */
		t_oldMemoryCtx = MemoryContextSwitchTo(
			t_funcCtx->multi_call_memory_ctx
		);

		/* Allocate memory for our user-defined structure and initialize
		  it */
		t_funcCtx->user_fctx = t_certPoliciesCtx
					= palloc(sizeof(tCertPoliciesCtx));
		memset(t_certPoliciesCtx, '\0', sizeof(tCertPoliciesCtx));

		/* One-time setup code */
		if (!PG_ARGISNULL(0)) {
			t_bytea = PG_GETARG_BYTEA_P(0);
			t_pointer = (unsigned char*)VARDATA(t_bytea);
			t_x509 = d2i_X509(
				NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ
			);
		}
		if (t_x509) {
			t_certPoliciesCtx->m_certPolicies = X509_get_ext_d2i(
				t_x509, NID_certificate_policies, NULL, NULL
			);
			X509_free(t_x509);
		}

		MemoryContextSwitchTo(t_oldMemoryCtx);
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_certPoliciesCtx = t_funcCtx->user_fctx;

	if (t_certPoliciesCtx->m_certPolicies) {
		while (t_certPoliciesCtx->m_index < sk_POLICYINFO_num(
					t_certPoliciesCtx->m_certPolicies)) {
			t_policyInfo = sk_POLICYINFO_value(
				t_certPoliciesCtx->m_certPolicies,
				t_certPoliciesCtx->m_index++
			);

			text* t_text = palloc(MAX_OIDSTRING_LENGTH + VARHDRSZ);

			(void)OBJ_obj2txt(
				VARDATA(t_text), MAX_OIDSTRING_LENGTH,
				t_policyInfo->policyid, 1
			);

			SET_VARSIZE(t_text, strlen(VARDATA(t_text)) + VARHDRSZ);

			SRF_RETURN_NEXT(
				t_funcCtx, PointerGetDatum(t_text)
			);
		}
		CERTIFICATEPOLICIES_free(t_certPoliciesCtx->m_certPolicies);
	}

	SRF_RETURN_DONE(t_funcCtx);
}


/******************************************************************************
 * x509_ispolicypermitted()                                                   *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_ispolicypermitted);
Datum x509_ispolicypermitted(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	CERTIFICATEPOLICIES* t_certificatePolicies;
	POLICYINFO* t_policyInfo;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;
	char* t_policyOID = NULL;
	char t_policyOID2[MAX_OIDSTRING_LENGTH];
	int l_indexNo;
	bool t_bResult = false;

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (t_x509) {
		t_text = PG_GETARG_TEXT_P(1);
		t_policyOID = calloc(VARSIZE(t_text) - VARHDRSZ + 1, 1);
		if (t_policyOID) {
			strncpy(
				t_policyOID, VARDATA(t_text),
				VARSIZE(t_text) - VARHDRSZ
			);
			if (!strcmp(t_policyOID, "2.5.29.32.0")) {
				t_bResult = true;
				goto label_done;
			}

			t_certificatePolicies = X509_get_ext_d2i(
				t_x509, NID_certificate_policies, NULL, NULL
			);
			if (!t_certificatePolicies) {
				t_bResult = true;
				goto label_done;
			}
			for (l_indexNo = 0; l_indexNo < sk_POLICYINFO_num(
							t_certificatePolicies
						); l_indexNo++) {
				t_policyInfo = sk_POLICYINFO_value(
					t_certificatePolicies, l_indexNo
				);
				memset(t_policyOID2, '\0',
					MAX_OIDSTRING_LENGTH);
				(void)OBJ_obj2txt(
					t_policyOID2, MAX_OIDSTRING_LENGTH,
					t_policyInfo->policyid, 1
				);
				if ((!strcmp(t_policyOID, t_policyOID2))
						|| (!strcmp(t_policyOID2,
							"2.5.29.32.0"))) {
					t_bResult = true;
					break;
				}
			}
			CERTIFICATEPOLICIES_free(t_certificatePolicies);
		}

	label_done:
		if (t_policyOID)
			free(t_policyOID);
		X509_free(t_x509);
	}

	PG_RETURN_BOOL(t_bResult);
}


/******************************************************************************
 * x509_canissuecerts()                                                       *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_canissuecerts);
Datum x509_canissuecerts(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	BASIC_CONSTRAINTS* t_basicConstraints;
	BASIC_CONSTRAINTS_OLD* t_bCold = NULL;
	ASN1_BIT_STRING* t_keyUsage;
	SIGNATURE_BIT_STRING* t_signature;
	ASN1_OCTET_STRING* t_oldBasicConstraints;
	bytea* t_bytea = NULL;
	const unsigned char* t_pointer = NULL;
	unsigned long t_keyUsageBits;
	unsigned long t_subjTypeBits;
	int t_pos = -1;
	bool t_bResult = false;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (t_x509) {
		if (X509_get_version(t_x509) < 2) {
			/* Assume that self-signed v1/v2 certificates may issue,
			  but all other v1/v2 certificates may not issue */
			t_bResult = !X509_NAME_cmp(
				X509_get_subject_name(t_x509),
				X509_get_issuer_name(t_x509)
			);
			goto label_done;
		}

		/* Is the Basic Constraints extension present? */
		t_basicConstraints = X509_get_ext_d2i(
			t_x509, NID_basic_constraints, NULL, NULL
		);
		if (t_basicConstraints) {
			if (t_basicConstraints->ca)
				t_bResult = true;
			BASIC_CONSTRAINTS_free(t_basicConstraints);
			if (t_bResult)
				goto label_checkKeyUsage;
			else
				goto label_done;
		}

		/* Is the old draft Basic Constraints extension present? */
		t_pos = X509_get_ext_by_NID(t_x509, v3_bcOld.ext_nid, -1);
		if (t_pos > -1) {
			t_oldBasicConstraints = X509_EXTENSION_get_data(
				X509_get_ext(t_x509, t_pos)
			);
			t_pointer = t_oldBasicConstraints->data;
			t_bCold = (BASIC_CONSTRAINTS_OLD*)ASN1_item_d2i(
				NULL, &t_pointer, t_oldBasicConstraints->length,
				ASN1_ITEM_ptr(v3_bcOld.it)
			);
			if (!t_bCold)
				goto label_done;
			else if (t_bCold->subjtype->length > 0) {
				t_subjTypeBits = t_bCold->subjtype->data[0];
				if (t_bCold->subjtype->length > 1)
					t_subjTypeBits |= t_bCold->subjtype->
								data[1] << 8;
			}
			else
				t_subjTypeBits = 0;
			BASIC_CONSTRAINTS_OLD_free(t_bCold);

			if (t_subjTypeBits & CERT_CA_SUBJECT_FLAG) {
				t_bResult = true;
				goto label_checkKeyUsage;
			}
			else
				goto label_done;
		}

		/* Is this the "Root SGC Authority"?  The self-signed Root SGC
		  Authority Root Certificate doesn't contain either of the Basic
		  Constraints extensions, yet old CryptoAPI versions treat is as
		  a valid issuer nonetheless */
		X509_GET_SIGNATURE(&t_signature, t_x509);
		if (t_signature->length == 256)
			if (!memcmp(g_rootSGCAuthority_sig, t_signature->data,
					256)) {
				t_bResult = true;
				goto label_checkKeyUsage;
			}

		/* If we reach this point, the certificate definitely can't
		  issue, so skip the Key Usage check */
		goto label_done;

	label_checkKeyUsage:
		t_keyUsage = X509_get_ext_d2i(
			t_x509, NID_key_usage, NULL, NULL
		);
		if (t_keyUsage) {
			if (t_keyUsage->length > 0) {
				t_keyUsageBits = t_keyUsage->data[0];
				if (t_keyUsage->length > 1)
					t_keyUsageBits |=
						t_keyUsage->data[1] << 8;
			}
			else
				t_keyUsageBits = 0;
			ASN1_BIT_STRING_free(t_keyUsage);

			if (!(t_keyUsageBits & KU_KEY_CERT_SIGN))
				t_bResult = false;
		}

	label_done:
		X509_free(t_x509);
	}

	PG_RETURN_BOOL(t_bResult);
}


/******************************************************************************
 * x509_getpathlenconstraint()                                                *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_getpathlenconstraint);
Datum x509_getpathlenconstraint(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	BASIC_CONSTRAINTS* t_basicConstraints;
	BASIC_CONSTRAINTS_OLD* t_bCold = NULL;
	SIGNATURE_BIT_STRING* t_signature;
	ASN1_OCTET_STRING* t_oldBasicConstraints;
	bytea* t_bytea = NULL;
	const unsigned char* t_pointer = NULL;
	unsigned long t_subjTypeBits;
	int t_pos = -1;
	int t_iResult = -1;

	if (PG_ARGISNULL(0))
		PG_RETURN_INT32(-2);
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (t_x509) {
		/* Any X509v1 or X509v2 certificate can issue certs without a
		  path length constraint */
		if (X509_get_version(t_x509) < 2) {
			t_iResult = -999;
			goto label_done;
		}

		/* Is the Basic Constraints extension present? */
		t_basicConstraints = X509_get_ext_d2i(
			t_x509, NID_basic_constraints, NULL, NULL
		);
		if (t_basicConstraints) {
			if (t_basicConstraints->ca) {
				if (t_basicConstraints->pathlen)
					t_iResult = ASN1_INTEGER_get(
						t_basicConstraints->pathlen
					);
				else
					t_iResult = -999;
			}
			else
				t_iResult = -3;
			BASIC_CONSTRAINTS_free(t_basicConstraints);
			goto label_done;
		}

		/* Is the draft Basic Constraints extension present? */
		t_pos = X509_get_ext_by_NID(t_x509, v3_bcOld.ext_nid, -1);
		if (t_pos > -1) {
			t_oldBasicConstraints = X509_EXTENSION_get_data(
				X509_get_ext(t_x509, t_pos)
			);
			t_pointer = t_oldBasicConstraints->data;
			t_bCold = (BASIC_CONSTRAINTS_OLD*)ASN1_item_d2i(
				NULL, &t_pointer, t_oldBasicConstraints->length,
				ASN1_ITEM_ptr(v3_bcOld.it)
			);
			if (!t_bCold)
				goto label_done;
			else if (t_bCold->subjtype->length > 0) {
				t_subjTypeBits = t_bCold->subjtype->data[0];
				if (t_bCold->subjtype->length > 1)
					t_subjTypeBits |= t_bCold->
						subjtype->data[1] << 8;
			}
			else
				t_subjTypeBits = 0;

			if (t_subjTypeBits & CERT_CA_SUBJECT_FLAG) {
				if (t_bCold->pathlen)
					t_iResult = ASN1_INTEGER_get(
						t_bCold->pathlen
					);
				else
					t_iResult = -999;
			}
			else
				t_iResult = -3;
			BASIC_CONSTRAINTS_OLD_free(t_bCold);
			goto label_done;
		}

		/* Is this the "Root SGC Authority"?  The self-signed Root SGC
		  Authority Root Certificate doesn't contain either of the Basic
		  Constraints extensions, yet old CryptoAPI versions treat is as
		  a valid issuer nonetheless */
		X509_GET_SIGNATURE(&t_signature, t_x509);
		if (t_signature->length == 256)
			if (!memcmp(g_rootSGCAuthority_sig, t_signature->data,
					256)) {
				t_iResult = -999;
				goto label_done;
			}

		/* No Basic Constraints extension in this v3 certificate, so
		  it must be an end-entity certificate */
		t_iResult = -4;

	label_done:
		X509_free(t_x509);
	}

	if (t_iResult == -999)
		PG_RETURN_NULL();
	else
		PG_RETURN_INT32(t_iResult);
}


typedef struct tX509NameCtx_st{
	X509* m_x509;
	X509_NAME* m_name;
	int m_index;
	int m_nid;
} tX509NameCtx;


/******************************************************************************
 * x509_nameattributes()                                                      *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_nameattributes);
Datum x509_nameattributes(
	PG_FUNCTION_ARGS
)
{
	tX509NameCtx* t_x509NameCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		MemoryContext t_oldMemoryCtx;
		bytea* t_bytea = NULL;
		const unsigned char* t_pointer = NULL;

		/* Create a function context for cross-call persistence */
		t_funcCtx = SRF_FIRSTCALL_INIT();
		/* Switch to memory context appropriate for multiple function
		  calls */
		t_oldMemoryCtx = MemoryContextSwitchTo(
			t_funcCtx->multi_call_memory_ctx
		);

		/* Allocate memory for our user-defined structure and initialize
		  it */
		t_funcCtx->user_fctx = t_x509NameCtx
						= palloc(sizeof(tX509NameCtx));
		memset(t_x509NameCtx, '\0', sizeof(tX509NameCtx));
		t_x509NameCtx->m_nid = NID_X509;

		/* One-time setup code */
		if (!PG_ARGISNULL(0)) {
			t_bytea = PG_GETARG_BYTEA_P(0);
			t_pointer = (unsigned char*)VARDATA(t_bytea);
			t_x509NameCtx->m_x509 = d2i_X509(
				NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ
			);
		}
		if (t_x509NameCtx->m_x509) {
			if (PG_GETARG_BOOL(2))
				t_x509NameCtx->m_name = X509_get_subject_name(
					t_x509NameCtx->m_x509
				);
			else
				t_x509NameCtx->m_name = X509_get_issuer_name(
					t_x509NameCtx->m_x509
				);
		}

		if (!PG_ARGISNULL(1)) {
			text* t_text = PG_GETARG_TEXT_P(1);
			char* t_oidName = palloc(VARSIZE(t_text) - VARHDRSZ + 1);
			memcpy(t_oidName, VARDATA(t_text),
				VARSIZE(t_text) - VARHDRSZ);
			t_oidName[VARSIZE(t_text) - VARHDRSZ] = '\0';
			t_x509NameCtx->m_nid = OBJ_txt2nid(t_oidName);
		}

		MemoryContextSwitchTo(t_oldMemoryCtx);
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_x509NameCtx = t_funcCtx->user_fctx;

	if ((t_x509NameCtx->m_nid == NID_undef) && (t_funcCtx->call_cntr == 0)) {
		char* c_unsupportedAttribute = "Unsupported Attribute";
		text* t_text = palloc(
			strlen(c_unsupportedAttribute + VARHDRSZ)
		);
		SET_VARSIZE(
			t_text, strlen(c_unsupportedAttribute) + VARHDRSZ
		);
		memcpy((void*)VARDATA(t_text), c_unsupportedAttribute,
			strlen(c_unsupportedAttribute));
		SRF_RETURN_NEXT(t_funcCtx, PointerGetDatum(t_text));
	}

	if ((t_x509NameCtx->m_nid != NID_undef) && (t_x509NameCtx->m_name)) {
		while (t_x509NameCtx->m_index < X509_NAME_entry_count(
						t_x509NameCtx->m_name)) {
			X509_NAME_ENTRY* t_nameEntry = X509_NAME_get_entry(
				t_x509NameCtx->m_name, t_x509NameCtx->m_index
			);
			ASN1_STRING* t_asn1String;
			int t_thisNID = OBJ_obj2nid(
				X509_NAME_ENTRY_get_object(t_nameEntry)
			);
			char* t_utf8String = NULL;

			/* Increment the counter while we can */
			t_x509NameCtx->m_index++;

			/* Check if this component is of interest */
			if ((t_x509NameCtx->m_nid != t_thisNID)
					&& (t_x509NameCtx->m_nid != NID_X509))
				continue;

			text* t_text = NULL;
			if (PG_GETARG_BOOL(3)) {
				t_asn1String = X509_NAME_ENTRY_get_data(
					t_nameEntry
				);
				(void)ASN1_STRING_to_UTF8(
					(unsigned char**)&t_utf8String,
					t_asn1String
				);
				if (t_utf8String) {
					t_text = palloc(
						strlen(t_utf8String) + VARHDRSZ
					);
					SET_VARSIZE(
						t_text,
						strlen(t_utf8String) + VARHDRSZ
					);
					memcpy((void*)VARDATA(t_text),
						t_utf8String,
						strlen(t_utf8String));
					OPENSSL_free(t_utf8String);
				}
			}
			else {
				char t_buffer[80];
				OBJ_obj2txt(
					t_buffer, sizeof t_buffer,
					X509_NAME_ENTRY_get_object(t_nameEntry),
					1
				);
				t_text = palloc(strlen(t_buffer) + VARHDRSZ);
				SET_VARSIZE(
					t_text, strlen(t_buffer) + VARHDRSZ
				);
				memcpy((void*)VARDATA(t_text), t_buffer,
					strlen(t_buffer));
			}

			SRF_RETURN_NEXT(
				t_funcCtx, PointerGetDatum(t_text)
			);
		}
	}

	if (t_x509NameCtx->m_x509)
		X509_free(t_x509NameCtx->m_x509);

	SRF_RETURN_DONE(t_funcCtx);
}


typedef struct tNameAttributesRawCtx_st{
	X509* m_x509;
	X509_NAME* m_name;
	int m_index;
	bool* m_nulls;
} tNameAttributesRawCtx;


/******************************************************************************
 * x509_nameattributes_raw()                                                  *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_nameattributes_raw);
Datum x509_nameattributes_raw(
	PG_FUNCTION_ARGS
)
{
	tNameAttributesRawCtx* t_nameAttributesRawCtx;
	FuncCallContext* t_funcCtx;
	TupleDesc t_tupleDesc;

	if (SRF_IS_FIRSTCALL()) {
		MemoryContext t_oldMemoryCtx;
		bytea* t_bytea = NULL;
		const unsigned char* t_pointer = NULL;

		/* Create a function context for cross-call persistence */
		t_funcCtx = SRF_FIRSTCALL_INIT();
		/* Switch to memory context appropriate for multiple function
		  calls */
		t_oldMemoryCtx = MemoryContextSwitchTo(
			t_funcCtx->multi_call_memory_ctx
		);

		/* Allocate memory for our user-defined structure and initialize
		  it */
		t_funcCtx->user_fctx = t_nameAttributesRawCtx
					= palloc(sizeof(tNameAttributesRawCtx));
		memset(t_nameAttributesRawCtx, '\0', sizeof(tNameAttributesRawCtx));

		/* Build a tuple descriptor for our result type */
		if (get_call_result_type(fcinfo, NULL, &t_tupleDesc) != TYPEFUNC_COMPOSITE)
			ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg("function returning record called in context "
					"that cannot accept type record"))
			);

		t_funcCtx->tuple_desc = BlessTupleDesc(t_tupleDesc);
		t_nameAttributesRawCtx->m_nulls = (bool*)palloc((t_tupleDesc->natts) * sizeof(bool));
		memset(t_nameAttributesRawCtx->m_nulls, true, (t_tupleDesc->natts) * sizeof(bool));

		/* One-time setup code */
		if (!PG_ARGISNULL(0)) {
			t_bytea = PG_GETARG_BYTEA_P(0);
			t_pointer = (unsigned char*)VARDATA(t_bytea);
			t_nameAttributesRawCtx->m_x509 = d2i_X509(
				NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ
			);
		}
		if (t_nameAttributesRawCtx->m_x509) {
			if (PG_GETARG_BOOL(1))
				t_nameAttributesRawCtx->m_name = X509_get_subject_name(
					t_nameAttributesRawCtx->m_x509
				);
			else
				t_nameAttributesRawCtx->m_name = X509_get_issuer_name(
					t_nameAttributesRawCtx->m_x509
				);
		}

		MemoryContextSwitchTo(t_oldMemoryCtx);
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_nameAttributesRawCtx = t_funcCtx->user_fctx;

	if (t_nameAttributesRawCtx->m_name) {
		while (t_nameAttributesRawCtx->m_index < X509_NAME_entry_count(
					t_nameAttributesRawCtx->m_name)) {
			X509_NAME_ENTRY* t_nameEntry = X509_NAME_get_entry(
				t_nameAttributesRawCtx->m_name,
				t_nameAttributesRawCtx->m_index
			);
			char* t_utf8String = NULL;
			Datum t_datum[2];

			/* Increment the counter while we can */
			t_nameAttributesRawCtx->m_index++;

			ASN1_STRING* t_asn1String = X509_NAME_ENTRY_get_data(t_nameEntry);
			int t_length = ASN1_STRING_to_UTF8(
				(unsigned char**)&t_utf8String, t_asn1String
			);
			if ((t_length < 0) || (t_utf8String == NULL))
				continue;	/* Ignore unsupported attribute types */

			char t_oid_numerical[80] = "";
			OBJ_obj2txt(t_oid_numerical, sizeof(t_oid_numerical),
					X509_NAME_ENTRY_get_object(t_nameEntry), 1);
			text* t_oidText = palloc(strlen(t_oid_numerical) + VARHDRSZ);
			SET_VARSIZE(t_oidText, strlen(t_oid_numerical) + VARHDRSZ);
			memcpy((void*)VARDATA(t_oidText), t_oid_numerical, strlen(t_oid_numerical));
			t_datum[0] = PointerGetDatum(t_oidText);
			t_nameAttributesRawCtx->m_nulls[0] = false;

			bytea* t_rawValue = palloc(t_length + VARHDRSZ);
			SET_VARSIZE(t_rawValue, t_length + VARHDRSZ);
			memcpy((void*)VARDATA(t_rawValue), t_utf8String, t_length);
			OPENSSL_free(t_utf8String);
			t_datum[1] = PointerGetDatum(t_rawValue);
			t_nameAttributesRawCtx->m_nulls[1] = false;

			Datum t_compositeDatum;
			HeapTuple t_heapTuple = heap_form_tuple(
				t_funcCtx->tuple_desc, t_datum,
				t_nameAttributesRawCtx->m_nulls
			);
			if (t_heapTuple) {
				t_compositeDatum = HeapTupleGetDatum(t_heapTuple);
				if (t_compositeDatum)
					SRF_RETURN_NEXT(t_funcCtx, t_compositeDatum);
			}
		}
	}

	if (t_nameAttributesRawCtx->m_x509)
		X509_free(t_nameAttributesRawCtx->m_x509);

	SRF_RETURN_DONE(t_funcCtx);
}


typedef struct tAltNamesCtx_st{
	STACK_OF(GENERAL_NAME)* m_genNames;
	int m_index;
	int m_type;
} tAltNamesCtx;


/******************************************************************************
 * x509_altnames()                                                            *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_altnames);
Datum x509_altnames(
	PG_FUNCTION_ARGS
)
{
	tAltNamesCtx* t_altNamesCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;
		MemoryContext t_oldMemoryCtx;
		bytea* t_bytea = NULL;
		const unsigned char* t_pointer = NULL;

		/* Create a function context for cross-call persistence */
		t_funcCtx = SRF_FIRSTCALL_INIT();
		/* Switch to memory context appropriate for multiple function
		  calls */
		t_oldMemoryCtx = MemoryContextSwitchTo(
			t_funcCtx->multi_call_memory_ctx
		);

		/* Allocate memory for our user-defined structure and initialize
		  it */
		t_funcCtx->user_fctx = t_altNamesCtx
						= palloc(sizeof(tAltNamesCtx));
		memset(t_altNamesCtx, '\0', sizeof(tAltNamesCtx));

		/* One-time setup code */
		if (!PG_ARGISNULL(0)) {
			t_bytea = PG_GETARG_BYTEA_P(0);
			t_pointer = (unsigned char*)VARDATA(t_bytea);
			t_x509 = d2i_X509(
				NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ
			);
		}
		if (t_x509) {
			if (PG_GETARG_BOOL(2))
				t_altNamesCtx->m_genNames = X509_get_ext_d2i(
					t_x509, NID_subject_alt_name, NULL, NULL
				);
			else
				t_altNamesCtx->m_genNames = X509_get_ext_d2i(
					t_x509, NID_issuer_alt_name, NULL, NULL
				);

			X509_free(t_x509);
		}

		if (!PG_ARGISNULL(1)) {
			switch (PG_GETARG_INT32(1)) {
				case 1: /* GEN_EMAIL */
				case 2: /* GEN_DNS */
				case 4: /* GEN_DIRNAME */
				case 6: /* GEN_URI */
				case 7: /* GEN_IPADD */
					t_altNamesCtx->m_type
							= PG_GETARG_INT32(1);
					break;
				default:
					t_altNamesCtx->m_type = -2;
			}
		}
		else
			t_altNamesCtx->m_type = -1;

		MemoryContextSwitchTo(t_oldMemoryCtx);
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_altNamesCtx = t_funcCtx->user_fctx;

	if ((t_altNamesCtx->m_type == -2) && (t_funcCtx->call_cntr == 0)) {
		char* c_unsupportedGenName = "Unsupported GeneralName";
		text* t_text = palloc(strlen(c_unsupportedGenName + VARHDRSZ));
		SET_VARSIZE(t_text, strlen(c_unsupportedGenName) + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), c_unsupportedGenName,
			strlen(c_unsupportedGenName));
		SRF_RETURN_NEXT(t_funcCtx, PointerGetDatum(t_text));
	}

	if ((t_altNamesCtx->m_type != -2) && (t_altNamesCtx->m_genNames)) {
		while (t_altNamesCtx->m_index < sk_GENERAL_NAME_num(
						t_altNamesCtx->m_genNames)) {
			char* t_utf8String = NULL;
			/* Pull out this GeneralName */
			const GENERAL_NAME* t_generalName
				= sk_GENERAL_NAME_value(
					t_altNamesCtx->m_genNames,
					t_altNamesCtx->m_index
				);

			/* Increment the counter while we can */
			t_altNamesCtx->m_index++;

			/* Check if this GeneralName is of interest */
			if ((t_altNamesCtx->m_type != t_generalName->type)
						&& (t_altNamesCtx->m_type != -1))
				continue;

			/* IA5String types */
			if (!PG_GETARG_BOOL(3))
				/* We're only interested in OtherName OIDs */
				;
			else if ((t_generalName->type == GEN_EMAIL)
					|| (t_generalName->type == GEN_DNS)
					|| (t_generalName->type == GEN_URI))
				(void)ASN1_STRING_to_UTF8(
					(unsigned char**)&t_utf8String,
					t_generalName->d.ia5
				);
			/* Name types */
			else if (t_generalName->type == GEN_DIRNAME) {
				/* Create a memory BIO and tell it to make sure
				  that it clears up all its memory when we close
				  it later */
				char* t_memData = NULL;
				BIO* t_bio = BIO_new(BIO_s_mem());
				(void)BIO_set_close(t_bio, BIO_CLOSE);
				/* Express the directoryName as a one-line
				  string */
				(void)X509_NAME_print_ex(
					t_bio, t_generalName->d.dirn, 0,
					(ASN1_STRFLGS_RFC2253
							| ASN1_STRFLGS_ESC_QUOTE
							| XN_FLAG_SEP_CPLUS_SPC
							| XN_FLAG_FN_SN)
						& ~ASN1_STRFLGS_ESC_MSB
				);
				/* Get a pointer to the string and its size */
				int t_size = BIO_get_mem_data(
					t_bio, &t_memData
				);
				t_utf8String = OPENSSL_malloc(t_size + 1);
				memcpy(t_utf8String, t_memData, t_size);
				t_utf8String[t_size] = '\0';
				BIO_free(t_bio);
			}
			/* OCTET STRING types */
			else if ((t_generalName->type == GEN_IPADD)
					&& (t_generalName->d.iPAddress->length
								== 4)) {
				/* IPv4 */
				t_utf8String = OPENSSL_malloc(16);
				sprintf(t_utf8String, "%d.%d.%d.%d",
					t_generalName->d.iPAddress->data[0],
					t_generalName->d.iPAddress->data[1],
					t_generalName->d.iPAddress->data[2],
					t_generalName->d.iPAddress->data[3]
				);
			}
			else if ((t_generalName->type == GEN_IPADD)
					&& (t_generalName->d.iPAddress->length
								== 16)) {
				/* IPv6 */
				t_utf8String = OPENSSL_malloc(46);
				sprintf(t_utf8String,
					":%X:%X:%X:%X:%X:%X:%X:%X",
					t_generalName->d.iPAddress->data[0] << 8
						| t_generalName->d.iPAddress->data[1],
					t_generalName->d.iPAddress->data[2] << 8
						| t_generalName->d.iPAddress->data[3],
					t_generalName->d.iPAddress->data[4] << 8
						| t_generalName->d.iPAddress->data[5],
					t_generalName->d.iPAddress->data[6] << 8
						| t_generalName->d.iPAddress->data[7],
					t_generalName->d.iPAddress->data[8] << 8
						| t_generalName->d.iPAddress->data[9],
					t_generalName->d.iPAddress->data[10] << 8
						| t_generalName->d.iPAddress->data[11],
					t_generalName->d.iPAddress->data[12] << 8
						| t_generalName->d.iPAddress->data[13],
					t_generalName->d.iPAddress->data[14] << 8
						| t_generalName->d.iPAddress->data[15]
				);
			}

			text* t_text = NULL;
			if (t_utf8String) {
				t_text = palloc(
					strlen(t_utf8String) + VARHDRSZ
				);
				SET_VARSIZE(
					t_text, strlen(t_utf8String) + VARHDRSZ
				);
				memcpy((void*)VARDATA(t_text), t_utf8String,
					strlen(t_utf8String));
				OPENSSL_free(t_utf8String);
			}
			else if ((!PG_GETARG_BOOL(3)) && (t_generalName->type
							== GEN_OTHERNAME)) {
				ASN1_OBJECT* t_oid;
				char t_buffer[80];
				(void)GENERAL_NAME_get0_otherName(
					(GENERAL_NAME*)t_generalName, &t_oid,
					NULL
				);
				OBJ_obj2txt(
					t_buffer, sizeof t_buffer, t_oid, 1
				);
				t_text = palloc(strlen(t_buffer) + VARHDRSZ);
				SET_VARSIZE(
					t_text, strlen(t_buffer) + VARHDRSZ
				);
				memcpy((void*)VARDATA(t_text), t_buffer,
					strlen(t_buffer));
			}

			if (t_text)
				SRF_RETURN_NEXT(
					t_funcCtx, PointerGetDatum(t_text)
				);
		}
	}

	if (t_altNamesCtx->m_genNames)
		GENERAL_NAMES_free(t_altNamesCtx->m_genNames);

	SRF_RETURN_DONE(t_funcCtx);
}


typedef struct tAltNamesRawCtx_st{
	STACK_OF(GENERAL_NAME)* m_genNames;
	int m_index;
	bool* m_nulls;
} tAltNamesRawCtx;



/******************************************************************************
 * x509_altnames_raw()                                                        *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_altnames_raw);
Datum x509_altnames_raw(
	PG_FUNCTION_ARGS
)
{
	tAltNamesRawCtx* t_altNamesRawCtx;
	FuncCallContext* t_funcCtx;
	TupleDesc t_tupleDesc;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;
		MemoryContext t_oldMemoryCtx;
		bytea* t_bytea = NULL;
		const unsigned char* t_pointer = NULL;

		/* Create a function context for cross-call persistence */
		t_funcCtx = SRF_FIRSTCALL_INIT();
		/* Switch to memory context appropriate for multiple function
		  calls */
		t_oldMemoryCtx = MemoryContextSwitchTo(
			t_funcCtx->multi_call_memory_ctx
		);

		/* Allocate memory for our user-defined structure and initialize
		  it */
		t_funcCtx->user_fctx = t_altNamesRawCtx
					= palloc(sizeof(tAltNamesRawCtx));
		memset(t_altNamesRawCtx, '\0', sizeof(tAltNamesRawCtx));

		/* Build a tuple descriptor for our result type */
		if (get_call_result_type(fcinfo, NULL, &t_tupleDesc) != TYPEFUNC_COMPOSITE)
			ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg("function returning record called in context "
					"that cannot accept type record"))
			);

		t_funcCtx->tuple_desc = BlessTupleDesc(t_tupleDesc);
		t_altNamesRawCtx->m_nulls = (bool*)palloc((t_tupleDesc->natts) * sizeof(bool));
		memset(t_altNamesRawCtx->m_nulls, true, (t_tupleDesc->natts) * sizeof(bool));

		/* One-time setup code */
		if (!PG_ARGISNULL(0)) {
			t_bytea = PG_GETARG_BYTEA_P(0);
			t_pointer = (unsigned char*)VARDATA(t_bytea);
			t_x509 = d2i_X509(
				NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ
			);
		}
		if (t_x509) {
			t_altNamesRawCtx->m_genNames = X509_get_ext_d2i(
				t_x509,
				PG_GETARG_BOOL(1) ? NID_subject_alt_name
						: NID_issuer_alt_name,
				NULL, NULL
			);

			X509_free(t_x509);
		}

		MemoryContextSwitchTo(t_oldMemoryCtx);
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_altNamesRawCtx = t_funcCtx->user_fctx;

	if (t_altNamesRawCtx->m_genNames) {
		while (t_altNamesRawCtx->m_index < sk_GENERAL_NAME_num(
						t_altNamesRawCtx->m_genNames)) {
			char* t_utf8String = NULL;
			int t_length = -1;
			ASN1_OBJECT* t_oid = NULL;

			/* Pull out this GeneralName */
			const GENERAL_NAME* t_generalName
				= sk_GENERAL_NAME_value(
					t_altNamesRawCtx->m_genNames,
					t_altNamesRawCtx->m_index
				);

			/* Increment the counter while we can */
			t_altNamesRawCtx->m_index++;

			/* IA5String types */
			if ((t_generalName->type == GEN_EMAIL)
					|| (t_generalName->type == GEN_DNS)
					|| (t_generalName->type == GEN_URI))
				t_length = ASN1_STRING_to_UTF8(
					(unsigned char**)&t_utf8String,
					t_generalName->d.ia5
				);
			/* OCTET STRING types */
			else if (t_generalName->type == GEN_IPADD) {
				if (t_generalName->d.iPAddress->length == 4) {
					/* IPv4 */
					t_utf8String = OPENSSL_malloc(16);
					t_length = sprintf(
						t_utf8String, "%d.%d.%d.%d",
						t_generalName->d.iPAddress->data[0],
						t_generalName->d.iPAddress->data[1],
						t_generalName->d.iPAddress->data[2],
						t_generalName->d.iPAddress->data[3]
					);
				}
				else if (t_generalName->d.iPAddress->length == 16) {
					/* IPv6 */
					t_utf8String = OPENSSL_malloc(46);
					t_length = sprintf(
						t_utf8String, ":%X:%X:%X:%X:%X:%X:%X:%X",
						t_generalName->d.iPAddress->data[0] << 8
							| t_generalName->d.iPAddress->data[1],
						t_generalName->d.iPAddress->data[2] << 8
							| t_generalName->d.iPAddress->data[3],
						t_generalName->d.iPAddress->data[4] << 8
							| t_generalName->d.iPAddress->data[5],
						t_generalName->d.iPAddress->data[6] << 8
							| t_generalName->d.iPAddress->data[7],
						t_generalName->d.iPAddress->data[8] << 8
							| t_generalName->d.iPAddress->data[9],
						t_generalName->d.iPAddress->data[10] << 8
							| t_generalName->d.iPAddress->data[11],
						t_generalName->d.iPAddress->data[12] << 8
							| t_generalName->d.iPAddress->data[13],
						t_generalName->d.iPAddress->data[14] << 8
							| t_generalName->d.iPAddress->data[15]
					);
				}
				else {
					/* Invalid IP address */
					t_length = 17;
					t_utf8String = OPENSSL_malloc(18);
					memcpy(t_utf8String, "Invalid iPAddress", 18);
				}
			}
			/* OtherName UTF8String types */
			else if (t_generalName->type == GEN_OTHERNAME) {
				ASN1_TYPE* t_asn1Type;
				(void)GENERAL_NAME_get0_otherName(
					(GENERAL_NAME*)t_generalName, &t_oid, &t_asn1Type
				);
				t_length = ASN1_STRING_to_UTF8(
					(unsigned char**)&t_utf8String,
					t_asn1Type->value.asn1_string
				);
			}

			if ((t_length >= 0) && t_utf8String) {
				bytea* t_rawValue = palloc(t_length + VARHDRSZ);
				SET_VARSIZE(t_rawValue, t_length + VARHDRSZ);
				memcpy((void*)VARDATA(t_rawValue), t_utf8String,
					t_length);
				OPENSSL_free(t_utf8String);

				Datum t_datum[3];
				t_datum[0] = Int32GetDatum(t_generalName->type);
				t_altNamesRawCtx->m_nulls[0] = false;
				t_datum[1] = PointerGetDatum(t_rawValue);
				t_altNamesRawCtx->m_nulls[1] = false;

				if (t_oid) {
					char t_oid_numerical[80] = "";
					OBJ_obj2txt(t_oid_numerical, sizeof(t_oid_numerical), t_oid, 1);
					text* t_oidText = palloc(strlen(t_oid_numerical) + VARHDRSZ);
					SET_VARSIZE(t_oidText, strlen(t_oid_numerical) + VARHDRSZ);
					memcpy((void*)VARDATA(t_oidText), t_oid_numerical, strlen(t_oid_numerical));
					t_datum[2] = PointerGetDatum(t_oidText);
					t_altNamesRawCtx->m_nulls[2] = false;
				}
				else
					t_altNamesRawCtx->m_nulls[2] = true;

				Datum t_compositeDatum;
				HeapTuple t_heapTuple = heap_form_tuple(
					t_funcCtx->tuple_desc, t_datum,
					t_altNamesRawCtx->m_nulls
				);
				if (t_heapTuple) {
					t_compositeDatum = HeapTupleGetDatum(t_heapTuple);
					if (t_compositeDatum)
						SRF_RETURN_NEXT(t_funcCtx, t_compositeDatum);
				}
			}
		}
	}

	if (t_altNamesRawCtx->m_genNames)
		GENERAL_NAMES_free(t_altNamesRawCtx->m_genNames);
	if (t_altNamesRawCtx->m_nulls)
		pfree(t_altNamesRawCtx->m_nulls);

	SRF_RETURN_DONE(t_funcCtx);
}


typedef struct tCRLDistributionPointsCtx_st{
	CRL_DIST_POINTS* m_cRLDistributionPoints;
	int m_index;
	int m_index2;
} tCRLDistributionPointsCtx;


/******************************************************************************
 * x509_crldistributionpoints()                                               *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_crldistributionpoints);
Datum x509_crldistributionpoints(
	PG_FUNCTION_ARGS
)
{
	DIST_POINT* t_distPoint;
	tCRLDistributionPointsCtx* t_cRLDistributionPointsCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;
		MemoryContext t_oldMemoryCtx;
		bytea* t_bytea = NULL;
		const unsigned char* t_pointer = NULL;

		/* Create a function context for cross-call persistence */
		t_funcCtx = SRF_FIRSTCALL_INIT();
		/* Switch to memory context appropriate for multiple function
		  calls */
		t_oldMemoryCtx = MemoryContextSwitchTo(
			t_funcCtx->multi_call_memory_ctx
		);

		/* Allocate memory for our user-defined structure and initialize
		  it */
		t_funcCtx->user_fctx = t_cRLDistributionPointsCtx
				= palloc(sizeof(tCRLDistributionPointsCtx));
		memset(t_cRLDistributionPointsCtx, '\0',
			sizeof(tCRLDistributionPointsCtx));

		/* One-time setup code */
		if (!PG_ARGISNULL(0)) {
			t_bytea = PG_GETARG_BYTEA_P(0);
			t_pointer = (unsigned char*)VARDATA(t_bytea);
			t_x509 = d2i_X509(
				NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ
			);
		}
		if (t_x509) {
			t_cRLDistributionPointsCtx->m_cRLDistributionPoints
				= X509_get_ext_d2i(
					t_x509, NID_crl_distribution_points,
					NULL, NULL
				);
			X509_free(t_x509);
		}

		MemoryContextSwitchTo(t_oldMemoryCtx);
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_cRLDistributionPointsCtx = t_funcCtx->user_fctx;

	if (t_cRLDistributionPointsCtx->m_cRLDistributionPoints) {
		while (t_cRLDistributionPointsCtx->m_index < sk_DIST_POINT_num(t_cRLDistributionPointsCtx->m_cRLDistributionPoints)) {
			t_distPoint = sk_DIST_POINT_value(
				t_cRLDistributionPointsCtx->m_cRLDistributionPoints,
				t_cRLDistributionPointsCtx->m_index
			);
			if ((t_distPoint->distpoint == NULL)
					|| (t_distPoint->distpoint->type != 0)	/* We'll only consider distributionPoint->fullName */
					|| (t_cRLDistributionPointsCtx->m_index2 >= sk_GENERAL_NAME_num(t_distPoint->distpoint->name.fullname))) {
				/* If we've processed all of the GeneralNames in this DistributionPoint, move on to the next one */
				t_cRLDistributionPointsCtx->m_index++;
				t_cRLDistributionPointsCtx->m_index2 = 0;
				continue;
			}

			char* t_utf8String = NULL;
			const GENERAL_NAME* t_generalName = sk_GENERAL_NAME_value(
				t_distPoint->distpoint->name.fullname,
				t_cRLDistributionPointsCtx->m_index2++
			);

			/* Check if this GeneralName is of interest */
			if (t_generalName->type == GEN_URI)
				(void)ASN1_STRING_to_UTF8(
					(unsigned char**)&t_utf8String,
					t_generalName->d.ia5
				);

			if (t_utf8String) {
				text* t_text = palloc(
					strlen(t_utf8String) + VARHDRSZ
				);
				SET_VARSIZE(
					t_text, strlen(t_utf8String) + VARHDRSZ
				);
				memcpy((void*)VARDATA(t_text), t_utf8String,
					strlen(t_utf8String));
				OPENSSL_free(t_utf8String);
				SRF_RETURN_NEXT(
					t_funcCtx, PointerGetDatum(t_text)
				);
			}
		}
		CRL_DIST_POINTS_free(
			t_cRLDistributionPointsCtx->m_cRLDistributionPoints
		);
	}

	SRF_RETURN_DONE(t_funcCtx);
}


typedef struct tAuthorityInfoAccessCtx_st{
	AUTHORITY_INFO_ACCESS* m_authorityInfoAccess;
	int m_index;
	int m_type;
} tAuthorityInfoAccessCtx;


/******************************************************************************
 * x509_authorityinfoaccess()                                                 *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_authorityinfoaccess);
Datum x509_authorityinfoaccess(
	PG_FUNCTION_ARGS
)
{
	ACCESS_DESCRIPTION* t_accessDescription;
	tAuthorityInfoAccessCtx* t_authorityInfoAccessCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;
		MemoryContext t_oldMemoryCtx;
		bytea* t_bytea = NULL;
		const unsigned char* t_pointer = NULL;

		/* Create a function context for cross-call persistence */
		t_funcCtx = SRF_FIRSTCALL_INIT();
		/* Switch to memory context appropriate for multiple function
		  calls */
		t_oldMemoryCtx = MemoryContextSwitchTo(
			t_funcCtx->multi_call_memory_ctx
		);

		/* Allocate memory for our user-defined structure and initialize
		  it */
		t_funcCtx->user_fctx = t_authorityInfoAccessCtx
				= palloc(sizeof(tAuthorityInfoAccessCtx));
		memset(t_authorityInfoAccessCtx, '\0',
			sizeof(tAuthorityInfoAccessCtx));

		/* One-time setup code */
		if (!PG_ARGISNULL(0)) {
			t_bytea = PG_GETARG_BYTEA_P(0);
			t_pointer = (unsigned char*)VARDATA(t_bytea);
			t_x509 = d2i_X509(
				NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ
			);
		}
		if (t_x509) {
			t_authorityInfoAccessCtx->m_authorityInfoAccess =
				X509_get_ext_d2i(
					t_x509, NID_info_access, NULL, NULL
				);
			X509_free(t_x509);
		}

		t_authorityInfoAccessCtx->m_type = 0;
		if (!PG_ARGISNULL(1)) {
			if (PG_GETARG_INT32(1) == 1)
				t_authorityInfoAccessCtx->m_type = NID_ad_OCSP;
			else if (PG_GETARG_INT32(1) == 2)
				t_authorityInfoAccessCtx->m_type
							= NID_ad_ca_issuers;
			else
				t_authorityInfoAccessCtx->m_type = -1;
		}

		MemoryContextSwitchTo(t_oldMemoryCtx);
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_authorityInfoAccessCtx = t_funcCtx->user_fctx;

	if (t_authorityInfoAccessCtx->m_type == -1)
		;
	else if (t_authorityInfoAccessCtx->m_authorityInfoAccess) {
		while (t_authorityInfoAccessCtx->m_index
				< sk_ACCESS_DESCRIPTION_num(
					t_authorityInfoAccessCtx->
						m_authorityInfoAccess)) {
			t_accessDescription = sk_ACCESS_DESCRIPTION_value(
				t_authorityInfoAccessCtx->m_authorityInfoAccess,
				t_authorityInfoAccessCtx->m_index++
			);

			char* t_utf8String = NULL;

			/* Check if this GeneralName is of interest */
			if (!t_authorityInfoAccessCtx->m_type)
				;
			else if (OBJ_obj2nid(t_accessDescription->method)
					!= t_authorityInfoAccessCtx->m_type)
				continue;

			if (t_accessDescription->location->type != GEN_URI)
				continue;

			(void)ASN1_STRING_to_UTF8(
				(unsigned char**)&t_utf8String,
				t_accessDescription->location->d.ia5
			);

			if (t_utf8String) {
				text* t_text = palloc(
					strlen(t_utf8String) + VARHDRSZ
				);
				SET_VARSIZE(
					t_text, strlen(t_utf8String) + VARHDRSZ
				);
				memcpy((void*)VARDATA(t_text), t_utf8String,
					strlen(t_utf8String));
				OPENSSL_free(t_utf8String);
				SRF_RETURN_NEXT(
					t_funcCtx, PointerGetDatum(t_text)
				);
			}
		}
		AUTHORITY_INFO_ACCESS_free(
			t_authorityInfoAccessCtx->m_authorityInfoAccess
		);
	}

	SRF_RETURN_DONE(t_funcCtx);
}


/******************************************************************************
 * x509_print()                                                               *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_print);
Datum x509_print(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509) {
		t_text = palloc(strlen(g_error) + VARHDRSZ);
		SET_VARSIZE(t_text, strlen(g_error) + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), g_error, strlen(g_error));
	}
	else {
		/* Create a memory BIO and tell it to make sure that it clears
		  up all its memory when we close it later */
		char* t_string = NULL;
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

		/* Get a pointer to the string and its size */
		int t_size = BIO_get_mem_data(t_bio, &t_string);

		/* Copy the string to the return parameter */
		t_text = palloc(t_size + VARHDRSZ);
		SET_VARSIZE(t_text, t_size + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), t_string, t_size);

		/* Free stuff */
		BIO_free(t_bio);
		X509_free(t_x509);
	}

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_verify()                                                              *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_verify);
Datum x509_verify(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	bytea* t_bytea = NULL;
	const unsigned char* t_pointer = NULL;
	bool t_bResult = false;

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (t_x509) {
		t_bytea = PG_GETARG_BYTEA_P(1);
		t_pointer = (unsigned char*)VARDATA(t_bytea);
		t_publicKey = d2i_PUBKEY(
			NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ
		);
		if (t_publicKey) {
			if (X509_verify(t_x509, t_publicKey) == 1)
				t_bResult = true;
			EVP_PKEY_free(t_publicKey);
		}
		X509_free(t_x509);
	}

	PG_RETURN_BOOL(t_bResult);
}


/******************************************************************************
 * x509_anynameswithnuls()                                                    *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_anynameswithnuls);
Datum x509_anynameswithnuls(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	X509_NAME* t_name;
	X509_NAME_ENTRY* t_nameEntry;
	STACK_OF(GENERAL_NAME)* t_genNames;
	const GENERAL_NAME* t_generalName;
	bytea* t_bytea = NULL;
	const unsigned char* t_pointer = NULL;
	int l_indexNo;
	bool t_bResult = false;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		PG_RETURN_NULL();

	t_name = X509_get_subject_name(t_x509);
	if (t_name) {
		for (l_indexNo = 0; l_indexNo < X509_NAME_entry_count(t_name);
								l_indexNo++) {
			char* t_utf8String = NULL;
			t_nameEntry = X509_NAME_get_entry(t_name, l_indexNo);
			int t_length = ASN1_STRING_to_UTF8(
				(unsigned char**)&t_utf8String,
				X509_NAME_ENTRY_get_data(t_nameEntry)
			);
			if (t_utf8String) {
				if (t_length != strlen(t_utf8String))
					t_bResult = true;
				OPENSSL_free(t_utf8String);
			}
		}
	}

	t_name = X509_get_issuer_name(t_x509);
	if (t_name) {
		for (l_indexNo = 0; l_indexNo < X509_NAME_entry_count(t_name);
								l_indexNo++) {
			char* t_utf8String = NULL;
			t_nameEntry = X509_NAME_get_entry(t_name, l_indexNo);
			int t_length = ASN1_STRING_to_UTF8(
				(unsigned char**)&t_utf8String,
				X509_NAME_ENTRY_get_data(t_nameEntry)
			);
			if (t_utf8String) {
				if (t_length != strlen(t_utf8String))
					t_bResult = true;
				OPENSSL_free(t_utf8String);
			}
		}
	}

	t_genNames = X509_get_ext_d2i(t_x509, NID_subject_alt_name, NULL, NULL);
	if (t_genNames) {
		for (l_indexNo = 0; l_indexNo < sk_GENERAL_NAME_num(t_genNames);
								l_indexNo++) {
			char* t_utf8String = NULL;
			t_generalName = sk_GENERAL_NAME_value(
				t_genNames, l_indexNo
			);
			if ((t_generalName->type == GEN_EMAIL)
					|| (t_generalName->type == GEN_DNS)
					|| (t_generalName->type == GEN_URI)) {
				int t_length = ASN1_STRING_to_UTF8(
					(unsigned char**)&t_utf8String,
					t_generalName->d.ia5
				);
				if (t_utf8String) {
					if (t_length != strlen(t_utf8String))
						t_bResult = true;
					OPENSSL_free(t_utf8String);
				}
			}
		}
		GENERAL_NAMES_free(t_genNames);
	}

	t_genNames = X509_get_ext_d2i(t_x509, NID_issuer_alt_name, NULL, NULL);
	if (t_genNames) {
		for (l_indexNo = 0; l_indexNo < sk_GENERAL_NAME_num(t_genNames);
								l_indexNo++) {
			char* t_utf8String = NULL;
			t_generalName = sk_GENERAL_NAME_value(
				t_genNames, l_indexNo
			);
			if ((t_generalName->type == GEN_EMAIL)
					|| (t_generalName->type == GEN_DNS)
					|| (t_generalName->type == GEN_URI)) {
				int t_length = ASN1_STRING_to_UTF8(
					(unsigned char**)&t_utf8String,
					t_generalName->d.ia5
				);
				if (t_utf8String) {
					if (t_length != strlen(t_utf8String))
						t_bResult = true;
					OPENSSL_free(t_utf8String);
				}
			}
		}
		GENERAL_NAMES_free(t_genNames);
	}

	X509_free(t_x509);

	PG_RETURN_BOOL(t_bResult);
}


typedef struct tExtensionsCtx_st{
	X509* m_x509;
	const STACK_OF(X509_EXTENSION)* m_extensions;
	int m_index;
} tExtensionsCtx;


/******************************************************************************
 * X509_extensions()                                                          *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_extensions);
Datum x509_extensions(
	PG_FUNCTION_ARGS
)
{
	X509_EXTENSION* t_extension;
	ASN1_OBJECT* t_extensionOID;
	tExtensionsCtx* t_extensionsCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		MemoryContext t_oldMemoryCtx;
		bytea* t_bytea = NULL;
		const unsigned char* t_pointer = NULL;

		/* Create a function context for cross-call persistence */
		t_funcCtx = SRF_FIRSTCALL_INIT();
		/* Switch to memory context appropriate for multiple function
		  calls */
		t_oldMemoryCtx = MemoryContextSwitchTo(
			t_funcCtx->multi_call_memory_ctx
		);

		/* Allocate memory for our user-defined structure and initialize
		  it */
		t_funcCtx->user_fctx = t_extensionsCtx
					= palloc(sizeof(tExtensionsCtx));
		memset(t_extensionsCtx, '\0', sizeof(tExtensionsCtx));

		/* One-time setup code */
		if (!PG_ARGISNULL(0)) {
			t_bytea = PG_GETARG_BYTEA_P(0);
			t_pointer = (unsigned char*)VARDATA(t_bytea);
			t_extensionsCtx->m_x509 = d2i_X509(
				NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ
			);
		}
		if (t_extensionsCtx->m_x509) {
			t_extensionsCtx->m_extensions = X509_get0_extensions(
				t_extensionsCtx->m_x509
			);
		}

		MemoryContextSwitchTo(t_oldMemoryCtx);
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_extensionsCtx = t_funcCtx->user_fctx;

	if (t_extensionsCtx->m_extensions) {
		while (t_extensionsCtx->m_index < sk_X509_EXTENSION_num(
					t_extensionsCtx->m_extensions)) {
			t_extension = sk_X509_EXTENSION_value(
				t_extensionsCtx->m_extensions,
				t_extensionsCtx->m_index++
			);
			t_extensionOID = X509_EXTENSION_get_object(t_extension);

			text* t_text = palloc(MAX_OIDSTRING_LENGTH + VARHDRSZ);

			(void)OBJ_obj2txt(
				VARDATA(t_text), MAX_OIDSTRING_LENGTH,
				t_extensionOID, PG_GETARG_BOOL(1) ? 1 : 0
			);

			SET_VARSIZE(t_text, strlen(VARDATA(t_text)) + VARHDRSZ);

			SRF_RETURN_NEXT(
				t_funcCtx, PointerGetDatum(t_text)
			);
		}
	}

	if (t_extensionsCtx->m_x509)
		X509_free(t_extensionsCtx->m_x509);

	SRF_RETURN_DONE(t_funcCtx);
}


/******************************************************************************
 * X509_hasextension()                                                        *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_hasextension);
Datum x509_hasextension(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	ASN1_OBJECT* t_extnObj = NULL;
	bytea* t_bytea = PG_GETARG_BYTEA_P(0);
	text* t_text = PG_GETARG_TEXT_P(1);
	const unsigned char* t_pointer = (unsigned char*)VARDATA(t_bytea);
	char* t_extnTxt = NULL;
	bool t_bResult = false;

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		PG_RETURN_NULL();

	if ((t_x509 = d2i_X509(NULL, &t_pointer,
				VARSIZE(t_bytea) - VARHDRSZ)) == NULL)
		PG_RETURN_NULL();

	/* NUL-terminate the OID string */
	if ((t_extnTxt = calloc(VARSIZE(t_text) - VARHDRSZ + 1, 1)) == NULL)
		goto label_done;
	strncpy(t_extnTxt, VARDATA(t_text), VARSIZE(t_text) - VARHDRSZ);
	if ((t_extnObj = OBJ_txt2obj(t_extnTxt, 0)) == NULL)
		goto label_done;

	int t_index = X509_get_ext_by_OBJ(t_x509, t_extnObj, -1);
	t_bResult = (t_index != -1);
	if (t_bResult && (!PG_ARGISNULL(2))) {
		t_bResult = (
			PG_GETARG_BOOL(2)
				== X509_EXTENSION_get_critical(X509_get_ext(t_x509, t_index))
		);
	}

label_done:
	if (t_extnObj)
		ASN1_OBJECT_free(t_extnObj);
	if (t_extnTxt)
		free(t_extnTxt);
	X509_free(t_x509);

	PG_RETURN_BOOL(t_bResult);
}


/******************************************************************************
 * x509_tbscert_strip_ct_ext()                                                *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_tbscert_strip_ct_ext);
Datum x509_tbscert_strip_ct_ext(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	bytea* t_bytea = PG_GETARG_BYTEA_P(0);
	bytea* t_derTBSCert = NULL;
	const unsigned char* t_pointer = (unsigned char*)VARDATA(t_bytea);
	unsigned char* t_pointer2 = NULL;
	int t_extPos;
	int t_derTBSCert_size;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();

	if ((t_x509 = d2i_X509(NULL, &t_pointer,
				VARSIZE(t_bytea) - VARHDRSZ)) == NULL)
		PG_RETURN_NULL();

	if ((t_extPos = X509_get_ext_by_NID(t_x509, NID_ct_precert_scts, -1)) != -1)
		X509_EXTENSION_free(X509_delete_ext(t_x509, t_extPos));
	if ((t_extPos = X509_get_ext_by_NID(t_x509, NID_ct_precert_poison, -1)) != -1)
		X509_EXTENSION_free(X509_delete_ext(t_x509, t_extPos));

	if ((t_derTBSCert_size = i2d_re_X509_tbs(t_x509, NULL)) < 0)
		goto label_error;
	t_derTBSCert = palloc(VARHDRSZ + t_derTBSCert_size);
	SET_VARSIZE(t_derTBSCert, VARHDRSZ + t_derTBSCert_size);
	t_pointer2 = (unsigned char*)VARDATA(t_derTBSCert);
	if (i2d_re_X509_tbs(t_x509, &t_pointer2) < 0)
		goto label_error;

	X509_free(t_x509);

	PG_RETURN_BYTEA_P(t_derTBSCert);

label_error:
	X509_free(t_x509);

	PG_RETURN_NULL();
}


/******************************************************************************
 * BN_bitand_is_zero()                                                        *
 ******************************************************************************/
static int BN_bitand_is_zero(
	const BIGNUM* a,
	const BIGNUM* b
)
{
	int i;

	for (i = 0; i < BN_num_bits(a); i++)
		if (BN_is_bit_set(a, i) && BN_is_bit_set(b, i))
			return 0;

	return 1;
}


/******************************************************************************
 * x509_hasrocafingerprint()                                                  *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_hasrocafingerprint);
Datum x509_hasrocafingerprint(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	const BIGNUM* t_modulus = NULL;
	BN_CTX* t_ctx = BN_CTX_new();
	BN_CTX_start(t_ctx);
	BIGNUM* t_prime = BN_CTX_get(t_ctx);
	BIGNUM* t_temp = BN_CTX_get(t_ctx);
	bytea* t_bytea = NULL;
	const unsigned char* t_pointer = NULL;
	bool t_bResult = false;
	bool t_bResultIsNULL = true;
	int i;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		PG_RETURN_NULL();

	t_publicKey = X509_get_pubkey(t_x509);
	if ((!t_publicKey) || !((EVP_PKEY_id(t_publicKey) == EVP_PKEY_RSA)
				|| (EVP_PKEY_id(t_publicKey) == EVP_PKEY_RSA2)))
		goto label_return;

	RSA_get0_key(EVP_PKEY_get0_RSA(t_publicKey), &t_modulus, NULL, NULL);
	if (!t_modulus)
		goto label_return;

	for (i = 0; i < ROCA_PRINTS_LENGTH; i++) {
		BN_set_word(t_prime, g_primes[i]);
		if (!BN_mod(t_temp, t_modulus, t_prime, t_ctx))
			goto label_return;
		if (!BN_lshift(t_temp, BN_value_one(), BN_get_word(t_temp)))
			goto label_return;
		if (BN_bitand_is_zero(t_temp, g_prints[i])) {
			t_bResultIsNULL = false;
			goto label_return;
		}
	}
	t_bResultIsNULL = false;
	t_bResult = true;

label_return:
	BN_CTX_end(t_ctx);
	BN_CTX_free(t_ctx);

	if (t_publicKey)
		EVP_PKEY_free(t_publicKey);
	if (t_x509)
		X509_free(t_x509);

	if (t_bResultIsNULL)
		PG_RETURN_NULL();
	else
		PG_RETURN_BOOL(t_bResult);
}


/******************************************************************************
 * BN_isqrt()                                                                 *
 *   The OpenSSL BN library doesn't have a sqrt or isqrt function.  This      *
 * function is adapted from BoringSSL's BN_sqrt.                              *
 ******************************************************************************/
int BN_isqrt(
	BIGNUM *out_sqrt,
	const BIGNUM *in,
	BN_CTX *ctx
)
{
	BIGNUM *estimate, *tmp, *delta, *last_delta, *tmp2;
	int ok = 0, last_delta_valid = 0;

	if (BN_is_negative(in)) {
		return 0;
	}
	if (BN_is_zero(in)) {
		BN_zero(out_sqrt);
		return 1;
	}

	BN_CTX_start(ctx);
	if (out_sqrt == in) {
		estimate = BN_CTX_get(ctx);
	} else {
		estimate = out_sqrt;
	}
	tmp = BN_CTX_get(ctx);
	last_delta = BN_CTX_get(ctx);
	delta = BN_CTX_get(ctx);
	if (estimate == NULL || tmp == NULL || last_delta == NULL || delta == NULL) {
		goto err;
	}

	// We estimate that the square root of an n-bit number is 2^{n/2}.
	if (!BN_lshift(estimate, BN_value_one(), BN_num_bits(in)/2)) {
		goto err;
	}

	// This is Newton's method for finding a root of the equation |estimate|^2 -
	// |in| = 0.
	for (;;) {
		// |estimate| = 1/2 * (|estimate| + |in|/|estimate|)
		if (!BN_div(tmp, NULL, in, estimate, ctx) ||
				!BN_add(tmp, tmp, estimate) ||
				!BN_rshift1(estimate, tmp) ||
				// |tmp| = |estimate|^2
				!BN_sqr(tmp, estimate, ctx) ||
				// |delta| = |in| - |tmp|
				!BN_sub(delta, in, tmp)) {
			goto err;
		}

		BN_set_negative(delta, 0);
		// The difference between |in| and |estimate| squared is required to always
		// decrease. This ensures that the loop always terminates, but I don't have
		// a proof that it always finds the square root for a given square.
		if (last_delta_valid && BN_cmp(delta, last_delta) >= 0) {
			break;
		}

		last_delta_valid = 1;

		tmp2 = last_delta;
		last_delta = delta;
		delta = tmp2;
	}

	ok = 1;

err:
	if (ok && out_sqrt == in && !BN_copy(out_sqrt, estimate)) {
		ok = 0;
	}
	BN_CTX_end(ctx);
	return ok;
}


/******************************************************************************
 * BN_is_square()                                                             *
 ******************************************************************************/
int BN_is_square(
	const BIGNUM* bn,
	BN_CTX *ctx
)
{
	BN_CTX_start(ctx);
	BIGNUM* tmp = BN_CTX_get(ctx);
	int t_result = 0;

	if (!BN_isqrt(tmp, bn, ctx) || !BN_sqr(tmp, tmp, ctx))
		goto label_return;

	if (!BN_cmp(bn, tmp))
		t_result = 1;

label_return:
	BN_CTX_end(ctx);
	return t_result;
}


/******************************************************************************
 * x509_hasrocafingerprint()                                                  *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_hascloseprimes);
Datum x509_hascloseprimes(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	const BIGNUM* t_modulus = NULL;
	BN_CTX* t_ctx = BN_CTX_new();
	BN_CTX_start(t_ctx);
	BIGNUM* a = BN_CTX_get(t_ctx);
	BIGNUM* a_squared_minus_n = BN_CTX_get(t_ctx);
	bytea* t_bytea = NULL;
	const unsigned char* t_pointer = NULL;
	bool t_bResult = false;
	bool t_bResultIsNULL = true;
	int i;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		PG_RETURN_NULL();

	t_publicKey = X509_get_pubkey(t_x509);
	if ((!t_publicKey) || !((EVP_PKEY_id(t_publicKey) == EVP_PKEY_RSA)
				|| (EVP_PKEY_id(t_publicKey) == EVP_PKEY_RSA2)))
		goto label_return;

	RSA_get0_key(EVP_PKEY_get0_RSA(t_publicKey), &t_modulus, NULL, NULL);
	if (!t_modulus)
		goto label_return;

	if (BN_is_square(t_modulus, t_ctx) == 1			// Modulus is a perfect square.
			|| !BN_isqrt(a, t_modulus, t_ctx))	// Error.
		goto label_return;

	for (i = 0; i < PG_GETARG_INT16(1); i++, BN_add(a, a, BN_value_one())) {
		if (!BN_sqr(a_squared_minus_n, a, t_ctx) || !BN_sub(a_squared_minus_n, a_squared_minus_n, t_modulus))
			goto label_return;			// Error.
		if (BN_is_square(a_squared_minus_n, t_ctx) == 1) {
			t_bResult = true;			// Factored.
			t_bResultIsNULL = false;
			goto label_return;
		}
	}

	t_bResultIsNULL = false;				// Not factored.

label_return:
	BN_CTX_end(t_ctx);
	BN_CTX_free(t_ctx);

	if (t_publicKey)
		EVP_PKEY_free(t_publicKey);
	if (t_x509)
		X509_free(t_x509);

	if (t_bResultIsNULL)
		PG_RETURN_NULL();
	else
		PG_RETURN_BOOL(t_bResult);
}


/******************************************************************************
 * ocspresponse_print()                                                       *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(ocspresponse_print);
Datum ocspresponse_print(
	PG_FUNCTION_ARGS
)
{
	OCSP_RESPONSE* t_ocspResponse = NULL;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_ocspResponse = d2i_OCSP_RESPONSE(
		NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ
	);
	if (!t_ocspResponse) {
		t_text = palloc(strlen(g_error) + VARHDRSZ);
		SET_VARSIZE(t_text, strlen(g_error) + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), g_error, strlen(g_error));
	}
	else {
		/* Create a memory BIO and tell it to make sure that it clears
		  up all its memory when we close it later */
		char* t_string = NULL;
		BIO* t_bio = BIO_new(BIO_s_mem());
		(void)BIO_set_close(t_bio, BIO_CLOSE);

		/* "Print" the OCSP response */
		(void)OCSP_RESPONSE_print(
			t_bio, t_ocspResponse,
			PG_ARGISNULL(1) ? 0 : PG_GETARG_INT32(2)
		);

		/* Get a pointer to the string and its size */
		int t_size = BIO_get_mem_data(t_bio, &t_string);

		/* Copy the string to the return parameter */
		t_text = palloc(t_size + VARHDRSZ);
		SET_VARSIZE(t_text, t_size + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), t_string, t_size);

		/* Free stuff */
		BIO_free(t_bio);
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
PG_FUNCTION_INFO_V1(urlencode);
Datum urlencode(
	PG_FUNCTION_ARGS
)
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
PG_FUNCTION_INFO_V1(urldecode);
Datum urldecode(
	PG_FUNCTION_ARGS
)
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
PG_FUNCTION_INFO_V1(x509pq_opensslversion);
Datum x509pq_opensslversion(
	PG_FUNCTION_ARGS
)
{
	size_t t_len = strlen(SSLeay_version(SSLEAY_VERSION));
	text* t_text = palloc(t_len + VARHDRSZ);
	SET_VARSIZE(t_text, t_len + VARHDRSZ);
	memcpy((void*)VARDATA(t_text), SSLeay_version(SSLEAY_VERSION), t_len);
	PG_RETURN_TEXT_P(t_text);
}

/******************************************************************************
 * x509_version()
 *	This function returns the X509 version of the certificate 
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_version);
Datum x509_version(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	bytea* t_bytea = NULL;
	int t_iResult;
	const unsigned char* t_pointer = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		PG_RETURN_NULL();

	t_iResult = X509_get_version(t_x509);

	X509_free(t_x509);

	if (!t_iResult)
		PG_RETURN_NULL();

	PG_RETURN_INT32(t_iResult+1);
}

/******************************************************************************
 * x509_bcca()  
 * This function returns if the certificate contains the basic contraints extension with a value of CA = true
 * true = BC extension exists, CA is true
 * false = BC extension exists, CA is false
 * NULL = BC extension doesn't exist
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_bcca);
Datum x509_bcca(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	bytea* t_bytea = NULL;
	BASIC_CONSTRAINTS* t_basicConstraints;
	const unsigned char* t_pointer = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509)
		PG_RETURN_NULL();

	t_basicConstraints = X509_get_ext_d2i(
		t_x509, NID_basic_constraints, NULL, NULL
	);

	X509_free(t_x509);
	
	if(!t_basicConstraints)
		PG_RETURN_NULL();

	PG_RETURN_BOOL(t_basicConstraints->ca);
	
}

/******************************************************************************
 * x509_keyusage()                                                       *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_keyusage);
Datum x509_keyusage(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	ASN1_BIT_STRING* t_keyUsage;
	bytea* t_bytea = NULL;
	const unsigned char* t_pointer = NULL;
	unsigned long t_keyUsageBits;
	

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (t_x509) {
	
		t_keyUsage = X509_get_ext_d2i(
			t_x509, NID_key_usage, NULL, NULL
		);
		if (t_keyUsage) {
			if (t_keyUsage->length > 0) {
				t_keyUsageBits = t_keyUsage->data[0];
				if (t_keyUsage->length > 1)
					t_keyUsageBits |=
						t_keyUsage->data[1] << 8;
			}
			else
				t_keyUsageBits = 0;
			ASN1_BIT_STRING_free(t_keyUsage);

		}

	label_done:
		X509_free(t_x509);
	}

	PG_RETURN_INT32(t_keyUsageBits);
}

/******************************************************************************
 * x509_printkeyusage()                                                       *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_printkeyusage);
Datum x509_printkeyusage(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	X509_EXTENSION* t_extension;
	BIO* t_bio;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;
	char* t_string = NULL;
	long t_size;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_P(0);
	t_pointer = (unsigned char*)VARDATA(t_bytea);
	t_x509 = d2i_X509(NULL, &t_pointer, VARSIZE(t_bytea) - VARHDRSZ);
	if (!t_x509) {
		t_text = palloc(strlen(g_error) + VARHDRSZ);
		SET_VARSIZE(t_text, strlen(g_error) + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), g_error, strlen(g_error));
	}
	else {
		/* Create a memory BIO and tell it to make sure that it clears
		  up all its memory when we close it later */
		t_bio = BIO_new(BIO_s_mem());
		(void)BIO_set_close(t_bio, BIO_CLOSE);

		t_extension = X509_get_ext(t_x509, X509_get_ext_by_NID(t_x509, NID_key_usage, -1));

		(void)X509V3_EXT_print(
			t_bio, t_extension, NULL, NULL
		);

		/* Get a pointer to the Issuer Name string and its size */
		t_size = BIO_get_mem_data(t_bio, &t_string);

		/* Copy the Issuer Name string to the return parameter */
		t_text = palloc(t_size + VARHDRSZ);
		SET_VARSIZE(t_text, t_size + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), t_string, t_size);

		/* Free stuff */
		BIO_free(t_bio);
		X509_free(t_x509);
	}

	PG_RETURN_TEXT_P(t_text);
}

/******************************************************************************
 * X509_hasextension_critical()                                                
 * Returns 'true' if extension found and is critical, 'false' if found and
 * not critical, and 'NULL' if not found
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509_hasextension_critical);
Datum x509_hasextension_critical(
	PG_FUNCTION_ARGS
)
{
	X509* t_x509 = NULL;
	ASN1_OBJECT* t_extnObj = NULL;
	X509_EXTENSION* t_x509Ext = NULL;
	bytea* t_bytea = PG_GETARG_BYTEA_P(0);
	text* t_text = PG_GETARG_TEXT_P(1);
	const unsigned char* t_pointer = (unsigned char*)VARDATA(t_bytea);
	char* t_extnTxt = NULL;
	int t_iCritical = -1;
	int t_iExtIdx = -2;

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		PG_RETURN_NULL();

	if ((t_x509 = d2i_X509(NULL, &t_pointer,
				VARSIZE(t_bytea) - VARHDRSZ)) == NULL)
		PG_RETURN_NULL();

	/* NUL-terminate the OID string */
	if ((t_extnTxt = calloc(VARSIZE(t_text) - VARHDRSZ + 1, 1)) == NULL)
		goto label_done;
	strncpy(t_extnTxt, VARDATA(t_text), VARSIZE(t_text) - VARHDRSZ);
	if ((t_extnObj = OBJ_txt2obj(t_extnTxt, 0)) == NULL)
		goto label_done;
	if ((t_iExtIdx = X509_get_ext_by_OBJ(t_x509, t_extnObj, -1)) < 0)
		goto label_done;
	
	t_iCritical = X509_EXTENSION_get_critical(X509_get_ext(t_x509, t_iExtIdx));

label_done:
	if (t_extnObj)
		ASN1_OBJECT_free(t_extnObj);
	if (t_extnTxt)
		free(t_extnTxt);
		
	X509_free(t_x509);

	switch (t_iCritical) {
		
		case 1:
			PG_RETURN_BOOL(true);
			break;
		case 0:
			PG_RETURN_BOOL(false);
			break;
		default:
			PG_RETURN_NULL();
			
	}
}
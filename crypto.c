/* libx509pq - Public-key, signature, verification, ROCA, close-primes
 * See libx509pq.c for the full copyright notice. Licensed under GPLv3+. */

#include "libx509pq.h"


/* ROCA (CVE-2017-15361) fingerprint primes and discriminator bitmasks.
  See the process-global state note next to g_gostEngine in libx509pq.c.
  g_primes[] is compile-time constant; g_prints[] is populated once in
  _PG_init() via rocacheck_init() and freed in _PG_fini() via
  rocacheck_cleanup(). */
static unsigned char g_primes[ROCA_PRINTS_LENGTH] = {
	11, 13, 17, 19, 37, 53, 61, 71, 73, 79, 97, 103, 107, 109, 127, 151, 157
};
static BIGNUM* g_prints[ROCA_PRINTS_LENGTH];

void rocacheck_init(void)
{
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

void rocacheck_cleanup(void)
{
	int i;
	for (i = 0; i < ROCA_PRINTS_LENGTH; i++)
		BN_free(g_prints[i]);
}


/******************************************************************************
 * x509_keyalgorithm()                                                        *
 ******************************************************************************/
PG_FN(x509_keyalgorithm)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	text* t_text = NULL;
	char* t_string = NULL;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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

	t_text = text_from_cstring_len(t_string, strlen(t_string));

	goto label_return;

label_error:
	t_text = text_from_cstring_len(g_error, strlen(g_error));

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
PG_FN(x509_keysize)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	int32 t_int32 = -1;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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
 * x509_publickeymd5()                                                        *
 ******************************************************************************/
PG_FN(x509_publickeymd5)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	bytea* t_publicKeyMD5 = NULL;
	const EVP_MD* t_md5 = EVP_md5();

	if (!t_md5) {
		/* OpenSSL built with OPENSSL_NO_MD5, or strict FIPS mode is
		  active. MD5 is used here as a non-security fingerprint, but
		  the algorithm is simply unavailable in this build. */
		ereport(WARNING,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("x509_publicKeyMD5: MD5 is not available in this OpenSSL build"))
		);
		PG_RETURN_NULL();
	}

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (!t_x509)
		goto label_error;

	t_publicKey = X509_get_pubkey(t_x509);
	if (!t_publicKey)
		goto label_error;

	t_publicKeyMD5 = palloc(VARHDRSZ + 16);
	SET_VARSIZE(t_publicKeyMD5, VARHDRSZ + 16);

	if (!X509_pubkey_digest(t_x509, t_md5,
				(unsigned char*)t_publicKeyMD5 + VARHDRSZ,
				NULL)) {
		ereport(WARNING,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("x509_publicKeyMD5: MD5 digest computation failed (MD5 may be disabled by FIPS policy)"))
		);
		goto label_error;
	}

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
PG_FN(x509_publickey)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	bytea* t_derPublicKey = NULL;
	unsigned char* t_pointer2 = NULL;
	int t_derPublicKey_size;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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
PG_FN(x509_rsamodulus)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	const BIGNUM* t_modulus = NULL;
	bytea* t_derModulus = NULL;
	int t_derModulus_size;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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
 * x509_signaturehashalgorithm()                                              *
 ******************************************************************************/
PG_FN(x509_signaturehashalgorithm)
{
	X509* t_x509 = NULL;
	SIGNATURE_ALGORITHM* t_sigAlg;
	text* t_text = NULL;
	const char* t_string = g_error;
	int t_iResult;
	int t_sigAlgNID;
	int t_sigHashAlgNID;
	int t_sigKeyAlgNID;
	const char* t_name;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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
	t_name = hash_alg_name(t_sigHashAlgNID);
	if (t_name)
		t_string = t_name;

label_return:
	t_text = text_from_cstring_len(t_string, strlen(t_string));

	if (t_x509)
		X509_free(t_x509);

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_signaturekeyalgorithm()                                               *
 ******************************************************************************/
PG_FN(x509_signaturekeyalgorithm)
{
	X509* t_x509 = NULL;
	SIGNATURE_ALGORITHM* t_sigAlg;
	text* t_text = NULL;
	const char* t_string = g_error;
	int t_iResult;
	int t_sigAlgNID;
	int t_sigHashAlgNID;
	int t_sigKeyAlgNID;
	const char* t_name;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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
	t_name = pkey_alg_name(t_sigKeyAlgNID);
	if (t_name)
		t_string = t_name;

label_return:
	t_text = text_from_cstring_len(t_string, strlen(t_string));

	if (t_x509)
		X509_free(t_x509);

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_verify()                                                              *
 ******************************************************************************/
PG_FN(x509_verify)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	bytea* t_bytea = NULL;
	const unsigned char* t_pointer = NULL;
	bool t_bResult = false;

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (t_x509) {
		t_bytea = PG_GETARG_BYTEA_PP(1);
		t_pointer = (unsigned char*)VARDATA_ANY(t_bytea);
		t_publicKey = d2i_PUBKEY(
			NULL, &t_pointer, VARSIZE_ANY_EXHDR(t_bytea)
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
PG_FN(x509_hasrocafingerprint)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	const BIGNUM* t_modulus = NULL;
	BN_CTX* t_ctx = BN_CTX_new();
	BN_CTX_start(t_ctx);
	BIGNUM* t_prime = BN_CTX_get(t_ctx);
	BIGNUM* t_temp = BN_CTX_get(t_ctx);
	bool t_bResult = false;
	bool t_bResultIsNULL = true;
	int i;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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
static int BN_isqrt(
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
	if (estimate == NULL || tmp == NULL || last_delta == NULL || delta == NULL)
		goto err;

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
static int BN_is_square(
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
PG_FN(x509_hascloseprimes)
{
	X509* t_x509 = NULL;
	EVP_PKEY* t_publicKey = NULL;
	const BIGNUM* t_modulus = NULL;
	BN_CTX* t_ctx = BN_CTX_new();
	BN_CTX_start(t_ctx);
	BIGNUM* a = BN_CTX_get(t_ctx);
	BIGNUM* a_squared_minus_n = BN_CTX_get(t_ctx);
	bool t_bResult = false;
	bool t_bResultIsNULL = true;
	int i;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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



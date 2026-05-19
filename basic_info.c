/* libx509pq - x509_basic_info: single-pass cert field extraction
 * See libx509pq.c for the full copyright notice. Licensed under GPLv3+. */

#include "libx509pq.h"


/******************************************************************************
 * x509_basic_info()                                                          *
 *   Parse the certificate once and return all the cheap-to-extract fields    *
 *   as a single composite row.  Equivalent to calling the individual         *
 *   x509_issuerName/x509_subjectName/x509_notBefore/... functions but with   *
 *   a single d2i_X509() and a single X509_get_pubkey().                      *
 *                                                                            *
 *   Each output column is filled by a small static fill_*() helper so that   *
 *   the field indices are named (see the XBI_* enum) rather than scattered   *
 *   magic numbers.  Helpers leave their column NULL on any failure path.     *
 ******************************************************************************/

/* Column indices for the x509_basic_info() composite row.  Keep in sync with
 * the OUT-parameter order of the SQL function declaration. */
enum {
	XBI_ISSUER_NAME = 0,
	XBI_SUBJECT_NAME,
	XBI_COMMON_NAME,
	XBI_SERIAL_NUMBER,
	XBI_NOT_BEFORE,
	XBI_NOT_AFTER,
	XBI_KEY_ALGORITHM,
	XBI_KEY_SIZE,
	XBI_SIG_HASH_ALGORITHM,
	XBI_SIG_KEY_ALGORITHM,
	XBI_SUBJECT_KEY_IDENTIFIER,
	XBI_AUTHORITY_KEY_IDENTIFIER,
	XBI_NFIELDS
};

/* Render an X509_NAME with the same flags used by x509_issuerName /
 * x509_subjectName when called with default arguments. */
static void fill_name_rfc2253(
	Datum* values, bool* nulls, int idx, X509_NAME* name, BIO* bio
)
{
	char* s;
	long n;

	(void)BIO_reset(bio);
	(void)X509_NAME_print_ex(
		bio, name, 0,
		(ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_ESC_QUOTE
			| XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN)
			& ~ASN1_STRFLGS_ESC_MSB
	);
	n = BIO_get_mem_data(bio, &s);
	if (n >= 0) {
		values[idx] = PointerGetDatum(text_from_cstring_len(s, n));
		nulls[idx] = false;
	}
}

static void fill_issuer_name(
	Datum* values, bool* nulls, X509* x509, BIO* bio
)
{
	fill_name_rfc2253(
		values, nulls, XBI_ISSUER_NAME,
		X509_get_issuer_name(x509), bio
	);
}

static void fill_subject_name(
	Datum* values, bool* nulls, X509* x509, BIO* bio
)
{
	fill_name_rfc2253(
		values, nulls, XBI_SUBJECT_NAME,
		X509_get_subject_name(x509), bio
	);
}

/* First commonName attribute in the subject, decoded as UTF-8. */
static void fill_common_name(Datum* values, bool* nulls, X509* x509)
{
	X509_NAME* t_name = X509_get_subject_name(x509);
	int t_idx = X509_NAME_get_index_by_NID(t_name, NID_commonName, -1);
	X509_NAME_ENTRY* t_ne;
	ASN1_STRING* t_as;
	unsigned char* t_utf8 = NULL;
	int t_len;

	if (t_idx == -1)
		return;
	t_ne = X509_NAME_get_entry(t_name, t_idx);
	t_as = X509_NAME_ENTRY_get_data(t_ne);
	t_len = ASN1_STRING_to_UTF8(&t_utf8, t_as);
	if ((t_len >= 0) && t_utf8) {
		values[XBI_COMMON_NAME] = PointerGetDatum(
			text_from_cstring_len(t_utf8, t_len)
		);
		nulls[XBI_COMMON_NAME] = false;
		OPENSSL_free(t_utf8);
	}
}

/* DER-encoded serialNumber body, sans the outer tag+length octets, as
 * x509_serialNumber does. */
static void fill_serial_number(Datum* values, bool* nulls, X509* x509)
{
	ASN1_INTEGER* t_si = X509_get_serialNumber(x509);
	int t_sz = i2d_ASN1_INTEGER(t_si, NULL);
	bytea* b;
	unsigned char* p;

	if ((t_sz <= 2) || (t_sz > 129))
		return;
	b = (bytea*)palloc(VARHDRSZ + t_sz - 2);
	p = (unsigned char*)b + VARHDRSZ - 2;
	(void)i2d_ASN1_INTEGER(t_si, &p);
	SET_VARSIZE(b, VARHDRSZ + t_sz - 2);
	values[XBI_SERIAL_NUMBER] = PointerGetDatum(b);
	nulls[XBI_SERIAL_NUMBER] = false;
}

/* Fills both notBefore (XBI_NOT_BEFORE) and notAfter (XBI_NOT_AFTER). */
static void fill_validity(Datum* values, bool* nulls, X509* x509)
{
	struct tm t_time;

	if (ASN1_TIME_parse(X509_get0_notBefore(x509), &t_time)) {
		Timestamp ts = (timegm(&t_time) - 946684800) * USECS_PER_SEC;
		values[XBI_NOT_BEFORE] = TimestampGetDatum(ts);
		nulls[XBI_NOT_BEFORE] = false;
	}
	if (ASN1_TIME_parse(X509_get0_notAfter(x509), &t_time)) {
		Timestamp ts = (timegm(&t_time) - 946684800) * USECS_PER_SEC;
		values[XBI_NOT_AFTER] = TimestampGetDatum(ts);
		nulls[XBI_NOT_AFTER] = false;
	}
}

/* Fills both key_algorithm (XBI_KEY_ALGORITHM) and key_size (XBI_KEY_SIZE). */
static void fill_pubkey_info(Datum* values, bool* nulls, X509* x509)
{
	EVP_PKEY* t_pk = X509_get_pubkey(x509);
	const char* t_kname = NULL;
	int t_bits;

	if (!t_pk)
		return;
	switch (EVP_PKEY_id(t_pk)) {
		case EVP_PKEY_RSA: case EVP_PKEY_RSA2:
			t_kname = "RSA"; break;
		case EVP_PKEY_DSA: case EVP_PKEY_DSA1:
		case EVP_PKEY_DSA2: case EVP_PKEY_DSA3:
		case EVP_PKEY_DSA4:
			t_kname = "DSA"; break;
		case EVP_PKEY_DH:
			t_kname = "DH"; break;
		case EVP_PKEY_EC:
			t_kname = "EC"; break;
		case EVP_PKEY_NONE:
			t_kname = "NONE"; break;
		default:
			break;
	}
	if (t_kname) {
		values[XBI_KEY_ALGORITHM] = PointerGetDatum(
			text_from_cstring_len(t_kname, strlen(t_kname))
		);
		nulls[XBI_KEY_ALGORITHM] = false;
	}
	t_bits = EVP_PKEY_bits(t_pk);
	if (t_bits > 0) {
		values[XBI_KEY_SIZE] = Int32GetDatum(t_bits);
		nulls[XBI_KEY_SIZE] = false;
	}
	EVP_PKEY_free(t_pk);
}

/* Fills both signature_hash_algorithm (XBI_SIG_HASH_ALGORITHM) and
 * signature_key_algorithm (XBI_SIG_KEY_ALGORITHM). */
static void fill_signature_algorithms(
	Datum* values, bool* nulls, X509* x509
)
{
	SIGNATURE_ALGORITHM* t_sa;
	int t_sigNID, t_hashNID, t_pkeyNID;
	const char* s;

	X509_GET_SIGALGNID(&t_sa, x509);
	t_sigNID = OBJ_obj2nid(t_sa->algorithm);
	if (!OBJ_find_sigid_algs(t_sigNID, &t_hashNID, &t_pkeyNID))
		return;

	s = hash_alg_name(t_hashNID);
	if (s) {
		values[XBI_SIG_HASH_ALGORITHM] = PointerGetDatum(
			text_from_cstring_len(s, strlen(s))
		);
		nulls[XBI_SIG_HASH_ALGORITHM] = false;
	}
	s = pkey_alg_name(t_pkeyNID);
	if (s) {
		values[XBI_SIG_KEY_ALGORITHM] = PointerGetDatum(
			text_from_cstring_len(s, strlen(s))
		);
		nulls[XBI_SIG_KEY_ALGORITHM] = false;
	}
}

static void fill_subject_key_identifier(
	Datum* values, bool* nulls, X509* x509
)
{
	ASN1_OCTET_STRING* t_ski = X509_get_ext_d2i(
		x509, NID_subject_key_identifier, NULL, NULL
	);
	int t_sz;

	if (!t_ski)
		return;
	t_sz = ASN1_STRING_length(t_ski);
	values[XBI_SUBJECT_KEY_IDENTIFIER] = PointerGetDatum(
		bytea_from_buffer(ASN1_STRING_get0_data(t_ski), t_sz)
	);
	nulls[XBI_SUBJECT_KEY_IDENTIFIER] = false;
	ASN1_OCTET_STRING_free(t_ski);
}

static void fill_authority_key_identifier(
	Datum* values, bool* nulls, X509* x509
)
{
	AUTHORITY_KEYID* t_aki = X509_get_ext_d2i(
		x509, NID_authority_key_identifier, NULL, NULL
	);
	int t_sz;

	if (!t_aki)
		return;
	if (t_aki->keyid) {
		t_sz = ASN1_STRING_length(t_aki->keyid);
		values[XBI_AUTHORITY_KEY_IDENTIFIER] = PointerGetDatum(
			bytea_from_buffer(
				ASN1_STRING_get0_data(t_aki->keyid), t_sz
			)
		);
		nulls[XBI_AUTHORITY_KEY_IDENTIFIER] = false;
	}
	AUTHORITY_KEYID_free(t_aki);
}

PG_FN(x509_basic_info)
{
	TupleDesc t_tupleDesc;
	X509* t_x509 = NULL;
	Datum t_values[XBI_NFIELDS];
	bool t_nulls[XBI_NFIELDS];
	HeapTuple t_heapTuple;
	BIO* t_bio;
	int l_field;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();

	if (get_call_result_type(fcinfo, NULL, &t_tupleDesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			errmsg("function returning record called in context "
				"that cannot accept type record"))
		);
	t_tupleDesc = BlessTupleDesc(t_tupleDesc);

	for (l_field = 0; l_field < XBI_NFIELDS; l_field++) {
		t_values[l_field] = (Datum) 0;
		t_nulls[l_field] = true;
	}

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (!t_x509) {
		t_heapTuple = heap_form_tuple(t_tupleDesc, t_values, t_nulls);
		PG_RETURN_DATUM(HeapTupleGetDatum(t_heapTuple));
	}

	t_bio = BIO_new(BIO_s_mem());
	(void)BIO_set_close(t_bio, BIO_CLOSE);

	fill_issuer_name(t_values, t_nulls, t_x509, t_bio);
	fill_subject_name(t_values, t_nulls, t_x509, t_bio);
	fill_common_name(t_values, t_nulls, t_x509);
	fill_serial_number(t_values, t_nulls, t_x509);
	fill_validity(t_values, t_nulls, t_x509);
	fill_pubkey_info(t_values, t_nulls, t_x509);
	fill_signature_algorithms(t_values, t_nulls, t_x509);
	fill_subject_key_identifier(t_values, t_nulls, t_x509);
	fill_authority_key_identifier(t_values, t_nulls, t_x509);

	BIO_free(t_bio);
	X509_free(t_x509);

	t_heapTuple = heap_form_tuple(t_tupleDesc, t_values, t_nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(t_heapTuple));
}

/* libx509pq - X.509 Name (issuer/subject/CN) accessors
 * See libx509pq.c for the full copyright notice. Licensed under GPLv3+. */

#include "libx509pq.h"


/******************************************************************************
 * x509_issuername()                                                          *
 ******************************************************************************/
PG_FN(x509_issuername)
{
	X509* t_x509 = NULL;
	BIO* t_bio;
	text* t_text = NULL;

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (!t_x509)
		t_text = text_from_cstring_len(g_error, strlen(g_error));
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

		/* Build the return text from the BIO contents */
		t_text = text_from_bio(t_bio);

		X509_free(t_x509);
	}

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_subjectname()                                                         *
 ******************************************************************************/
PG_FN(x509_subjectname)
{
	X509* t_x509 = NULL;
	BIO* t_bio;
	text* t_text = NULL;

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (!t_x509)
		t_text = text_from_cstring_len(g_error, strlen(g_error));
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

		/* Build the return text from the BIO contents */
		t_text = text_from_bio(t_bio);

		X509_free(t_x509);
	}

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_name()                                                                *
 ******************************************************************************/
PG_FN(x509_name)
{
	X509* t_x509 = NULL;
	const X509_NAME* t_x509Name = NULL;
	bytea* t_derName = NULL;
	unsigned char* t_pointer2 = NULL;
	int t_derName_size;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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
PG_FN(x509_name_print)
{
	X509_NAME* t_x509Name = NULL;
	BIO* t_bio;
	bytea* t_bytea = NULL;
	text* t_text = NULL;
	const unsigned char* t_pointer = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	t_bytea = PG_GETARG_BYTEA_PP(0);
	t_pointer = (unsigned char*)VARDATA_ANY(t_bytea);
	t_x509Name = d2i_X509_NAME(NULL, &t_pointer, VARSIZE_ANY_EXHDR(t_bytea));
	if (!t_x509Name)
		t_text = text_from_cstring_len(g_error, strlen(g_error));
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

		/* Build the return text from the BIO contents */
		t_text = text_from_bio(t_bio);

		X509_NAME_free(t_x509Name);
	}

	PG_RETURN_TEXT_P(t_text);
}


/******************************************************************************
 * x509_commonname()                                                          *
 ******************************************************************************/
PG_FN(x509_commonname)
{
	X509* t_x509 = NULL;
	const X509_NAME_ENTRY* t_nameEntry;
	const ASN1_STRING* t_asn1String;
	text* t_text = NULL;
	unsigned char* t_utf8String = NULL;
	int t_lastPos = -1;

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (!t_x509)
		t_text = text_from_cstring_len(g_error, strlen(g_error));
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
				t_text = text_from_cstring_len(
					(char*)t_utf8String,
					strlen((char*)t_utf8String)
				);
				OPENSSL_free(t_utf8String);
			}
		}
		X509_free(t_x509);
	}

	PG_RETURN_TEXT_P(t_text);
}


typedef struct tX509NameCtx_st{
	X509* m_x509;
	const X509_NAME* m_name;
	int m_index;
	int m_nid;
} tX509NameCtx;


/******************************************************************************
 * x509_nameattributes()                                                      *
 ******************************************************************************/
PG_FN(x509_nameattributes)
{
	tX509NameCtx* t_x509NameCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		SRF_FIRSTCALL_BEGIN(tX509NameCtx, t_x509NameCtx);
		t_x509NameCtx->m_nid = NID_X509;

		X509_FROM_BYTEA_ARG_OR_NULL(t_x509NameCtx->m_x509, 0);
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

		{
			text* t_text = PG_GETARG_TEXT_P(1);
			char* t_oidName = palloc(VARSIZE(t_text) - VARHDRSZ + 1);
			memcpy(t_oidName, VARDATA(t_text),
				VARSIZE(t_text) - VARHDRSZ);
			t_oidName[VARSIZE(t_text) - VARHDRSZ] = '\0';
			t_x509NameCtx->m_nid = OBJ_txt2nid(t_oidName);
		}

		SRF_FIRSTCALL_END();
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_x509NameCtx = t_funcCtx->user_fctx;

	if ((t_x509NameCtx->m_nid == NID_undef) && (t_funcCtx->call_cntr == 0)) {
		char* c_unsupportedAttribute = "Unsupported Attribute";
		text* t_text = text_from_cstring_len(
			c_unsupportedAttribute,
			strlen(c_unsupportedAttribute)
		);
		SRF_RETURN_NEXT(t_funcCtx, PointerGetDatum(t_text));
	}

	if ((t_x509NameCtx->m_nid != NID_undef) && (t_x509NameCtx->m_name)) {
		while (t_x509NameCtx->m_index < X509_NAME_entry_count(
						t_x509NameCtx->m_name)) {
			const X509_NAME_ENTRY* t_nameEntry = X509_NAME_get_entry(
				t_x509NameCtx->m_name, t_x509NameCtx->m_index
			);
			const ASN1_STRING* t_asn1String;
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
					t_text = text_from_cstring_len(
						t_utf8String,
						strlen(t_utf8String)
					);
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
				t_text = text_from_cstring_len(
					t_buffer, strlen(t_buffer)
				);
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
	const X509_NAME* m_name;
	int m_index;
	bool* m_nulls;
} tNameAttributesRawCtx;


/******************************************************************************
 * x509_nameattributes_raw()                                                  *
 ******************************************************************************/
PG_FN(x509_nameattributes_raw)
{
	tNameAttributesRawCtx* t_nameAttributesRawCtx;
	FuncCallContext* t_funcCtx;
	TupleDesc t_tupleDesc;

	if (SRF_IS_FIRSTCALL()) {
		SRF_FIRSTCALL_BEGIN(tNameAttributesRawCtx, t_nameAttributesRawCtx);

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

		X509_FROM_BYTEA_ARG_OR_NULL(t_nameAttributesRawCtx->m_x509, 0);
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

		SRF_FIRSTCALL_END();
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_nameAttributesRawCtx = t_funcCtx->user_fctx;

	if (t_nameAttributesRawCtx->m_name) {
		while (t_nameAttributesRawCtx->m_index < X509_NAME_entry_count(
					t_nameAttributesRawCtx->m_name)) {
			const X509_NAME_ENTRY* t_nameEntry = X509_NAME_get_entry(
				t_nameAttributesRawCtx->m_name,
				t_nameAttributesRawCtx->m_index
			);
			char* t_utf8String = NULL;
			Datum t_datum[2];

			/* Increment the counter while we can */
			t_nameAttributesRawCtx->m_index++;

			const ASN1_STRING* t_asn1String = X509_NAME_ENTRY_get_data(t_nameEntry);
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


/******************************************************************************
 * x509_anynameswithnuls()                                                    *
 ******************************************************************************/
PG_FN(x509_anynameswithnuls)
{
	X509* t_x509 = NULL;
	const X509_NAME* t_name;
	const X509_NAME_ENTRY* t_nameEntry;
	STACK_OF(GENERAL_NAME)* t_genNames;
	const GENERAL_NAME* t_generalName;
	int l_indexNo;
	bool t_bResult = false;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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



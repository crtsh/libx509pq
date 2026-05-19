/* libx509pq - X.509 extension accessors
 * See libx509pq.c for the full copyright notice. Licensed under GPLv3+. */

#include "libx509pq.h"


/* Definition of the old draft Basic Constraints extension and the
  hard-coded "Root SGC Authority" signature. See libx509pq.h for the
  BASIC_CONSTRAINTS_OLD typedef and DECLARE_ASN1_FUNCTIONS forward
  declarations. */

X509V3_EXT_METHOD v3_bcOld = {
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

/******************************************************************************
 * x509_subjectkeyidentifier()                                                *
 ******************************************************************************/
PG_FN(x509_subjectkeyidentifier)
{
	X509* t_x509 = NULL;
	ASN1_OCTET_STRING* t_asn1OctetString;
	bytea* t_subjectKeyIdentifier = NULL;
	unsigned char* t_pointer = NULL;
	int t_size;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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
PG_FN(x509_authoritykeyid)
{
	X509* t_x509 = NULL;
	AUTHORITY_KEYID* t_authorityKeyIdentifier;
	bytea* t_keyid = NULL;
	unsigned char* t_pointer = NULL;
	int t_size;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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
PG_FN(x509_extkeyusages)
{
	ASN1_OBJECT* t_ekuOID;
	tExtKeyUsageCtx* t_extKeyUsageCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;

		SRF_FIRSTCALL_BEGIN(tExtKeyUsageCtx, t_extKeyUsageCtx);

		X509_FROM_BYTEA_ARG_OR_NULL(t_x509, 0);
		if (t_x509) {
			t_extKeyUsageCtx->m_extKeyUsages = X509_get_ext_d2i(
				t_x509, NID_ext_key_usage, NULL, NULL
			);
			X509_free(t_x509);
		}

		SRF_FIRSTCALL_END();
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
PG_FN(x509_isekupermitted)
{
	X509* t_x509 = NULL;
	EXTENDED_KEY_USAGE* t_extendedKeyUsage;
	text* t_text = NULL;
	char* t_ekuOID = NULL;
	char t_ekuOID2[MAX_OIDSTRING_LENGTH];
	int l_indexNo;
	bool t_bResult = false;

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (t_x509) {
		t_text = PG_GETARG_TEXT_P(1);
		t_ekuOID = palloc0(VARSIZE(t_text) - VARHDRSZ + 1);
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
			pfree(t_ekuOID);
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
PG_FN(x509_certpolicies)
{
	POLICYINFO* t_policyInfo;
	tCertPoliciesCtx* t_certPoliciesCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;

		SRF_FIRSTCALL_BEGIN(tCertPoliciesCtx, t_certPoliciesCtx);

		X509_FROM_BYTEA_ARG_OR_NULL(t_x509, 0);
		if (t_x509) {
			t_certPoliciesCtx->m_certPolicies = X509_get_ext_d2i(
				t_x509, NID_certificate_policies, NULL, NULL
			);
			X509_free(t_x509);
		}

		SRF_FIRSTCALL_END();
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
PG_FN(x509_ispolicypermitted)
{
	X509* t_x509 = NULL;
	CERTIFICATEPOLICIES* t_certificatePolicies;
	POLICYINFO* t_policyInfo;
	text* t_text = NULL;
	char* t_policyOID = NULL;
	char t_policyOID2[MAX_OIDSTRING_LENGTH];
	int l_indexNo;
	bool t_bResult = false;

	X509_FROM_BYTEA_ARG(t_x509, 0);
	if (t_x509) {
		t_text = PG_GETARG_TEXT_P(1);
		t_policyOID = palloc0(VARSIZE(t_text) - VARHDRSZ + 1);
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
			pfree(t_policyOID);
		X509_free(t_x509);
	}

	PG_RETURN_BOOL(t_bResult);
}


/******************************************************************************
 * x509_canissuecerts()                                                       *
 ******************************************************************************/
PG_FN(x509_canissuecerts)
{
	X509* t_x509 = NULL;
	BASIC_CONSTRAINTS* t_basicConstraints;
	BASIC_CONSTRAINTS_OLD* t_bCold = NULL;
	ASN1_BIT_STRING* t_keyUsage;
	SIGNATURE_BIT_STRING* t_signature;
	ASN1_OCTET_STRING* t_oldBasicConstraints;
	const unsigned char* t_pointer = NULL;
	unsigned long t_keyUsageBits;
	unsigned long t_subjTypeBits;
	int t_pos = -1;
	bool t_bResult = false;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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
PG_FN(x509_getpathlenconstraint)
{
	X509* t_x509 = NULL;
	BASIC_CONSTRAINTS* t_basicConstraints;
	BASIC_CONSTRAINTS_OLD* t_bCold = NULL;
	SIGNATURE_BIT_STRING* t_signature;
	ASN1_OCTET_STRING* t_oldBasicConstraints;
	const unsigned char* t_pointer = NULL;
	unsigned long t_subjTypeBits;
	int t_pos = -1;
	int t_iResult = -1;

	X509_FROM_BYTEA_ARG(t_x509, 0);
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


typedef struct tAltNamesCtx_st{
	STACK_OF(GENERAL_NAME)* m_genNames;
	int m_index;
	int m_type;
} tAltNamesCtx;


/******************************************************************************
 * x509_altnames()                                                            *
 ******************************************************************************/
PG_FN(x509_altnames)
{
	tAltNamesCtx* t_altNamesCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;

		SRF_FIRSTCALL_BEGIN(tAltNamesCtx, t_altNamesCtx);

		X509_FROM_BYTEA_ARG_OR_NULL(t_x509, 0);
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

		SRF_FIRSTCALL_END();
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_altNamesCtx = t_funcCtx->user_fctx;

	if ((t_altNamesCtx->m_type == -2) && (t_funcCtx->call_cntr == 0)) {
		char* c_unsupportedGenName = "Unsupported GeneralName";
		text* t_text = text_from_cstring_len(
			c_unsupportedGenName,
			strlen(c_unsupportedGenName)
		);
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
				snprintf(t_utf8String, 16, "%d.%d.%d.%d",
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
				snprintf(t_utf8String, 46,
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
				t_text = text_from_cstring_len(
					t_utf8String, strlen(t_utf8String)
				);
				OPENSSL_free(t_utf8String);
			}
			else if ((!PG_GETARG_BOOL(3)) && (t_generalName->type
							== GEN_OTHERNAME)) {
				ASN1_OBJECT* t_oid;
				char t_buffer[80];
				(void)GENERAL_NAME_get0_otherName(
					t_generalName, &t_oid, NULL
				);
				OBJ_obj2txt(
					t_buffer, sizeof t_buffer, t_oid, 1
				);
				t_text = text_from_cstring_len(
					t_buffer, strlen(t_buffer)
				);
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
PG_FN(x509_altnames_raw)
{
	tAltNamesRawCtx* t_altNamesRawCtx;
	FuncCallContext* t_funcCtx;
	TupleDesc t_tupleDesc;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;

		SRF_FIRSTCALL_BEGIN(tAltNamesRawCtx, t_altNamesRawCtx);

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

		X509_FROM_BYTEA_ARG_OR_NULL(t_x509, 0);
		if (t_x509) {
			t_altNamesRawCtx->m_genNames = X509_get_ext_d2i(
				t_x509,
				PG_GETARG_BOOL(1) ? NID_subject_alt_name
						: NID_issuer_alt_name,
				NULL, NULL
			);

			X509_free(t_x509);
		}

		SRF_FIRSTCALL_END();
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
					t_length = snprintf(
						t_utf8String, 16, "%d.%d.%d.%d",
						t_generalName->d.iPAddress->data[0],
						t_generalName->d.iPAddress->data[1],
						t_generalName->d.iPAddress->data[2],
						t_generalName->d.iPAddress->data[3]
					);
				}
				else if (t_generalName->d.iPAddress->length == 16) {
					/* IPv6 */
					t_utf8String = OPENSSL_malloc(46);
					t_length = snprintf(
						t_utf8String, 46, ":%X:%X:%X:%X:%X:%X:%X:%X",
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
					t_generalName, &t_oid, &t_asn1Type
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
PG_FN(x509_crldistributionpoints)
{
	DIST_POINT* t_distPoint;
	tCRLDistributionPointsCtx* t_cRLDistributionPointsCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;

		SRF_FIRSTCALL_BEGIN(tCRLDistributionPointsCtx,
				t_cRLDistributionPointsCtx);

		X509_FROM_BYTEA_ARG_OR_NULL(t_x509, 0);
		if (t_x509) {
			t_cRLDistributionPointsCtx->m_cRLDistributionPoints
				= X509_get_ext_d2i(
					t_x509, NID_crl_distribution_points,
					NULL, NULL
				);
			X509_free(t_x509);
		}

		SRF_FIRSTCALL_END();
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
				text* t_text = text_from_cstring_len(
					t_utf8String, strlen(t_utf8String)
				);
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
PG_FN(x509_authorityinfoaccess)
{
	ACCESS_DESCRIPTION* t_accessDescription;
	tAuthorityInfoAccessCtx* t_authorityInfoAccessCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		X509* t_x509 = NULL;

		SRF_FIRSTCALL_BEGIN(tAuthorityInfoAccessCtx,
				t_authorityInfoAccessCtx);

		X509_FROM_BYTEA_ARG_OR_NULL(t_x509, 0);
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

		SRF_FIRSTCALL_END();
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
				text* t_text = text_from_cstring_len(
					t_utf8String, strlen(t_utf8String)
				);
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


typedef struct tExtensionsCtx_st{
	X509* m_x509;
	const STACK_OF(X509_EXTENSION)* m_extensions;
	int m_index;
} tExtensionsCtx;


/******************************************************************************
 * X509_extensions()                                                          *
 ******************************************************************************/
PG_FN(x509_extensions)
{
	X509_EXTENSION* t_extension;
	ASN1_OBJECT* t_extensionOID;
	tExtensionsCtx* t_extensionsCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		SRF_FIRSTCALL_BEGIN(tExtensionsCtx, t_extensionsCtx);

		X509_FROM_BYTEA_ARG_OR_NULL(t_extensionsCtx->m_x509, 0);
		if (t_extensionsCtx->m_x509) {
			t_extensionsCtx->m_extensions = X509_get0_extensions(
				t_extensionsCtx->m_x509
			);
		}

		SRF_FIRSTCALL_END();
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
PG_FN(x509_hasextension)
{
	X509* t_x509 = NULL;
	ASN1_OBJECT* t_extnObj = NULL;
	bytea* t_bytea = PG_GETARG_BYTEA_PP(0);
	text* t_text = PG_GETARG_TEXT_P(1);
	const unsigned char* t_pointer = (unsigned char*)VARDATA_ANY(t_bytea);
	char* t_extnTxt = NULL;
	bool t_bResult = false;

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		PG_RETURN_NULL();

	if ((t_x509 = d2i_X509(NULL, &t_pointer,
				VARSIZE_ANY_EXHDR(t_bytea))) == NULL)
		PG_RETURN_NULL();

	/* NUL-terminate the OID string */
	if ((t_extnTxt = palloc0(VARSIZE(t_text) - VARHDRSZ + 1)) == NULL)
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
		pfree(t_extnTxt);
	X509_free(t_x509);

	PG_RETURN_BOOL(t_bResult);
}


/******************************************************************************
 * x509_tbscert_strip_ct_ext()                                                *
 ******************************************************************************/
PG_FN(x509_tbscert_strip_ct_ext)
{
	X509* t_x509 = NULL;
	bytea* t_bytea = PG_GETARG_BYTEA_PP(0);
	bytea* t_derTBSCert = NULL;
	const unsigned char* t_pointer = (unsigned char*)VARDATA_ANY(t_bytea);
	unsigned char* t_pointer2 = NULL;
	int t_extPos;
	int t_derTBSCert_size;

	if ((t_x509 = d2i_X509(NULL, &t_pointer,
				VARSIZE_ANY_EXHDR(t_bytea))) == NULL)
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



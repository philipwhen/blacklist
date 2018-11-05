#pragma once

#define sm3_digest_BYTES 32

#define sm4_rounds 32
#define sm4_block_size 16
#define sm4_key_BYTES 16
#define sm4_iv_BYTES 16

int verifyLic();
int Version_control();

void ENGINE_load_CipherSuite(void);

#define ciphersuite_SM(csid) (csid == TLS1_CK_ECDHE_SM4_SM3 || csid == TLS1_CK_ECC_SM4_SM3 \
    || csid == TLS1_CK_ECDHE_SM4_GCM_SM3 || csid == TLS1_CK_ECC_SM4_GCM_SM3  \
    || csid == TLS1_CK_RSA_SM4_SM3 || csid == TLS1_CK_RSA_SM4_SHA1 \
    || csid == TLS1_CK_RSA_SM4_GCM_SM3)

#define ciphersuite_SM_ECDHE(csid) (csid == TLS1_CK_ECDHE_SM4_SM3 || csid == TLS1_CK_ECDHE_SM4_GCM_SM3)
#define ciphersuite_SM_ECC(csid) (csid == TLS1_CK_ECC_SM4_SM3 || csid == TLS1_CK_ECC_SM4_GCM_SM3)
#define ciphersuite_SM_RSA(csid) (csid == TLS1_CK_RSA_SM4_SM3 || csid == TLS1_CK_RSA_SM4_SHA1 \
    || csid == TLS1_CK_RSA_SM4_GCM_SM3)

/*TLS error code*/
#define SSL_F_TLS_CONSTRUCT_CKE_ECC    1001
#define SSL_F_TLS_PROCESS_CKE_ECC   1002


#define SSL_R_MISSING_ECC_ENCRYPTING_CERT 1031

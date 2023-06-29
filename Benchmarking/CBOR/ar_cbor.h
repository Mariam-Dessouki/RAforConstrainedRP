#ifndef AR_CBOR_H
#define AR_CBOR_H

#ifndef MAX_NUM_AR_SUBMODS
# define MAX_NUM_AR_SUBMODS 100
#endif

#ifndef CBOR_EAT_PROFILE
# define CBOR_EAT_PROFILE 256
#endif

#ifndef CBOR_IAT
# define CBOR_IAT 6
#endif

#ifndef CBOR_VERIFIER_ID
# define CBOR_VERIFIER_ID 1004
#endif

#ifndef CBOR_VERIFIER_DEVELOPER
# define CBOR_VERIFIER_DEVELOPER 0
#endif

#ifndef CBOR_VERIFIER_BUILD
# define CBOR_VERIFIER_BUILD 1
#endif

#ifndef CBOR_RAW_EVIDENCE
# define CBOR_RAW_EVIDENCE 1002
#endif

#ifndef CBOR_EAT_SUBMODS
# define CBOR_EAT_SUBMODS 266
#endif

#ifndef CBOR_EAR_STATUS
# define CBOR_EAR_STATUS 1000
#endif

#ifndef CBOR_EAR_TRUSTWORTHINESS_VECTOR
# define CBOR_EAR_TRUSTWORTHINESS_VECTOR 1001
#endif

#ifndef CBOR_INSTANCE_IDENTITY
# define CBOR_INSTANCE_IDENTITY 0
#endif

#ifndef CBOR_CONFIGURATION
# define CBOR_CONFIGURATION 1
#endif

#ifndef CBOR_EXECUTABLES
# define CBOR_EXECUTABLES 2
#endif

#ifndef CBOR_FILE_SYSTEM
# define CBOR_FILE_SYSTEM 3
#endif

#ifndef CBOR_HARDWARE
# define CBOR_HARDWARE 4
#endif

#ifndef CBOR_RUNTIME_OPAQUE
# define CBOR_RUNTIME_OPAQUE 5
#endif

#ifndef CBOR_STORAGE_OPAQUE
# define CBOR_STORAGE_OPAQUE 6
#endif

#ifndef CBOR_SOURCED_DATA
# define CBOR_SOURCED_DATA 7
#endif


#ifndef CBOR_EAR_APPRAISAL_POLICY_ID
# define CBOR_EAR_APPRAISAL_POLICY_ID 1003
#endif

typedef struct
{
    char *build;
    char *developer;
} ar_ear_verifier_id_st;

typedef struct
{
    int instance_identity;
    int configuration;
    int executables;
    int file_system;
    int hardware;
    int runtime_opaque;
    int storage_opaque;
    int sourced_data;
} ar_ear_trustworthiness_vector_st;

typedef struct
{
    unsigned int ear_status;
    ar_ear_trustworthiness_vector_st ear_trustworthiness_vector;
    int has_ear_trustworthiness_vector;
    char *ear_appraisal_policy_id;
} ar_ear_appraisal_st;


typedef struct
{
    char *attester_id;
    ar_ear_appraisal_st ear_appraisal;
} ar_ear_submod_st;

typedef struct
{
    char *eat_profile;
    unsigned int iat;
    ar_ear_verifier_id_st ear_verifier_id;
    char *ear_raw_evidence;
    ar_ear_submod_st submods[MAX_NUM_AR_SUBMODS];
    size_t num_submods;
    char *eat_nonce;
} ar_ear_st;

#endif
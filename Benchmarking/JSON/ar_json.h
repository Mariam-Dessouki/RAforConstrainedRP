
#ifndef AR_JSON_H
#define AR_JSON_H

#ifndef MAX_NUM_AR_SUBMODS
# define MAX_NUM_AR_SUBMODS 100
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
    char * ear_status; // TODO change to enum?
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
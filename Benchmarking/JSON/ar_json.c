#include <jansson.h>
#include <string.h>
#include <sys/stat.h>
// #include <time.h>

#include "ar_json.h"

// gcc -o ar_app ar_json.c -ljansson

int read_file(
    char * filename,
    char ** out)
{
    unsigned char *data;
    size_t data_len;
    FILE *fp;
    struct stat file_stat;
    size_t nbytes;

    fp = fopen(filename, "rb");
 
    if (fp == NULL) 
    {
        printf("Error opening file \n");
        return 1;
    }

    if(fstat(fileno(fp), &file_stat) != 0)
    {
        printf("Error getting file size \n");  
        return 1;
    }

    data_len = file_stat.st_size;
    data = calloc(data_len, 1);

    nbytes = fread(data, 1, data_len, fp);
    if (ferror(fp) || nbytes != data_len)
    {
        printf("File read error\n");
        return 1;
    }

    *out = data;
    fclose(fp);
    return 0;
}

void usage(const char *binary_name)
{
    printf("Usage: %s [ARGS] \n", binary_name);
    printf("--attestation-result [filename]: the file containing JSON object\n");
    printf("--benchmark: if specified, the program will run the benchmark \n");
}

int parse_ear(ar_ear_st *ear_parsed, json_t *root)
{

    size_t i;
    json_t *eat_profile_obj = json_object_get(root, "eat_profile");
    if (json_is_string(eat_profile_obj)) 
    {
        ear_parsed->eat_profile = strdup(json_string_value(eat_profile_obj));
    }

    json_t *iat_obj = json_object_get(root, "iat");
    if (json_is_integer(iat_obj)) 
    {
        ear_parsed->iat = json_integer_value(iat_obj);
    }

    json_t *verifier_id_obj = json_object_get(root, "ear.verifier-id");
    if (json_is_object(verifier_id_obj)) 
    {
        json_t *verifier_build_obj = json_object_get(verifier_id_obj, "build");
        if (json_is_string(verifier_build_obj)) 
        {
            ear_parsed->ear_verifier_id.build = strdup(json_string_value(verifier_build_obj));
        }
        json_t *verifier_developer_obj = json_object_get(verifier_id_obj, "developer");
        if (json_is_string(verifier_developer_obj)) 
        {
            ear_parsed->ear_verifier_id.developer = strdup(json_string_value(verifier_developer_obj));
        }
    }

    json_t *ear_raw_evidence = json_object_get(root, "ear.raw-evidence");
    if (json_is_string(ear_raw_evidence)) {
        ear_parsed->ear_raw_evidence = strdup(json_string_value(ear_raw_evidence));
    }

    json_t *submods_obj = json_object_get(root, "submods");
    if (json_is_object(submods_obj))
    {
        const char *attester_id;
        json_t *appraisal_obj;
        i = 0;
        json_object_foreach(submods_obj, attester_id, appraisal_obj) 
        {
            ar_ear_submod_st submod;
            submod.attester_id = strdup(attester_id);
            if (json_is_object(appraisal_obj)) 
            {
                json_t *status_obj = json_object_get(appraisal_obj, "ear.status");
                if (json_is_string(status_obj)) 
                {
                    submod.ear_appraisal.ear_status = strdup(json_string_value(status_obj));
                }
                json_t *trustworthiness_obj = json_object_get(appraisal_obj, "ear.trustworthiness-vector");
                if (json_is_object(trustworthiness_obj)) 
                {
                    submod.ear_appraisal.has_ear_trustworthiness_vector = 1;

                    json_t *claim = json_object_get(trustworthiness_obj, "instance-identity");
                    if (json_is_integer(claim)) 
                    {
                        submod.ear_appraisal.ear_trustworthiness_vector.instance_identity = json_integer_value(claim);
                    }

                    claim = json_object_get(trustworthiness_obj, "configuration");
                    if (json_is_integer(claim)) 
                    {
                        submod.ear_appraisal.ear_trustworthiness_vector.configuration = json_integer_value(claim);
                    }

                    claim = json_object_get(trustworthiness_obj, "executables");
                    if (json_is_integer(claim)) 
                    {
                        submod.ear_appraisal.ear_trustworthiness_vector.executables = json_integer_value(claim);
                    }

                    claim = json_object_get(trustworthiness_obj, "file-system");
                    if (json_is_integer(claim)) 
                    {
                        submod.ear_appraisal.ear_trustworthiness_vector.file_system = json_integer_value(claim);
                    }

                    claim = json_object_get(trustworthiness_obj, "hardware");
                    if (json_is_integer(claim)) 
                    {
                        submod.ear_appraisal.ear_trustworthiness_vector.hardware = json_integer_value(claim);
                    }

                    claim = json_object_get(trustworthiness_obj, "runtime-opaque");
                    if (json_is_integer(claim)) 
                    {
                        submod.ear_appraisal.ear_trustworthiness_vector.runtime_opaque = json_integer_value(claim);
                    }

                    claim = json_object_get(trustworthiness_obj, "storage-opaque");
                    if (json_is_integer(claim))
                    {
                        submod.ear_appraisal.ear_trustworthiness_vector.storage_opaque = json_integer_value(claim);
                    }

                    claim = json_object_get(trustworthiness_obj, "sourced-data");
                    if (json_is_integer(claim))
                    {
                        submod.ear_appraisal.ear_trustworthiness_vector.sourced_data = json_integer_value(claim);
                    }
            
                } 
                json_t *appraisal_policy_id_obj = json_object_get(appraisal_obj, "ear.appraisal-policy-id");
                if (json_is_string(appraisal_policy_id_obj)) 
                {
                    submod.ear_appraisal.ear_appraisal_policy_id = strdup(json_string_value(appraisal_policy_id_obj));
                }
            }
            ear_parsed->submods[i] = submod;
            i++;
        }
        ear_parsed->num_submods = i;
        
    }

    json_t *eat_nonce_obj = json_object_get(root, "eat.nonce");
    if (json_is_string(eat_nonce_obj)) 
    {
        ear_parsed->eat_nonce = strdup(json_string_value(eat_nonce_obj));
    }

}

void free_ear(ar_ear_st *ear)
{
    free(ear->eat_profile);
    free(ear->ear_verifier_id.build);
    free(ear->ear_verifier_id.developer);
    free(ear->ear_raw_evidence);
    for(int i=0; i < ear->num_submods; i++)
    {
        free(ear->submods[i].attester_id);
        free(ear->submods[i].ear_appraisal.ear_appraisal_policy_id);
    }
}

int print_ear(ar_ear_st *ear_parsed)
{
    int i;

    printf("EAT Profile: %s \n", ear_parsed->eat_profile);

    printf("IAT: %d \n", ear_parsed->iat);

    printf("Verifier Build: %s \n", ear_parsed->ear_verifier_id.build);

    printf("Verifier Developer: %s \n", ear_parsed->ear_verifier_id.developer);


    printf("Raw Evidence: %s \n", ear_parsed->ear_raw_evidence);

    if(ear_parsed->num_submods > 0)
    {
        printf("Submods: \n");
        for(i = 0; i < ear_parsed->num_submods; i++)
        {
            ar_ear_submod_st submod = ear_parsed->submods[i];

            printf("    Attester ID: %s \n", submod.attester_id);
            
            printf("        Status: %s \n", submod.ear_appraisal.ear_status);

            if(submod.ear_appraisal.has_ear_trustworthiness_vector)
            {
                printf("        Trustworthiness Vector: \n");
                printf("            Instance Identity: %i \n",
                submod.ear_appraisal.ear_trustworthiness_vector.instance_identity);
                printf("            Configuration: %i \n",
                submod.ear_appraisal.ear_trustworthiness_vector.configuration);
                printf("            Executables: %i \n",
                submod.ear_appraisal.ear_trustworthiness_vector.executables);
                printf("            File System: %i \n",
                submod.ear_appraisal.ear_trustworthiness_vector.file_system);
                printf("            Hardware: %i \n",
                submod.ear_appraisal.ear_trustworthiness_vector.hardware);
                printf("            Runtime Opaque: %i \n",
                submod.ear_appraisal.ear_trustworthiness_vector.runtime_opaque);
                printf("            Storage Opaque: %i \n",
                submod.ear_appraisal.ear_trustworthiness_vector.storage_opaque);
                printf("            Sourced Data: %i \n",
                submod.ear_appraisal.ear_trustworthiness_vector.sourced_data);
            }

            printf("        Appraisal Policy ID: %s \n", submod.ear_appraisal.ear_appraisal_policy_id);
  
        }
    }

    if(ear_parsed->eat_nonce)
    {
        printf("EAT nonce: %s \n", ear_parsed->eat_nonce);
    }

    return 0;
}

int main(int argc, char **argv)
{
    int i;
    char *ear_data;
    char *filename;
    int err;
    // int benchmark = 0;
    // int generate = 0;

    json_t *root;
    json_error_t error;

    ar_ear_st ear_parsed;

# define PP(opt) \
    do                                                          \
    {                                                           \
        if (i + 1 >= argc)                                      \
        {                                                       \
            printf("Please provide %s\n", #opt);                \
            return 1;                                           \
        }                                                       \
    } while (0)

    if (argc < 2)
    {
        usage(argv[0]);
        return 1;
    }
    for (i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "--attestation-result"))
        {
            PP("Attestation Result");
            filename = argv[i+1];
            i++;
        }
        // else if(!strcmp(argv[i], "--benchmark")){
        //     benchmark = 1;
        // }
        // else if(!strcmp(argv[i], "--generate")){
        //     generate = 1;
        // }
        else 
        {
            printf("Invalid input \n");             
            return 1; 
        }
    }
    

        err = read_file(filename, &ear_data);

        if(err)
        {
            return 1;
        }

        root = json_loads(ear_data, 0, &error);
        free(ear_data);

        if(!root)
        {
            fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
            return 1;
        }

        if(!json_is_object(root))
        {
            fprintf(stderr, "error: AR is not an object\n");
            json_decref(root);
            return 1;
        }


    // if(benchmark)
    // {
    //     clock_t start_time = clock();
    //     for(i = 0; i < 100000; i++)
    //     {
    //         parse_ear(&ear_parsed, root);
    //     }
    //     clock_t end_time = clock();
    //     double time_taken = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
    //     printf("Time taken: %f seconds for %i iterations \n", time_taken, i);
    // }

    // else 
    // {
        parse_ear(&ear_parsed, root);
    // }
 
    json_decref(root);
    print_ear(&ear_parsed);
    free_ear(&ear_parsed);

    return 0;
}

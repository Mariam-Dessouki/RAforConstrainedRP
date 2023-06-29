#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tinycbor/cbor.h>
#include <time.h>

#include "ar_cbor.h"

// gcc -o ar_app ar_cbor.c -ltinycbor
// ./ar_app --generate --output-file test.cbor

int parse_cbor(CborValue *ear_obj, ar_ear_st *ear)
{


    CborValue map;
    if (!cbor_value_is_map(ear_obj)) {
        printf("Invalid CBOR: expected map\n");
        return 1;
    }

    cbor_value_enter_container(ear_obj, &map);
    while (cbor_value_is_valid(&map)) {
        CborError err;
        int key;
        cbor_value_get_int(&map, &key);
        cbor_value_advance(&map);
        size_t n;
        switch(key)
        {
            case CBOR_EAT_PROFILE: 
                err = cbor_value_dup_text_string(&map, &ear->eat_profile, &n, &map);
                // cbor_value_advance(&map);
                if (err)
                    return err;
                break;
            case CBOR_IAT: {
                err = cbor_value_get_int(&map, &ear->iat);
                if(err)
                    return err;
                cbor_value_advance(&map);
                break;
            } 
            case CBOR_VERIFIER_ID: {
                CborValue recursed;
                err = cbor_value_enter_container(&map, &recursed);
                if (err)
                    return err;       // parse error
                int verifier_dev, verifier_build;

                // Verifier Developer
                err = cbor_value_get_int(&recursed, &verifier_dev);
                if(err || verifier_dev != CBOR_VERIFIER_DEVELOPER)
                {
                    printf("Error parsing verifier developer \n");
                    return 1;
                }
                cbor_value_advance(&recursed);
                err = cbor_value_dup_text_string(&recursed, &ear->ear_verifier_id.developer, &n, &recursed);
                
                // cbor_value_calculate_string_length(&recursed,  &n);
                // char test[n];
                // err = cbor_value_copy_text_string(&recursed, &ear->ear_verifier_id.developer, &n, &recursed);
                // printf("verifier devv %s \n", test);
                if (err)
                {
                    printf("Error parsing verifier developer \n");
                    return 1;
                }

                // Verifier Build
                err = cbor_value_get_int(&recursed, &verifier_build);
                if(err || verifier_build != CBOR_VERIFIER_BUILD)
                {
                    printf("Error parsing verifier build \n");
                    return 1;
                }
                cbor_value_advance(&recursed);
                err = cbor_value_dup_text_string(&recursed, &ear->ear_verifier_id.build, &n, &recursed);
                if (err)
                {
                    printf("Error parsing verifier build \n");
                    return 1;
                }
                err = cbor_value_leave_container(&map, &recursed);
                if (err)
                    return err; 

                break;
            }
            case CBOR_RAW_EVIDENCE: {
                err = cbor_value_dup_byte_string(&map, &ear->ear_raw_evidence, &n, &map);
                if (err)
                    return err;
                break;
            } 
            case CBOR_EAT_SUBMODS: {
                CborValue recursed;
                err = cbor_value_enter_container(&map, &recursed);
                if (err)
                    return err;       // parse error
                
                int i = 0;
                while(cbor_value_is_valid(&recursed))
                {
                    ar_ear_submod_st submod;
                    err = cbor_value_dup_text_string(&recursed, &submod.attester_id, &n, &recursed);
                    if (err)
                    {
                        printf("Error parsing attester id \n");
                        return 1;
                    }

                    CborValue ear_appraisal;
                    err = cbor_value_enter_container(&recursed, &ear_appraisal);
                    // Status
                    int appraisal_status;
                    err = cbor_value_get_int(&ear_appraisal, &appraisal_status);
                    if(err || appraisal_status != CBOR_EAR_STATUS)
                    {
                        printf("Error parsing EAR status \n");
                        return 1;
                    }
                    cbor_value_advance(&ear_appraisal);
                    err = cbor_value_get_int(&ear_appraisal, &submod.ear_appraisal.ear_status);
                    cbor_value_advance(&ear_appraisal);

                    // check if trustworthiness vector or profile is present
                    int key;
                    err = cbor_value_get_int(&ear_appraisal, &key);
                    cbor_value_advance(&ear_appraisal);
                    if(key == CBOR_EAR_TRUSTWORTHINESS_VECTOR)
                    {
                        submod.ear_appraisal.has_ear_trustworthiness_vector = 1;
                        CborValue trustworthiness_vector;
                        err = cbor_value_enter_container(&ear_appraisal, &trustworthiness_vector);

                        for(int j=0; j < 8; j++){
                            int claim, verdict;
                            err = cbor_value_get_int(&trustworthiness_vector, &claim);
                            cbor_value_advance(&trustworthiness_vector);
                            if(err){
                                printf("Error reading trustworthiness vector \n");
                                return 1;
                            }
                            err = cbor_value_get_int(&trustworthiness_vector, &verdict);
                            cbor_value_advance(&trustworthiness_vector);
                            if(err){
                                printf("Error reading trustworthiness vector \n");
                                return 1;
                            }
                            switch (claim)
                            {
                            case CBOR_INSTANCE_IDENTITY: {
                                submod.ear_appraisal.ear_trustworthiness_vector.instance_identity = verdict;
                                break;
                            }
                            case CBOR_CONFIGURATION: {
                                submod.ear_appraisal.ear_trustworthiness_vector.configuration = verdict;
                                break;
                            }
                            case CBOR_EXECUTABLES: {
                                submod.ear_appraisal.ear_trustworthiness_vector.executables = verdict;
                                break;
                            }
                            case CBOR_FILE_SYSTEM: {
                                submod.ear_appraisal.ear_trustworthiness_vector.file_system = verdict;
                                break;
                            }
                            case CBOR_HARDWARE: {
                                submod.ear_appraisal.ear_trustworthiness_vector.hardware = verdict;
                                break;
                            }
                            case CBOR_RUNTIME_OPAQUE: {
                                submod.ear_appraisal.ear_trustworthiness_vector.runtime_opaque = verdict;
                                break;
                            }
                            case CBOR_STORAGE_OPAQUE: {
                                submod.ear_appraisal.ear_trustworthiness_vector.storage_opaque = verdict;
                                break;
                            }
                            case CBOR_SOURCED_DATA: {
                                submod.ear_appraisal.ear_trustworthiness_vector.sourced_data = verdict;
                                break;
                            }
                            default:
                                printf("Unknown claim value \n");
                                return 1;
                            }
                        }
                        err = cbor_value_leave_container(&ear_appraisal, &trustworthiness_vector);
                        err = cbor_value_get_int(&ear_appraisal, &key);
                        cbor_value_advance(&ear_appraisal);
                    }
                    if(key == CBOR_EAR_APPRAISAL_POLICY_ID){
                        err = cbor_value_dup_text_string(&ear_appraisal, &submod.ear_appraisal.ear_appraisal_policy_id, &n, &ear_appraisal);
                        if (err)
                        {
                            printf("Error parsing policy id \n");
                            return 1;
                        }
                    }
                    cbor_value_leave_container(&recursed, &ear_appraisal);
                    ear->submods[i] = submod;
                    i++;
                }
                ear->num_submods = i;
                
                err = cbor_value_leave_container(&map, &recursed);
                if (err)
                    return err; 
                break;
            }
            default:
                printf("Malformed CBOR object \n");
                return 1;
        }
    }
    // cbor_value_leave_container(ear_obj, &map);
    return 0;
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
            
            printf("        Status: %i \n", submod.ear_appraisal.ear_status);

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

void usage(const char *binary_name)
{
    printf("Usage: %s [ARGS] \n", binary_name);
    printf("--attestation-result [filename]: the file containing CBOR object\n");
    printf("--generate: if specified, the program will encode ear object \n");
    printf("--output-file [filename]: the file to write CBOR-encoded object to\n");
    printf("--parse: if specified, the program will parse object in attest-result file\n");
}

int read_file(char *filename, char ** out)
{
    FILE *fp;
    unsigned char *data;
    int size;

    fp = fopen(filename, "rb"); // open file in binary mode
    if (fp == NULL) {
        printf("Error opening file.\n");
        return -1;
    }

    // get file size
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    data = calloc(size, 1);

    // read file into buffer
    fread(data, size, 1, fp);
    fclose(fp);
    *out = data;
    return size;
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

int main(int argc, char **argv) {

    ar_ear_st ear;
    CborEncoder encoder;
    uint8_t buffer[512];
    int len;
    int benchmark = 0, generate = 0;
    // char *output_filename;
    char *input_filename;
    int i;
    int rc;

    memset(&ear, 0, sizeof(ear));

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
        // if (!strcmp(argv[i], "--output-file"))
        // {
        //     PP("Output file name");
        //     output_filename = argv[i+1];
        //     i++;
        // }
        // else if(!strcmp(argv[i], "--benchmark")){
        //     benchmark = 1;
        // }
        // else if(!strcmp(argv[i], "--generate")){
        //     generate = 1;
        // }
        // else 
        if (!strcmp(argv[i], "--attestation-result"))
        {
            PP("Attestation result file name");
            input_filename = argv[i+1];
            i++;
        }
        else 
        {
            printf("Invalid input \n");             
            return 1; 
        }
    }

   


    // else
    // {
        char *ear_cbor_byte_array;
        len = read_file(input_filename, &ear_cbor_byte_array);
        if(len < 0)
        {
            printf("Error reading file \n");             
            return 1; 
        }
        CborParser parser;
        CborValue ear_obj, map;
        cbor_parser_init(ear_cbor_byte_array, len, 0, &parser, &ear_obj);

        // if(benchmark)
        // {
        //     clock_t start_time = clock();
        //     for(i = 0; i < 100000; i++)
        //     {
        //         rc = parse_cbor(&ear_obj, &ear);
        //         // free_ear(&ear);
        //     }
        //     clock_t end_time = clock();
        //     double time_taken = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
        //     printf("Time taken: %f seconds for %i iterations \n", time_taken, i);
        //     print_ear(&ear);
        // } 
        // else
        // {
            rc = parse_cbor(&ear_obj, &ear);
            if(!rc)
            {
                print_ear(&ear);
            }
        // }
    
        free(ear_cbor_byte_array);
    // }
    return rc;

}


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tinycbor/cbor.h>

#include "ar_cbor.h"


int write_file(char *filename, uint8_t *buffer, size_t len)
{
    FILE* file = fopen(filename, "wb");
    if (file == NULL)
    {
        perror("Failed to open file");
        return 1;
    }

    if (fwrite(buffer, 1, len, file) != len)
    {
        perror("Failed to write to file");
        fclose(file);
        return 1;
    }
    printf("Wrote to file: %s \n", filename); 
    fclose(file);
    return 0;
}

void generate_cbor(CborEncoder *encoder, ar_ear_st *ear)
{
    int i;
    // start encoding the CBOR object
    cbor_encoder_create_map(encoder, encoder, 5);

    // encode the "tag" key and value
    cbor_encode_int(encoder, CBOR_EAT_PROFILE);
    cbor_encode_text_string(encoder, ear->eat_profile, strlen(ear->eat_profile));

    // encode the "iat" key and value
    cbor_encode_int(encoder, CBOR_IAT);
    cbor_encode_uint(encoder, ear->iat);

    // encode the "ear.verifier-id" key and value
    cbor_encode_int(encoder, CBOR_VERIFIER_ID);
    cbor_encoder_create_map(encoder, encoder, 2);
    cbor_encode_int(encoder, CBOR_VERIFIER_DEVELOPER);
    cbor_encode_text_string(encoder, ear->ear_verifier_id.developer, strlen(ear->ear_verifier_id.developer));
    cbor_encode_int(encoder, CBOR_VERIFIER_BUILD);
    cbor_encode_text_string(encoder, ear->ear_verifier_id.build, strlen(ear->ear_verifier_id.developer));
    cbor_encoder_close_container(encoder, encoder);

    // encode the "ear.raw-evidence" key and value
    cbor_encode_int(encoder, CBOR_RAW_EVIDENCE);
    cbor_encode_byte_string(encoder, (const uint8_t*)ear->ear_raw_evidence, strlen(ear->ear_raw_evidence));

    // encode the "submods" key and value
    cbor_encode_int(encoder, CBOR_EAT_SUBMODS);
    cbor_encoder_create_map(encoder, encoder, ear->num_submods);
    for(i = 0; i < ear->num_submods; i++)
    {
        cbor_encode_text_string(encoder, ear->submods[i].attester_id, strlen(ear->submods[i].attester_id));
        cbor_encoder_create_map(encoder, encoder, 3);
        cbor_encode_int(encoder, CBOR_EAR_STATUS);
        cbor_encode_uint(encoder, ear->submods[i].ear_appraisal.ear_status);

        if(ear->submods[i].ear_appraisal.has_ear_trustworthiness_vector)
        {
            cbor_encode_int(encoder, CBOR_EAR_TRUSTWORTHINESS_VECTOR);
            cbor_encoder_create_map(encoder, encoder, 8);
            cbor_encode_int(encoder, CBOR_INSTANCE_IDENTITY); 
            cbor_encode_int(encoder, ear->submods[i].ear_appraisal.ear_trustworthiness_vector.instance_identity);
            cbor_encode_int(encoder, CBOR_CONFIGURATION); 
            cbor_encode_int(encoder, ear->submods[i].ear_appraisal.ear_trustworthiness_vector.configuration);
            cbor_encode_int(encoder, CBOR_EXECUTABLES); 
            cbor_encode_int(encoder, ear->submods[i].ear_appraisal.ear_trustworthiness_vector.executables);
            cbor_encode_int(encoder, CBOR_FILE_SYSTEM); 
            cbor_encode_int(encoder, ear->submods[i].ear_appraisal.ear_trustworthiness_vector.file_system);
            cbor_encode_int(encoder, CBOR_HARDWARE); 
            cbor_encode_int(encoder, ear->submods[i].ear_appraisal.ear_trustworthiness_vector.hardware);
            cbor_encode_int(encoder, CBOR_RUNTIME_OPAQUE); 
            cbor_encode_int(encoder, ear->submods[i].ear_appraisal.ear_trustworthiness_vector.runtime_opaque);
            cbor_encode_int(encoder, CBOR_STORAGE_OPAQUE); 
            cbor_encode_int(encoder, ear->submods[i].ear_appraisal.ear_trustworthiness_vector.storage_opaque);
            cbor_encode_int(encoder, CBOR_SOURCED_DATA); 
            cbor_encode_int(encoder, ear->submods[i].ear_appraisal.ear_trustworthiness_vector.sourced_data);
            cbor_encoder_close_container(encoder, encoder);
        }

        cbor_encode_int(encoder, CBOR_EAR_APPRAISAL_POLICY_ID);
        cbor_encode_text_string(encoder,
                ear->submods[i].ear_appraisal.ear_appraisal_policy_id,
                strlen(ear->submods[i].ear_appraisal.ear_appraisal_policy_id));
        cbor_encoder_close_container(encoder, encoder);
    }
    cbor_encoder_close_container(encoder, encoder);

}

int main(int argc, char **argv) {

    ar_ear_st ear;
    CborEncoder encoder;
    uint8_t buffer[512];
    size_t len;
    // char *output_filename;
    // int i;
    int rc;

    memset(&ear, 0, sizeof(ear));

// # define PP(opt) \
//     do                                                          \
//     {                                                           \
//         if (i + 1 >= argc)                                      \
//         {                                                       \
//             printf("Please provide %s\n", #opt);                \
//             return 1;                                           \
//         }                                                       \
//     } while (0)

    // if (argc < 2)
    // {
    //     usage(argv[0]);
    //     return 1;
    // }
    // for (i = 1; i < argc; i++)
    // {
    //     if (!strcmp(argv[i], "--output-file"))
    //     {
    //         PP("Output file name");
    //         output_filename = argv[i+1];
    //         i++;
    //     }
    //     // else if(!strcmp(argv[i], "--benchmark")){
    //     //     benchmark = 1;
    //     // }
    //     else if(!strcmp(argv[i], "--generate")){
    //         generate = 1;
    //     }
    //     // else if (!strcmp(argv[i], "--attestation-result"))
    //     // {
    //     //     PP("Attestation result file name");
    //     //     input_filename = argv[i+1];
    //     //     i++;
    //     // }
    //     else 
    //     {
    //         printf("Invalid input \n");             
    //         return 1; 
    //     }
    // }


        // INPUT 1

        ear.eat_profile = "tag:github.com,2023:veraison/ear";
        ear.iat = (unsigned int) 1666529300;
        ear.ear_verifier_id.build = "vts 0.0.1";
        ear.ear_verifier_id.developer = "https://veraison-project.org";
        ear.ear_raw_evidence = "3q2-7w";

        ar_ear_submod_st submod1;
        submod1.attester_id = "CCA Platform";
        submod1.ear_appraisal.ear_status = 2;
        submod1.ear_appraisal.has_ear_trustworthiness_vector = 1;
        submod1.ear_appraisal.ear_trustworthiness_vector.instance_identity = 2;
        submod1.ear_appraisal.ear_trustworthiness_vector.configuration = 2;
        submod1.ear_appraisal.ear_trustworthiness_vector.executables = 3;
        submod1.ear_appraisal.ear_trustworthiness_vector.file_system = 2;
        submod1.ear_appraisal.ear_trustworthiness_vector.hardware = 2;
        submod1.ear_appraisal.ear_trustworthiness_vector.runtime_opaque = 2;
        submod1.ear_appraisal.ear_trustworthiness_vector.storage_opaque = 2;
        submod1.ear_appraisal.ear_trustworthiness_vector.sourced_data = 2;
        submod1.ear_appraisal.ear_appraisal_policy_id = "https://veraison.example/policy/1/60a0068d";
        
        ear.submods[0] = submod1;
        ear.num_submods = 1;

        // INPUT 2

        // ear.eat_profile = "tag:github.com,2023:veraison/ear";
        // ear.iat = (unsigned int) 1666529300;
        // ear.ear_verifier_id.build = "vts 0.0.1";
        // ear.ear_verifier_id.developer = "https://veraison-project.org";
        // ear.ear_raw_evidence = "3q2-7w";

        // ar_ear_submod_st submod1;
        // submod1.attester_id = "CCA Platform";
        // submod1.ear_appraisal.ear_status = 2;
        // submod1.ear_appraisal.has_ear_trustworthiness_vector = 1;
        // submod1.ear_appraisal.ear_trustworthiness_vector.instance_identity = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.configuration = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.executables = 3;
        // submod1.ear_appraisal.ear_trustworthiness_vector.file_system = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.hardware = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.runtime_opaque = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.storage_opaque = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.sourced_data = 2;
        // submod1.ear_appraisal.ear_appraisal_policy_id = "https://veraison.example/policy/1/60a0068d";
        
        // ear.submods[0] = submod1;
        

        // ar_ear_submod_st submod2;
        // submod2.attester_id = "CCA Realm";
        // submod2.ear_appraisal.ear_status = 2;
        // submod2.ear_appraisal.has_ear_trustworthiness_vector = 1;
        // submod2.ear_appraisal.ear_trustworthiness_vector.instance_identity = 2;
        // submod2.ear_appraisal.ear_trustworthiness_vector.configuration = 2;
        // submod2.ear_appraisal.ear_trustworthiness_vector.executables = 3;
        // submod2.ear_appraisal.ear_trustworthiness_vector.file_system = 2;
        // submod2.ear_appraisal.ear_trustworthiness_vector.hardware = 2;
        // submod2.ear_appraisal.ear_trustworthiness_vector.runtime_opaque = 3;
        // submod2.ear_appraisal.ear_trustworthiness_vector.storage_opaque = 2;
        // submod2.ear_appraisal.ear_trustworthiness_vector.sourced_data = 3;
        // submod2.ear_appraisal.ear_appraisal_policy_id = "https://veraison.example/policy/1/60b0068d";
        
        // ear.submods[1] = submod2;
        // ear.num_submods = 2;

        // INPUT 3

        // ear.eat_profile = "tag:github.com,2023:veraison/ear";
        // ear.iat = (unsigned int) 1666529300;
        // ear.ear_verifier_id.build = "vts 0.0.1";
        // ear.ear_verifier_id.developer = "https://veraison-project.org";
        // ear.ear_raw_evidence = "aGV5dGhlcmUsdGhpc2lzbXl0ZXN0Zm9ydGhlZWZmZWN0b2ZyYXdldmlkZW5jZW9udGhlZGF0YWFuZHNpemVvZmVuY29kaW5nLHdob2V2ZXJ0b29rdGhldGltZXRvZGVjb2RldGhpcyx0aGFua3lvdSx5b3VoYXZlbXlhZG1pcmF0aW9uYW5kcGxlYXNlY29udGFjdG1lZm9yYWNoYXRpZnlvdWxpa2Usa3R4YnlleG94b3hveG8=";

        // ar_ear_submod_st submod1;
        // submod1.attester_id = "CCA Platform";
        // submod1.ear_appraisal.ear_status = 2;
        // submod1.ear_appraisal.has_ear_trustworthiness_vector = 1;
        // submod1.ear_appraisal.ear_trustworthiness_vector.instance_identity = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.configuration = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.executables = 3;
        // submod1.ear_appraisal.ear_trustworthiness_vector.file_system = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.hardware = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.runtime_opaque = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.storage_opaque = 2;
        // submod1.ear_appraisal.ear_trustworthiness_vector.sourced_data = 2;
        // submod1.ear_appraisal.ear_appraisal_policy_id = "https://veraison.example/policy/1/60a0068d";
        
        // ear.submods[0] = submod1;
        // ear.num_submods = 1;



         // TODO nonce

        // create a CBOR encoder
        cbor_encoder_init(&encoder, buffer, sizeof(buffer), 0);

        // if(benchmark)
        // {
        //     clock_t start_time = clock();
        //     for(i = 0; i < 100000; i++)
        //     {
                cbor_encoder_init(&encoder, buffer, sizeof(buffer), 0);
                generate_cbor(&encoder, &ear);
                // free_ear(&ear);
        //     }
        //     clock_t end_time = clock();
        //     double time_taken = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
        //     printf("Time taken bt: %f seconds for %i iterations \n", time_taken, i);
        //     print_ear(&ear);
        // } 
        // else
        // {
        //     cbor_encoder_init(&encoder, buffer, sizeof(buffer), 0);
        //     generate_cbor(&encoder, &ear);
        // }

        len = cbor_encoder_get_buffer_size(&encoder, buffer);
        printf("len %i \n", len);
        rc = write_file("output.cbor", buffer, len);

        return rc;

}
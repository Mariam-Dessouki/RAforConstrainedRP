#include <jansson.h>
#include <string.h>
#include <sys/stat.h>
// #include <time.h>

#include "ar_json.h"

// void usage(const char *binary_name)
// {
//     printf("Usage: %s [ARGS] \n", binary_name);
//     printf("--attestation-result [filename]: the file containing JSON object\n");
//     printf("--benchmark: if specified, the program will run the benchmark \n");
// }


int generate_ear(json_t *root, ar_ear_st *ear)
{


    // Add key-value pairs to the object
    json_object_set_new(root, "eat_profile", json_string(ear->eat_profile));
    json_object_set_new(root, "iat", json_integer(ear->iat));
    
    json_t *verifierObject = json_object();
    json_object_set_new(verifierObject, "developer", json_string(ear->ear_verifier_id.developer));
    json_object_set_new(verifierObject, "build", json_string(ear->ear_verifier_id.build));
    json_object_set_new(root, "ear.verifier-id", verifierObject);
    json_object_set_new(root, "ear.raw-evidence", json_string(ear->ear_raw_evidence));

    json_t *submodsObject = json_object();
    for(int i = 0; i < ear->num_submods; i++)
    {
        json_t *submodObject = json_object();

        json_object_set_new(submodObject, "ear.status" , json_string(ear->submods[i].ear_appraisal.ear_status));

        if(ear->submods[i].ear_appraisal.has_ear_trustworthiness_vector)
        {
            json_t *trustworthinessObject = json_object();
            json_object_set_new(trustworthinessObject, "instance-identity", json_integer(ear->submods[i].ear_appraisal.ear_trustworthiness_vector.instance_identity));
            json_object_set_new(trustworthinessObject, "configuration", json_integer(ear->submods[i].ear_appraisal.ear_trustworthiness_vector.configuration));
            json_object_set_new(trustworthinessObject, "executables", json_integer(ear->submods[i].ear_appraisal.ear_trustworthiness_vector.executables));
            json_object_set_new(trustworthinessObject, "file-system", json_integer(ear->submods[i].ear_appraisal.ear_trustworthiness_vector.file_system));
            json_object_set_new(trustworthinessObject, "hardware", json_integer(ear->submods[i].ear_appraisal.ear_trustworthiness_vector.hardware));
            json_object_set_new(trustworthinessObject, "runtime-opaque", json_integer(ear->submods[i].ear_appraisal.ear_trustworthiness_vector.runtime_opaque));
            json_object_set_new(trustworthinessObject, "storage-opaque", json_integer(ear->submods[i].ear_appraisal.ear_trustworthiness_vector.storage_opaque));
            json_object_set_new(trustworthinessObject, "sourced-data", json_integer(ear->submods[i].ear_appraisal.ear_trustworthiness_vector.sourced_data));
            json_object_set_new(submodObject, "ear.trustworthiness-vector" , trustworthinessObject);
        }
        json_object_set_new(submodObject, "ear.appraisal-policy-id" , json_string(ear->submods[i].ear_appraisal.ear_appraisal_policy_id));
        json_object_set_new(submodsObject, ear->submods[i].attester_id, submodObject);
    }

    json_object_set_new(root, "submods", submodsObject);

}

int write_file(json_t *root)
{
     // Open the file for writing
    FILE *file = fopen("testy.json", "w");
    if (!file) {
        fprintf(stderr, "Failed to open the file for writing.\n");
        json_decref(root);
        return 1;
    }

    // Write the JSON object to the file
    int flags = JSON_INDENT(4) | JSON_PRESERVE_ORDER;
    int result = json_dumpf(root, file, flags);

    // Close the file
    fclose(file);
    return 0;
}

int main(int argc, char **argv)
{
    int i;
    // char *ear_data;
    // char *filename;
    // int err;
    // int benchmark = 0;
    // int generate = 0;

    json_t *root = json_object();
    // json_error_t error;


# define PP(opt) \
    do                                                          \
    {                                                           \
        if (i + 1 >= argc)                                      \
        {                                                       \
            printf("Please provide %s\n", #opt);                \
            return 1;                                           \
        }                                                       \
    } while (0)

    // if (argc < 2)
    // {
    //     usage(argv[0]);
    //     return 1;
    // }
    for (i = 1; i < argc; i++)
    {
        // if (!strcmp(argv[i], "--attestation-result"))
        // {
        //     PP("Attestation Result");
        //     filename = argv[i+1];
        //     i++;
        // }
        // else if(!strcmp(argv[i], "--benchmark")){
        //     benchmark = 1;
        // }
        // else if(!strcmp(argv[i], "--generate")){
        //     generate = 1;
        // }
        // else 
        // {
        //     printf("Invalid input \n");             
        //     return 1; 
        // }
    }
    

    // if(generate)
    // {
    
        ar_ear_st ear;
  
        // INPUT 1

        ear.eat_profile = "tag:github.com,2023:veraison/ear";
        ear.iat = (unsigned int) 1666529300;
        ear.ear_verifier_id.build = "vts 0.0.1";
        ear.ear_verifier_id.developer = "https://veraison-project.org";
        ear.ear_raw_evidence = "3q2-7w";

        ar_ear_submod_st submod1;
        submod1.attester_id = "CCA Platform";
        submod1.ear_appraisal.ear_status = "affirming";
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
        // submod1.ear_appraisal.ear_status = "affirming";
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
        // submod2.ear_appraisal.ear_status = "affirming";
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
        // submod1.ear_appraisal.ear_status = "affirming";
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

        // if(benchmark)
        // {
        //     clock_t start_time = clock();
        //     for(i = 0; i < 100000; i++)
        //     {
        //         generate_ear(root, &ear);
        //         json_decref(root);
        //     }
        //     clock_t end_time = clock();
        //     double time_taken = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
        //     printf("Time taken: %f seconds for %i iterations \n", time_taken, i);
        // }
        // else 
        // {
            generate_ear(root, &ear);
        // }
        int result = write_file(root);

        // Check if writing to the file was successful
        if (result != 0) {
            fprintf(stderr, "Failed to write the JSON object to the file.\n");
            json_decref(root);
            return 1;
        }
        printf("JSON object successfully written to output.json.\n");
        // Cleanup: release the JSON object
        json_decref(root);
        
    // }

    

}
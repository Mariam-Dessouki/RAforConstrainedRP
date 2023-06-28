#ifndef AR_DECODER_H
#define AR_DECODER_H

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

#ifndef CBOR_EAT_SUBMODS
# define CBOR_EAT_SUBMODS 266
#endif

#ifndef CBOR_EAR_STATUS
# define CBOR_EAR_STATUS 1000
#endif


int encode_zcbor(uint8_t *payload, int payload_len);
int decode_zcbor(uint8_t *payload, int payload_len);

#endif
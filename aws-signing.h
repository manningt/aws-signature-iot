//
//  aws-signing.h
//
//  creates AWS signature to access AWS-IOT shadow's using REST
//  intended to be used on embedded devices to get desired state, and update reported state
//
//  Created by Tom Manning on 2017-01-23.
//

#ifndef aws_signing_h
#define aws_signing_h

#define BLOCK_LENGTH 64
#define INNER_PADDING '\x36'
#define OUTER_PADDING '\x5c'

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif
#define SHA256_DIGEST_HEX_LENGTH (SHA256_DIGEST_LENGTH *2)+4

#define AWS_KEY_PREFIX "AWS4"
#define AWS_ALGORITHM "AWS4-HMAC-SHA256"
#define AWS_SIGNED_HEADERS "host;x-amz-date"
#define AWS_REQUEST_TYPE "aws4_request"
#define AWS_DATE_LABEL "x-amz-date"

typedef struct {
    const char * method;
    const char * aws_region;
    const char * aws_endpt_prefix;
    const char * aws_service;
    const char * aws_shadow_id;
    const char * aws_access_key;
    const char * aws_secret_key;
    const char * date_time_stamp;
    const char * payload;
} aws_signing_inputs;

typedef struct {
    char date_header[32];
    char auth_header[256];
    char aws_host[64];
    char canonical_uri[64];
} aws_signing_outputs;

void hmac_gen( const uint8_t * const input_key, const uint8_t key_length, uint8_t * const msg, uint8_t hmac_out[SHA256_DIGEST_LENGTH]);

void init_inputs(aws_signing_inputs *input);

int generate_aignature(aws_signing_inputs *input, aws_signing_outputs *output);

#endif /* aws_signing_h */

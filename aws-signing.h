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
#define SHA256_DIGEST_HEX_LENGTH (SHA256_DIGEST_LENGTH *2)+4

#define AWS_KEY_PREFIX "AWS4"
#define AWS_ALGORITHM "AWS4-HMAC-SHA256"
#define AWS_SIGNED_HEADERS "host;x-amz-date"
#define AWS_REQUEST_TYPE "aws4_request"
#define AWS_DATE_LABEL "x-amz-date"

//debug output control:
#define VERBOSE 0
#define VERBOSE_SIGNING_KEY 0
#define DUMMY_TOD_FOR_AMZDATE 0

struct aws_signing_inputs {
    char * method;
    char * aws_region;
    char * aws_endpt_prefix;
    char * aws_service;
    char * aws_shadow_id;
    char * aws_access_key;
    char * aws_secret_key;
    char * payload;
};

struct aws_signing_outputs {
    char date_header[32];
    char auth_header[256];
    char request_url[128];
};

void hmac_gen( const uint8_t * const input_key, const uint8_t key_length, uint8_t * const msg, uint8_t hmac_out[SHA256_DIGEST_LENGTH], uint8_t print_it);

void init_inputs(struct aws_signing_inputs *input);

int generate_aignature(struct aws_signing_inputs *input, struct aws_signing_outputs *output);

void print_inputs(struct aws_signing_inputs *input);

#endif /* aws_signing_h */

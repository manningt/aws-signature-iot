//
//  aws-signing.c
//
//  creates AWS signature to access AWS-IOT shadow's using REST
//  intended to be used on embedded devices to get desired state, and update reported state
//
//  uses this sha2 code: https://github.com/mikejsavage/hmac
//    but [with effort] use others, like: https://github.com/micropython/micropython/blob/master/extmod/crypto-algorithms/sha256.c
//
//  Created by Tom Manning on 2017-01-23.
//

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sha256.h"
#include "aws-signing.h"

void init_inputs(struct aws_signing_inputs *input) {
    //set defaults:
    input->method = "GET";
    input->payload = NULL;
    input->aws_region = "us-east-1";
    input->aws_service = "iotdata";
    //clear mandatory params:
    input->aws_endpt_prefix = NULL;
    input->aws_shadow_id = NULL;
    input->aws_access_key = NULL;
    input->aws_secret_key = NULL;
    return;
}

void hmac_gen( const uint8_t * const input_key, const uint8_t key_length, uint8_t * const msg, uint8_t hmac_out[SHA256_DIGEST_LENGTH], uint8_t print_it) {
    uint8_t key[ BLOCK_LENGTH ];
    uint8_t inner_key[ BLOCK_LENGTH ];
    uint8_t outer_key[ BLOCK_LENGTH ];
    struct sha256 inner_s;
    struct sha256 outer_s;
    uint8_t inner_hash[ SHA256_DIGEST_LENGTH ];
    
    memcpy( key, input_key, key_length );
    memset( key + key_length, '\0', BLOCK_LENGTH - key_length );
    
    for( size_t i = 0; i < BLOCK_LENGTH; i++ ) {
        inner_key[ i ] = key[ i ] ^ INNER_PADDING;
        outer_key[ i ] = key[ i ] ^ OUTER_PADDING;
    }
    sha256_init( &inner_s );
    sha256_update( &inner_s, inner_key, BLOCK_LENGTH );
    
    sha256_update( &inner_s, msg, strlen( (char *) msg ) );
    
    memset( inner_hash, 0, SHA256_DIGEST_LENGTH );
    sha256_sum( &inner_s, inner_hash );
    
    sha256_init( &outer_s );
    sha256_update( &outer_s, outer_key, BLOCK_LENGTH );
    sha256_update( &outer_s, inner_hash, SHA256_DIGEST_LENGTH );
    
    memset( hmac_out, 0, SHA256_DIGEST_LENGTH );
    sha256_sum( &outer_s, hmac_out );
    
    if (print_it) {
        printf("msg: %s   -- key_length: %02d   -- hmac: ", (char*) msg, key_length);
        for( size_t i = 0; i < SHA256_DIGEST_LENGTH; i++ )
            printf( "%02x", hmac_out[ i ] );
        putchar( '\n' );
    }
}

void hash_sha256_hex_gen (const char * const input, char * hex_out) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    struct sha256 digest_s;
    sha256_init( &digest_s );
    if (input != NULL)
        sha256_update( &digest_s, (uint8_t *)input, strlen(input) );
    sha256_sum( &digest_s, digest );
    hex_out[0] = '\0';
    for( size_t i = 0; i < SHA256_DIGEST_LENGTH; i++ )
        sprintf(hex_out, "%s%02x", hex_out, digest[ i ] );
}

int generate_aignature(struct aws_signing_inputs *in, struct aws_signing_outputs *out) {
    
    if (in->aws_endpt_prefix == NULL)
        return -1;
    if (in->aws_shadow_id == NULL)
        return -2;
    if (in->aws_access_key == NULL)
        return -3;
    if (in->aws_secret_key == NULL)
        return -4;

    char date_time_stamp[20];
    char datestamp[12];
    time_t sig_time = time(0);
    struct tm  *tstruct = gmtime(&sig_time);
    strftime(date_time_stamp, sizeof(date_time_stamp), "%Y%m%dT%H%M%SZ", tstruct);
    strftime(datestamp, sizeof(datestamp), "%Y%m%d", tstruct);
    if (DUMMY_TOD_FOR_AMZDATE) sprintf(date_time_stamp, "%sT12:34:56Z", datestamp);
    
    
    // ************* TASK 1: CREATE A CANONICAL REQUEST *************
    char canonical_uri[64];
    sprintf(canonical_uri, "/things/%s/shadow", in->aws_shadow_id);
    if (VERBOSE) printf("canonical_uri length: %03lu  value: %s\n", strlen(canonical_uri), canonical_uri);
    
    char aws_host[64]; // = endpt_prefix + '.' + 'iot' + '.' + aws_region + '.' + 'amazonaws.com'
    sprintf(aws_host, "%s.iot.%s.amazonaws.com", in->aws_endpt_prefix, in->aws_region);

    char canonical_headers[128];// = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'
    sprintf(canonical_headers, "host:%s\n%s:%s\n", aws_host, AWS_DATE_LABEL, date_time_stamp);
    if (VERBOSE) printf("canonical_headers length: %03lu  value: %s\n", strlen(canonical_headers), canonical_headers);
    
    char hmac_payload_hex[ SHA256_DIGEST_HEX_LENGTH ];
    hash_sha256_hex_gen(in->payload, hmac_payload_hex);
    
    char canonical_request[256]; //= method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hmac
    sprintf(canonical_request, "%s\n%s\n\n%s\n%s\n%s", in->method, canonical_uri, canonical_headers, AWS_SIGNED_HEADERS, hmac_payload_hex);
    if (VERBOSE) printf("canonical_request length: %03lu  value: %s\n", strlen(canonical_request), canonical_request);
    
    char hmac_canonical_request_hex[SHA256_DIGEST_HEX_LENGTH];
    hash_sha256_hex_gen(canonical_request, hmac_canonical_request_hex);
    if (VERBOSE) printf("canonical_request hmac hex: %s\n", hmac_canonical_request_hex);
    
    
    //# ************* TASK 2: CREATE THE STRING TO SIGN *************
    char credential_scope[64];
    sprintf(credential_scope, "%s/%s/%s/%s", datestamp, in->aws_region, in->aws_service, AWS_REQUEST_TYPE);
    if (VERBOSE) printf("credential_scope length: %03lu  value: %s\n", strlen(credential_scope), credential_scope);
    
    char string_to_sign[256]; //= algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()
    sprintf(string_to_sign, "%s\n%s\n%s\n%s", AWS_ALGORITHM, date_time_stamp, credential_scope, hmac_canonical_request_hex);
    //sprintf(string_to_sign, "%s", aws_algorithm);
    if (VERBOSE) printf("string_to_sign length: %03lu  value: %s\n", strlen(string_to_sign), string_to_sign);
    
    
    //# ************* TASK 3: CALCULATE THE SIGNATURE *************
    //generate signing key
    uint8_t hmac_signing_interim[ SHA256_DIGEST_LENGTH];
    uint8_t hmac_signing_key[ SHA256_DIGEST_LENGTH];
    char prefixed_secret_key[64] = AWS_KEY_PREFIX;
    strcat(prefixed_secret_key,in->aws_secret_key);
    hmac_gen( (uint8_t *) prefixed_secret_key, strlen(prefixed_secret_key), (uint8_t *)datestamp, hmac_signing_interim, VERBOSE_SIGNING_KEY);
    // key for next step is the hmac from the previous step, 32 bytes (SHA256_DIGEST_LENGTH) hmac_gen will normalize the key to the BLOCK_LENGTH (64)
    hmac_gen( (uint8_t *) &hmac_signing_interim, SHA256_DIGEST_LENGTH, (uint8_t *)in->aws_region, hmac_signing_interim, VERBOSE_SIGNING_KEY);
    hmac_gen( (uint8_t *) &hmac_signing_interim, SHA256_DIGEST_LENGTH, (uint8_t *)in->aws_service, hmac_signing_interim, VERBOSE_SIGNING_KEY);
    hmac_gen( (uint8_t *) &hmac_signing_interim, SHA256_DIGEST_LENGTH, (uint8_t *)AWS_REQUEST_TYPE, hmac_signing_key, VERBOSE_SIGNING_KEY);
    // the previous step produces the signing_key
    
    //then sign the signature
    uint8_t hmac_signature[ SHA256_DIGEST_LENGTH ];
    hmac_gen( (uint8_t *) &hmac_signing_key, SHA256_DIGEST_LENGTH, (uint8_t *)string_to_sign, hmac_signature, 0);
    char hmac_signature_hex[SHA256_DIGEST_HEX_LENGTH];
    memset(hmac_signature_hex, '\0', 4);
    for( size_t i = 0; i < SHA256_DIGEST_LENGTH; i++ )
        sprintf(hmac_signature_hex, "%s%02x", hmac_signature_hex, hmac_signature[ i ] );
    if (VERBOSE) printf("signature hmac hex: %s\n", hmac_signature_hex);
    
    
    //# ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST [headers] *************
    sprintf(out->auth_header, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s", AWS_ALGORITHM, in->aws_access_key, credential_scope, AWS_SIGNED_HEADERS, hmac_signature_hex);
    
    sprintf(out->date_header, "%s: %s", AWS_DATE_LABEL, date_time_stamp);

    sprintf(out->request_url, "https://%s/things/%s/shadow", aws_host, in->aws_shadow_id);
    if (VERBOSE) printf("request_url length: %03lu  value: %s\n", strlen(out->request_url), out->request_url);

    return 0;
}

void print_inputs(struct aws_signing_inputs *inputs) {
    printf("method (m): %s\n", inputs->method);
    printf("aws_region (r): %s\n", inputs->aws_region);
    printf("aws_service (v): %s\n", inputs->aws_service);
    printf("aws_endpt_prefix (e): %s\n", inputs->aws_endpt_prefix);
    printf("aws_shadow_id (s): %s\n", inputs->aws_shadow_id);
    printf("aws_access_key (a): %s\n", inputs->aws_access_key);
    printf("secret_key (k): %s\n", inputs->aws_secret_key);
    printf("payload (p): %s\n", inputs->payload);
}

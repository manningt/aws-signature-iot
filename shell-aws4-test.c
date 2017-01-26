//
//  shell-aws4-test.c
//
//  provides command line interface for aws-signing functions.
//  The output is a valid curl command so it can be piped into a shell:  shell-aws4-test [arguments] | bash
//
//  Created by Tom Manning on 2017-01-23.
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sha256.h"
#include "aws-signing.h"


int main( int argc, char **argv ) {
    struct aws_signing_inputs inputs;
    init_inputs(&inputs);
    int c;
    
    // fill signing_inputs from command line arguments
    while ((c = getopt (argc, argv, "hm:r:e::s::a::k::p:")) != -1)
        switch (c) {
            case 'h':
                printf("usage: %s -m <GET/POST> -r aws_region -e iot_endpt_prefix -s shadow_id -a access_key -k secret_key -p payload (if POST); m,r,p are optional\n", argv[ 0 ] );
                exit(0);
            case 'm':
                inputs.method = optarg;
                break;
            case 'r':
                inputs.aws_region = optarg;
                break;
            case 'e':
                inputs.aws_endpt_prefix = optarg;
                break;
            case 's':
                inputs.aws_shadow_id = optarg;
                break;
            case 'a':
                inputs.aws_access_key = optarg;
                break;
            case 'k':
                inputs.aws_secret_key = optarg;
                break;
            case 'p':
                inputs.payload = optarg;
                break;
            default:
                printf ("Non-option argument %c\n", (char) c);
                abort ();
        }
    
    int index;
    for (index = optind; index < argc; index++)
        printf ("Non-option argument %s\n", argv[index]);


    struct aws_signing_outputs outputs;
    int rc = generate_aignature(&inputs, &outputs);
    
    switch (rc) {
        case 0:
            // output in curl format:
            printf("curl -X %s -H \"%s\" -H \"%s\" ", inputs.method, outputs.date_header, outputs.auth_header);
            if (inputs.payload != NULL) {
                printf("--data \"");
                //escape the quote characters
                for (size_t i = 0; i < strlen(inputs.payload); i++ ) {
                    if (strncmp(&inputs.payload[i],"\"", 1) == 0)
                        putchar('\\');
                    putchar(inputs.payload[i]);
                }
                printf("\" ");
            }
            printf("%s\n", outputs.request_url);
            break;
        case -1:
            printf("Error: missing endpoint_prefix (-e)\n");
            break;
        case -2:
            printf("Error: missing shadow_id (-s)\n");
            break;
        case -3:
            printf("Error: missing aws_access_key (-a)\n");
            break;
        case -4:
            printf("Error: missing aws_secret_key (-k)\n");
            break;
        default:
            printf ("Unknown error code %d\n", rc);
    }
    exit(rc);
}

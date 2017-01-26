# aws-signature-iot
aws signature generator creates headers for the REST API for AWS-IOT shadows

aws-sign.c can run in an embedded environment (like ESP or Photon) so that REST can be used to get and update AWS-IOT shadows. This an alternative to using MQTT + TLS or a webhook.  It does require secure storage of the AWS secret key.

It uses this sha2 code:  https://github.com/mikejsavage/hmac.  The sha256.c/h files are not included in this repository and have to be retrieved seperately.

shell-aws4-test.c provides a command line interface for aws-signing functions.  The output is a valid curl command so it can be piped into a shell:  shell-aws4-test [arguments] | bash

shell-aws4-test.c provides a -h option that describes the command line arguments.

The code has been tested on Mac OS X.  The next step is to test with Photon and then maybe nodeMCU as a C library.

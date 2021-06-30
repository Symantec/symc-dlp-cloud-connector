# symc-dlp-cloud-connector
DLP Cloud Connector Client

This repo contains a python client for the Symantec DLP Cloud Connector API service. Customers or partners can pick it up
and get started, provided they have an instance of DLP Cloud Connector service running. In the future it may contain other
API/SPI schema documents.

# Features
Allows the client to send REST requests using a pre-defined JSON payload to a Symantec DLP Cloud Connector. Client can use alternate payloads by pointing to different files, change the user agent, provide a client certificiate for client auth. In addition the client is able to verify the validity of the server TLS certificate, and perform concurrent requests with multiple itterations.

# Requirements
**NOTE:** You should be able to do a `pip install -r requirements.txt` and have the following with no necessary steps.

The following is required to be installed on the machine where the client is running from:

python 2.x

requests module

argparse module

time module 

json module

multiprocessing module

# Usage

Place the python script and settings.py file in the same directory, the json payload can be placed anywhere because the script requires a path to be provided to it.

example: python rest_client.py -i 10 -c 4 -p /tmp/sample_payload.json

Runs the client to the server with 4 simultaneous connections for 10 itterations, will make 40 requests in total.

usage: rest_client.py [-h] -p PAYLOAD [-a AGENT] [-ci CUSTOMER_ID]
                      [-di DETECTOR_ID] [-de DEVICE_ID] [-uc CERT] [-uk KEY]
                      [-u URL] [-i ITERATIONS] [-c CONCURRENCY] [-v] [-pr]
                      [-e]

Simple REST CDS client

optional arguments:
  -h, --help            show this help message and exit
  
  -p PAYLOAD, --payload PAYLOAD
                        required: json file with payload
                        
  -a AGENT, --agent AGENT
                        optional: string to override the user agent in the
                        settings file
                        
  -ci CUSTOMER_ID, --customer_id CUSTOMER_ID
                        optional: customerId
                        
  -di DETECTOR_ID, --detector_id DETECTOR_ID
                        optional: detectorId
                        
  -de DEVICE_ID, --device_id DEVICE_ID
                        optional: deviceId
                        
  -uc CERT, --cert CERT
                        optional: path to client certificate, used to override
                        the settings file, cert must be used with key
                        
  -uk KEY, --key KEY    optional: path to client key, used to override the
                        settings file, cert must be used with key
                        
  -u URL, --url URL     optional: path to REST server url, used to override
                        the settings file. Example:
                        https://example.com/V1.0/DetectionRequests
                        
  -i ITERATIONS, --iterations ITERATIONS
                        optional: Default is 1. Number of times to send a
                        request, per concurrent process. If user specifies -c
                        2 -i 2 then a total of 4 requests will be sent
                        
  -c CONCURRENCY, --concurrency CONCURRENCY
                        optional: Default is 1. Number of concurrent processes
                        
  -v, --verify          optional: If supplied then verify server certificate
  
  -pr, --process        optional: If supplied process the returned data from
                        REST server
                        
  -e, --exit            Exit on error with a status 1


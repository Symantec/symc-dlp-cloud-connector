#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2017 Symantec Corporation.  All Rights Reserved.

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This script generates a REST request, send the request to a server and displays a response together with the time it
took to receive the response. A http response code is shows in addition to the response. A JSON payload file must be
provided. A user can pass in arguments for the server URL, the user agent, the certificate path and the client key.
"""
import requests
import argparse
import time
import json
from multiprocessing import Process

# import from a settings file for the path to the REST server, client certificate, key and user agent
import settings as settings

# this removes all warnings from requests, depending on your version of urllib3 there might be a warning even for a REST
# server that has a valid certificate
requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description='Simple REST CDS client')
parser.add_argument("-p", "--payload", action="store", dest="payload", required=True,
                    help="required: json file with payload")
parser.add_argument("-a", "--agent", action="store", dest="agent", required=False,
                    help="optional: string to override the user agent in the settings file")
parser.add_argument("-ci", "--customer_id", action="store", dest="customer_id", required=False,
                    help="optional: customerId")
parser.add_argument("-di", "--detector_id", action="store", dest="detector_id", required=False,
                    help="optional: detectorId")
parser.add_argument("-de", "--device_id", action="store", dest="device_id", required=False,
                    help="optional: deviceId")
parser.add_argument("-uc", "--cert", action="store", dest="cert", required=False,
                    help="optional: path to client certificate, used to override the settings file, "
                         "cert must be used with key")
parser.add_argument("-uk", "--key", action="store", dest="key", required=False,
                    help="optional: path to client key, used to override the settings file, cert must be used with key")
parser.add_argument("-u", "--url", action="store", dest="url", required=False,
                    help="optional: path to REST server url, used to override the settings file.\n Example: "
                         "https://example.com/v2.0/DetectionRequests")
parser.add_argument("-i", "--iterations", action="store", dest="iterations", required=False, default=1, type=int,
                    help="optional: Default is 1. Number of times to send a request, per concurrent process. If user "
                         "specifies -c 2 -i 2 then a total of 4 requests will be sent")
parser.add_argument("-c", "--concurrency", action="store", dest="concurrency", required=False, default=1, type=int,
                    help="optional: Default is 1. Number of concurrent processes")
parser.add_argument("-v", "--verify", dest="verify", action='store_true',
                    help="optional: If supplied then verify server certificate")
parser.add_argument("-pr", "--process", dest="process", action='store_true',
                    help="optional: If supplied process the returned data from REST server")
parser.add_argument("-e", "--exit", action="store_true", dest="exit_on_error", required=False, help="Exit on error "
                                                                                                    "with a status 1")

# class that define the REST client object and methods to perform the REST request
class RestCDSClient:
    def __init__(self, url=None, cert=None, customer_id=None, detector_id=None, device_id=None, user_agent=None,
                 exit_on_error=None):
        self.exit_on_error = exit_on_error
        self.url = url
        self.cert = cert
        self.detectorId = detector_id
        self.deviceId = device_id
        self.customerId = customer_id
        self.headers = {'content-type': 'application/json'}
        # additional attributes that can be supplied via the setting file or argparse
        if customer_id is not None:
            self.headers['x-symc-dlp-customerid'] = customer_id
        if detector_id is not None:
            self.headers['x-symc-dlp-detectorid'] = detector_id
        if device_id is not None:
            self.headers['x-symc-client-deviceid'] = device_id
        if user_agent is not None:
            self.headers['User-Agent'] = user_agent

        self.session = None

    def status_request(self, verify=None):
        if self.session is None:
            self.session = requests.Session()
        # record the current timestamp in human readable format
        b1 = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        # current time is seconds since epoch as a floating number
        t1 = time.time()
        try:
            r = self.session.request("GET", self.url + "/Status", cert=self.cert, verify=verify,
                                     headers=self.headers)
            return b1, time.time() - t1, r.status_code, r.text
        except Exception as e:
            self.session = None
            return b1, time.time() - t1, -1, e

    def detection_request(self, payload=None, exit_on_error=None, verify=None, process=None):
        if self.session is None:
            self.session = requests.Session()
        # record the current timestamp in human readable format
        b1 = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        # current time is seconds since epoch as a floating number
        t1 = time.time()
        try:
            r = self.session.request("POST", self.url, cert=self.cert, verify=verify, data=payload,
                                     headers=self.headers)
            if process:
                # logic for parsing the response would go in here
                # if a 201 is received, parse the json result and perform action on it
                if r.status_code == 201:
                    # use json parser to convert to a dictionary
                    result = json.loads(r.text)
                    # at this point client can perform actions based on the result
                    print("requestId: {}".format(result['requestId']))
                    # a violation can have a dictionary of attributes, things like policy id and policy name
                    print("violation: {}".format(result['violation']))
                    # there can be multiple response actions, for example, block, delete, quarantine..etc
                    print("responseAction: {}".format(result['responseAction']))
                    print("warning: {}".format(result['warning']))

                # if status 404 return an error
                if r.status_code == 404:
                    print("Received a 404 message, check you URL path")
                # if a 503 is received, server is overloaded or is down for maintenance
                if r.status_code == 503:
                    print("Server is busy ir down for maintenance")
                # if a 400 is received, bad request is sent
                if r.status_code == 400:
                    print("Bad request is sent")
                # if a 401 is received, client is unauthorized
                if r.status_code == 401:
                    print("Unauthorized")
                # if a 403 is received, forbidden
                if r.status_code == 403:
                    print("Forbidden")
            return b1, time.time() - t1, r.status_code, r.text
        # if exitOnError is specified then exit program, otherwise return timestamp, elapsed time since request, status
        # of "-1" and the exception itself
        except Exception as e:
            if not exit_on_error:
                self.session = None
                return b1, time.time() - t1, -1, e
            else:
                exit(1)

    # close session, this returns the connection back to the pool to be used for another request
    def close(self):
        if self.session is None:
            return
        self.session.close()
        self.session = None


def send_requests(pid, cds_client, file_name,  payload, iterations, exit_on_error, verify, process):
    # using range, in newer python version xrange is removed and range is implemented as xrange
    for i in range(iterations):
        b1, t1, status, text = cds_client.detection_request(payload=payload, exit_on_error=exit_on_error,
                                                            verify=verify, process=process)
        #cds_client.close()
        print("{0}\t{1}\t{2}\t{3}\t{4}\t{5}".format(pid, file_name, b1, t1, status, text))



def main():

    # parse argument
    args = parser.parse_args()
    # read in json payload file
    with open(args.payload) as json_file:
        payload = json_file.read()

    # this block of code checks argparse options and overrides anything that comes from the settings file with supplied
    # values
    # if the user overrides the cert and key then verify that both are supplied, else use the one from the settings file
    if args.cert and args.key:
        cert = (args.cert, args.key)
    # if not supplied then use from setting file
    elif settings.CDS_CERT is not None and settings.CDS_KEY is not None:
        cert = (settings.CDS_CERT, settings.CDS_KEY)
    else:
        cert = None

    # set the url from either the argument passed or from the settings file
    if args.url:
        url = args.url
    else:
        url = settings.CDS_URL

    # set the agent from either the argument passed or from the settings file
    if args.agent:
        user_agent = args.agent
    else:
        user_agent = settings.USER_AGENT

    # number of simultaneous connections
    if args.concurrency == 1:
        cds_client = RestCDSClient(url=url, cert=cert, user_agent=user_agent, customer_id=args.customer_id,
                                   detector_id=args.detector_id, device_id=args.device_id)
        send_requests(1, cds_client, args.payload, payload, args.iterations, args.exit_on_error, args.verify,
                      args.process)
    else:
        processes = []
        # using range, in newer python version xrange is removed and range is implemented as xrange
        for i in range(args.concurrency):
            cds_client = RestCDSClient(url=url, cert=cert, user_agent=user_agent, customer_id=args.customer_id,
                                       detector_id=args.detector_id, device_id=args.device_id)
            p = Process(target=send_requests, args=(i + 1, cds_client, args.payload, payload, args.iterations,
                                                    args.exit_on_error, args.verify, args.process))
            p.start()
            processes.append(p)
        for p in processes:
            p.join()

if __name__ == "__main__":
    main()

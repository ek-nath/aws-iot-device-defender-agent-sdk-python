# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License").
#   You may not use this file except in compliance with the License.
#   A copy of the License is located at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   or in the "license" file accompanying this file. This file is distributed
#   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
#   express or implied. See the License for the specific language governing
#   permissions and limitations under the License.


# Use this code snippet in your app.
# If you need more information about configurations or implementing the sample code, visit the AWS docs:
# https://aws.amazon.com/developers/getting-started/python/

import argparse
import logging
import tempfile
from time import sleep

import boto3
import cbor
import json
import requests
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient

from AWSIoTDeviceDefenderAgentSDK import collector

import os

PRIVATE_KEY = "private_key"
CERTIFICATE = "certificate"
POLICY_NAME = "service_host_agent_policy"

# Variable to track publish metrics response
latest_accepted_report_id = 0


def get_mqtt_endpoint(session, cp_endpoint_url):
    iot = session.client(service_name="iot", endpoint_url=cp_endpoint_url)
    resp = iot.describe_endpoint(endpointType="iot:Data-ATS")
    return resp["endpointAddress"]


def get_instance_metadata():
    return requests.get(
        "http://169.254.169.254/latest/dynamic/instance-identity/document"
    ).json()


def get_region():
    return get_instance_metadata().get("region")


def get_instance_id():
    return get_instance_metadata().get("instanceId")


def get_root_ca():
    url = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"
    ca_text = requests.get(url).text
    ca_temp_file = tempfile.NamedTemporaryFile("w")
    ca_temp_file.write(ca_text)
    ca_temp_file.file.flush()
    return ca_temp_file


def get_client_id():
    return get_instance_id()


def get_cp_endpoint_url(domain, region):
    if domain == "prod":
        return "https://" + region + ".iot.amazonaws.com"
    else:
        return "https://" + domain + "." + region + ".iot.amazonaws.com"


def parse_args():
    parser = argparse.ArgumentParser(fromfile_prefix_chars="@")
    parser.add_argument(
        "-r",
        "--region",
        action="store",
        required=False,
        dest="region",
        help="AWS Region Code (ex: us-east-1), defaults to the region of the instance",
    )
    parser.add_argument(
        "-d",
        "--domain",
        action="store",
        required=False,
        dest="domain",
        help="application domain (ex: prod or gamma), defaults to gamma",
    )
    parser.add_argument(
        "-n",
        "--name",
        action="store",
        required=False,
        dest="name",
        help="Supply a thing name instead of using EC2 Instance Id",
    )
    parser.add_argument(
        "-e",
        "--cp-endpoint-url",
        action="store",
        required=False,
        dest="cp_endpoint_url",
        help="Supply the URL for the control plane APIs, defaults to"
        " https://gamma.us-west-2.iot.amazonaws.com",
    )
    parser.add_argument(
        "-m",
        "--mqtt-endpoint",
        action="store",
        required=False,
        dest="mqtt_endpoint",
        help="Supply the MQTT endpoint to submit metrics to, defaults to"
        " the endpoint retrieved by calling describe-endpoint",
    )
    return parser.parse_args()


def ack_callback(client, userdata, message):
    response_payload = json.loads(message.payload.decode("ASCII"))
    if "json" in message.topic:
        logging.info(
            "Received a new message: {} from topic: {}".format(
                message.payload, message.topic
            )
        )
    else:
        response_payload = json.loads(cbor.loads(message.payload))
        logging.info(
            "Received a new message: {} from topic: {}".format(
                cbor.loads(message.payload), message.topic
            )
        )
    global latest_accepted_report_id
    if "accepted" in message.topic:
        report_id = response_payload.get("reportId")
        latest_accepted_report_id = report_id


def start_metrics_collection(
    region_name, cp_endpoint_url, client_id, iot_client, topic, sample_rate
):
    #  Collector samples metrics from the system, it can track the previous metric to generate deltas
    coll = collector.Collector(False)
    metric = None
    first_sample = (
        True  # don't publish first sample, so we can accurately report delta metrics
    )
    while True:
        logging.info("collecting metrics")
        metric = coll.collect_metrics()
        if first_sample:
            first_sample = False
        else:
            session = boto3.session.Session(region_name=region_name)

            # This is a cheap hack to ensure we reset the creds every so often,
            # since the temporary creds expire. SDK doesn't seem to have a way
            # to reset these creds other than periodically updating these creds
            # by calling iot_client.configureIAMCredentials or subclassing the
            # MQTT client for listening to the onOffline callback. Details in
            # this SIM: https://t.corp.amazon.com/issues/SDK-15249/communication
            credentials = session.get_credentials()
            iot_client.configureIAMCredentials(
                credentials.access_key, credentials.secret_key, credentials.token
            )

            report_id = metric._v1_metrics().get("header").get("report_id")
            iot_client.publish(topic=topic, payload=metric.to_json_string(), QoS=0)
            logging.info("Published report with report_id: {}".format(report_id))

            max_iterations = 5
            while max_iterations > 0:
                # Sleep 10s to allow receiving a response for the latest publish.
                sleep(10)
                max_iterations = max_iterations - 1
                if latest_accepted_report_id == report_id:
                    logging.info(
                        "Received successful ack for reportId: {}".format(
                            latest_accepted_report_id
                        )
                    )
                    break

                logging.info(
                    "Republishing report with reportId: {}, last accepted reportId: {}".format(
                        report_id, latest_accepted_report_id
                    )
                )
                iot_client.publish(topic=topic, payload=metric.to_json_string(), QoS=0)
        sleep(float(sample_rate))


def main():
    logger = logging.getLogger("AWSIoTPythonSDK.core")
    logger.setLevel(logging.DEBUG)
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    args = parse_args()

    if args.region:
        region_name = args.region
    else:
        region_name = get_region()

    if args.domain:
        domain_name = args.domain
    else:
        domain_name = "prod"

    if args.cp_endpoint_url:
        cp_endpoint_url = args.cp_endpoint_url
    else:
        cp_endpoint_url = get_cp_endpoint_url(domain=domain_name, region=region_name)

    session = boto3.session.Session(region_name=region_name)

    if args.name:
        client_id = args.name
    else:
        client_id = (
            get_client_id()
        )  # This will set the client-id based on the ec2 instance id

    if not client_id:
        logging.info("Failed to determine client_id, quitting")
        exit(1)

    logging.info(
        "Running agent with domain: {}, region: {}, clientId: {}, cp_endpoint_url: {}".format(
            domain_name, region_name, client_id, cp_endpoint_url
        )
    )

    ca_cert_file = get_root_ca()

    if args.mqtt_endpoint:
        mqtt_endpoint = args.mqtt_endpoint
    else:
        logging.info("Attempting to retrieve Mqtt endpoint")
        mqtt_endpoint = get_mqtt_endpoint(session, cp_endpoint_url)

    logging.info("Using Mqtt endpoint: {}".format(mqtt_endpoint))

    iot_client = AWSIoTMQTTClient(client_id, useWebsocket=True)
    iot_client.configureEndpoint(mqtt_endpoint, 443, region_name)
    credentials = session.get_credentials()
    iot_client.configureCredentials(ca_cert_file.name)
    iot_client.configureIAMCredentials(
        credentials.access_key, credentials.secret_key, credentials.token
    )

    # AWSIoTMQTTClient connection configuration
    iot_client.configureAutoReconnectBackoffTime(1, 32, 20)
    iot_client.configureOfflinePublishQueueing(-1)  # Infinite offline Publish queueing
    iot_client.configureDrainingFrequency(2)  # Draining: 2 Hz
    iot_client.configureConnectDisconnectTimeout(30)
    iot_client.configureMQTTOperationTimeout(20)  # 5 sec

    # Connect and subscribe to AWS IoT
    iot_client.connect()
    sleep(2)
    topic = "$aws/things/{}/defender/metrics/{}".format(client_id, "json")
    # Subscribe to the accepted/rejected topics to indicate status of published metrics reports
    # topic=subscribe_to_topic, callback=callback, QoS=1,
    iot_client.subscribe(
        topic="{}/accepted".format(topic), callback=ack_callback, QoS=1
    )
    iot_client.subscribe(
        topic="{}/rejected".format(topic), callback=ack_callback, QoS=1
    )

    start_metrics_collection(
        region_name=region_name,
        cp_endpoint_url=cp_endpoint_url,
        client_id=client_id,
        iot_client=iot_client,
        topic=topic,
        sample_rate=300,
    )

    ca_cert_file.close()


if __name__ == "__main__":
    main()

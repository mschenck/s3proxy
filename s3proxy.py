#!/usr/bin/env python2.6

import base64
import re
import string
import sys
import hmac
import hashlib
import logging
import logging.handlers
import time
import simplejson
import ConfigParser

from flask import Flask, render_template, request
app = Flask('Uploader')

from boto.sqs.connection import SQSConnection
from boto.sqs.message import MHMessage

config_file = "s3proxy.conf"
success_path = "upload-success"

def gen_file_policy(success_url="/"):
    file_policy = {}
    file_policy["expiration"] = time.strftime( "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + signature_timeout) )
    file_policy["conditions"] = [
        {"bucket": s3_bucket},
        ["starts-with", "$key", "uploads/"],
        {"acl": "public-read" },
        {"success_action_redirect": success_url },
    ]
    return simplejson.dumps(file_policy)


def encode_policy(policy=None):
    try:
        return base64.b64encode("%s" % policy)
    except Exception, e:
	logging.error("Caught exception in 'encode_policy' for policy [%s]: %s" % (policy, e) )
        return None


def sign_encoded_policy(encoded_policy=None):
    try:
        return base64.b64encode(hmac.new(aws_secret_key, encoded_policy, hashlib.sha1).digest())
    except Exception, e:
	logging.error("Caught exception in 'sign_encoded_policy' for encoded_policy [%s]: %s" % (encoded_policy, e) )
        return None


@app.route("/")
def draw_form():
    url = request.url_root

    # Create upload hash
    try:
        timestamp = time.gmtime()
        hash = base64.encodestring(hmac.new("ID", str(timestamp), hashlib.sha224).hexdigest()).strip()
        success_url = "%s%s?id=%s" % (url, success_path, hash)
    except Exception, e:
        logging.error( "Error generating job hash: %s" % e )

    file_policy = gen_file_policy(success_url)
    policy = encode_policy(file_policy)
    signature = sign_encoded_policy(policy)
    return render_template('index.html', policy=policy, access_key=aws_access_key, \
		signature=signature, url=success_url)


@app.route("/upload-success")
def uploadSuccess():
    hash = request.args.get("id", "")
    bucket = request.args.get("bucket", "")
    key = request.args.get("key", "")
    asset_url = "http://%s.s3.amazonaws.com/%s" % (bucket, key)

    logging.info( "Successful uploaded asset URL: %s" % asset_url )

    # If SQS enabled, create job in uploading state
    if sqs_enabled:
        message = MHMessage()
        message["ID"] = hash
        message["STATUS"] = "READY"
        message["ASSET_URL"] = asset_url
        status = queue.write(message)
        logging.info("Successfully queued asset URL: %s" % asset_url)

    return "Upload Successful! hash=%s" % hash


@app.route("/queue")
def get_queue():
    if sqs_enabled:
        try:
            job_count = queue.count()
            job_queue = queue.get_messages(num_messages=max(1, job_count), visibility_timeout=0)
            return render_template('queue.html', job_count=job_count, job_queue=job_queue)
        except Exception, e:
            return "Unabled to fetch job queue: %s" % e 
    else:
        return "Job queue not enabled"


@app.route("/queue/count")
def get_count():
    if sqs_enabled:
        return str(queue.count())
    else:
        return "-1"


if __name__ == "__main__":
    config = ConfigParser.ConfigParser()
    config.read(config_file)

    logging.getLogger().setLevel(logging.INFO)

    try:
        # AWS auth details
        aws_access_key = config.get("AWSauth", "aws_access_key")
        aws_secret_key = config.get("AWSauth", "aws_secret_key")

        # S3 configuration details
        s3_bucket = config.get("S3config", "s3_bucket")
        signature_timeout = int(config.get("S3config", "signature_timeout"))

        # SQS job queue configuration details
        sqs_enabled = bool(config.get("SQSconfig", "enabled"))
        logging.info("sqs_enabled: %s" % sqs_enabled)
        if sqs_enabled:
            queue_name = config.get("SQSconfig", "queue_name")
            conn = SQSConnection(aws_access_key, aws_secret_key)
            queue = conn.create_queue(queue_name)
            queue.set_message_class(MHMessage)

    except Exception, e:
        logging.error("Error reading config file [%s]: %s" % (config_file, e))    
        sys.exit(1)

    # Start the application
    app.run()

#!/usr/bin/env python2.6

import base64
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
from boto.sqs.message import Message

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
        hash = base64.encodestring(hmac.new("ID", str(timestamp), hashlib.sha1).digest()).strip()
        success_url = "%s%s?id=%s" % (url, success_path, hash)
    except Exception, e:
        logging.error( "Error generating job hash: %s" % e )

    # If SQS enabled, create job in uploading state
    if sqs_enabled:
        message = Message()
        message_dict = {}
        message_dict["ID"] = hash
        message.set_body( simplejson.dumps("%s" % message_dict) )
        status = queue.write(message)

    file_policy = gen_file_policy(success_url)
    policy = encode_policy(file_policy)
    signature = sign_encoded_policy(policy)
    return render_template('index.html', policy=policy, access_key=aws_access_key, \
		signature=signature, url=success_url)

@app.route("/upload-success")
def uploadSuccess():
    hash = request.args.get("id", "")
    logging.info( "Request: %s" % request)
    return "Upload Successful! hash=%s" % hash

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

    except Exception, e:
        logging.error("Error reading config file [%s]: %s" % (config_file, e))    
        sys.exit(1)

    # Start the application
    app.run()

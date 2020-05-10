########################################################################
# File name: xhu.py
# This file is part of: xmpp-http-upload
#
# LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
########################################################################
import atexit
import boto3
import contextlib
import errno
import flask
import fnmatch
import json
import hashlib
import hmac
import pathlib
import typing
import os
import sys
import time

from apscheduler.schedulers.background import BackgroundScheduler
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta

app = flask.Flask("xmpp-http-upload")
app.config.from_envvar("XMPP_HTTP_UPLOAD_CONFIG")
application = app

if app.config.get("S3_ENDPOINT_URL"):
    s3 = boto3.resource("s3", endpoint_url=app.config["S3_ENDPOINT_URL"])
else:
    s3 = boto3.resource("s3")

bucket = s3.Bucket(app.config["DATA_BUCKET"])

def remove_old_uploads():
    for s3object in bucket.objects.all():
        delta = (datetime.now(timezone.utc) - s3object.last_modified)
        if (delta > timedelta(days = app.config["EXPIRE_DAYS"])):
            s3object.delete()

if (int(app.config.get("EXPIRE_DAYS", 0)) > 0):
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=remove_old_uploads, trigger="interval", hours=1)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())

if app.config['ENABLE_CORS']:
    from flask_cors import CORS
    CORS(app)

@app.route("/")
def index():
    return flask.Response(
        "Welcome to XMPP HTTP Upload. State your business.",
        mimetype="text/plain",
    )

@app.route("/<path:path>", methods=["PUT"])
def put_file(path):
    verification_key = flask.request.args.get("v", "")
    length = int(flask.request.headers.get("Content-Length", 0))
    hmac_input = "{} {}".format(path, length).encode("utf-8")
    key = app.config["SECRET_KEY"]
    mac = hmac.new(key, hmac_input, hashlib.sha256)
    digest = mac.hexdigest()

    if not hmac.compare_digest(digest, verification_key):
        return flask.Response(
            "Invalid verification key",
            403,
            mimetype="text/plain",
        )

    content_type = flask.request.headers.get(
        "Content-Type",
        "application/octet-stream",
    )

    try:
        s3object = bucket.Object(path)
        s3object.load()
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            s3object.upload_fileobj(flask.request.stream,
                ExtraArgs={'ContentType': content_type})
            return flask.Response(
                "Created",
                201,
                mimetype="text/plain",
            )
        else:
            raise
    else:
        return flask.Response(
                "Conflict",
                409,
                mimetype="text/plain",
            )



def generate_headers(response_headers):
    content_type = response_headers["Content-Type"]
    for mimetype_glob in app.config.get("NON_ATTACHMENT_MIME_TYPES", []):
        if fnmatch.fnmatch(content_type, mimetype_glob):
            break
        else:
            response_headers["Content-Disposition"] = "attachment"

    response_headers["X-Content-Type-Options"] = "nosniff"
    response_headers["X-Frame-Options"] = "DENY"
    response_headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; sandbox"


@app.route("/<path:path>", methods=["HEAD"])
def head_file(path):
    try:
        s3object = bucket.Object(path)
        s3object.load()
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return flask.Response(
                "Not Found",
                404,
                mimetype="text/plain",
            )
        else:
            raise

    response = flask.Response()
    response.headers["Content-Length"] = s3object.content_length
    response.headers["Content-Type"] = s3object.content_type
    generate_headers(response.headers)
    return response


@app.route("/<path:path>", methods=["GET"])
def get_file(path):
    try:
        s3object = bucket.Object(path)
        s3object.load()
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return flask.Response(
                "Not Found",
                404,
                mimetype="text/plain",
            )
        else:
            raise

    response = flask.make_response(flask.send_file(
        s3object.get()['Body'], mimetype = s3object.content_type
    ))
    response.headers["Content-Length"] = s3object.content_length
    generate_headers(response.headers)
    return response

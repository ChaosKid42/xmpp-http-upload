XMPP HTTP Upload Service (with S3 backend)
##########################################

This provides a Flask-based HTTP service (with S3 backend) which can be used with
prosodys
`mod_http_upload_external <https://modules.prosody.im/mod_http_upload_external.html>`_
or ejabberds
`mod_http_upload <https://docs.ejabberd.im/admin/configuration/modules/#mod-http-upload>`_.

Configuration
=============

The configuration file is specified using the environment variable
``XMPP_HTTP_UPLOAD_CONFIG``. It must contain the full path to the configuration
file.

The configuration file must contain the following keys:

``SECRET_KEY``
    A ``bytes`` object which is the shared secret between the Prosody module
    and this service. See the `mod_http_upload_external documentation
    <https://modules.prosody.im/mod_http_upload_external.html>`_ for details.

``DATA_BUCKET``
    Name of the S3 bucket where service stores the uploaded files.

``NON_ATTACHMENT_MIME_TYPES``
    A list of string globs which specify the content types which are *not* sent
    as attachment. Defaults to the empty list if not given.

    Example use::

        NON_ATTACHMENT_MIME_TYPES = [
            "image/*",
            "video/*",
            "audio/*",
            "text/plain",
        ]

    Everything which does not match any of the entries here will be sent with
    ``Content-Disposition: attachment`` in order to prevent funny attacks.

    It is not recommended to add things like ``text/html`` or ``*`` to this
    list.

``ENABLE_CORS``
  Allow cross-origin access to all endpoints unconditionally. This is needed
  to allow web clients to use the upload feature.

``EXPIRE_DAYS``
  If set to a value greater than 0 xhu.py will remove all files older than
  the given number of days.

``S3_ENDPOINT_URL``
  Set different S3 endpoint, e.g. if you're not using aws.

  Example use::

      S3_ENDPOINT_URL="https://s3.us-west-000.backblazeb2.com"

Issues, Bugs, Limitations
=========================

* This service **does not handle any kind of quota**.
* This blindly trusts the clients Content-Type. I don't think this is a major issue, because we also tell the browser to blindly trust the clients MIME type. This, in addition with forcing all but a white list of MIME types to be downloaded instead of shown inline, should provide safety against any type of XSS attacks.
* I have no idea about web security. The headers I set may be subtly wrong and circumvent all security measures I intend this to have. Please double-check for yourself and report if you find anything amiss.

Example Installation instructions
=================================

Example instructions for debian based systems, if you don't use debian check your distributions repositories for the correct python3 flask package name.
You probably also want to use something else then ``apt-get`` on non debian based distributions.

In this example we will install the flask http server and proxy requests from an already installed and configured webserver (nginx) to the flask http server.
It is also possible to run the python script with ``wsgi`` which should yield in better performance.

I assume your webserver uses ``www-data`` as service account. If you have a different user update the systemd service and the permissions for the data directory.

Clone and install::

    git clone https://github.com/horazont/xmpp-http-upload
    sudo mv xmpp-http-upload /opt/xmpp-http-upload
    cd /opt/xmpp-http-upload
    copy config.example.py config.py
    sudo apt-get install python3-flask

Edit ``config.py`` and change ``SECRET_KEY``. Be sure to only change between ``''``.

Create file ``~/.aws/credentials`` with the following contents::

    [default]
    aws_access_key_id=foo
    aws_secret_access_key=bar

For other options for configuring S3 credentials look
`here <https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html#credentials>`_.

Enable systemd service::

    sudo copy contrib/xmpp-http-upload.service /etc/systemd/system
    sudo systemctl enable xmpp-http-upload.service
    sudo systemctl start xmpp-http-upload.service

Configure your webserver:

As final step you need to point your external webserver to your xmpp-http-upload flask app.
Check the ``contrib`` directory, there is an example for nginx there.

Upload your files to S3:

If you already have a set of files you want to upload to an S3 bucket you might want to look
at the ``contrib/upload_dir_to_s3`` subdir for help.

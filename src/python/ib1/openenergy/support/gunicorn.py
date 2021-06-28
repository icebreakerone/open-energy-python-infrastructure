"""
Support for gunicorn with client certificates, with much help from a blog
at https://eugene.kovalev.systems/blog/flask_client_auth
"""
import gunicorn.app.base
from cryptography import x509
from cryptography.x509 import Certificate
from gunicorn.workers.sync import SyncWorker
import logging
import flask
import certifi
import base64

#: Log to ib1.openenergy.support.gunicorn
LOG = logging.getLogger('ib1.openenergy.support.gunicorn')

#: Name for the header containing the client certificate as a BASE64 encoded DER file
CERT_NAME = 'X-OE-CLIENT-CERT'


def gunicorn_cert_parser() -> Certificate:
    """
    Pull x509 client cert out of the header used by the sync worker defined in this
    package. Header contains BASE64 encoded DER format certificate.

    Use this as the client_cert_parser argument to `AccessTokenValidator` to allow it
    to pull certificates out of the named header.
    """
    cert_bytes = base64.b64decode(flask.request.headers[CERT_NAME])
    return x509.load_der_x509_certificate(data=cert_bytes)


class CustomSyncWorker(SyncWorker):
    """
    Push x509 certificate from SSL context into the named header in BASE64 encoded format. Uses the header
    name defined as `CERT_NAME`
    """

    def handle_request(self, listener, req, client, addr):
        cert_bytes = client.getpeercert(binary_form=True)
        cert = base64.b64encode(cert_bytes)
        LOG.info(f'retrieved client certificate {cert} with type {type(cert)}')
        # Push certificate into headers
        headers = dict(req.headers)
        headers[CERT_NAME] = cert
        req.headers = list(headers.items())
        # Delegate to super
        LOG.info(req.headers)
        super(CustomSyncWorker, self).handle_request(listener, req, client, addr)


class ClientAuthApplication(gunicorn.app.base.BaseApplication):
    """
    GUnicorn application using the custom SSL worker. Uses certifi for its CA store. This is a helper class, mostly
    useful when you need to run a data provider as part of a unit test, all it really does is remove the need for a
    gunicorn.conf.py configuration file. See `this blog <https://eugene.kovalev.systems/blog/flask_client_auth>`_ for
    more details on how to run a data provider within a test context using this class.
    """

    def __init__(self, app, cert_path, key_path, hostname='localhost', port='443', num_workers=4, timeout=30):
        """
        Create a new application runner

        :param app:
            WSGP app to run
        :param cert_path:
            Path to the server certificate
        :param key_path:
            Path to the server private key
        :param hostname:
            Hostname, defaults to 'localhost'
        :param port:
            Port, defaults to 443
        :param num_workers:
            Number of concurrent workers, defaults to 4
        :param timeout:
            Timeout, defaults to 30
        """
        self.options = {
            'bind': f'{hostname}:{port}',
            'workers': num_workers,
            'worker_class': 'ib1.openenergy.support.gunicorn.CustomSyncWorker',
            'timeout': timeout,
            'ca_certs': certifi.where(),
            'certfile': cert_path,
            'keyfile': key_path,
            'cert_reqs': 2,
            'do_handshake_on_connect': True
        }
        self.application = app
        super().__init__()

    def init(self, parser, opts, args):
        return super().init(parser, opts, args)

    def load_config(self):
        """
        Overrides default configuration with that defined in self.options
        """
        config = dict([(key, value) for key, value in self.options.items()
                       if key in self.cfg.settings and value is not None])
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application

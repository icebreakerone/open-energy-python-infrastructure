import logging
import ssl
from argparse import ArgumentParser
from os.path import abspath, isfile

import werkzeug.serving
from cryptography import x509

LOG = logging.getLogger('ib1.oe.support.flask_ssl_dev')


class _PeerCertWSGIRequestHandler(werkzeug.serving.WSGIRequestHandler):
    """
    From https://www.ajg.id.au/2018/01/01/mutual-tls-with-python-flask-and-werkzeug/

    We subclass this class so that we can gain access to the connection
    property. self.connection is the underlying client socket. When a TLS
    connection is established, the underlying socket is an instance of
    SSLSocket, which in turn exposes the getpeercert() method.
    The output from that method is what we want to make available elsewhere
    in the application.
    """

    def make_environ(self):
        """
        The superclass method develops the environ hash that eventually
        forms part of the Flask request object.
        We allow the superclass method to run first, then we insert the
        peer certificate into the hash. That exposes it to us later in
        the request variable that Flask provides
        """
        environ = super(_PeerCertWSGIRequestHandler, self).make_environ()
        LOG.info('Creating environment')
        x509_binary = self.connection.getpeercert(binary_form=True)
        if x509_binary:
            cert = x509.load_der_x509_certificate(x509_binary)
            environ['peercert'] = cert
        else:
            environ['peercert'] = None
        return environ


def get_command_line_ssl_args(default_server_private_key='./a.key',
                              default_server_private_key_password=None,
                              default_server_certificate='./a.pem',
                              default_client_private_key='./b.key',
                              default_client_private_key_password=None,
                              default_client_certificate='./b.pem',
                              default_client_id='CLIENT_ID',
                              default_authority='./ca.pem'):
    """
    Parse command line arguments for SSL file paths and private key password (optional)

    :param default_authority:
        default location for the certificate authority cert, './ca.crt'. This should contain the certificate chain
        needed to validate any client certificate presented, this appears to work with the raidiam root / issuer chain
        combined .pem file
    :param default_certificate:
        default location for app certificate, './app.crt'. This is the certificate the web server is going to use to
        create an HTTPS endpoint, it is not the one from the directory!
    :param default_private_key_password:
        default app private key password, None
    :param default_private_key:
        default location for app private key, './app.key'. This is the private key of the app certificate, and not the
        one you used when creating the raidiam cert.
    :return:
        parsed options object
    :raises ValueError: if any files are not specified, or not found
    """
    parser = ArgumentParser()
    parser.add_argument('-sk', '--server_private_key', type=str,
                        help=f'Server private key file, default "{default_server_private_key}"',
                        default=default_server_private_key)
    parser.add_argument('-sp', '--server_private_key_password', type=str,
                        help='Server private key password if required',
                        default=default_server_private_key_password)
    parser.add_argument('-sc', '--server_certificate', type=str,
                        help=f'Server certificate file, default "{default_server_certificate}"',
                        default=default_server_certificate)
    parser.add_argument('-ck', '--client_private_key', type=str,
                        help=f'Client private key file, default "{default_client_private_key}"',
                        default=default_client_private_key)
    parser.add_argument('-cp', '--client_private_key_password', type=str,
                        help='Client private key password if required',
                        default=default_client_private_key_password)
    parser.add_argument('-cc', '--client_certificate', type=str,
                        help=f'Client certificate file, default "{default_client_certificate}"',
                        default=default_client_certificate)
    parser.add_argument('-cid', '--client_id', type=str, help='OAuth2 client ID for calls made from this app',
                        default=default_client_id)
    parser.add_argument('-a', '--authority', type=str,
                        help=f'Certificate of the CA to verify client certs, default "{default_authority}"',
                        default=default_authority)
    options = parser.parse_args()

    def check_file(f, name):
        """
        Check that a file exists, logging complaints and returning false if it doesn't
        """
        if f:
            path = abspath(f)
            if not (file_found := isfile(path)):
                LOG.error(f'SSL - {name} = {path} not found!')
            else:
                LOG.info(f'SSL - {name} = {path}')
            return file_found
        else:
            return True

    # Require that all files are provided
    if not all([check_file(*f) for f in [(options.authority, 'authority'),
                                         (options.client_certificate, 'client_certificate'),
                                         (options.client_private_key, 'client_private_key'),
                                         (options.server_certificate, 'server_certificate'),
                                         (options.server_private_key, 'server_private_key')
                                         ]]):
        LOG.error('SSL - critical files not found')
        raise ValueError('Critical SSL files not available')

    return options


def run_app(app, *args, server_private_key, server_private_key_password, server_certificate, authority, **kwargs):
    """
    Run the provided app object, parsing command line arguments to get the various SSL parameters
    needed for client cert validation. Checks for existence of SSL related file paths, then runs the supplied
    flask app. This shouldn't be used in production, but is a quick way to spin up an app with HTTPS and client auth
    enabled. Any routes in the resultant app will have access to a client cert (if present) through
    request.environ["peercert"].

    In any real case we'd be running flask behind something like nginx, in which case client certificates are handled
    first by the proxy, and then generally pushed through as an additional header. This mechanism wouldn't work in those
    cases, it really is just for development mode and any access to the client certs should allow for both possible
    mechanisms so that code works in both dev and production contexts.

    :param app: flask app to run with client certificate support
    :param args:
        any additional positional arguments to pass to app.run
    :param server_private_key:
        location of private key file for app SSL
    :param server_private_key_password:
        password for private key, if needed (None if not)
    :param server_certificate:
        app SSL certificate
    :param authority:
        certificate chain to validate app certificate
    :param kwargs:
        any keyword arguments to pass to app.run, ssl_context and request_handler are already
        set up by this function
    """

    # Set up SSL context. This does two things - it enables the HTTPS endpoint, and it
    # also configures the root CA used to validate client certificates, if presented
    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH,
                                             cafile=authority)
    ssl_context.load_cert_chain(certfile=server_certificate,
                                keyfile=server_private_key,
                                password=server_private_key_password)
    # Make the certificate optional otherwise we can't have unprotected
    # endpoints in this server, which would be annoying. The fapi decorator
    # will check for the presence of a certificate when required
    ssl_context.verify_mode = ssl.CERT_OPTIONAL

    app.run(*args, ssl_context=ssl_context,
            request_handler=_PeerCertWSGIRequestHandler, **kwargs)

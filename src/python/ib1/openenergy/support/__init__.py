import ssl
from argparse import ArgumentParser
import OpenSSL
import requests
import werkzeug.serving
import logging
from os.path import abspath, isfile
from time import time, strftime, gmtime

LOG = logging.getLogger('ib1.oe.support')


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
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_binary)
            environ['peercert'] = x509
        else:
            environ['peercert'] = None
        return environ


def run_app(app, *args,
            default_private_key='./app.key',
            default_private_key_password=None,
            default_certificate='./app.crt',
            default_authority='./ca.crt', **kwargs):
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
    :param kwargs:
        any keyword arguments to pass to app.run, ssl_context and request_handler are already
        set up by this function
    """
    parser = ArgumentParser()
    parser.add_argument('-k', '--private_key', type=str,
                        help=f'Server private key file, default "{default_private_key}"',
                        default=default_private_key)
    parser.add_argument('-p', '--private_key_password', type=str,
                        help='Server private key password if required',
                        default=default_private_key_password)
    parser.add_argument('-c', '--certificate', type=str,
                        help=f'Server certificate file, default "{default_certificate}"',
                        default=default_certificate)
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
                                         (options.certificate, 'certificate'),
                                         (options.private_key, 'private_key')]]):
        LOG.error('SSL - critical files not found, exiting')
        exit(-1)

    # Set up SSL context. This does two things - it enables the HTTPS endpoint, and it
    # also configures the root CA used to validate client certificates, if presented
    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH,
                                             cafile=options.authority)
    ssl_context.load_cert_chain(certfile=options.certificate,
                                keyfile=options.private_key,
                                password=options.private_key_password)
    # Make the certificate optional otherwise we can't have unprotected
    # endpoints in this server, which would be annoying. The fapi decorator
    # will check for the presence of a certificate when required
    ssl_context.verify_mode = ssl.CERT_OPTIONAL

    app.run(*args, ssl_context=ssl_context,
            request_handler=_PeerCertWSGIRequestHandler, **kwargs)


class FAPISession:
    """
    Similar to a requests session, but handles management of a single access token. It acquires the token when required,
    manages token expiry etc. Implicitly uses client-credentials, there's no user consent or similar involved.
    """

    def __init__(self, client_id, token_url, requested_scopes, private_key, certificate):
        """
        Build a new FAPI session. This doesn't immediately trigger any requests to the token
        endpoint, these are made when the session is accessed, and only if needed.

        :param token_url:
            URL to the token endpoint of an authorization server, i.e. for the raidiam UAT sandbox this is
            https://matls-auth.directory.energydata.org.uk/token
        :param requested_scopes:
            Scopes requested for this session
        :param private_key:
            Location of private key used for MTLS
        :param certificate:
            Location of certificate used for MTLS
        """
        self.client_id = client_id
        self._session = requests.Session()
        self._session.cert = certificate, private_key
        self.token = None
        self.scopes = requested_scopes
        self.token_url = token_url

    def clear_token(self):
        """
        Explicitly clear the current token, if present. This will force a refresh the next time
        the session is accessed.
        """
        self.token = None

    def _get_token(self) -> str:
        """
        Internal method to fetch a new bearer token if necessary and return it. A new token is
        obtained if there either isn't one, or we have one but it's expired

        :return:
            String representation of the access token
        :raises requests.HTTPError:
            if the token acquisition fails for any reason, this method raises the corresponding
            HTTPError from the requests librar

        """
        now = time()
        if self.token is None or self.token['expiry_time'] <= now:
            response = self._session.post(url=self.token_url,
                                          data={'client_id': self.client_id,
                                                'scope': self.scopes,
                                                'grant_type': 'client_credentials'})
            if response.status_code == 200:
                d = response.json()
                LOG.debug(f'_get_token - response is {d}')
                if 'expires_in' in d:
                    self.token = {'access_token': d['access_token'],
                                  'expiry': now + int(d['expires_in'])}
                    LOG.info(
                        f'_get_token - got access token, expires at '
                        f'{strftime("%b %d %Y %H:%M:%S", gmtime(self.token["expiry"]))}, '
                        f'scope=\'{d["scope"]}\'')
                else:
                    LOG.error(f'_get_token - no expiry time specified in token response {d}')
            else:
                response.raise_for_status()
        return self.token['access_token']

    @property
    def session(self) -> requests.Session:
        """
        Get a configured requests.Session set up with the necessary bearer token and client
        certificates to make a MTLS request to a secured endpoint.
        """
        self._session.headers.update({'Authorization': f'Bearer {self._get_token()}'})
        return self._session

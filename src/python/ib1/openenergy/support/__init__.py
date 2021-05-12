import base64
import email.utils
import http.client
import logging
import uuid
from functools import wraps, partial
from time import time, strftime, gmtime
from typing import Dict

import flask
import requests
from cryptography.hazmat.primitives import hashes
from requests.auth import AuthBase
from cachetools import cached, TTLCache

LOG = logging.getLogger('ib1.oe.support')


def httpclient_logging_patch(level=logging.DEBUG):
    """Enable HTTPConnection debug logging to the logging framework"""

    def httpclient_log(*args):
        logging.getLogger("http.client").log(level, " ".join(args))

    # mask the print() built-in in the http.client module to use
    # logging instead
    http.client.print = httpclient_log
    # enable debugging
    http.client.HTTPConnection.debuglevel = 1


class FAPISession(AuthBase):
    """
    Similar to a requests session, but handles management of a single access token. It acquires the token when required,
    manages token expiry etc. Implicitly uses client-credentials, there's no user consent or similar involved.

    Can also be used as a requests authenticator
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
        self._session.auth = self
        self._plain_session = requests.Session()
        self._plain_session.cert = certificate, private_key
        self._token = None
        self.scopes = requested_scopes
        self.token_url = token_url

    def clear_token(self):
        """
        Explicitly clear the current token, if present. This will force a refresh the next time
        the session is accessed.
        """
        self._token = None

    @property
    def access_token(self):
        return self._get_token()

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
        if self._token is None or self._token['expiry_time'] <= now:
            response = self._plain_session.post(url=self.token_url,
                                                data={'client_id': self.client_id,
                                                      'scope': self.scopes,
                                                      'grant_type': 'client_credentials'})
            if response.status_code == 200:
                d = response.json()
                LOG.debug(f'_get_token - response is {d}')
                if 'expires_in' in d:
                    self._token = {'access_token': d['access_token'],
                                   'expiry_time': now + int(d['expires_in'])}
                    LOG.info(
                        f'_get_token - got access token, expires at '
                        f'{strftime("%b %d %Y %H:%M:%S", gmtime(self._token["expiry_time"]))}, '
                        f'scope=\'{d["scope"] if "scope" in d else "NONE"}\'')
                else:
                    LOG.error(f'_get_token - no expiry time specified in token response {d}')
            else:
                response.raise_for_status()
        return self._token['access_token']

    @property
    def session(self) -> requests.Session:
        """
        Get a configured requests.Session set up with the necessary bearer token and client
        certificates to make a MTLS request to a secured endpoint. Also assigns a new unique
        x-fapi-interaction-id.
        """
        return self._session

    @property
    def plain_session(self) -> requests.Session:
        """
        For convenience, a session configured with the private and public key pair to use TLS but without
        the token management. Use this for calling regular endpoints such as the token introspection one.
        """
        return self._plain_session

    def __call__(self, r):
        """
        Used when acting as an authenticator, including when the authenticated session is accessed. Responsible
        for allocating a unique interaction ID per call as well as supplying (or acquiring) the bearer token and
        including it in the request as needed.
        """
        r.headers.update({'Authorization': f'Bearer {self._get_token()}',
                          'x-fapi-interaction-id': str(uuid.uuid4())})
        return r


def build_error_response(error=None, code=400, scope=None, description=None, uri=None):
    """
    RFC 6750 has a slightly odd way to complain about invalid tokens! This is used in the token authenticator
    class to build responses for invalid or missing tokens.

    :param error:
        One of 'invalid request', 'invalid token', or 'insufficient scope'
    :param code:
        HTTP status code
    :param description:
        Description of the error
    :param uri:
        URL of the page describing the error in detail
    :param scope:
        Scopes required to access the protected resource
    """
    res = flask.Response()
    res.status_code = code
    res.headers.extend(
        {'WWW-Authenticate': f'Bearer ' +
                             (f'error="{error}", ' if error else '') +
                             (f'error_description="{description}", ' if description else '') +
                             (f'error_uri="{uri}", ' if uri else '') +
                             (f'scope="{scope}"' if scope else ''),
         'Cache-Control': 'no-store',
         'Pragma': 'no-cache'})
    return res


class AccessTokenValidator:
    """
    Perform checks on a presented bearer token as defined in section 6.2.1 here
    https://openid.net/specs/openid-financial-api-part-1-1_0-final.html#accessing-protected-resources

    Uses https://tools.ietf.org/html/rfc7662 - OAuth 2.0 Token Introspection to check a supplied bearer token
    against an introspection endpoint for part 6.2.1.13
    """

    LOG = logging.getLogger('ib1.oe.support.validator')

    def __init__(self, client_id: str, private_key: str, certificate: str,
                 introspection_url: str = 'https://matls-auth.directory.energydata.org.uk/token/introspection',
                 client_cert_parser=None):
        """
        Create a new access token validator. In this context the data provider attempting to validate an access token
        is acting as a client to the directory's API, so client_id, private_key and certificate are those of the
        data provider and not the client requesting data from it. These are not the transport keys, they're the ones
        issued by the directory.

        :param client_id:
            OAuth client ID of the data provider, used to authenticate with the introspection endpoint
        :param private_key:
            Location of the private key of the data provider, used in the client auth for the introspection endpoint
        :param certificate:
            Location of the public key of the data provider, used in the client auth for the introspection endpoint
        :param introspection_url:
            URL of the oauth2 introspection endpoint. Defaults to
            https://matls-auth.directory.energydata.org.uk/token/introspection to use our UAT instance of the directory
        :param client_cert_parser:
            A zero argument function which returns an X509 object for the active client certificate, or none if no
            certificate is present. Defaults to a simple implementation that pulls the cert out of the flask environment
            as provided by the local dev mode runner in flask_ssl_dev.py, but should be replaced when running in
            production mode behind e.g. nginx
        """
        self.session = requests.Session()
        self.session.cert = certificate, private_key
        self.introspection_url = introspection_url
        self.client_id = client_id

        def dev_cert_parser():
            """
            Default function to pull x509 certs out of the environment, they're inserted there by the runner in
            flask_ssl_dev, but this should only be used in a development environment.
            :return:
            """
            if 'peercert' in flask.request.environ:
                return flask.request.environ['peercert']
            else:
                return None

        if not client_cert_parser:
            AccessTokenValidator.LOG.warning(
                'using dev ssl cert extractor, if not running in local dev mode this is an error')
        self._cert_parser = client_cert_parser or dev_cert_parser

    @cached(cache=TTLCache(maxsize=1024, ttl=60))
    def inspect_token(self, token: str) -> Dict:
        """
        Send an access token to the introspection endpoint, returning the introspection response

        :param token:
            access token as received as authorization in a request to the data provider's API
        :return:
            object containing parsed JSON response from the introspection endpoint
        """

        # Note - MTLS requires the addition of the client_id to the POST body as the certificate doesn't
        # contain this information. File under 'things that are not immediately obvious about OAuth2...'
        response = self.session.post(url=self.introspection_url,
                                     data={'token': token,
                                           'client_id': self.client_id})
        # If this failed for some reason, raise the appropriate error. This can happen if we're not
        # properly authenticated against the token introspection endpoint itself, it won't happen if we
        # have an invalid or expired token.
        response.raise_for_status()
        return response.json()

    def introspects(self, f=None, scope=None):
        """
        Build a decorator that can be used on flask routes to automatically introspect on any
        provided bearer tokens, passing the resulting object into g.introspection_response. If
        the introspection indicates a failed validation, the underlying route will not be called
        at all and an appropriate error response will be sent.

        Introspection fails if:
            1. Querying the token introspection endpoint fails
            2. A token is returned with active: false
            3. Scope is specified, and the required scope is not in the token scopes
            4. Issued time is in the future
            5. Expiry time is in the past
            6. Certificate binding is enabled (default) and the fingerprint of the presented client cert
               isn't a match for the claim in the introspection response

        If introspection succeeds, the decorated function is called and the Date and x-fapi-interaction-id headers
        injected into the response before returning.
        """
        if not f:
            # If function not specified, decorate self, effectively wrapping the decorator in a
            # second decorator which already includes the scopes argument
            return partial(self.introspects, scope=scope)

        @wraps(f)
        def decorated_function(*args, **kwargs):

            # Deny access to non-MTLS connections
            cert = self._cert_parser()
            if cert is None:
                AccessTokenValidator.LOG.warning('no client cert presented')
                return build_error_response(code=401)

            # Require authorization header with bearer token
            if 'Authorization' in flask.request.headers:
                token_header = flask.request.headers.get('Authorization')

                # Check that this is a bearer token header
                if token_header.lower()[:7] != 'bearer ':
                    AccessTokenValidator.LOG.info('Authorization header does not contain a bearer token')
                    return build_error_response(code=401)

                # Extract the actual token
                token = token_header[7:]
                AccessTokenValidator.LOG.debug(f'found bearer token {token}')
                i_response = self.inspect_token(token=token)
                AccessTokenValidator.LOG.debug(f'introspection response {i_response}')

                # All valid introspection responses contain 'active', as the default behaviour
                # for an invalid token is to create a simple JSON {'active':false} response
                if 'active' not in i_response:
                    AccessTokenValidator.LOG.warning(f'invalid introspection response, does not contain \'active\'')
                    return build_error_response(error='invalid_request', code=400, scope=scope)

                # The response should specify that the token is active
                if i_response['active'] is not True:
                    AccessTokenValidator.LOG.warning(f'token introspection failed, token is not active')
                    return build_error_response(error='invalid_token', code=401, scope=scope)

                # Check token issued and expiry times. This is necessary because we cache the token introspection
                # response, so it's possible to have a token which is marked as valid but is no longer live due to
                # having become invalid within the caching period.
                now = time()
                if 'iat' in i_response:
                    # Issue time must be in the past
                    if now < i_response['iat']:
                        AccessTokenValidator.LOG.warning(f'token issued in the future')
                        return build_error_response(error='invalid_token', code=401, scope=scope)
                if 'exp' in i_response:
                    # Expiry time must be in the future
                    if now > i_response['exp']:
                        AccessTokenValidator.LOG.warning(f'token expired')
                        return build_error_response(error='invalid_token', code=401, scope=scope)

                # If the token response contains a certificate binding then check it against the
                # current client cert. See https://tools.ietf.org/html/rfc8705
                if 'cnf' in i_response:
                    # thumbprint from introspection response
                    sha256 = i_response['cnf']['x5t#S256']
                    # thumbprint from presented client certificate
                    fingerprint = str(base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).replace(b'=', b''),
                                      'utf-8')
                    if fingerprint != sha256:
                        # Mismatch, complain vigorously
                        AccessTokenValidator.LOG.warning(
                            f'introspection response thumbprint {sha256} does not match '
                            f'presented client cert thumbprint {fingerprint}')
                        return build_error_response(error='invalid_token', code=401, scope=scope)
                else:
                    # No CNF claim in the introspection response
                    AccessTokenValidator.LOG.warning('No cnf claim in token response, unable to proceed!')
                    return build_error_response(error='invalid_token', code=401, scope=scope)

                # If we required a particular scope, check that it's in the list of scopes
                # defined for this token. Scope comparison is case insensitive
                if scope:
                    token_scopes = i_response['scope'].lower().split(' ') if 'scope' in i_response else []
                    AccessTokenValidator.LOG.debug(f'found scopes in token {token_scopes}')
                    if scope.lower() not in token_scopes:
                        AccessTokenValidator.LOG.warning(f'scope \'{scope}\' not in token scopes {token_scopes}')
                        return build_error_response(error='insufficient_scope', code=403, scope=scope)

                # Token checks passed, put the token response in g.token_introspection
                flask.g.introspection_response = i_response

                # Call the underlying function, ensure it's a response object
                response = flask.make_response(f(*args, **kwargs))

                # FAPI requires that the resource server set the date header in the response
                response.headers['Date'] = email.utils.formatdate()

                # Get FAPI interaction ID if set, or create a new one otherwise
                if 'x-fapi-interaction-id' in flask.request.headers:
                    fii = flask.request.headers['x-fapi-interaction-id']
                    response.headers['x-fapi-interaction-id'] = fii
                    AccessTokenValidator.LOG.debug(f'using existing interaction ID = {fii}')
                else:
                    fii = str(uuid.uuid4())
                    AccessTokenValidator.LOG.debug(f'issuing new interaction ID = {fii}')
                    response.headers['x-fapi-interaction-id'] = fii

                return response
            else:
                # No authentication provided
                AccessTokenValidator.LOG.warning('no token presented')
                return build_error_response(code=401)

        return decorated_function

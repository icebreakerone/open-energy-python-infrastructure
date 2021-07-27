import base64
import email.utils
import hashlib
import http.client
import inspect
import json
import logging
import secrets
import string
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime
from functools import wraps, partial
from time import time, strftime, gmtime
from typing import Dict, List, Type, TypeVar
from urllib.parse import quote_plus

import flask
import jwt
import requests
from cachetools import cached, TTLCache
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from requests.adapters import HTTPAdapter
from requests.auth import AuthBase
from requests.exceptions import RetryError
from requests.packages.urllib3.util.retry import Retry

import ib1.openenergy.support.raidiam as raidiam

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


def code_verifier(length: int = 128):
    """
    Return a cryptographically random string as specified in RFC7636 section 4.1

    See https://datatracker.ietf.org/doc/html/rfc7636#section-4.1

    :param length:
        length of the generated string, minimum 43, maximum 128. Defaults to 128
    :return:
    """
    vocab = string.ascii_letters + '-._~0123456789'
    return ''.join([secrets.choice(vocab) for _ in range(length)])


class CodeAuthMethod:
    """
    Additional auth logic passed to the FAPISession to enable code grant handling. Handles PKCE (RFC7636)
    """

    def __init__(self, redirect_uri: str, client_id: str, issuer_uri: str):
        """
        Create a new code auth method with empty state, this needs to have a code created before use

        :param redirect_uri:
            The redirect back to the login callback
        :param client_id:
            Client ID, used for validation of response JWT
        :param issuer_uri:
            Issuer URI, used for validation of response JWT
        """
        self.redirect_uri = redirect_uri
        self.client_id = client_id
        self._code = None
        self._refresh_token = None
        # RFC7636 logic (OAuth PKCE)
        self._verifier = code_verifier()
        self._code_challenge = CodeAuthMethod.code_challenge(self._verifier)
        # State, re-use the verifier logic here because why not
        self._state = code_verifier()
        self.issuer_uri = issuer_uri

    def as_jwt(self, secret: str) -> str:
        """
        Serialise the state of this code auth method to a JWT, encoding with the supplied symmetric key

        :param secret:
            Symmetric key used to encode the JWT
        :returns:
            Serialised JWT string represnting this object
        """
        d = {
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'state': self._state,
            'verifier': self._verifier,
            'code_challenge': self._code_challenge,
            'issuer_uri': self.issuer_uri
        }
        if self._code:
            d['code'] = self._code
        if self._refresh_token:
            d['refresh_token'] = self._refresh_token
        return jwt.encode(d, secret, algorithm='HS256')

    @property
    def state(self):
        return self._state

    def invalidate_state(self):
        self._state = code_verifier()

    @staticmethod
    def from_jwt(encoded_jwt: str, secret: str) -> 'CodeAuthMethod':
        """
        Deserialise the supplied JWT, as a string, into a CodeAuthMethod, decoding with the supplied symmetric key

        :param encoded_jwt:
            String containing a JWT
        :param secret:
            Symmetric key used to decode the JWT
        :returns:
            Deserialised instance of `CodeAuthMethod`
        """
        d = jwt.decode(encoded_jwt, secret, algorithms=['HS256'])
        code_auth = CodeAuthMethod(redirect_uri=d['redirect_uri'],
                                   client_id=d['client_id'],
                                   issuer_uri=d['issuer_uri'])
        code_auth._state = d['state']
        code_auth._verifier = d['verifier']
        code_auth._code_challenge = d['code_challenge']
        if 'code' in d:
            code_auth._code = d['code']
        if 'refresh_token' in d:
            code_auth._refresh_token = d['refresh_token']
        return code_auth

    def get_auth_uri(self, scopes: List[str], auth_uri: str):
        """
        Build an appropriate URI for the auth endpoint, including the necessary parameters

        :param scopes:
            Scopes to request, list of strings
        :param auth_uri:
            Base URI of the auth endpoint, query parameters will be added to this
        :return:
            URI of the auth endpoint with appropriate query parameters
        """
        query_data = {'client_id': self.client_id,
                      'redirect_uri': self.redirect_uri,
                      'scope': ' '.join(scopes or []),
                      'state': self._state,
                      'prompt': 'consent',
                      'response_mode': 'fragment.jwt',
                      'response_type': 'code',
                      'code_challenge': self._code_challenge,
                      'code_challenge_method': 'S256'}
        url_parts = list(urllib.parse.urlparse(auth_uri))
        url_parts[4] = urllib.parse.urlencode(query_data, quote_via=urllib.parse.quote)
        LOG.debug(query_data)
        return urllib.parse.urlunparse(url_parts)

    @property
    def code(self):
        return self._code

    @code.setter
    def code(self, value):
        if self._code is None:
            self._code = value
        else:
            raise ValueError(f'attempt to set code, but code is already defined')

    @staticmethod
    def code_challenge(verifier: str):
        """
        Create a code challenge based on a code verifier, as defined by RFC7636 section 4.2

        See https://datatracker.ietf.org/doc/html/rfc7636#section-4.2

        :param verifier:
            code verifier string
        :return:
            code challenge string
        """
        m = hashlib.sha256()
        m.update(verifier.encode(encoding='ASCII'))
        hash_bytes = m.digest()
        return base64.urlsafe_b64encode(hash_bytes).decode(encoding='ASCII').replace('=', '')

    def get_token(self, session, client_id, scopes, openid_configuration):
        """
        Method to either use a refresh token to obtain an access token (if we have one) or
        to use an auth code to get the access / refresh token pair if we don't
        """
        if self._code is None:
            raise ValueError(f'must set code before attempting to acquire access token for client {client_id}')

        def make_request(token_request):
            LOG.debug(f'Attempting to acquire authorization_code token {token_request}')
            response = session.post(url=openid_configuration.token_endpoint,
                                    data=token_request)
            if response.status_code == 200:
                LOG.debug('Acquired authorization_code token')
                j = response.json()
                if 'refresh_token' in j:
                    LOG.debug(f'Acquired refresh token')
                    self._refresh_token = j['refresh_token']
                return j
            LOG.error(f'Unable to acquire authorization_code token : {response.json()}')
            response.raise_for_status()

        if self._refresh_token is None:
            # No refresh token, use the code
            return make_request(token_request={'client_id': client_id,
                                               'scope': scopes,
                                               'grant_type': 'authorization_code',
                                               'code': self._code,
                                               'code_verifier': self._verifier,
                                               'redirect_uri': self.redirect_uri})
        else:
            # Use the refresh token, potentially updating it
            return make_request(token_request={'client_id': client_id,
                                               'scope': scopes,
                                               'grant_type': 'refresh_token',
                                               'refresh_token': self._refresh_token})


class JWTBearerAuthMethod:
    """
    Additional auth logic passed to the FAPISession to enable jwt-bearer tokens
    """

    def __init__(self, jwt_bearer_email: str, signing_private_key: str, signing_key_password: str = None):
        """
        :param jwt_bearer_email:
            This should be the email address of a user to impersonate. This will then
            switch the client to jwt-bearer grant type. This will only work if the corresponding client has been
            provisioned appropriately in the directory itself, otherwise this will fail. It should only ever be used
            by our internal Open Energy clients needing to write to the directory, and can be entirely ignored by other
            users.
        :param signing_private_key:
            Path to private key set as a signing key in the directory.
        :param signing_key_password:
            If specified, will be used as the password when loading the private signing key
        """
        self.jwt_bearer_email = jwt_bearer_email
        with open(signing_private_key, 'rb') as key_file:
            self.signing_private_key = serialization.load_pem_private_key(data=key_file.read(),
                                                                          backend=default_backend(),
                                                                          password=signing_key_password)

    def get_token(self, session, client_id, scopes, openid_configuration):
        """
        Method to get a token using jwt-bearer grant

        :return:
            A dict containing the response from the token endpoint
        :raises:
            HTTPError if the call doesn't return status 200
        """
        if 'urn:ietf:params:oauth:grant-type:jwt-bearer' not in openid_configuration.grant_types_supported:
            raise ValueError(f'Client {client_id} does not support jwt-bearer tokens')
        now = int(time())
        data = {'client_id': client_id,
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'scope': scopes,
                'assertion': jwt.encode({'iss': client_id,
                                         'sub': self.jwt_bearer_email,
                                         'aud': openid_configuration.token_endpoint,
                                         'exp': now + 60 * 1,
                                         'iat': now,
                                         'jti': str(uuid.uuid4())},
                                        key=self.signing_private_key,
                                        algorithm='PS256')}
        LOG.debug(f'Attempting to acquire jwt-bearer token for {self.jwt_bearer_email} : {data}')
        response = session.post(url=openid_configuration.token_endpoint,
                                data=data)
        if response.status_code == 200:
            LOG.debug(f'Acquired jwt-bearer token for {self.jwt_bearer_email}')
            return response.json()
        LOG.error(f'Unable to acquire jwt-bearer token : {response.json()}')
        response.raise_for_status()


class FAPISession(AuthBase):
    """
    Similar to a requests session, but handles management of a single access token. It acquires the token when required,
    manages token expiry etc. Implicitly uses client-credentials, there's no user consent or similar involved.

    Can also be used as a requests authenticator
    """

    def __init__(self, client_id, issuer_url, requested_scopes, private_key, certificate, retries=3, auth_method=None,
                 openid_configuration=None):
        """
        Build a new FAPI session. This doesn't immediately trigger any requests to the token
        endpoint, these are made when the session is accessed, and only if needed.

        :param issuer_url:
            URL of an authorization server, i.e. for the raidiam UAT sandbox this is
            https://matls-auth.directory.energydata.org.uk/
        :param requested_scopes:
            Scopes requested for this session
        :param private_key:
            Location of private key used for MTLS, and to sign
        :param certificate:
            Location of certificate used for MTLS
        :param retries:
            Number of retries that will be used when accessing GET endpoints through the underlying plain and FAPI
            enabled sessions within this object. Defaults to 3, set to 0 to disable retries. Requests which respond
            with statii in [429, 502, 503, 504] will be retried, exponential back-off is applied to avoid overwhelming
            resources.
        :param auth_method:
            If not specified, the FAPISession will use a client_credentials, otherwise the supplied object will be used
            to acquire new tokens. Currently `CodeAuthMethod` and `JWTBearerAuthMethod` are implemented.
        """
        self.client_id = client_id
        self._session = requests.Session()
        self._session.cert = certificate, private_key
        self._session.auth = self
        self.plain_session = requests.Session()
        self.plain_session.cert = certificate, private_key
        self.issuer_url = issuer_url
        self._introspection_response = None

        # Configure retries
        retry_strategy = Retry(total=retries,
                               status_forcelist=[429, 502, 503, 504],
                               method_whitelist=["HEAD", "GET", "OPTIONS"],
                               backoff_factor=1)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount('https://', adapter)
        self._session.mount('http://', adapter)
        self.plain_session.mount('https://', adapter)
        self.plain_session.mount('http://', adapter)

        # Holds the current token state, initially None
        self._token = None

        # If not already specified, retrieve the openid configuration
        if openid_configuration:
            self.openid_configuration = openid_configuration
        else:
            self.openid_configuration = build(cls=OpenIDConfiguration, d=self.plain_session.get(
                OpenIDConfiguration.oidc_configuration_url(self.issuer_url)).json())

        # Check whether the scopes requested are in the supported scopes from the config
        self.scopes = requested_scopes
        for scope in self.scopes.split(' '):
            if scope not in self.openid_configuration.scopes_supported:
                LOG.warning(f'Requested scope "{scope}" not in supported scopes.')

        # Auth-meta specifies alternative token acquisition algorithms, in our case these are used
        # for code and jwt-bearer grants when needed, if not provided we default to client_credentials
        self.auth_method = auth_method

    def as_jwt(self, secret: str) -> str:
        d = {
            'client_id': self.client_id,
            'scopes': self.scopes,
            'private_key': self._session.cert[1],
            'certificate': self._session.cert[0],
            'issuer_url': self.issuer_url
        }
        if self._token:
            d['token'] = self._token
        LOG.debug(f'serialising to jwt {d}')
        return jwt.encode(d, secret, algorithm='HS256')

    @staticmethod
    def from_jwt(encoded_jwt: str, secret: str, openid_configuration=None) -> 'FAPISession':
        d = jwt.decode(encoded_jwt, secret, algorithms=['HS256'])
        LOG.debug(f'restoring from jwt {d}')
        fapi = FAPISession(client_id=d['client_id'],
                           issuer_url=d['issuer_url'],
                           requested_scopes=d['scopes'],
                           private_key=d['private_key'],
                           certificate=d['certificate'],
                           openid_configuration=openid_configuration
                           )
        if 'token' in d:
            fapi._token = d['token']
        return fapi

    @property
    def session(self):
        """
        A requests session configured to automatically acquire tokens when needed and to use MTLS
        """
        return self._session

    def clear_token(self):
        """
        Explicitly clear the current token, if present. This will force a refresh the next time
        the session is accessed.
        """
        self._token = None

    @property
    def access_token(self):
        return self._get_token()

    @property
    def introspection_response(self) -> Dict:
        """
        Introspect on our own token, useful to see what the resource server will see when it asks
        about this client. Fetches once then caches
        """
        if self._introspection_response is None:
            response = self.plain_session.post(url=self.openid_configuration.introspection_endpoint,
                                               data={'token': self.access_token,
                                                     'client_id': self.client_id})
            response.raise_for_status()
            self._introspection_response = response.json()
        return self._introspection_response

    def _get_token(self) -> str:
        """
        Internal method to fetch a new bearer token if necessary and return it. A new token is
        obtained if there either isn't one, or we have one but it's expired. If an alternative
        auth meta object was provided this will be used to acquire the token, otherwise the default
        is to use a client_credentials grant.

        :return:
            String representation of the access token
        :raises requests.HTTPError:
            if the token acquisition fails for any reason, this method raises the corresponding
            HTTPError from the requests library
        """
        now = time()
        if self._token is None or self._token['expiry_time'] <= now:
            if self.auth_method:
                d = self.auth_method.get_token(session=self.plain_session,
                                               client_id=self.client_id,
                                               scopes=self.scopes,
                                               openid_configuration=self.openid_configuration)
            else:
                d = self._get_client_credentials_grant_token()

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
        return self._token['access_token']

    def _get_client_credentials_grant_token(self) -> Dict:
        """
        Method to get a token using client-credentials grant

        :return:
            A dict containing the response from the token endpoint
        :raises:
            HTTPError if the call doesn't return status 200
        """
        data = {'client_id': self.client_id,
                'scope': self.scopes,
                'grant_type': 'client_credentials'}
        LOG.debug(f'Attempting to acquire client_credentials token {data}')
        response = self.plain_session.post(url=self.openid_configuration.token_endpoint,
                                           data=data)
        if response.status_code == 200:
            LOG.debug('Acquired client_credentials token')
            return response.json()
        LOG.error(f'Unable to acquire client_credentials token : {response.json()}')
        response.raise_for_status()

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


def nginx_cert_parser():
    """
    A certificate parser to be used with the `AccessTokenValidator` when running behind nginx or another
    similar proxy which terminates SSL connections and can be configured to push the presented client
    certificate into a header. In this case we use the header ``X-OE-CLIENT-CERT``, this function removes
    any errant tab characters (introduced by nginx for some reason) and parses the contents of this header
    as a PEM format certificate.

    :return:
        A parsed x509 Certificate object, or None if no cert presented in the header
    """
    log = logging.getLogger('ib1.oe.support.nginx_cert_parser')
    try:
        cert_str = flask.request.headers['X-OE-CLIENT-CERT'].replace('\t', '')
        log.info(f'found cert in header \n{cert_str}')
        return x509.load_pem_x509_certificate(cert_str.encode('ASCII'), default_backend())
    except KeyError:
        log.info(f'no header X-OE-CLIENT-CERT in request')
        return None
    except ValueError as ve:
        log.info(f'unable to parse certificate : {str(ve)}')
        return None
    except Exception as fallback:
        log.info(f'unanticipated exception while parsing certificate from header : {str(fallback)}')
        return None


class AccessTokenValidator:
    """
    Perform checks on a presented bearer token as defined in section 6.2.1 here
    https://openid.net/specs/openid-financial-api-part-1-1_0-final.html#accessing-protected-resources

    Uses https://tools.ietf.org/html/rfc7662 - OAuth 2.0 Token Introspection to check a supplied bearer token
    against an introspection endpoint for part 6.2.1.13
    """

    LOG = logging.getLogger('ib1.oe.support.validator')

    def __init__(self, client_id: str, private_key: str, certificate: str,
                 issuer_url: str = 'https://matls-auth.directory.energydata.org.uk/',
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
        :param issuer_url:
            URL of an authorization server, i.e. for the raidiam UAT sandbox this is
            https://matls-auth.directory.energydata.org.uk/ - uses
            https://openid.net/specs/openid-connect-discovery-1_0.html part 4 to discover the token introspection
            endpoint
        :param client_cert_parser:
            A zero argument function which returns an X509 object for the active client certificate, or none if no
            certificate is present. Defaults to a simple implementation that pulls the cert out of the flask environment
            as provided by the local dev mode runner in flask_ssl_dev.py, but should be replaced when running in
            production mode behind e.g. nginx
        """
        self.session = requests.Session()
        self.session.cert = certificate, private_key
        self.openid_configuration = build(cls=OpenIDConfiguration, d=self.session.get(
            OpenIDConfiguration.oidc_configuration_url(issuer_url)).json())
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
        response = self.session.post(url=self.openid_configuration.introspection_endpoint,
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


@dataclass
class OpenIDConfiguration:
    """
    Information returned from the .well-known/openid-configuration document by
    an OpenID provider such as the raidiam authz service.
    """

    token_endpoint: str
    introspection_endpoint: str
    issuer: str
    authorization_endpoint: str
    scopes_supported: List[str]
    grant_types_supported: List[str]
    jwks_uri: str

    @staticmethod
    def oidc_configuration_url(issuer_url: str):
        """
        Implements the logic in 4.1 of https://openid.net/specs/openid-connect-discovery-1_0.html to find the URL
        for the configuration document which can populate an instance of OpenIDConfiguration

        :param issuer_url:
            Base URL of the issuer
        :return:
            URL of the configuration document
        """
        u = urllib.parse.urlparse(issuer_url)
        path = u.path
        if path and path.endswith('/'):
            u = u._replace(path=path + '.well-known/openid-configuration')
        else:
            u = u._replace(path=path + '/.well-known/openid-configuration')
        return urllib.parse.urlunparse(u)


D = TypeVar('D', bound=object)


def build(d: Dict, cls: Type[D], date_format_string='%Y-%m-%dT%H:%M:%S.%fZ') -> D:
    """
    Build a dataclass from a dict, massaging CamelCase form into the more normal pythonic_representation, then
    filtering by properties available to the dataclass constructor before using the filtered set to create a
    new instance of the dataclass. Handles entries which are typed to other dataclasses recursively including
    List[OtherDataClass] types.

    :param d:
        Dict containing properties to pass to constructor
    :param cls:
        Class, typically a dataclass, to receive properties. Should be the class of the root object.
    :param data_format_string:
        Format string to use when parsing dates into datetime objects, defaults to the one we're seeing in the
        Raidiam directory, i.e. "%Y-%m-%dT%H:%M:%S.%fZ"
    :return:
        Instance of cls configured from the supplied dict
    """

    def is_data_class(cls: Type[D]):
        return '__dataclass_fields__' in vars(cls)

    def camelcase_to_python(s: str):
        """
        Convert camelcase name to python convention for function and property names
        """
        result = ''
        for c in s:
            if c.isupper() and result:
                result += '_'
            result += c
        return result.lower()

    def map_field(name, value):
        """
        Handle recursion and collection types, including handling of generic List and similar typing
        """
        field = cls.__dataclass_fields__[name]
        field_type = field.type
        # If this is a generic type like List[Organisation] or similar, pull out
        # the underlying real type
        if '__origin__' in vars(field_type) and field_type._name == 'List':
            field_type = field.type.__args__[0]
        if field_type == datetime:
            # Handle dates, with the format the directory uses
            value = datetime.strptime(value, date_format_string)
        # Handle nested (potential collections of) data classes
        if is_data_class(field_type):
            if isinstance(value, dict):
                return build(value, field_type)
            elif isinstance(value, list):
                return list([build(item, field_type) for item in value])
        # Or just return raw, with date processing applied
        return value

    known_fields = list(cls.__dataclass_fields__.keys())
    try:
        return cls(**{camelcase_to_python(key): map_field(camelcase_to_python(key), d[key])
                      for key in d
                      if camelcase_to_python(key) in known_fields})
    except TypeError as te:
        # Handle this for logging, it's not recoverable, indicates that the data class and
        # the supplied JSON don't match in some fashion
        LOG.error(f'unable to construct instance of {cls} from {d}')
        raise te


class RaidiamDirectory:
    """
    Encapsulates access to the Raidiam Directory, currently just the read API. Parses responses and builds the
    appropriate dataclasses from the `ib1.openenergy.support.raidiam` module.
    """

    def __init__(self, fapi: FAPISession, base_url: str = 'https://matls-dirapi.directory.energydata.org.uk/'):
        self.fapi = fapi
        self.base_url = base_url
        self._jwks_uri = None
        self._ss_id = None

    @property
    def self_org_id(self) -> str:
        """
        Introspect on our own token to get the org ID of the org to which the token was issued
        """
        return self.fapi.introspection_response['organisation_id']

    @property
    def self_ss_id(self) -> str:
        """
        Introspect on our own token to get the software statement ID corresponding to our internal client ID,
        caches the value as this cannot change and we have to traverse the directory model to find it.
        """
        if self._ss_id is None:
            for ss in self.software_statements(org_id=self.self_org_id):
                if ss.client_id is not None and ss.client_id == self.fapi.client_id:
                    self._ss_id = ss.software_statement_id
                    break
        return self._ss_id

    def get_ssa_claims(self, org_id: str, ss_id: str) -> Dict:
        """
        Retrieves the SSA claims (currently does not perform signature verification)

        :param org_id:
            organisation ID
        :param ss_id:
            software statement ID
        :return:
            dict of claims in the SSA
        """
        ssa_response = self.fapi.session.get(
            f'{self.base_url}organisations/{org_id}/softwarestatements/{ss_id}/assertion')
        ssa_response.raise_for_status()
        encoded_jwt = ssa_response.text
        decoded_jwt = jwt.decode(jwt=encoded_jwt, options={"verify_signature": False})
        return decoded_jwt

    def update_client_metadata(self, org_id: str, client_metadata: dict) -> bool:
        """
        Admin users only, this will not work with regular access tokens. This method is only applicable to internal
        Open Energy use, a regular org admin capability will not work with it. The associated session must have the
        ``software:website`` scope using a ``jwt-bearer`` token to impersonate a super-user within the directory. To
        do this the client used must be provisioned for these tokens, which is something only Raidiam can do.

        :param org_id:
            organisation ID, all clients under this org ID will be updated
        :param client_metadata:
            new client metadata to set for all clients within this organisation
        :returns:
            True if the update succeeded, False otherwise
        """
        if client_metadata is None:
            client_metadata = {}
        try:
            u = f'{self.base_url}organisations/{quote_plus(org_id)}/softwarestatements'
            response = self.fapi.session.get(u)
            response.raise_for_status()
            statements = response.json()
            for statement in statements:
                ss_id = statement['SoftwareStatementId']
                LOG.debug(f'RaidiamDirectory.update_client_metadata : updating client metadata '
                          f'for org {org_id}, software statement {ss_id}')
                filtered = {k: statement[k] for k in statement if
                            k in ['ClientName', 'ClientUri', 'Description', 'Environment', 'LogoUri', 'Mode',
                                  'RedirectUri', 'TermsOfServiceUri', 'Version', 'AdditionalSoftwareMetadata']}
                if 'RedirectUri' not in filtered or len(filtered['RedirectUri']) == 0:
                    filtered['RedirectUri'] = ['https://fakeuri.example.org']
                filtered['RedirectUri'] = ['https://127.0.0.1:5001/login/callback']
                filtered['AdditionalSoftwareMetadata'] = json.dumps(client_metadata)
                response = self.fapi.session.put(url=f'{u}/{quote_plus(ss_id)}', json=filtered)
                response.raise_for_status()
            LOG.debug(f'RaidiamDirectory.update_client_metadata : updated {len(statements)} statements')
            return True
        except RetryError:
            LOG.error('RaidiamDirectory.update_client_metadata : max retries exceeded')
        except Exception as e:
            LOG.error(e)
        return False

    def organisations(self) -> List[raidiam.Organisation]:
        return self._resolve(entity_type=raidiam.Organisation, url=f'{self.base_url}organisations', wrap='content')

    def authorisation_servers(self, org_id: str) -> List[raidiam.AuthorisationServer]:
        return self._resolve(entity_type=raidiam.AuthorisationServer,
                             url=f'{self.base_url}organisations/{quote_plus(org_id)}/authorisationservers')

    def _resolve(self, entity_type, url, wrap=None) -> List:
        """
        Retrieve JSON and build entities

        :param entity_type:
            entity type to construct
        :param url:
            URL to query
        :param wrap:
            optional, query this property of the top level item returned by the API call
        :return:
            a list of ``entity_type``
        """
        caller_name = inspect.getouterframes(inspect.currentframe())[1][3]
        try:
            response = self.fapi.session.get(url=url)
            try:
                response.raise_for_status()
            except Exception as e:
                logging.error(f'RaidiamDirectory.{caller_name} {e}')
                return []
            j = response.json()
            if wrap is not None:
                j = j[wrap]
            return [build(entity, entity_type) for entity in j]
        except RetryError:
            logging.error(f'RaidiamDirectory.{caller_name} : max retries exceeded')
            return []

    def software_statements(self, org_id: str) -> List[raidiam.SoftwareStatement]:
        return self._resolve(entity_type=raidiam.SoftwareStatement,
                             url=f'{self.base_url}organisations/{quote_plus(org_id)}/softwarestatements')

    def software_statement_certificates(self, org_id: str, ss_id: str) -> List[raidiam.SoftwareStatementCertificate]:
        return self._resolve(entity_type=raidiam.SoftwareStatementCertificate,
                             url=f'{self.base_url}organisations/{quote_plus(org_id)}'
                                 f'/softwarestatements/{quote_plus(ss_id)}/certificates')

    def admin_users(self, org_id: str):
        return self._resolve(entity_type=raidiam.AdminUser,
                             url=f'{self.base_url}organisations/{quote_plus(org_id)}/adminusers')

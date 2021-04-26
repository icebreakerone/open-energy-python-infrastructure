import http.client
import logging
from functools import wraps, partial
from time import time, strftime, gmtime
from typing import Dict
from http import HTTPStatus
import flask
import requests

from ib1.openenergy.support.func import timed_lru_cache

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
            response = self._session.post(url=self.token_url,
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
        certificates to make a MTLS request to a secured endpoint.
        """
        self._session.headers.update({'Authorization': f'Bearer {self._get_token()}'})
        return self._session

    @property
    def plain_session(self) -> requests.Session:
        """
        For convenience, a session configured with the private and public key pair to use TLS but without
        the token management. Use this for calling regular endpoints such as the token introspection one.
        """
        return self._plain_session


class AccessTokenValidator:
    """
    Uses https://tools.ietf.org/html/rfc7662 - OAuth 2.0 Token Introspection to check a supplied bearer token
    against an introspection endpoint.
    """

    def __init__(self, introspection_url: str, client_id: str, private_key: str, certificate: str):
        """
        Create a new access token validator. In this context the data provider attempting to validate an access token
        is acting as a client to the directory's API, so client_id, private_key and certificate are those of the
        data provider and not the client requesting data from it. These are not the transport keys, they're the ones
        issued by the directory.

        :param introspection_url:
            URL of the oauth2 introspection endpoint
        :param client_id:
            OAuth client ID of the data provider, used to authenticate with the introspection endpoint
        :param private_key:
            Location of the private key of the data provider, used in the client auth for the introspection endpoint
        :param certificate:
            Location of the public key of the data provider, used in the client auth for the introspection endpoint
        """
        self.session = requests.Session()
        self.session.cert = certificate, private_key
        self.introspection_url = introspection_url
        self.client_id = client_id

    @timed_lru_cache(seconds=60)
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
        """
        if not f:
            # If function not specified, decorate self, effectively wrapping the decorator in a
            # second decorator which already includes the scopes argument
            return partial(self.introspects, scope=scope)

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'Authorization' in flask.request.headers:
                token = flask.request.headers.get('Authorization')[7:]
                LOG.debug(f'token was {token}')
                response = self.inspect_token(token=token)
                # All valid introspection responses contain 'active', as the default behaviour
                # for an invalid token is to create a simple JSON {'active':false} response
                if 'active' not in response:
                    LOG.warning(f'invalid introspection response, does not contain "valid"')
                    return 'Not authorized', int(HTTPStatus.UNAUTHORIZED)
                # The response should specify that the token is active
                if not response['active']:
                    LOG.warning(f'token introspection failed, token is not valid')
                    return 'Not authorized', int(HTTPStatus.UNAUTHORIZED)
                # If we required a particular scope, check that it's in the list of scopes
                # defined for this token. Scope comparison is case insensitive
                if scope:
                    token_scopes = response['scope'].lower().split(' ')
                    LOG.info(f'found scopes in token {token_scopes}')
                    if scope.lower() not in token_scopes:
                        LOG.warning(f'scope \'{scope}\' not in token scopes {token_scopes}')
                        return 'Not authorized', int(HTTPStatus.UNAUTHORIZED)
                # Checks passed, put the token response in g.token_introspection
                flask.g.introspection_response = response
            return f(*args, **kwargs)

        return decorated_function

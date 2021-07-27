import logging
from functools import wraps
from typing import Dict, List, Any

import flask
import jwt
from flask import request, redirect, session

from ib1.openenergy.support import FAPISession, CodeAuthMethod, code_verifier, RaidiamDirectory

JWT_SYMMETRIC_KEY_CONFIG = 'ib1.openenergy.support.webclient.config.jwt_symmetric_key'
CODE_AUTH_SESSION_KEY = 'ib1.openenergy.support.webclient.session.code_auth'
FAPI_SESSION_KEY = 'ib1.openenergy.support.webclient.session.fapi'
REDIRECT_AFTER_LOGIN_KEY = 'ib1.openenergy.support.webclient.session.redirect'

LOG = logging.getLogger('ib1.openenergy.support.webclient')


class FAPIFlaskClient:
    """
    Adds routes and security decorators to simplify creation of relying parties using the code grant flow
    """

    def __init__(self, app,
                 client_id: str, client_key: str, client_cert: str, issuer_url: str, auth_url: str, scopes: List[str],
                 login_path: str = 'login',
                 login_callback_path: str = 'login/callback',
                 directory_base_uri: str = 'https://matls-dirapi.directory.energydata.org.uk/'):
        """
        Configure login and callback routes on the supplied app, and expose an @fapi decorator which will use these
        to acquire a `FAPISession` and insert it into flask.g.fapi

        :param app:
            flask app to decorate
        :param client_id:
            client ID
        :param client_key:
            file location of the client private key used for MTLS
        :param client_cert:
            file location of the client certificate used for MTLS
        :param issuer_url:
            issuer URL, used for open ID discovery
        :param auth_url:
            auth URL, this is different from the auth URL in the discovery block in our case so specify it explicitly
        :param scopes:
            list of string scopes to request
        :param login_path:
            path to insert the login route, defaults to 'login'
        :param login_callback_path:
            path to insert the login callback route (GET and POST forms), defaults to 'login/callback'
        """
        app.config[JWT_SYMMETRIC_KEY_CONFIG] = code_verifier()
        self.app = app
        self.login_path = login_path
        _fapi = FAPISession(client_id=client_id, private_key=client_key, certificate=client_cert,
                            issuer_url=issuer_url,
                            requested_scopes='directory:software')
        _directory = RaidiamDirectory(fapi=_fapi, base_url=directory_base_uri)
        app.config['OPENID_CONFIG'] = _fapi.openid_configuration

        class SecurePyJWKClient(jwt.PyJWKClient):

            def __init__(self):
                super().__init__(uri=_fapi.openid_configuration.jwks_uri)

            def fetch_data(self) -> Any:
                LOG.debug(f'fetching JWKS from {self.uri}')
                response = _fapi.plain_session.get(self.uri)
                response.raise_for_status()
                return response.json()

        _jwk_client = SecurePyJWKClient()

        @app.route('/' + login_path)
        def login():
            """
            Create a `CodeAuthMethod`, store it in the session, then use it to build a redirect to the appropriate
            auth endpoint, returning the redirect.
            """
            code_auth = CodeAuthMethod(redirect_uri=request.root_url + login_callback_path, client_id=client_id,
                                       issuer_uri=issuer_url)
            self._store_code_auth(code_auth)
            return redirect(location=code_auth.get_auth_uri(scopes=scopes,
                                                            auth_uri=auth_url))

        @app.route('/' + login_callback_path, methods=['GET'])
        def callback_inner():
            """
            Receives the response JWT as a URL fragment, renders a template which has a very simple form and
            bit of javascript to retrieve the URL fragment (which is only accessible on the client side) and
            POST it to the callback() function below.
            """
            return """<!doctype html><html lang="en-gb"><body><form method='post' id='fragment_form'>
                      <input type='hidden' name='fragment'/></form>
                      <script>
                        form = document.getElementById('fragment_form');
                        form.fragment.value = window.location.hash;
                        history.pushState("", document.title, window.location.pathname
                                                               + window.location.search);
                        form.submit()
                      </script></body></html>"""

        @app.route('/' + login_callback_path, methods=['POST'])
        def callback():
            """
            Handle the callback from the javascript in the page from callback_inner, this posts the URL fragment
            to *this* route, passing the entire fragment in through a form. We can then attempt to pull the JWT
            out of this data and parse it to get success or failure messages along with the necessary details
            to acquire a code
            """
            code_auth = self._get_code_auth()
            # Check we have a valid session
            if code_auth is None or not isinstance(code_auth, CodeAuthMethod):
                raise ValueError('no code_auth defined in session, or invalid type!')

            def parse_urlhash(u: str) -> Dict:
                """
                Parse a fragment string (which may start with an # or not) into multiple key=value
                pairs, returning the result as a dict
                """
                if u.startswith('#'):
                    u = u[1:]
                return {item[0]: item[1] for item in [p.split('=') for p in u.split('&')]}

            # Pull the fragment out of the POSTed data
            if request.form.get('fragment'):
                urlhash = parse_urlhash(request.form.get('fragment'))
                encoded_jwt = urlhash['response']

                # https://openid.net/specs/openid-financial-api-jarm.html#processing-rules
                # 1. Decrypt (optional) - JWTs in our case are not encrypted, so no need
                # for any processing here
                # 6. Obtain key needed to verify, use it to decode the JWT with verification
                # enabled. Also checks (3) iss, (4) client ID match to aud, (5) exp within range

                # TODO - this should be set to True to comply with JARM, but can't find the certs for now
                verify = False
                if verify:
                    signing_key = _jwk_client.get_signing_key_from_jwt(encoded_jwt)
                    decoded_jwt = jwt.decode(jwt=encoded_jwt,
                                             key=signing_key.key,
                                             algorithms=['PS256'],
                                             audience=client_id,
                                             issuer=issuer_url,
                                             options={'require': ['state', 'iss', 'aud', 'exp'],
                                                      'verify_signature': True})
                else:
                    decoded_jwt = jwt.decode(jwt=encoded_jwt,
                                             audience=client_id,
                                             issuer=issuer_url,
                                             options={'require': ['state', 'iss', 'aud', 'exp'],
                                                      'verify_signature': False})

                # (2) Check state parameter, invalidate the code auth state, and fail if mismatch
                jwt_state = decoded_jwt['state']
                auth_state = code_auth.state
                code_auth.invalidate_state()
                if auth_state != jwt_state:
                    raise ValueError('state property mismatch')

                d = {'args': request.args,
                     'jwt': decoded_jwt}
                LOG.info(d)
                code_auth.code = decoded_jwt['code']
            else:
                # No fragment available, complain
                raise ValueError('response not present')

            # If we get here we should have a correctly configured CodeAuthMethod, so use it to build a FAPISession
            f = FAPISession(client_id=client_id, private_key=client_key, certificate=client_cert, issuer_url=issuer_url,
                            requested_scopes=' '.join(scopes),
                            auth_method=code_auth, openid_configuration=app.config['OPENID_CONFIG'])
            # Use the code to get an access token and stash the FAPISession in the requests session
            _ = f.access_token
            self._store_fapi_session(f)

            # Redirect to wherever it was we were going originally
            return redirect(location=session[REDIRECT_AFTER_LOGIN_KEY])

    def _store_code_auth(self, code_auth: CodeAuthMethod):
        """
        Store the code auth to the session as an encrypted JWT
        """
        session[CODE_AUTH_SESSION_KEY] = code_auth.as_jwt(secret=self.app.config[JWT_SYMMETRIC_KEY_CONFIG])

    def _get_code_auth(self) -> CodeAuthMethod:
        """
        Get the code auth from the session, parsing and unscrambling the encrypted JWT
        """
        if CODE_AUTH_SESSION_KEY not in session:
            raise ValueError('no code_auth in requests session!')
        return CodeAuthMethod.from_jwt(session.get(CODE_AUTH_SESSION_KEY),
                                       secret=self.app.config[JWT_SYMMETRIC_KEY_CONFIG])

    def _store_fapi_session(self, fapi: FAPISession):
        """
        Store the FAPISession metadata in the session as an encrypted JWT
        """
        session[FAPI_SESSION_KEY] = fapi.as_jwt(secret=self.app.config[JWT_SYMMETRIC_KEY_CONFIG])

    def get_fapi_session(self) -> FAPISession:
        """
        Restore a FAPISession from the session store
        """
        if FAPI_SESSION_KEY not in session:
            raise ValueError('no fapi session in requests session')
        f = FAPISession.from_jwt(session.get(FAPI_SESSION_KEY),
                                 secret=self.app.config[JWT_SYMMETRIC_KEY_CONFIG],
                                 openid_configuration = self.app.config['OPENID_CONFIG'])
        f.auth_method = self._get_code_auth()
        return f

    def fapi(self, f):
        """
        Build a decorator that can be used on flask routes to indicate that login is required. If this is applied,
        the route thus decorated will pull the `FAPISession` out of the requests session if possible, otherwise
        it will redirect to the login route, eventually redirecting back to the URL of the called route if login
        is successful.
        """

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if FAPI_SESSION_KEY in session:
                flask.g.fapi = self.get_fapi_session()
                return flask.make_response(f(*args, **kwargs))
            else:
                session[REDIRECT_AFTER_LOGIN_KEY] = request.url
                return redirect(request.root_url + self.login_path)

        return decorated_function

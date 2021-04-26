import logging

import flask

from ib1.openenergy.support import AccessTokenValidator
from ib1.openenergy.support.flask_ssl_dev import get_command_line_ssl_args, run_app

logging.basicConfig(level=logging.INFO)

LOG = logging.getLogger('ib1.oe.testapp')

options = get_command_line_ssl_args(default_client_private_key='a.key',
                                    default_client_certificate='a.pem',
                                    default_server_private_key='127.0.0.1/key.pem',
                                    default_server_certificate='127.0.0.1/cert.pem',
                                    default_client_id='kZuAsn7UYZ98WWh29hDPf',
                                    default_authority='raidiam_certificate_chain.pem')

validator = AccessTokenValidator(client_id=options.client_id, certificate=options.client_certificate,
                                 private_key=options.client_private_key,
                                 introspection_url='https://matls-auth.directory.energydata.org.uk/token/introspection')
app = flask.Flask(__name__)


@app.route('/')
@validator.introspects(scope='directory:software')
def homepage():
    """
    This is a very simple route that doesn't do much, but as it's decorated with the validator
    token introspection endpoint it will trigger inspection of the supplied bearer token via the
    directory introspection point, and the resultant object will be passed in to the route.

    :param introspection_respose:
        Introspection result from a supplied bearer token, or None if no token was supplied
    """
    LOG.info(f'home: received MTLS HTTPS request from {flask.request.remote_addr}')
    LOG.info(f'home: token introspection response is {flask.g.introspection_response}')
    return '<html><body><h1>Success</h1></body></html>'


run_app(app=app,
        server_private_key=options.server_private_key,
        server_certificate=options.server_certificate,
        server_private_key_password=options.server_private_key_password,
        authority=options.authority)

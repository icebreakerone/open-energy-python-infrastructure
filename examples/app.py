import logging

import flask

from icebreakerone.trust import AccessTokenValidator
from icebreakerone.trust.flask_ssl_dev import get_command_line_ssl_args, run_app

logging.basicConfig(level=logging.INFO)

LOG = logging.getLogger('icebreakerone.trust.testapp')

options = get_command_line_ssl_args(default_client_private_key='a.key',
                                    default_client_certificate='a.pem',
                                    default_server_private_key='127.0.0.1/key.pem',
                                    default_server_certificate='127.0.0.1/cert.pem',
                                    default_client_id='kZuAsn7UYZ98WWh29hDPf')

validator = AccessTokenValidator(client_id=options.client_id, certificate=options.client_certificate,
                                 private_key=options.client_private_key,
                                 issuer_url='https://matls-auth.directory.energydata.org.uk/')
app = flask.Flask(__name__)


@app.route('/')
@validator.introspects(scope='')
def homepage():
    """
    This is a very simple route that doesn't do much, but as it's decorated with the validator
    token introspection endpoint it will trigger inspection of the supplied bearer token via the
    directory introspection point, and the resultant object will be passed as flask.g.introspection_response.
    """
    LOG.info(f'home: received MTLS HTTPS request from {flask.request.remote_addr}')
    LOG.info(f'home: token introspection response is {flask.g.introspection_response}')
    return flask.send_from_directory(directory='/home/tom/Desktop/data-provider',
                                     filename='Postcode_level_all_meters_electricity_2019.csv')


run_app(app=app,
        server_private_key=options.server_private_key,
        server_certificate=options.server_certificate)

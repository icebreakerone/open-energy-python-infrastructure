import logging

import flask

from ib1.openenergy.support import AccessTokenValidator
from ib1.openenergy.support.gunicorn import gunicorn_cert_parser

LOG = logging.getLogger('ib1.oe.testapp')

validator = AccessTokenValidator(client_id='kZuAsn7UYZ98WWh29hDPf', certificate='/home/tom/Desktop/certs/a.pem',
                                 private_key='/home/tom/Desktop/certs/a.key',
                                 issuer_url='https://matls-auth.directory.energydata.org.uk/',
                                 client_cert_parser=gunicorn_cert_parser)
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

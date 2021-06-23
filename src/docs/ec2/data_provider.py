import logging

import flask
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ib1.openenergy.support import AccessTokenValidator

LOG = logging.getLogger('example.energydata.org.uk')

logging.basicConfig(level=logging.INFO)


def nginx_cert_parser():
    """
    Pull certificate out of X-OE-CLIENT-CERT header from nginx
    """
    cert_str = flask.request.headers['X-OE-CLIENT-CERT'].replace('\t', '')
    LOG.info(f'found cert in header \n{cert_str}')
    return x509.load_pem_x509_certificate(cert_str.encode('ASCII'), default_backend())


validator = AccessTokenValidator(client_id='olQh4BLV0mQUaM3OZbpXy',
                                 certificate='/home/ec2-user/certs/a.pem',
                                 private_key='/home/ec2-user/certs/a.key',
                                 issuer_url='https://matls-auth.directory.energydata.org.uk/',
                                 client_cert_parser=nginx_cert_parser)
app = flask.Flask(__name__)


@app.route('/<path:data_file>')
@validator.introspects(scope='')
def homepage(data_file):
    """
    This is a very simple route that doesn't do much, but as it's decorated with the validator
    token introspection endpoint it will trigger inspection of the supplied bearer token via the
    directory introspection point, and the resultant object will be passed as
    flask.g.introspection_response.
    """
    LOG.info(f'home: token introspection response is {flask.g.introspection_response}')
    return flask.send_from_directory('/home/ec2-user/shared_data', data_file + '.csv')

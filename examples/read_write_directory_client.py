import logging
import pprint
from ib1.openenergy.support import FAPISession, httpclient_logging_patch, build, OpenIDConfiguration

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                    level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')

# httpclient_logging_patch(level=logging.INFO)

# Set up a session, this will get a token from the directory when needed
f = FAPISession(client_id='4_egpDo0lMugQbMOaNjn0',
                issuer_url='https://matls-auth.directory.energydata.org.uk',
                requested_scopes='directory:software openid profile email',
                private_key='/home/tom/Desktop/jwt-bearer-certs/transport.key',
                certificate='/home/tom/Desktop/jwt-bearer-certs/transport.pem',
                signing_private_key='/home/tom/Desktop/jwt-bearer-certs/signing.key',
                jwt_bearer_email='tom.oinn@icebreakerone.org')

# Pretty print the config
pp = pprint.PrettyPrinter()
pp.pprint(f.openid_configuration.__dict__)
# Attempt to introspect on our own token, this causes a request to get the token in the first place
pp.pprint(f.introspection_response)

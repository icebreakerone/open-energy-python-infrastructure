from ib1.openenergy.support import FAPISession
import logging
import pprint

# Enable logging, both of our code and requests
logging.basicConfig(level=logging.DEBUG)

# Configure a new FAPISession to use a previously generated key pair and client ID
f = FAPISession(client_id='kZuAsn7UYZ98WWh29hDPf',
                token_url='https://matls-auth.directory.energydata.org.uk/token',
                requested_scopes='directory:software',
                private_key='/home/tom/Desktop/certs/a.key',
                certificate='/home/tom/Desktop/certs/a.pem')

# Get the requests session from it, then issue a GET to the directory to fetch a list
# of configured organisations. 'f.session' is a requests.Session object preconfigured
# to acquire and convey an appropriate access token.
response = f.session.get('https://matls-dirapi.directory.energydata.org.uk/organisations')

# The response is JSON, so we can pull it out and pretty-print it to the console
pprint.PrettyPrinter().pprint(response.json())

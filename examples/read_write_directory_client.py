import logging
import logging
import pprint

from ib1.openenergy.support import FAPISession, RaidiamDirectory

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                    level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')

# httpclient_logging_patch(level=logging.INFO)

# Set up a session, this will get a token from the directory when needed
jf = FAPISession(client_id='4_egpDo0lMugQbMOaNjn0',
                 issuer_url='https://matls-auth.directory.energydata.org.uk',
                 requested_scopes='directory:website',
                 private_key='/home/tom/Desktop/jwt-bearer-certs/transport.key',
                 certificate='/home/tom/Desktop/jwt-bearer-certs/transport.pem',
                 signing_private_key='/home/tom/Desktop/jwt-bearer-certs/signing.key',
                 jwt_bearer_email='tom.oinn@icebreakerone.org')

# Pretty print the config
pp = pprint.PrettyPrinter()
pp.pprint(jf.openid_configuration.__dict__)
# Attempt to introspect on our own token, this causes a request to get the token in the first place
pp.pprint(jf.introspection_response)

DIRECTORY = 'https://matls-dirapi.directory.energydata.org.uk/'

u = f'{DIRECTORY}organisations/8/softwarestatements/0ac540f7-7269-43b5-b4fb-3b06900bf910'

current = jf.session.get(url=u)
current.raise_for_status()
j = current.json()
pp.pprint(j)

org_id = '8'
directory = RaidiamDirectory(fapi=jf)
directory.update_client_metadata(org_id=org_id, client_metadata={'something': 'something else'})

#filtered = {k: j[k] for k in j if
#            k in ['ClientName', 'ClientUri', 'Description', 'Environment', 'LogoUri', 'Mode', 'RedirectUri',
#                  'TermsOfServiceUri', 'Version', 'AdditionalSoftwareMetadata']}
#filtered['RedirectUri'] = ['https://fake.example.com']
#filtered['AdditionalSoftwareMetadata'] = json.dumps({'foo': 'wibble'})

#resp = jf.session.put(url=u, json=filtered)
#resp.raise_for_status()

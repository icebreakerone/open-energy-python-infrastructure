import logging
import pprint

from ib1.openenergy.support import FAPISession, httpclient_logging_patch, RaidiamDirectory

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                    level=logging.WARN,
                    datefmt='%Y-%m-%d %H:%M:%S')

httpclient_logging_patch(level=logging.INFO)

# Set up a session, this will get a token from the directory when needed
f = FAPISession(client_id='kZuAsn7UYZ98WWh29hDPf',
                issuer_url='https://matls-auth.directory.energydata.org.uk',
                requested_scopes='directory:software foo',
                private_key='/home/tom/Desktop/certs/a.key',
                certificate='/home/tom/Desktop/certs/a.pem')

directory = RaidiamDirectory(fapi=f, base_url='https://matls-dirapi.directory.energydata.org.uk/')

pp = pprint.PrettyPrinter()
# Iterate through all organisations, pulling out the list of authorisation servers for each one. The result
# is a map of org ID to list of configured AuthorisationServer, these contain all the information in the
# response ready for parsing.
pp.pprint(
    {org.organisation_id: directory.authorisation_servers(org_id=org.organisation_id)
     for org in directory.organisations()})

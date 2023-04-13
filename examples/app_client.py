import logging

from icebreakerone.trust import FAPISession, httpclient_logging_patch

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                    level=logging.INFO,
                    datefmt='%Y-%m-%d %H:%M:%S')

httpclient_logging_patch(level=logging.INFO)

# Set up a session, this will get a token from the directory when needed
f = FAPISession(client_id='kZuAsn7UYZ98WWh29hDPf',
                issuer_url='https://matls-auth.directory.energydata.org.uk',
                requested_scopes='directory:software',
                private_key='/home/tom/Desktop/certs/a.key',
                certificate='/home/tom/Desktop/certs/a.pem')

print(f.openid_configuration.jwks_uri)
print(f.introspection_response)
print(f.plain_session.get(f'{f.openid_configuration.jwks_uri}').json())

# Call the server running on localhost, this assumes the server in 'app.py' is running
#f.session.get(url='https://127.0.0.1:5000')

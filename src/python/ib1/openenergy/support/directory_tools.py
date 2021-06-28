"""
Command line tools used to monitor the contents of the directory, largely for internal Icebreaker use.
"""
import logging
from argparse import ArgumentParser
from os.path import abspath, isfile

from ib1.openenergy.support import FAPISession, RaidiamDirectory

LOG = logging.getLogger('ib1.openenergy.support.directory_tools')


def get_directory_client(parser=None) -> RaidiamDirectory:
    """
    Parse arguments and get a directory client

    :param parser:
        Existing parser to use, None by default will create a new one
    :return:
        A `RaidiamDirectory` client
    """

    def check_file(f, name):
        """
        Check that a file exists, logging complaints and returning false if it doesn't. If the argument
        is None then interpret as optional.
        """
        if f:
            path = abspath(f)
            if not (file_found := isfile(path)):
                LOG.error(f'SSL - {name} = {path} not found!')
            else:
                LOG.info(f'SSL - {name} = {path}')
            return file_found
        else:
            return True

    parser = parser or ArgumentParser()
    parser.add_argument('-k', '--client_private_key', type=str,
                        help='Client private key file location', default='/home/tom/Desktop/certs/a.key')
    parser.add_argument('-c', '--client_certificate', type=str,
                        help='Client certificate file location', default='/home/tom/Desktop/certs/a.pem')
    parser.add_argument('-id', '--client_id', type=str, help='OAuth2 client ID for calls made from this app',
                        default='kZuAsn7UYZ98WWh29hDPf')
    parser.add_argument('-iu', '--issuer_url', type=str, help='Issuer URL for auth service',
                        default='https://matls-auth.directory.energydata.org.uk')
    parser.add_argument('-u', '--directory_url', type=str, help='Root directory URL',
                        default='https://matls-dirapi.directory.energydata.org.uk/')
    options = parser.parse_args()
    check_file(options.client_certificate, name='client cert')
    check_file(options.client_private_key, name='client key')
    f = FAPISession(client_id=options.client_id, issuer_url=options.issuer_url, requested_scopes='directory:software',
                    private_key=options.client_private_key, certificate=options.client_certificate)
    return RaidiamDirectory(fapi=f, base_url=options.directory_url)

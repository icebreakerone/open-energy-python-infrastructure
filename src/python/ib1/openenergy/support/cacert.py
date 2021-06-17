import certifi
import pem
import requests
import logging
from argparse import ArgumentParser

LOG = logging.getLogger('ib1.openenergy.support.castore')

UAT_CACERT_URL = 'https://raw.githubusercontent.com/icebreakerone/open-energy-python-infrastructure/main/certificates/raidiam_certificate_chain.pem'

parser = ArgumentParser()
parser.add_argument('-u', '--url', type=str,
                    help='URL of additional root certificates, defaults to certs from Open Energy github',
                    default=UAT_CACERT_URL)


def main():
    """
    Set up logging and install any missing certs
    """
    logging.basicConfig(level=logging.INFO)
    options = parser.parse_args()
    install_oe_ca_certs(options.url)


def install_oe_ca_certs(url):
    """
    Command line tool to append the necessary certs for the directory to certifi's castore.pem

    :param url:
        URL referencing any extra certs needed to make open energy work
    """

    # Load current certificates from wherever certifi has put them
    current_certs = pem.parse_file(certifi.where())
    LOG.info(f'found {len(current_certs)} existing certificates in {certifi.where()}')

    # Retrieve the extra remote certs we need for open energy
    remote_certs = pem.parse(requests.get(url=url).content)
    LOG.info(f'downloaded {len(remote_certs)} certificates from {url}')

    # Calculate hashes, use them to avoid duplication
    current_hashes = set([cert.sha1_hexdigest for cert in current_certs])
    certs_to_add = [cert for cert in remote_certs if cert.sha1_hexdigest not in current_hashes]

    # If we need to add certs, open the file in append mode and do so, otherwise
    # exit after informing the user that everything's already there
    if certs_to_add:
        LOG.info(f'appending {len(certs_to_add)} to {certifi.where()}')
        with open(certifi.where(), 'a') as f:
            for cert in certs_to_add:
                f.write(str(cert))
        LOG.info('done, Open Energy certificates installed successfully')
    else:
        LOG.info('all remote certificates already present in store, not updating')

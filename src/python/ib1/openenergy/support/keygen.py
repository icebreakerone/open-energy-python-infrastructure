"""
Provides generation of key and CSR without requiring the installation of OpenSSL. Based on
example code at https://cryptography.io/en/latest/x509/tutorial/
"""

import logging
from argparse import ArgumentParser

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import CertificateSigningRequest
from cryptography.x509.oid import NameOID

LOG = logging.getLogger('ib1.openenergy.support.keygen')


def create_private_key() -> RSAPrivateKey:
    """
    Create a new RSA private key
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def create_csr(key: RSAPrivateKey, software_statement_id: str, country: str = 'UK', organisation: str = 'Open Energy',
               organisation_unit: str = 'open_energy') -> CertificateSigningRequest:
    """
    Create a certificate signing request for the given private key and software statement identifier

    :param key:
        private key used to sign the CSR
    :param software_statement_id:
        internal ID of the software statement within the directory for which this key pair should be created
    :param country:
        country, defaults to 'UK'
    :param organisation:
        organisation, defaults to 'Open Energy'
    :param organisation_unit:
        organisation unit, defaults to 'open_energy'
    :return:
        csr object ready for export
    """
    return x509.CertificateSigningRequestBuilder().subject_name(
        name=x509.Name(
            [x509.NameAttribute(NameOID.COUNTRY_NAME, country),
             x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
             x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organisation_unit),
             x509.NameAttribute(NameOID.COMMON_NAME, software_statement_id)])).sign(private_key=key,
                                                                                    algorithm=hashes.SHA256())


def oe_keygen():
    """
    Entry point to generate key and CSR for a given software statement ID
    """
    # Parse command line args
    parser = ArgumentParser()
    parser.description = 'Create a private key and corresponding certificate signing request for use with Open Energy'
    parser.add_argument('-s', '--software_statement_id', type=str, help='Software statement ID', required=True)
    parser.add_argument('-k', '--key_file', type=str, help='Key filename, defaults to oe.key', default='oe.key')
    parser.add_argument('-c', '--csr_file', type=str, help='CSR filename, defaults to oe.csr', default='oe.csr')
    parser.add_argument('-o', '--organisation', type=str, help='Organisation field for certificate', required=True)
    parser.add_argument('-u', '--organisation_unit', type=str,
                        help='Organisation unit field, must match org ID in directory', required=True)
    options = parser.parse_args()
    logging.basicConfig(level=logging.INFO)

    # Create key and CSR
    key = create_private_key()
    csr = create_csr(key=key, software_statement_id=options.software_statement_id, organisation=options.organisation,
                     organisation_unit=options.organisation_unit)

    LOG.info(f'created key / csr pair for software statement {options.software_statement_id}')

    # Write out key
    with open(options.key_file, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        LOG.info(f'private key written to {options.key_file}')
    # Write out csr
    with open(options.csr_file, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
        LOG.info(f'certificate signing request written to {options.csr_file}')

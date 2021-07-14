from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass(frozen=True)
class Organisation:
    organisation_id: str
    status: str
    organisation_name: str
    created_on: datetime
    legal_entity_name: str
    country_of_registration: str
    company_register: str
    registration_number: str
    registered_name: str
    city: str
    postcode: str
    country: str
    requires_participant_terms_and_conditions_signing: bool
    registration_id: str = ''
    address_line1: str = ''
    address_line2: str = ''
    parent_organisation_reference: str = ''


@dataclass(frozen=True)
class SoftwareStatement:
    status: str
    client_id: str
    client_name: str
    environment: str
    organisation_id: str
    software_statement_id: str
    description: str = ''
    mode: str = ''
    rts_client_created: bool = False
    on_behalf_of: str = ''
    policy_uri: str = ''
    client_uri: str = ''
    logo_uri: str = ''
    terms_of_service_uri: str = ''
    version: int = 0
    locked: bool = ''
    redirect_url: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class SoftwareStatementCertificate:
    organisation_id: str = ''
    client_name: str = ''
    status: str = ''
    valid_from_date_time: str = ''
    expiry_date_time: str = ''
    e: str = ''
    key_type: str = ''
    kid: str = ''
    kty: str = ''
    n: str = ''
    use: str = ''
    x5t: str = ''
    x5thash256: str = ''
    x5u: str = ''
    signed_cert_path: str = ''
    jwk_path: str = ''
    org_jwk_path: str = ''
    x5c: List[str] = field(default_factory=list)
    software_statement_ids: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class DomainRoleDetails:
    authorisation_domain_name: str
    authorisation_domain_role_name: str
    status: str
    contact_role: str


@dataclass(frozen=True)
class AdminUser:
    status: str
    user_email: str
    domain_role_details: List[DomainRoleDetails] = field(default_factory=list)


@dataclass(frozen=True)
class OrganisationAuthorityDomainClaim:
    organisation_authority_domain_claim_id: str
    authorisation_domain_name: str
    authority_id: str
    authority_name: str
    registration_id: str
    status: str


@dataclass(frozen=True)
class OrganisationContact:
    contact_id: str
    organisation_id: str
    contact_type: dict
    first_name: str
    last_name: str
    department: str
    email_address: str
    phone_number: str
    address_line1: str
    address_line2: str
    city: str
    postcode: str
    country: str
    additional_information: str
    pgp_public_key: str


@dataclass(frozen=True)
class ApiDiscoveryEndpoint:
    api_discovery_id: str
    api_endpoint: str


@dataclass(frozen=True)
class ApiResource:
    api_resource_id: str
    api_family_type: str
    api_version: str
    api_discovery_endpoints: List[ApiDiscoveryEndpoint]


@dataclass(frozen=True)
class AuthorisationServer:
    authorisation_server_id: str
    organisation_id: str
    auto_registration_supported: bool = False

    customer_friendly_description: str = ''
    customer_friendly_logo_uri: str = ''
    customer_friendly_name: str = ''
    developer_portal_uri: str = ''
    terms_of_service_uri: str = ''

    open_i_d_discovery_document: str = ''
    payload_signing_cert_location_uri: str = ''
    parent_authorisation_server_id: str = ''
    api_resources: List[ApiResource] = None
    notification_webhook: str = ''
    notification_webhook_status: str = ''

import logging
import pprint
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, Future

from ib1.openenergy.support import FAPISession, httpclient_logging_patch, RaidiamDirectory

LOG = logging.getLogger('ib1.sample_metadata_harvester')

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                    level=logging.INFO,
                    datefmt='%Y-%m-%d %H:%M:%S')

httpclient_logging_patch(level=logging.DEBUG)

# Set up a session, this will get a token from the directory when needed
from ib1.openenergy.support.raidiam import Organisation, AuthorisationServer
from ib1.openenergy.support.metadata import Metadata, load_metadata

f = FAPISession(client_id='kZuAsn7UYZ98WWh29hDPf',
                issuer_url='https://matls-auth.directory.energydata.org.uk',
                requested_scopes='directory:software foo',
                private_key='/home/tom/Desktop/certs/a.key',
                certificate='/home/tom/Desktop/certs/a.pem')

# Create a client to the directory
directory = RaidiamDirectory(fapi=f, base_url='https://matls-dirapi.directory.energydata.org.uk/')

# Get all organisations from the directory
organisations: List[Organisation] = directory.organisations()

# Fetch all authorisation servers for organisations within the directory, building a
# map of org ID to list of authorisation server objects
orgid_to_auth: Dict[str, List[AuthorisationServer]] = {
    org.organisation_id: directory.authorisation_servers(org_id=org.organisation_id) for org
    in organisations}

# Build a map of org_id to org to use later when looking things up
orgid_to_org: Dict[str, Organisation] = {org.organisation_id: org for org in organisations}

# Build a map of org_id to metadata url list for all orgs, ignoring
# ones that don't specify any metadata urls in the customer_friendly_logo_uri
# property of an authorisation server
orgid_to_urls: Dict[str, List[str]] = {org_id: [server.customer_friendly_logo_uri for server in orgid_to_auth[org_id]]
                                       for org_id in orgid_to_auth if orgid_to_auth[org_id]}


# Schedules all URL fetch and parse jobs on a thread pool executor, returning a generator
# over futures to lists of dictionaries from organisation to lists of metadata objects
def crawl(max_workers=4) -> List[Future]:
    # Use an executor to schedule jobs, yield list of futures
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Iterate over the previously determined list of metadata URLs for each org
        for org_id, urls in orgid_to_urls.items():

            # Fetch from the locally bound url list for this org
            def fetch_and_parse() -> List[Dict[Organisation, List[Metadata]]]:
                def inner():
                    # Iterate over URLs, trying to fetch and parse each in sequence
                    for url in urls:
                        try:
                            metadata = load_metadata(url)
                            LOG.info(f'fetched metadata for url={url}')
                            # Yield the successfully parsed metadata in a single item dict
                            # containing the organisation itself as the key, this retains
                            # the link between metadata and org without having to go through
                            # too many convolutions later
                            yield {orgid_to_org[org_id]: metadata}
                        except Exception as e:
                            LOG.warning(f'unable to retrieve and parse metadata from url={url}', e)

                # Fully exhaust the generator, returning the list of {org:metadata} dicts
                return list(inner())

            # Return the future corresponding to this URL fetch and parse job
            yield executor.submit(fetch_and_parse)


org_to_meta = {}
# Actually schedule the jobs, iterating over the futures returned
for f in crawl(max_workers=4):
    # Block on completion of each future in turn
    for d in f.result():
        # Futures return a single item dict, but iterate for sanity
        for org, metadata_list in d.items():
            # Put a record in org_to_meta if there wasn't one
            if org not in org_to_meta:
                org_to_meta[org] = []
            # Add all the metadata objects to the record for this org
            org_to_meta[org] += metadata_list

# Just print the organisation -> metadata list for now. In a real harvester at this
# point we'd do the business of generating unique IDs from the Organisation and Metadata
# objects, then working out whether bits and pieces needed updating etc etc and poking
# CKAN.
pp = pprint.PrettyPrinter(indent=4)
pp.pprint(org_to_meta)

import csv
import logging
import pprint
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, Future
from io import StringIO
from typing import List, Dict, Tuple, Generator, Optional

import jinja2
from jinja2 import TemplateNotFound, Template

from ib1.openenergy.support import RaidiamDirectory
from ib1.openenergy.support.ckan import update_or_create_ckan_record, ckan_dataset_name, ckan_dict_from_metadata
from ib1.openenergy.support.directory_tools import get_directory_client
from ib1.openenergy.support.metadata import Metadata, load_metadata, MetadataLoadResult
from ib1.openenergy.support.raidiam import Organisation, AuthorisationServer

LOG = logging.getLogger('ib1.openenergy.support.metadata_harvester')


def configure_logging(options):
    def level():
        lv = options.log_level
        if lv == 'DEBUG':
            return logging.DEBUG
        if lv == 'INFO':
            return logging.INFO
        if lv == 'WARNING':
            return logging.WARNING
        return logging.ERROR

    logging.basicConfig(level=level())


def get_template(options) -> Optional[Template]:
    """
    Load a jinja2 template from options.template, returning it or None if either no template is specified or
    the specified template file can't be found.
    """
    if options.template:
        try:
            template_loader = jinja2.FileSystemLoader(searchpath='./')
            template_environment = jinja2.Environment(loader=template_loader)
            return template_environment.get_template(options.template)
        except TemplateNotFound:
            LOG.error(f'unable to find jinja2 template at {options.template}, using default description')
    return None


def check_metadata():
    """
    Command line tool to fetch a metadata file, attempt to parse it, and print the MetadataLoadResult to stdout

    Run with ``oe_check_metadata --url=URL [-l=[DEBUG|INFO|WARN|ERROR]]``
    """
    parser = ArgumentParser()
    parser.description = 'Fetch a metadata file and attempt to parse it, printing the results. Use this to check ' \
                         'individual metadata file locations for compatibility with the harvester.'
    parser.add_argument('-l', '--log_level', type=str, help='log level, defaults to ERROR', default='ERROR',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    parser.add_argument('-u', '--url', type=str, help='url for metadata file', required=True)
    parser.add_argument('-t', '--template', type=str, help='location for a Jinja2 template on disk to use',
                        default=None, required=False)
    options = parser.parse_args()
    configure_logging(options)
    result = load_metadata(url=options.url)
    print(f'Metadata load result [{"error" if result.error else "success"}]:')
    print(result)

    if result.metadata:
        for index, m in enumerate(result.metadata):
            print(f'\nCKAN dictionary from item {index}:')
            pprint.PrettyPrinter(indent=2).pprint(
                ckan_dict_from_metadata(m=m, description_template=get_template(options)))


def harvest():
    """
    Run the harvester, producing a CSV format file to stdout capturing the results.
    """
    # Add extra arguments to capture CKAN properties
    parser = ArgumentParser()
    parser.description = 'Runs the Open Energy metadata harvester. Traverses the directory looking for metadata file ' \
                         'links, resolves them, fetches files, parses as metadata, pushes information to CKAN'
    parser.add_argument('-l', '--log_level', type=str, help='log level, defaults to ERROR', default='ERROR',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    parser.add_argument('-ck', '--ckan_api_key', type=str, help='CKAN API key', required=True)
    parser.add_argument('-cu', '--ckan_url', type=str,
                        help='CKAN URL, defaults to http://search-beta.energydata.org.uk/',
                        default='http://search-beta.energydata.org.uk/')
    parser.add_argument('-t', '--template', type=str, help='location for a Jinja2 template on disk to use',
                        default=None, required=False)

    # Get cryptographic and directory properties
    directory = get_directory_client(parser=parser)

    # Retrieve the CKAN specific properties from the arg parser
    options = parser.parse_args()
    ckan_url = options.ckan_url
    ckan_api_key = options.ckan_api_key

    configure_logging(options)

    # Access directory, get metadata URLs, fetch and parse metadata
    org_to_reports = gather_metadata_files(directory=directory)

    # Iterate over results
    for org in org_to_reports:
        # Flatten the list of lists of `Metadata` objects
        metadata_list = [item for sublist in [report.metadata for report in org_to_reports[org]] for item in sublist]
        if metadata_list:
            # If we had any metadata, update the entries in CKAN
            update_or_create_ckan_record(org=org, data_sets=metadata_list,
                                         ckan_url=ckan_url, ckan_api_key=ckan_api_key,
                                         description_template=get_template(options))

    # Print out the CSV format report to stdout, we'd expect this to be pushed somewhere as a report of
    # the metadata load process.
    print(build_report_csv(org_to_reports=org_to_reports))


def build_report_csv(org_to_reports: Dict[Organisation, List[MetadataLoadResult]], dialect='excel'):
    """
    Produce a CSV summary of the metadata load process

    :param org_to_reports:
        dict of `Organisation` to list of `MetadataLoadResult`
    :param dialect:
        dialect to use, defaults to ``excel``
    :return:
        string containing a CSV format summary of the load
    """

    def row(o: Organisation, rep: MetadataLoadResult, meta: Metadata = None) -> Dict[str, str]:
        """
        Build a single row of the report

        :param o:
            `Organisation`
        :param rep:
            `MetadataLoadResult`
        :param meta:
            `Metadata`, if present.
        :return:
            dict of items to add to a single row in the report
        """
        return {
            'org_id': o.organisation_id,
            'org_name': o.organisation_name,
            'success': rep.error is None,
            'auth_server_id': rep.server.authorisation_server_id,
            'metadata_location': rep.location,
            'error': rep.error,
            'ckan_dataset_name': ckan_dataset_name(org=org, data_set=meta) if meta else '',
            'ckan_dataset_title': meta.title if meta else ''
        }

    si = StringIO()
    cw = csv.DictWriter(si, fieldnames=['org_id', 'org_name', 'success', 'auth_server_id', 'metadata_location', 'error',
                                        'ckan_dataset_name', 'ckan_dataset_title'], dialect=dialect)
    cw.writeheader()
    for org, reports in org_to_reports.items():
        for report in reports:
            if report.metadata:
                for metadata in report.metadata:
                    cw.writerow(row(org, report, metadata))
            else:
                cw.writerow(row(org, report))
    return si.getvalue().strip()


def gather_metadata_files(directory: RaidiamDirectory, max_url_workers=4) -> \
        Dict[Organisation, List[MetadataLoadResult]]:
    """
    Get all organisations from the directory, crawl over them looking for auth servers. Pull URLs out of
    auth servers and fetch from these URLs in parallel, gather results and parse as `Metadata` objects,
    producing a `MetadataLoadResult` report object for each one, before gathering them back up and producing
    a dict with `Organisation` as keys and lists of `MetadataLoadResult` as values.

    :param directory:
        a `RaidiamDirectory` to use when accessing the directory
    :param max_url_workers:
        defaults to 4, number of parallel URL fetches
    """
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
    orgid_to_urls: Dict[str, List[Tuple[AuthorisationServer, str]]] = {
        org_id: [(server, server.customer_friendly_logo_uri) for server in orgid_to_auth[org_id]]
        for org_id in orgid_to_auth if orgid_to_auth[org_id]}

    # Schedules all URL fetch and parse jobs on a thread pool executor, returning a generator
    # over futures to lists of dictionaries from organisation to lists of metadata objects
    def crawl() -> Generator[Future, None, None]:
        # Use an executor to schedule jobs, yield list of futures
        with ThreadPoolExecutor(max_workers=max_url_workers) as executor:
            # Iterate over the previously determined list of metadata URLs for each org
            for org_id, urls in orgid_to_urls.items():

                # Fetch from the locally bound url list for this org
                def fetch_and_parse() -> List[Tuple[Organisation, MetadataLoadResult]]:
                    def inner():
                        # Iterate over URLs, trying to fetch and parse each in sequence
                        for server, url in urls:
                            metadata_report = load_metadata(server, url)
                            if metadata_report.metadata:
                                LOG.info(f'org_id={org_id} : fetched metadata for url={url}')
                            else:
                                if metadata_report.error:
                                    LOG.warning(
                                        f'org_id={org_id} : unable to retrieve and parse metadata from url={url}, '
                                        f'error={metadata_report.error}')
                                else:
                                    LOG.warning(
                                        f'org_id={org_id} : location url={url} parsed but contained no datasets')
                            yield orgid_to_org[org_id], metadata_report

                    # Fully exhaust the generator, returning the list of {org:metadata} dicts
                    return list(inner())

                # Return the future corresponding to this URL fetch and parse job
                yield executor.submit(fetch_and_parse)

    org_to_meta = {}
    # Actually schedule the jobs, iterating over the futures returned
    for f in crawl():
        # Block on completion of each future in turn, the future actually returns
        # a list of tuples (org, metadata[]) so first iterate over f.result() to get each
        # tuple
        for org, metadata_report_list in f.result():
            # Put a record in org_to_meta if there wasn't one
            if org not in org_to_meta:
                org_to_meta[org] = []
            # Add all the metadata objects to the record for this org
            org_to_meta[org].append(metadata_report_list)

    return org_to_meta

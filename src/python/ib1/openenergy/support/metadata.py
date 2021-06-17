import json
import logging
from json import JSONDecodeError
from typing import List, Dict, Tuple
import requests
import yaml
from pyld import jsonld
from requests import HTTPError
from yaml.parser import ParserError
from dataclasses import dataclass, field

from yaml.scanner import ScannerError

LOG = logging.getLogger('ib1.openenergy.support.metadata')

#: Data Catalogue namespace
DCAT = 'http://www.w3.org/ns/dcat#'

#: Dublin Core namespace
DC = 'http://purl.org/dc/terms/'

#: Open Energy ontology namespace
OE = 'http://energydata.org.uk/oe/terms/'


class Metadata:
    """
    Representation of the information held in a data set metadata file, as defined in
    https://icebreakerone.github.io/open-energy-technical-docs/main/metadata.html - this
    implementation will track the spec, but may not be complete, we'll build capabilities
    into it as and when we need them.

    Currently models the content part of the metadata file as a `JSONLDContainer`
    """

    def __init__(self, d: Dict = None):
        """
        Create a new metadata container. Currently just parses the ``content`` section
        of the metadata file.

        :param d:
            a dict containing the four top level keys from the metadata spec
        :raises ValueError:
            if the structure of the dict is invalid in some way
        """
        if 'content' not in d:
            raise ValueError('no content item defined')
        # Attempt to parse the JSON-LD content
        self.content = JSONLDContainer(d['content'])

    @property
    def stable_identifier(self) -> str:
        """
        content / oe:dataSetStableIdentifier
        """
        return self.content.get(OE, 'dataSetStableIdentifier')

    @property
    def data_sensitivity_class(self) -> str:
        """
        content / oe:sensitivityClass [OE-O|OE-SA|OE-SB]
        """
        return self.content.get(OE, 'sensitivityClass')

    @property
    def keywords(self) -> List[str]:
        """
        content / dcat:keywords
        """
        return self.content.get(DCAT, 'keyword', default=[])

    @property
    def title(self) -> str:
        """
        content / dc:title
        """
        return self.content.get(DC, 'title')

    @property
    def description(self):
        """
        content / dc:description
        """
        return self.content.get(DC, 'description')

    @property
    def version(self):
        """
        content / dcat:version
        """
        return self.content.get(DCAT, 'version')

    @property
    def version_notes(self):
        """
        content / dcat:versionNotes
        """
        return self.content.get(DCAT, 'versionNotes')

    def __repr__(self):
        return f'Metadata(id={self.stable_identifier}, oe:class={self.data_sensitivity_class}, title={self.title}, ' \
               f'description={self.description}, version={self.version}, keywords={self.keywords})'


class JSONLDContainer:
    """
    Wraps up the data structure returned by jsonld.expand and adds some convenience
    methods to query properties within it
    """

    def __init__(self, d: Dict):
        # Expand out any namespace prefixes defined in the context
        self.ld = jsonld.expand(d)[0]

    def get(self, namespace: str, term: str, default=None):
        """
        Get a property, handles looking for the @value entries
        within an expanded JSON-LD dictionary

        :param namespace:
            namespace for term to find
        :param term:
            term within that namespace
        :param default:
            default value to return if term isn't present, defaults to None
        :return:
            value of term, can be single item if only one value present or list if multiple
        """
        try:
            values = self.ld[namespace + term]
            if len(values) == 1:
                return values[0]['@value']
            return [item['@value'] for item in values]
        except KeyError or IndexError:
            return default

    @property
    def type(self):
        """
        ``@type`` of the entity described
        """
        if '@type' in self.ld:
            return self.ld['@type'][0]
        return None


@dataclass
class MetadataLoadResult:
    """
    Information about the process of loading a metadata file from a URL or file location along
    with the results. This is used instead of raising exceptions during the load process in order
    to provide better reporting with mappings between org IDs and problems with their respective
    metadata files.
    """
    location: str = None
    error: str = None
    exception: Exception = None
    metadata: List[Metadata] = field(default_factory=list)


def load_metadata(url: str = None, file: str = None, session=None, **kwargs) -> MetadataLoadResult:
    """
    Load metadata from a URL.

    :param url:
        url from which to load metadata
    :param file:
        file path from which to load metadata, use either this or url, not both
    :param session:
        if specified, use this `requests.Session`, if not, create a new one
    :param kwargs:
        any additional arguments to pass into the get request
    :return:
        a `MetadataLoadResult` containing a report on the process, including actual `Metadata` objects if
        the load succeeded and found any metadata.
    """

    if file is not None and url is not None:
        return MetadataLoadResult(location=f'file:{file} and {url}',
                                  error='must provide exactly one of "file" or "url"')
    if url is not None:
        LOG.debug(f'loading metadata from url = {url}')
        # Use supplied session, or build a new one
        if session is None:
            session = requests.session()


        try:
            # Fetch data from the specified URL
            response = session.get(url=url, **kwargs)
            # If any errors occurred, raise the corresponding HTTPError
            response.raise_for_status()
        except Exception as he:
            return MetadataLoadResult(location=url, error='unable to retrieve metadata file', exception=he)
        try:
            result = response.json()
        except ValueError:
            # Not a problem, try YAML
            LOG.debug(f'url={url} not valid JSON, trying YAML')
            try:
                result = yaml.safe_load(response.content)
                LOG.debug(f'url={url} parsed as YAML')
            except Exception as pe:
                LOG.error(f'unable to parse metadata file from url={url} as either JSON or YAML')
                # Not YAML either, or not a dialect we can handle
                return MetadataLoadResult(location=url,
                                          error='unable to parse metadata file as either JSON or YAML',
                                          exception=pe)
    elif file is not None:
        LOG.debug(f'loading metadata from file = {file}')
        # Read from file on disk
        try:
            with open(file, 'rb') as f:
                s = f.read()
                try:
                    result = json.loads(s)
                except JSONDecodeError:
                    LOG.debug(f'file={file} not valid JSON, trying YAML')
                    try:
                        result = yaml.safe_load(s)
                        LOG.debug(f'file={file} parsed as YAML')
                    except ParserError as pe:
                        LOG.error(f'unable to parse metadata file from file={file} as either JSON or YAML')
                        # Not YAML either, or not a dialect we can handle
                        return MetadataLoadResult(location=f'file:{file}',
                                                  error='unable to parse metadata file as either JSON or YAML',
                                                  exception=pe)
        except IOError as ioe:
            return MetadataLoadResult(location=f'file:{file}',
                                      error='unable to load metadata file from disk',
                                      exception=ioe)
    else:
        return MetadataLoadResult(location='NONE', error='must specify either file or url')

    location = f'{file}' if file else url

    if isinstance(result, list):
        LOG.debug(f'fetched and parsed location={location}, contains {len(result)} items')
        try:
            return MetadataLoadResult(location=location, metadata=[Metadata(item) for item in result])
        except ValueError as ve:
            return MetadataLoadResult(location=location, error='invalid metadata description', exception=ve)

    # No list item, this is a failure
    return MetadataLoadResult(location=location, error='metadata does not contain a list as top level item')

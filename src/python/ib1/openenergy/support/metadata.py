import json
import logging
from json import JSONDecodeError
from typing import List, Dict
import requests
import yaml
from pyld import jsonld
from yaml.parser import ParserError

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


def load_metadata(url: str = None, file: str = None, session=None, **kwargs) -> List[Metadata]:
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
    :raises requests.HTTPError:
        if any error occurs while attempting to fetch the URL and ``url`` specified
    :raises ValueError:
        if the content cannot be parsed for some reason
    :raises IOError:
        if unable to read from a local file, and ``file`` specified
    :return:
        a list of `Metadata` objects
    """

    if file is not None and url is not None:
        raise ValueError('must specify exactly one of file or url, not both')

    if url is not None:
        LOG.debug(f'loading metadata from url={url}')
        # Use supplied session, or build a new one
        if session is None:
            session = requests.session()
        # Fetch data from the specified URL
        response = session.get(url=url, **kwargs)
        # If any errors occurred, raise the corresponding HTTPError
        response.raise_for_status()
        try:
            result = response.json()
        except ValueError:
            # Not a problem, try YAML
            LOG.debug(f'url={url} not valid JSON, trying YAML')
            try:
                result = yaml.safe_load(response.content)
                LOG.debug(f'url={url} parsed as YAML')
            except ParserError as pe:
                LOG.error(f'unable to parse metadata file from url={url} as either JSON or YAML')
                # Not YAML either, or not a dialect we can handle
                raise ValueError(pe)
    elif file is not None:
        LOG.debug(f'loading metadata from file={file}')
        # Read from file on disk
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
                    raise ValueError(pe)
    else:
        raise ValueError('must specify either file or url')

    if isinstance(result, list):
        LOG.debug(f'fetched and parsed url={url}, contains {len(result)} items')
        return [Metadata(item) for item in result]

    raise ValueError(f'metadata does not contain a list as the top level item')

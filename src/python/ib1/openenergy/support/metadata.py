import json
import logging
from dataclasses import dataclass, field
from json import JSONDecodeError
from typing import List, Dict

import requests
import yaml
from pyld import jsonld
from yaml import YAMLError

from ib1.openenergy.support.raidiam import AuthorisationServer

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

    def __init__(self, d: Dict):
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
        # Complain if we don't have the necessary mandatory values present in the content section
        self.content.require_values({DCAT: ['version', 'versionNotes'],
                                     DC: ['title', 'description'],
                                     OE: ['sensitivityClass', 'dataSetStableIdentifier']})

        if 'transport' not in d:
            raise ValueError('no transport item defined')
        self.transport = d['transport']

        if 'access' not in d:
            raise ValueError('no access item defined')
        self.access = d['access']

        if 'representation' not in d:
            raise ValueError('no representation item defined')
        self.representation = d['representation']

    @property
    def mime(self) -> str:
        """
        representation / mime
        """
        if 'mime' in self.representation:
            return self.representation['mime']
        return ''

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
        keywords = self.content.get(DCAT, 'keyword', default=[])
        if not isinstance(keywords, list):
            # If there's a single keyword, wrap it up in a list
            keywords = [keywords]
        return keywords

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

    def require_values(self, d: Dict[str, List[str]]):
        """
        Require that this container has the specified values, defined as a dict of namespace to list of terms.

        :param d:
            Dict of str namespace to list of str terms that must be present
        :raises:
            ValueError if any specified values are not present in this container
        """

        def missing_values():
            for ns, terms in d.items():
                for term in terms:
                    if (fterm := f'{ns}{term}') not in self.ld:
                        yield fterm

        if missing := list(missing_values()):
            raise ValueError(f'container is missing required values {", ".join(missing)}')

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
    server: AuthorisationServer = None

    def __repr__(self):
        from pprint import pformat
        return pformat(vars(self), indent=4, width=1)


def load_yaml_from_bytes(b: bytes, convert_tabs_to_spaces=True):
    """
    Attempt to load YAML from a set of bytes.

    :param b:
        bytes to load
    :param convert_tabs_to_spaces:
        if True (default), an initial failure to load YAML will be retried after converting all
        tab characters in the input to double spaces. This is done after converting the bytes to
        a string with UTF8 encoding, and after the tabs are stripped the string is encoded back
        to UTF8 bytes before passing back to the yaml loader
    :return:
        yaml parsed as a dict
    :raises:
        YAMLError if unable to parse the input bytes
    """
    try:
        result = yaml.safe_load(b)
        return result
    except YAMLError as ye:
        if convert_tabs_to_spaces:
            new_bytes: bytes = b.decode('UTF8').replace('\t', ' ' * 2).encode('UTF8')
            result = yaml.safe_load(new_bytes)
            LOG.warning('YAML file parse passed after removing tabs, technically not valid but continuing...')
            return result
        else:
            raise ye


def load_metadata(server: AuthorisationServer = None, url: str = None, file: str = None, session=None,
                  convert_tabs_to_spaces=True,
                  **kwargs) -> MetadataLoadResult:
    """
    Load metadata from a URL.

    :param server:
        `AuthorisationServer` from which this url was retrieved, or None if fetching directly
    :param url:
        url from which to load metadata
    :param file:
        file path from which to load metadata, use either this or url, not both
    :param session:
        if specified, use this `requests.Session`, if not, create a new one
    :param convert_tabs_to_spaces:
        normally YAML is invalid if it uses tab characters as indentation. If this argument is set to true, a second
        attempt will be made to parse the file if a scanner error occurs, first doing a global search and replace to
        change all tab characters to double spaces. Defaults to False, as this isn't really 'allowed' according to the
        spec.
    :param kwargs:
        any additional arguments to pass into the get request
    :return:
        a `MetadataLoadResult` containing a report on the process, including actual `Metadata` objects if
        the load succeeded and found any metadata.
    """

    if file is not None and url is not None:
        return MetadataLoadResult(location=f'file:{file} and {url}',
                                  error='must provide exactly one of "file" or "url"',
                                  server=server)
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
            return MetadataLoadResult(location=url, error='unable to retrieve metadata file', exception=he,
                                      server=server)
        try:
            result = response.json()
        except ValueError:
            # Not a problem, try YAML
            LOG.debug(f'url={url} not valid JSON, trying YAML')
            try:
                result = load_yaml_from_bytes(response.content)
                LOG.debug(f'url={url} parsed as YAML')
            except YAMLError as ye:
                LOG.error(f'unable to parse metadata file from url={url} as either JSON or YAML')
                # Not YAML either, or not a dialect we can handle
                return MetadataLoadResult(location=url,
                                          error='unable to parse metadata file as either JSON or YAML',
                                          exception=ye, server=server)
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
                        result = load_yaml_from_bytes(s)
                        LOG.debug(f'file={file} parsed as YAML')
                    except YAMLError as ye:
                        LOG.error(f'unable to parse metadata file from file={file} as either JSON or YAML')
                        # Not YAML either, or not a dialect we can handle
                        return MetadataLoadResult(location=f'file:{file}',
                                                  error='unable to parse metadata file as either JSON or YAML',
                                                  exception=ye, server=server)
        except IOError as ioe:
            return MetadataLoadResult(location=f'file:{file}',
                                      error='unable to load metadata file from disk',
                                      exception=ioe, server=server)
    else:
        return MetadataLoadResult(location='NONE', error='must specify either file or url', server=server)

    location = f'{file}' if file else url

    if isinstance(result, list):
        LOG.debug(f'fetched and parsed location={location}, contains {len(result)} items')

        try:
            def build_metadata():
                for index, item in enumerate(result):
                    try:
                        yield Metadata(item)
                    except ValueError as ve:
                        raise ValueError(f'Unable to parse metadata item {index} : {str(ve)}') from ve

            return MetadataLoadResult(location=location, metadata=list(build_metadata()), server=server)
        except ValueError as ve:
            return MetadataLoadResult(location=location, error='invalid metadata description', exception=ve,
                                      server=server)

    # No list item, this is a failure
    return MetadataLoadResult(location=location, error='metadata does not contain a list as top level item',
                              server=server)

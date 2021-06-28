"""
Support for creating and updating records in a remote CKAN instance from various organisation and metadata types
from elsewhere in this library.
"""
import logging
import re

from ckanapi import RemoteCKAN, NotFound
from typing import List, Generator, Dict, Union

from ib1.openenergy.support.metadata import Metadata
from ib1.openenergy.support.raidiam import Organisation

LOG = logging.getLogger('ib1.openenergy.support.ckan')


def ckan_dataset_name(org: Organisation, data_set: Metadata) -> str:
    """
    Calculates a stable dataset ID for a given organisation and metadata object, uses the literal 'oe', and
    the ckan_legal_name forms of the organisation ID and data set stable identifier separated by '-' characters
    """
    return ckan_legal_name('-'.join(['oe',
                                     ckan_legal_name(org.organisation_id),
                                     ckan_legal_name(data_set.stable_identifier)]))


def ckan_legal_name(s: str) -> str:
    """
    CKAN names must be between 2 and 100 characters long and contain only lowercase alphanumeric characters,
    '-' and '_'. This function makes a reasonable best effort to convert an arbitrary input string. Strings
    below 2 characters long will raise a ValueError.

    Longer strings are converted to lower case, stripped of all non-alphanumeric, non underscore or dash, characters,
    then truncated to 100 characters if necessary.

    :param s:
        input string
    :return:
        valid CKAN name, as close as possible to the original
    :raises ValueError:
        if the string is too short
    """
    if s is None or len(s) < 2:
        raise ValueError(f'Unable to convert, input string is too short "{s}"')
    # Convert to lower case and remove all non-word characters except '_' and '-', then truncate to 100 chars
    return re.sub(r'[^\w_-]', '', s.lower())[:100]


def ckan_dict_from_metadata(m: Metadata) -> dict:
    """
    Create a CKAN dict suitable for data package create or update operations from a `Metadata` object. Currently
    handles title, notes, version, tags, and adds oe:dataSensitivityClass and dcat:versionNotes to the extras
    dict. Tags are added without any associated vocabulary at this point.

    :param m:
        a `Metadata` object containing information about the data set to store or update
    :return:
        a dict suitable for CKAN update / create operations on data packages
    """

    def ckan_extras(d):
        """
        CKAN expects extras in the form of a list of dicts {key:..., value:...}, this function
        converts a dictionary containing k:v pairs into a list of these dicts.
        """
        return [{'key': key, 'value': value} for key, value in d.items()]

    def ckan_tags(tags):
        """
        CKAN expects tags to be a list of {'name':...'} dicts, but we have lists of free text keywords
        from dcat's keyword term, so munge a list of strings into this form.
        """
        return [{'name': tag} for tag in tags]

    return {
        'title': m.title,
        'notes': m.description,
        'version': m.version,
        'tags': ckan_tags(m.keywords),
        'extras': ckan_extras({'oe-sensitivityClass': m.data_sensitivity_class,
                               'dcat-versionNotes': m.version_notes})
    }


def update_or_create_ckan_record(org: Organisation,
                                 data_sets: List[Metadata],
                                 ckan_api_key: str,
                                 ckan_url: str) -> List[Dict]:
    """
    Create or update records for a given datasets, each defined by a `Metadata` object, in the context
    of an `Organisation` from the directory. The organisation will be created if required.

    :param org:
        `Organisation` to use as owner of this data set
    :param data_sets:
        list of `Metadata` containing information about the data sets
    :param ckan_api_key:
        api key to write to CKAN
    :param ckan_url:
        url of the CKAN instance
    :return:
        list of created or modified record from CKAN as dicts
    :raises NotAuthorized:
        if the supplied access token doesn't have necessary permissions
    """
    ckan = RemoteCKAN(address=ckan_url, apikey=ckan_api_key)

    def inner():
        # Create the organisation in CKAN if it isn't already present
        try:
            ckan.action.organization_show(id=org.organisation_id)
            LOG.info(f'organisation id={org.organisation_id} already exists in CKAN')
        except NotFound:
            LOG.info(f'creating new organisation in CKAN, id={org.organisation_id}, title={org.organisation_name}')
            ckan.action.organization_create(name=org.organisation_id, title=org.organisation_name)

        # Iterate over data sets
        for data_set in data_sets:

            # Compute the ID for the dataset
            dataset_id = ckan_dataset_name(org=org, data_set=data_set)

            # Check whether the data package already exists in CKAN
            try:
                ckan.action.package_show(id=dataset_id)
                LOG.info(f'data package id={dataset_id} already exists in CKAN, updating')
                # Found existing package, use package update
                yield ckan.action.package_update(name=dataset_id,
                                                 **ckan_dict_from_metadata(data_set),
                                                 owner_org=org.organisation_id,
                                                 return_package_dict=True)
            except NotFound:
                # Not found in CKAN, use package_create to build a new one
                LOG.info(f'creating data package id={dataset_id} in CKAN')
                yield ckan.action.package_create(
                    name=dataset_id,
                    **ckan_dict_from_metadata(data_set),
                    owner_org=org.organisation_id,
                    return_package_dict=True)

    return list(inner())

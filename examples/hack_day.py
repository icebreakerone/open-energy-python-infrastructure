import csv
from ib1.openenergy.support import FAPISession, RaidiamDirectory
from ib1.openenergy.support.raidiam import Organisation, OrganisationContact

fapi = FAPISession(
    client_id='xZqGzEL8k14cbLJObUfKQ',
    issuer_url='https://matls-auth.directory.energydata.org.uk',
    private_key='/home/tom/new_directory.key',
    certificate='/home/tom/new_directory.pem',
    # The API's Swagger definition suggests we need to use
    # 'directory:website' to POST to /organisations
    requested_scopes='directory:software',
    #requested_scopes='directory:website',
)
directory = RaidiamDirectory(
    fapi=fapi,
    base_url='https://matls-dirapi.directory.energydata.org.uk/',
)


import pprint;
pprint.PrettyPrinter().pprint(fapi.openid_configuration.__dict__)
#pprint.PrettyPrinter().pprint(directory.organisations())

# Parse CSV (supplied by IB1, not directly from members)
with open("frank.csv", "r") as csv_file:
    csv_reader = csv.DictReader(csv_file, delimiter=',')
    for line in csv_reader:
        #print(line)
        org = Organisation(
            organisation_id         = line['Organisation ID'],
            status                  = 'Pending',        # TODO: 'Active'
            organisation_name       = line['Organisation Name'],
            legal_entity_name       = line['Organisation Legal Name'],
            country_of_registration = line['Organisation Registration Country'],
            company_register        = line['Organisation Registrar'],
            registration_number     = line['Organisation Registration Number'],
            registered_name         = line['Organisation Legal Name'],
            city                    = line['Organisation City'],
            postcode                = line['Organisation Postcode'],
            country                 = line['Organisation Country'],
            address_line1           = line['Organisation Address Line 1'],
            address_line2           = line['Organisation Address Line 2'],
        )
        print(org) # debug
        # TODO: Create the organisation in the directory
        directory.create_organisation()

        contact = OrganisationContact(
            organisation_id         = line['Organisation ID'],
            contact_type            = line['Contact Type'],
            first_name              = line['Contact First Name'],
            last_name               = line['Contact Last Name'],
            department              = line['Contact Department'],
            email_address           = line['Contact Email'],
            phone_number            = line['Contact Mobile Number'],
        )
        print(contact)  # debug
        # TODO: Create the contact in the directory

# Think about:
#   deleting this data after we've created it
#   not passing in the organisation_id and seeing if it gets created automatically
# ✓ passing in more fields, not just the required ones
#   passing in the CSV filename, not hardcoding it
#   how to check whether an organisation already exists (surrogate keys) and what to do
#   data cleaning (eg. remove spaces in phone numbers)
#   when processing the CSV, remove spaces and underscores from the heading names

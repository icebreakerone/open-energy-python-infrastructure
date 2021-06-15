from ib1.openenergy.support.metadata import load_metadata, Metadata

m = load_metadata(file='metadata_file.json')

for metadata in m:
    print(metadata)
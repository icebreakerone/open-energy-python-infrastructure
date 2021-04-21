# open-energy-python-infrastructure

Data provider based on Flask that can be run locally with all certificate based security in place.

Current status - HTTPS and client certificate auth working, but no OAUTH or FAPI validation.

```shell
virtualenv -p python3.8 venv
source venv/bin/activate
git clone git@github.com:icebreakerone/open-energy-python-infrastructure.git
cd open-energy-python-infrastructure/src/python
python setup.py develop
```
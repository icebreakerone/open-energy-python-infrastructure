# open-energy-python-infrastructure

Data provider based on Flask that can be run locally with all certificate based security in place.

Current status - HTTPS and client certificate auth working, decorator for Flask routes which performs token
introspection and checks scopes, passing introspection response into flask.g

```shell
virtualenv -p python3.8 venv
source venv/bin/activate
git clone git@github.com:icebreakerone/open-energy-python-infrastructure.git
cd open-energy-python-infrastructure/src/python
python setup.py develop
```
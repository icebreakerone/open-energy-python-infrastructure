from setuptools import setup, find_namespace_packages

setup(
    name='icebreakerone.trust',
    version='0.2.18',
    author='Tom Oinn',
    author_email='tom.oinn@icebreakerone.org',
    url='https://github.com/icebreakerone/open-energy-python-infrastructure',
    description='Tools, and Flask and Requests extensions, to support data providers '
                'and clients within the open energy ecosystem',
    classifiers=['Programming Language :: Python :: 3.7',
                 'Development Status :: 4 - Beta',
                 'Framework :: Flask',
                 'License :: OSI Approved :: MIT License',
                 'Topic :: Security',
                 'Topic :: Scientific/Engineering'],
    packages=find_namespace_packages(),
    install_requires=['requests', 'flask', 'cachetools', 'cryptography', 'pyyaml', 'PyLD', 'pyjwt', 'pem', 'gunicorn',
                      'ckanapi', 'jinja2'],
    entry_points={
        'console_scripts': ['oe_install_cacerts=icebreakerone.trust.cacert:main',
                            'oe_harvest=icebreakerone.trust.metadata_harvester:harvest',
                            'oe_check_metadata=icebreakerone.trust.metadata_harvester:check_metadata',
                            'oe_keygen=icebreakerone.trust.keygen:oe_keygen']
    }
)

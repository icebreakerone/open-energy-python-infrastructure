from setuptools import setup, find_namespace_packages

setup(
    name='ib1.openenergy.support',
    version='0.0.1',
    author='Tom Oinn',
    author_email='tom.oinn@icebreakerone.org',
    url='https://github.com/icebreakerone/open-energy-python-infrastructure',
    description='Flask and Requests extensions to support data providers and clients within the open energy ecosystem',
    classifiers=['Programming Language :: Python :: 3.8',
                 'Development Status :: 2 - Pre-Alpha',
                 'Framework :: Flask',
                 'License :: OSI Approved :: MIT License',
                 'Topic :: Security',
                 'Topic :: Scientific/Engineering'],
    packages=find_namespace_packages(),
    install_requires=['requests', 'flask', 'pyopenssl'],
    entry_points={
        'console_scripts': ['oe_test_provider=ib1.openenergy.support.app:run_simple_app']
    }
)
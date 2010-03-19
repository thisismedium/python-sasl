from __future__ import absolute_import
from setuptools import setup, find_packages

setup(
    name = 'python-sasl',
    version = '0.1.1',
    description = 'A SASL implementation.',
    author = 'Medium',
    author_email = 'labs@thisismedium.com',
    license = 'BSD',
    keywords = 'security protocol rfc sasl',

    packages = list(find_packages(exclude=('examples', ))),
    install_requires = ['md.py']
)

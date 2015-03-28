#!/usr/bin/env python

from setuptools import setup, find_packages
from os.path import join, dirname


setup(
    name='vulndb',

    version='0.0.1',
    license='3 clause BSD',
    platforms='Linux',

    description='Provides access to the vulndb information',
    long_description=open(join(dirname(__file__), 'README.md')).read(),

    author='Andres Riancho',
    author_email='andres@tagcube.io',
    url='https://github.com/vulndb/python-sdk/',

    packages=[p for p in find_packages() if p.startswith('vulndb')],
    include_package_data=True,

    install_requires=[],
    zip_safe=False,

    # https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security'
    ],
)


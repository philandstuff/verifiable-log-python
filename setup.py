#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    # TODO: put package requirements here
]

test_requirements = [
    "hypothesis"
    # TODO: put package test requirements here
]

setup(
    name='verifiable_log',
    version='0.1.0',
    description="A verifiable log is an append-only data structure with cryptographic guarantees of integrity.",
    long_description=readme + '\n\n' + history,
    author="Philip Potter",
    author_email='philip.g.potter@gmail.com',
    url='https://github.com/philandstuff/verifiable_log',
    packages=[
        'verifiable_log',
    ],
    package_dir={'verifiable_log':
                 'verifiable_log'},
    include_package_data=True,
    install_requires=requirements,
    license="MIT license",
    zip_safe=False,
    keywords='verifiable_log',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    test_suite='tests',
    tests_require=test_requirements
)

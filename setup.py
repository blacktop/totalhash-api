#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Josh Maine'

try:
    from setuptools import setup

except:
    from distutils.core import setup

import totalhash

setup(
    name = "totalhash-api",
    description = "#totalhash - Malware Analysis Database API",

    py_modules = ["totalhash"],
    test_suite = "tests",

    version = totalhash.__version__,
    author = totalhash.__author__,
    author_email = totalhash.__email__,
    url = "https://github.com/blacktop/totalhash-api",
    license = totalhash.__license__,
    classifiers = [
        "Development Status :: 1 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GPLv3",
        "Programming Language :: Python",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
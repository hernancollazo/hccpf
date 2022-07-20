#!/usr/bin/env python
# -*- coding: utf-8 -*-
# encoding=utf8
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name='hccpf',
    version='0.0.99',
    author='Hernán Collazo',
    author_email='hernan.collazo@gmail.com',
    description='Common useful python functions',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/hernancollazo/hccpf',
    project_urls = {
        "Bug Tracker": "https://github.com/hernancollazo/hccpf/issues"
    },
    license='MIT',
    packages=['hccpf'],
    install_requires=['simple-crypt'],
)

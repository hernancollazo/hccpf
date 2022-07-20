#!/usr/bin/env python
# -*- coding: utf-8 -*-
# encoding=utf8
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
import sys
import string 
import os
import os.path
import logging
import time
import socket

def get_domain(string):
    """ The a domain name from a URL """
    spltAr = string.split("://")
    i = (0, 1)[len(spltAr) > 1]
    dm = spltAr[i].split("?")[0].split('/')[0].split(':')[0].lower()
    return dm


def is_valid_ipv4_address(address):
    """ Check if a address is a valid IPv4 ip address """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def is_valid_ipv6_address(address):
    """ Check if a address is a valid IPv6 ip address """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def comp_dates(d1, d2):
    """ Compare two dates and return the diff in seconds """
    return time.mktime(time.strptime(d2, "%Y-%m-%d %H:%M:%S")) -\
        time.mktime(time.strptime(d1, "%Y-%m-%d %H:%M:%S"))
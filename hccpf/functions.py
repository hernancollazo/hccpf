#!/usr/bin/env python
# -*- coding: utf-8 -*-
# encoding=utf8
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
import sys
import os
import os.path
import logging
import time
import socket
import smtplib
import hashlib
import string
import re
import base64
import random
from binascii import hexlify
from random import choice, randint
from simplecrypt import encrypt, decrypt


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


def sendEmail(mail_from,
              mail_to,
              mail_subject,
              mail_body,
              smtp_server="localhost",
              smtp_port=25,
              smtp_timeout=30,
              smtp_user='',
              smtp_pass='',
              smtp_debug=0):
    """
    Send emails through an SMTP server
    """
    msg = "" + "From: " + mail_from + "\n"
    msg = msg + "To: " + mail_to + "\n"
    msg = msg + "Subject: " + mail_subject + "\n"
    msg = msg + "\n"
    msg = msg + mail_body
    socket.setdefaulttimeout(smtp_timeout)
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.set_debuglevel(smtp_debug)
        if smtp_pass != '' and smtp_user != '':
            server.starttls()
            server.login(smtp_user, smtp_pass)
    except socket.timeout:
        print("\n\n**** ERROR **** SMTP Server timeout!\n\n")
        sys.exit(0)
    except smtplib.socket.gaierror:
        return False
    server.sendmail(mail_from, mail_to, msg)
    server.quit()
    return


def input_validate(my_string, check_type):
    """ Basic string validation function """
    if check_type == 'username':
        return re.match("[A-Za-z\._-]*$", my_string)
    elif check_type == 'hostname':
        return re.match("[A-Za-z0-9_-]*$", my_string)
    elif check_type == 'int':
        return my_string.isdigit()
    elif check_type == 'email':
        return re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", my_string)
    elif check_type == 'comment':
        return re.match(r"[A-Za-z0-9\s\(\)_-]*$", my_string)
    elif check_type == 'version_name':
        return re.match(r"[A-Za-z0-9\.\s_-]*$", my_string)
    elif check_type == 'aws_ami_id':
        return re.match("^ami-\w*$", my_string)
    else:
        return False


def random_id():
    """ Return a random string """
    chars = string.ascii_letters + string.digits
    return "".join(choice(chars) for x in range(randint(8, 16)))


def resolve_hostname(hostname):
    """ Try to resolve a hostname """
    socket.setdefaulttimeout(10)
    try:
        addr = socket.gethostbyname(hostname)
    except socket.gaierror:
        addr = "NA"
    return addr


def stripComments(code):
    """ Remove # from a string """
    code = str(code)
    return re.sub(r'(?m)^ *#.*\n?', '', code)


def string_encode(crypt_pass, message):
    """ Encrypt and encode a message """
    my_cipher = encrypt(crypt_pass, message.encode('utf8'))
    return base64.urlsafe_b64encode(my_cipher)


def string_decode(crypt_pass, my_cipher):
    """ Decrypt and decode a message """
    my_cipher = base64.urlsafe_b64decode(my_cipher)
    plaintext = decrypt(crypt_pass, my_cipher)
    return plaintext.decode('utf8')


def ValidateEmail(email):
    """ is a valid email address ?"""
    if len(email) > 7:
        if re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", email) != None:
            return 1
    return 0


def random_password():
    """ Create a password of random length between 8 and 16
        characters long, made up of numbers and letters.
    """
    chars = string.ascii_letters + string.digits
    return "".join(choice(chars) for x in range(randint(8, 16)))


def twolists_to_dictionary(keys, values):
    """ Convert two lists into a dictionary

    Args:
        keys (_type_): keys = ["a", "b", "c"]
        values (_type_): values = [2, 3, 4]

    Returns:
        new dict

    Example:

        keys = ["a", "b", "c"]
        values = [2, 3, 4]
        print(to_dictionary(keys, values)) # {'a': 2, 'c': 4, 'b': 3}

    """
    return dict(zip(keys, values))


def validate_time_format(string):
    """
    Validates if a string matches the "hh:mm" format and represents a valid time.

    Args:
        string (str): The string to be validated.

    Returns:
        bool: True if the string matches the format and represents a valid time,
            False otherwise.

    print(validate_time_format("12:34"))  # True
    print(validate_time_format("25:00"))  # False (invalid hour)
    print(validate_time_format("12:60"))  # False (invalid minutes)
    print(validate_time_format("99:99"))  # False (invalid hour and minutes)

    """
    pattern = r'^\d{2}:\d{2}$'
    if not re.match(pattern, string):
        return False
    hours, minutes = map(int, string.split(':'))
    if hours < 0 or hours > 23:
        return False
    if minutes < 0 or minutes > 59:
        return False
    return True


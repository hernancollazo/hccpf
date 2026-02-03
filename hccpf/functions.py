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
import ipaddress
import subprocess
import platform
import requests
import dns.resolver
from binascii import hexlify
from random import choice, randint
from simplecrypt import encrypt, decrypt
from urllib.parse import urlparse
from datetime import datetime
from email.message import EmailMessage
from typing import List, Dict, Union, Optional


def get_domain(string):
    """Extract the domain name from a URL."""
    parsed_url = urlparse(string)
    return parsed_url.hostname.lower() if parsed_url.hostname else None


def is_valid_ipv4_address(address):
    """Check if an address is a valid IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_valid_ipv6_address(address):
    """Check if an address is a valid IPv6 address."""
    try:
        return isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address)
    except ValueError:
        return False


def comp_dates(d1, d2):
    """Compare two dates and return the difference in seconds."""
    fmt = "%Y-%m-%d %H:%M:%S"
    delta = datetime.strptime(d2, fmt) - datetime.strptime(d1, fmt)
    return int(delta.total_seconds())


def sendEmail(mail_from, mail_to, mail_subject, mail_body, smtp_server="localhost",
              smtp_port=25, smtp_timeout=30, smtp_user='', smtp_pass=None, smtp_debug=0):
    """Send emails through an SMTP server."""
    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg["Subject"] = mail_subject
    msg.set_content(mail_body)

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=smtp_timeout) as server:
            server.set_debuglevel(smtp_debug)
            if smtp_user and smtp_pass:
                server.starttls()
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    except (smtplib.SMTPException, socket.timeout) as e:
        print(f"SMTP error: {e}")
        return False
    return True


def input_validate(my_string, check_type):
    """Basic string validation function."""
    patterns = {
        "username": r"^[A-Za-z._-]*$",
        "hostname": r"^[A-Za-z0-9_-]*$",
        "int": r"^\d+$",
        "email": r"^[^@]+@[^@]+\.[^@]+$",
        "comment": r"^[A-Za-z0-9\s\(\)_-]*$",
        "version_name": r"^[A-Za-z0-9.\s_-]*$",
        "aws_ami_id": r"^ami-\w*$",
        "phone": r"^\+?1?\d{9,15}$",  # Basic international format
        "phone_us": r"^\+?1?\d{10}$",  # US format (10 digits)
        "phone_intl": r"^\+\d{1,3}[-\s]?\d{9,15}$"  # Strict international format
    }
    pattern = patterns.get(check_type)
    return bool(re.fullmatch(pattern, my_string)) if pattern else False


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
        if re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", email) is not None:
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


def get_shortname(fqdn):
    """
    This function extracts the hostname from a Fully Qualified Domain Name (FQDN).

    Args:
        fqdn (str): The Fully Qualified Domain Name.

    Returns:
        str: The hostname.
    """
    parts = fqdn.split('.')
    hostname = parts[0]
    return hostname


def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_ip_version(ip: str) -> Optional[int]:
    """Return IP version (4 or 6) or None if invalid."""
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


def ping_host(host: str, count: int = 4) -> Dict[str, Union[bool, float, int]]:
    """
    Ping a host and return statistics.
    Returns: Dict with success, avg_time, packet_loss
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, str(count), host]
    try:
        output = subprocess.check_output(command).decode()
        if platform.system().lower() == 'windows':
            loss = float(re.search(r'(\d+)% loss', output).group(1))
            avg = float(re.search(r'Average = (\d+)ms', output).group(1))
        else:
            loss = float(re.search(r'(\d+)% packet loss', output).group(1))
            avg = float(re.search(r'min/avg/max/mdev = [\d.]+/([\d.]+)/', output).group(1))
        return {'success': True, 'avg_time': avg, 'packet_loss': loss}
    except Exception:
        return {'success': False, 'avg_time': None, 'packet_loss': 100}


def get_dns_records(domain: str, record_type: str = 'A') -> List[str]:
    """Get DNS records for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open on a host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_subnet_info(cidr: str) -> Dict[str, Union[str, int]]:
    """Get information about a subnet."""
    try:
        network = ipaddress.ip_network(cidr)
        return {
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'netmask': str(network.netmask),
            'num_addresses': network.num_addresses,
            'hosts': network.num_addresses - 2 if network.version == 4 else network.num_addresses
        }
    except ValueError:
        return {}


def check_url_status(url: str, timeout: float = 5.0) -> Dict[str, Union[int, bool, float]]:
    """Check HTTP status and response time of a URL."""
    try:
        response = requests.get(url, timeout=timeout)
        return {
            'status_code': response.status_code,
            'success': response.ok,
            'response_time': response.elapsed.total_seconds()
        }
    except requests.RequestException:
        return {'status_code': None, 'success': False, 'response_time': None}

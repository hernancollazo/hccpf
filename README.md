# hccpf
Common useful python functions

# Installation

Install this directly into your project using PIP:

```pip install git+https://github.com/hernancollazo/hccpf.git@main```

# Functions Overview

## `get_domain(string)`
Extracts the domain name from a given URL.

**Example:**
```python
from hccpf import get_domain

url = "https://www.example.com/path?query=value"
print(get_domain(url))  # Output: "www.example.com"
```

---

## `is_valid_ipv4_address(address)`
Checks if the provided string is a valid IPv4 address.

**Example:**
```python
from hccpf import is_valid_ipv4_address

print(is_valid_ipv4_address("192.168.0.1"))  # Output: True
print(is_valid_ipv4_address("256.256.256.256"))  # Output: False
```

---

## `is_valid_ipv6_address(address)`
Checks if the provided string is a valid IPv6 address.

**Example:**
```python
from hccpf import is_valid_ipv6_address

print(is_valid_ipv6_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))  # Output: True
print(is_valid_ipv6_address("invalid-ip"))  # Output: False
```

---

## `comp_dates(d1, d2)`
Compares two date strings in the format `"%Y-%m-%d %H:%M:%S"` and returns the difference in seconds.

**Example:**
```python
from hccpf import comp_dates

d1 = "2024-01-01 12:00:00"
d2 = "2024-01-01 13:00:00"
print(comp_dates(d1, d2))  # Output: 3600
```

---

## `sendEmail(...)`
Sends an email using an SMTP server.

**Example:**
```python
from hccpf import sendEmail

sendEmail(
    mail_from="sender@example.com",
    mail_to="receiver@example.com",
    mail_subject="Test Email",
    mail_body="This is a test email.",
    smtp_server="smtp.example.com",
    smtp_port=587,
    smtp_user="user",
    smtp_pass="password"
)
```

---

## `input_validate(my_string, check_type)`
Validates a string based on the specified type (e.g., username, hostname, email).

Valid check types:

| Type | Description |
|---|---|
| username | A valid username |
| hostname | A valid hostname |
| int | It's a int? |
| email | A valid email address |
| comment | A valid comment (letters, numbers, spaces) |
| version_name | A product version name |
| aws_ami_id | A valid AWS AMI ID |
| phone | Basic international format |
| phone_us | US format (10 digits) |
| phone_intl | Strict international format |


**Example:**
```python
from hccpf import input_validate

print(input_validate("test_user", "username"))  # Output: True
print(input_validate("test@", "email"))  # Output: None
```

---

## `random_id()`
Generates a random alphanumeric string between 8 and 16 characters.

**Example:**
```python
from hccpf import random_id

print(random_id())  # Output: "A1b2C3d4E5"
```

---

## `resolve_hostname(hostname)`
Resolves a hostname to its corresponding IP address.

**Example:**
```python
from hccpf import resolve_hostname

print(resolve_hostname("example.com"))  # Output: "93.184.216.34"
```

---

## `stripComments(code)`
Removes comments from a given string.

**Example:**
```python
from hccpf import stripComments

code = """
# This is a comment
print("Hello, world!")  # Inline comment
"""
print(stripComments(code))
# Output:
# print("Hello, world!")
```

---

## `string_encode(crypt_pass, message)`
Encrypts and encodes a message using an encryption key and Base64.

**Example:**
```python
from hccpf import string_encode

key = "mypassword"
message = "This is a secret message"
encoded = string_encode(key, message)
print(encoded)
```

---

## `string_decode(crypt_pass, my_cipher)`
Decrypts and decodes a previously encrypted message.

**Example:**
```python
from hccpf import string_decode

key = "mypassword"
decoded = string_decode(key, encoded)
print(decoded)  # Output: "This is a secret message"
```

---

## `ValidateEmail(email)`
Checks if the provided string is a valid email address.

**Example:**
```python
from hccpf import ValidateEmail

print(ValidateEmail("user@example.com"))  # Output: 1
print(ValidateEmail("invalid-email"))  # Output: 0
```

---

## `random_password()`
Generates a random password between 8 and 16 characters.

**Example:**
```python
from hccpf import random_password

print(random_password())  # Output: "A1b2C3d4E5"
```

---

## `twolists_to_dictionary(keys, values)`
Combines two lists into a dictionary.

**Example:**
```python
from hccpf import twolists_to_dictionary

keys = ["a", "b", "c"]
values = [1, 2, 3]
print(twolists_to_dictionary(keys, values))  # Output: {"a": 1, "b": 2, "c": 3}
```

---

## `validate_time_format(string)`
Validates if a string matches the `"hh:mm"` format.

**Example:**
```python
from hccpf import validate_time_format

print(validate_time_format("12:34"))  # Output: True
print(validate_time_format("99:99"))  # Output: False
```

---

## `get_shortname(fqdn)`
Extracts the short hostname from a Fully Qualified Domain Name.

**Example:**
```python
from hccpf import get_shortname

print(get_shortname("host.example.com"))  # Output: "host"
```

## `is_valid_ip(ip: str)`
Validates if the provided string is a valid IPv4 or IPv6 address.
**Example:**
```python
from hccpf import is_valid_ip
print(is_valid_ip("192.168.0.1"))  # Output: True
print(is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))  # Output: True
print(is_valid_ip("256.256.256.256"))  # Output: False
```
---

## `get_ip_version(ip: str)`
Returns IP version (4 or 6) or None if invalid.
**Example:**
```python
from hccpf import get_ip_version
print(get_ip_version("192.168.0.1"))  # Output: 4
print(get_ip_version("2001:0db8::1"))  # Output: 6
print(get_ip_version("invalid"))  # Output: None
```
---

## `ping_host(host: str, count: int = 4)`
Pings a host and returns statistics including success, average time, and packet loss.
**Example:**
```python
from hccpf import ping_host
result = ping_host("google.com")
print(result)  # Output: {'success': True, 'avg_time': 20.1, 'packet_loss': 0.0}
```
---

## `get_dns_records(domain: str, record_type: str = 'A')`
Retrieves DNS records for a domain with specified record type.
**Example:**
```python
from hccpf import get_dns_records
print(get_dns_records("google.com"))  # Output: ['142.251.16.100', '142.251.16.101']
print(get_dns_records("google.com", "MX"))  # Output: ['10 smtp.google.com']
```
---

## `check_port(host: str, port: int, timeout: float = 2.0)`
Checks if a specific port is open on a host.
**Example:**
```python
from hccpf import check_port
print(check_port("google.com", 80))  # Output: True
print(check_port("google.com", 22))  # Output: False
```
---

## `get_subnet_info(cidr: str)`
Calculates subnet information from CIDR notation.
**Example:**
```python
from hccpf import get_subnet_info
print(get_subnet_info("192.168.1.0/24"))
# Output: {
#     'network_address': '192.168.1.0',
#     'broadcast_address': '192.168.1.255',
#     'netmask': '255.255.255.0',
#     'num_addresses': 256,
#     'hosts': 254
# }
```
---

## `check_url_status(url: str, timeout: float = 5.0)`
Checks HTTP status and response time of a URL.
**Example:**
```python
from hccpf import check_url_status
print(check_url_status("https://www.google.com"))
# Output: {'status_code': 200, 'success': True, 'response_time': 0.245}
```

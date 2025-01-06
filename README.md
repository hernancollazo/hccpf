# hccpf
Common useful python functions

# Installation

Install this directly into your project using PIP:

```pip install git+https://github.com/hernancollazo/hccpf.git@main```

# Functions Overview

## 1. `get_domain(string)`
Extracts the domain name from a given URL.

**Example:**
```python
from hccpf import get_domain

url = "https://www.example.com/path?query=value"
print(get_domain(url))  # Output: "www.example.com"
```

---

## 2. `is_valid_ipv4_address(address)`
Checks if the provided string is a valid IPv4 address.

**Example:**
```python
from hccpf import is_valid_ipv4_address

print(is_valid_ipv4_address("192.168.0.1"))  # Output: True
print(is_valid_ipv4_address("256.256.256.256"))  # Output: False
```

---

## 3. `is_valid_ipv6_address(address)`
Checks if the provided string is a valid IPv6 address.

**Example:**
```python
from hccpf import is_valid_ipv6_address

print(is_valid_ipv6_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))  # Output: True
print(is_valid_ipv6_address("invalid-ip"))  # Output: False
```

---

## 4. `comp_dates(d1, d2)`
Compares two date strings in the format `"%Y-%m-%d %H:%M:%S"` and returns the difference in seconds.

**Example:**
```python
from hccpf import comp_dates

d1 = "2024-01-01 12:00:00"
d2 = "2024-01-01 13:00:00"
print(comp_dates(d1, d2))  # Output: 3600
```

---

## 5. `sendEmail(...)`
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

## 6. `input_validate(my_string, check_type)`
Validates a string based on the specified type (e.g., username, hostname, email).

**Example:**
```python
from hccpf import input_validate

print(input_validate("test_user", "username"))  # Output: True
print(input_validate("test@", "email"))  # Output: None
```

---

## 7. `random_id()`
Generates a random alphanumeric string between 8 and 16 characters.

**Example:**
```python
from hccpf import random_id

print(random_id())  # Output: "A1b2C3d4E5"
```

---

## 8. `resolve_hostname(hostname)`
Resolves a hostname to its corresponding IP address.

**Example:**
```python
from hccpf import resolve_hostname

print(resolve_hostname("example.com"))  # Output: "93.184.216.34"
```

---

## 9. `stripComments(code)`
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

## 10. `string_encode(crypt_pass, message)`
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

## 11. `string_decode(crypt_pass, my_cipher)`
Decrypts and decodes a previously encrypted message.

**Example:**
```python
from hccpf import string_decode

key = "mypassword"
decoded = string_decode(key, encoded)
print(decoded)  # Output: "This is a secret message"
```

---

## 12. `ValidateEmail(email)`
Checks if the provided string is a valid email address.

**Example:**
```python
from hccpf import ValidateEmail

print(ValidateEmail("user@example.com"))  # Output: 1
print(ValidateEmail("invalid-email"))  # Output: 0
```

---

## 13. `random_password()`
Generates a random password between 8 and 16 characters.

**Example:**
```python
from hccpf import random_password

print(random_password())  # Output: "A1b2C3d4E5"
```

---

## 14. `twolists_to_dictionary(keys, values)`
Combines two lists into a dictionary.

**Example:**
```python
from hccpf import twolists_to_dictionary

keys = ["a", "b", "c"]
values = [1, 2, 3]
print(twolists_to_dictionary(keys, values))  # Output: {"a": 1, "b": 2, "c": 3}
```

---

## 15. `validate_time_format(string)`
Validates if a string matches the `"hh:mm"` format.

**Example:**
```python
from hccpf import validate_time_format

print(validate_time_format("12:34"))  # Output: True
print(validate_time_format("99:99"))  # Output: False
```

---

## 16. `get_shortname(fqdn)`
Extracts the short hostname from a Fully Qualified Domain Name.

**Example:**
```python
from hccpf import get_shortname

print(get_shortname("host.example.com"))  # Output: "host"

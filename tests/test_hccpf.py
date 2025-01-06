import unittest
from hccpf import (
    get_domain,
    is_valid_ipv4_address,
    is_valid_ipv6_address,
    comp_dates,
    sendEmail,
    input_validate,
    random_id,
    random_password,
)

class TestUtilityFunctions(unittest.TestCase):

    def test_get_domain(self):
        self.assertEqual(get_domain("http://example.com"), "example.com")
        self.assertEqual(get_domain("https://subdomain.example.com/path"), "subdomain.example.com")
        self.assertEqual(get_domain("ftp://example.com"), "example.com")
        self.assertIsNone(get_domain("not_a_url"))

    def test_is_valid_ipv4_address(self):
        self.assertTrue(is_valid_ipv4_address("192.168.1.1"))
        self.assertFalse(is_valid_ipv4_address("256.256.256.256"))
        self.assertFalse(is_valid_ipv4_address("not_an_ip"))

    def test_is_valid_ipv6_address(self):
        self.assertTrue(is_valid_ipv6_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
        self.assertFalse(is_valid_ipv6_address("not_an_ip"))

    def test_comp_dates(self):
        self.assertEqual(comp_dates("2024-01-01 00:00:00", "2024-01-01 00:01:00"), 60)
        self.assertEqual(comp_dates("2024-01-01 00:00:00", "2023-12-31 23:59:00"), -60)

    def test_input_validate(self):
        # self.assertTrue(input_validate("username123", "username"))
        # self.assertFalse(input_validate("user@name", "username"))
        self.assertTrue(input_validate("hostname", "hostname"))
        # self.assertFalse(input_validate("invalid_hostname!", "hostname"))

    def test_generate_random_id(self):
        random_string = random_id()
        self.assertGreaterEqual(len(random_string), 8)
        self.assertLessEqual(len(random_string), 16)
        self.assertTrue(all(c.isalnum() for c in random_string))

    def test_generate_random_password(self):
        random_string = random_password()
        self.assertGreaterEqual(len(random_string), 8)
        self.assertLessEqual(len(random_string), 16)
        self.assertTrue(all(c.isalnum() for c in random_string))

    # Note: For `sendEmail`, testing requires a mock SMTP server.

if __name__ == "__main__":
    unittest.main()

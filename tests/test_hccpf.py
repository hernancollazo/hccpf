import unittest
import ipaddress
from hccpf import (
    get_domain,
    is_valid_ipv4_address,
    is_valid_ipv6_address,
    comp_dates,
    sendEmail,
    input_validate,
    random_id,
    random_password,
    is_valid_ip,
    get_ip_version,
    ping_host,
    get_dns_records,
    check_port,
    get_subnet_info,
    check_url_status,
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
        self.assertTrue(input_validate("hostname", "hostname"))

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

    # New test methods for network functions
    def test_is_valid_ip(self):
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
        self.assertFalse(is_valid_ip("256.256.256.256"))
        self.assertFalse(is_valid_ip("not_an_ip"))

    def test_get_ip_version(self):
        self.assertEqual(get_ip_version("192.168.1.1"), 4)
        self.assertEqual(get_ip_version("2001:0db8::1"), 6)
        self.assertIsNone(get_ip_version("not_an_ip"))

    def test_ping_host(self):
        result = ping_host("localhost")
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
        self.assertIn('avg_time', result)
        self.assertIn('packet_loss', result)

    def test_get_dns_records(self):
        records = get_dns_records("google.com")
        self.assertIsInstance(records, list)
        for record in records:
            self.assertIsInstance(record, str)

    def test_check_port(self):
        result = check_port("localhost", 80)
        self.assertIsInstance(result, bool)

    def test_get_subnet_info(self):
        result = get_subnet_info("192.168.1.0/24")
        self.assertIn('network_address', result)
        self.assertIn('broadcast_address', result)
        self.assertIn('netmask', result)
        self.assertIn('num_addresses', result)
        self.assertEqual(result['num_addresses'], 256)

    def test_check_url_status(self):
        result = check_url_status("https://www.google.com")
        self.assertIn('status_code', result)
        self.assertIn('success', result)
        self.assertIn('response_time', result)

if __name__ == "__main__":
    unittest.main()

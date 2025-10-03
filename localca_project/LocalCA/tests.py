'''
This module contains the tests for the CertificateAuthority class.
'''
from datetime import datetime, timedelta
from django.test import TestCase
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from .ca import CertificateAuthority


class CertificateAuthorityTests(TestCase):
    """
    This class contains the tests for the CertificateAuthority class.
    """

    def setUp(self):
        self.ca = CertificateAuthority()
        self.common_name = "Test CA"
        self.validity_days = 365

    def test_generate_private_key(self):
        """Test private key generation"""
        private_key = self.ca.generate_private_key()
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertEqual(private_key.key_size, 2048)

    def test_create_root_certificate(self):
        """Test root certificate creation"""
        result = self.ca.create_root_certificate(
            self.common_name, self.validity_days)

        # Check if all expected keys are present
        self.assertIn("serial_number", result)
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
        self.assertIn("valid_until", result)

        # Verify the certificate format
        self.assertTrue(result["public_key"].startswith(
            "-----BEGIN CERTIFICATE-----"))
        self.assertTrue(result["public_key"].endswith(
            "-----END CERTIFICATE-----\n"))

        # Verify the private key format
        self.assertTrue(result["private_key"].startswith(
            "-----BEGIN RSA PRIVATE KEY-----"))
        self.assertTrue(result["private_key"].endswith(
            "-----END RSA PRIVATE KEY-----\n"))

        # Check validity period
        self.assertIsInstance(result["valid_until"], datetime)
        now = timezone.now()
        expected_expiry = now + timedelta(days=self.validity_days)
        # Both datetimes are already timezone-aware
        self.assertLess(abs(result["valid_until"] -
                            expected_expiry), timedelta(seconds=5))

    def test_create_root_certificate_with_different_validity(self):
        """Test root certificate creation with different validity period"""
        test_validity = 730  # 2 years
        result = self.ca.create_root_certificate(
            self.common_name, test_validity)
        now = timezone.now()
        expected_expiry = now + timedelta(days=test_validity)
        # Both datetimes are already timezone-aware
        self.assertLess(abs(result["valid_until"] -
                            expected_expiry), timedelta(seconds=5))

    def test_root_certificate_properties(self):
        """Test the properties of the created root certificate"""
        result = self.ca.create_root_certificate(
            self.common_name, self.validity_days)

        # Load the certificate for inspection
        cert_bytes = result["public_key"].encode()
        cert = x509.load_pem_x509_certificate(cert_bytes)

        # Check the common name
        cn = cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, self.common_name)

        # Check organization name
        org = cert.subject.get_attributes_for_oid(
            x509.NameOID.ORGANIZATION_NAME)[0].value
        self.assertEqual(org, "LocalCA")

        # Verify it's a CA certificate
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints)
        self.assertTrue(basic_constraints.value.ca)
        self.assertIsNone(basic_constraints.value.path_length)

    def test_create_root_certificate_with_invalid_inputs(self):
        """Test root certificate creation with invalid inputs"""
        # Test with empty common name
        with self.assertRaises(ValueError):
            self.ca.create_root_certificate("", self.validity_days)

        # Test with negative validity days
        with self.assertRaises(ValueError):
            self.ca.create_root_certificate(self.common_name, -365)

        # Test with zero validity days
        with self.assertRaises(ValueError):
            self.ca.create_root_certificate(self.common_name, 0)

    def test_create_intermediate_certificate(self):
        """Test intermediate certificate creation"""
        # First create a root certificate
        root_cert = self.ca.create_root_certificate("Root CA", 365)

        # Create intermediate certificate
        result = self.ca.create_intermediate_certificate(
            common_name="Intermediate CA",
            validity_days=365,
            root_public_key=root_cert["public_key"],
            root_private_key=root_cert["private_key"]
        )

        # Check if all expected keys are present
        self.assertIn("serial_number", result)
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
        self.assertIn("valid_until", result)

        # Verify the certificate format
        self.assertTrue(result["public_key"].startswith(
            "-----BEGIN CERTIFICATE-----"))
        self.assertTrue(result["public_key"].endswith(
            "-----END CERTIFICATE-----\n"))

        # Verify the private key format
        self.assertTrue(result["private_key"].startswith(
            "-----BEGIN RSA PRIVATE KEY-----"))
        self.assertTrue(result["private_key"].endswith(
            "-----END RSA PRIVATE KEY-----\n"))

        # Load and verify the certificate
        cert_bytes = result["public_key"].encode()
        cert = x509.load_pem_x509_certificate(cert_bytes)

        # Check the common name
        cn = cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, "Intermediate CA")

        # Check that it's signed by the root CA
        root_cert_obj = x509.load_pem_x509_certificate(
            root_cert["public_key"].encode())
        self.assertEqual(cert.issuer, root_cert_obj.subject)

    def test_intermediate_certificate_chain(self):
        """Test the certificate chain from root to intermediate"""
        # Create root certificate
        root_cert = self.ca.create_root_certificate("Root CA", 365)

        # Create intermediate certificate
        intermediate = self.ca.create_intermediate_certificate(
            common_name="Intermediate CA",
            validity_days=365,
            root_public_key=root_cert["public_key"],
            root_private_key=root_cert["private_key"]
        )

        # Load certificates
        root_cert_obj = x509.load_pem_x509_certificate(
            root_cert["public_key"].encode())
        intermediate_cert_obj = x509.load_pem_x509_certificate(
            intermediate["public_key"].encode())

        # Verify the chain
        self.assertEqual(intermediate_cert_obj.issuer, root_cert_obj.subject)
        self.assertNotEqual(
            intermediate_cert_obj.subject,
            root_cert_obj.subject)

    def test_create_intermediate_certificate_with_invalid_inputs(self):
        """Test intermediate certificate creation with invalid inputs"""
        root_cert = self.ca.create_root_certificate("Root CA", 365)

        # Test with empty common name
        with self.assertRaises(ValueError):
            self.ca.create_intermediate_certificate(
                common_name="",
                validity_days=365,
                root_public_key=root_cert["public_key"],
                root_private_key=root_cert["private_key"]
            )

        # Test with invalid root certificate
        with self.assertRaises(ValueError):
            self.ca.create_intermediate_certificate(
                common_name="Intermediate CA",
                validity_days=365,
                root_public_key="invalid-cert",
                root_private_key=root_cert["private_key"]
            )

        # Test with invalid root private key
        with self.assertRaises(ValueError):
            self.ca.create_intermediate_certificate(
                common_name="Intermediate CA",
                validity_days=365,
                root_public_key=root_cert["public_key"],
                root_private_key="invalid-key"
            )

    def test_create_leaf_certificate(self):
        """Test leaf certificate creation with DNS and IP SANs"""
        # Create root and intermediate certificates first
        root_cert = self.ca.create_root_certificate("Root CA", 365)
        intermediate = self.ca.create_intermediate_certificate(
            common_name="Intermediate CA",
            validity_days=365,
            root_public_key=root_cert["public_key"],
            root_private_key=root_cert["private_key"]
        )

        # Create leaf certificate with both DNS and IP SANs
        san_list = ["test.example.com", "192.168.1.1", "*.example.com"]
        result = self.ca.create_leaf_certificate(
            common_name="test.example.com",
            san_list=san_list,
            validity_days=90,
            intermediate_public_key=intermediate["public_key"],
            intermediate_private_key=intermediate["private_key"]
        )

        # Basic certificate checks
        self.assertIn("serial_number", result)
        self.assertIn("public_key", result)
        self.assertIn("private_key", result)
        self.assertIn("valid_until", result)

        # Load and verify the certificate
        cert = x509.load_pem_x509_certificate(result["public_key"].encode())

        # Check validity period
        now = timezone.now()
        expected_expiry = now + timedelta(days=90)
        self.assertLess(abs(result["valid_until"] -
                            expected_expiry), timedelta(seconds=5))

        # Verify SAN extension
        san_extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName)
        sans = san_extension.value

        # Check DNS names
        dns_names = [
            name.value for name in sans if isinstance(
                name, x509.DNSName)]
        self.assertIn("test.example.com", dns_names)
        self.assertIn("*.example.com", dns_names)

        # Check IP addresses
        ip_addresses = [
            ip.value for ip in sans if isinstance(
                ip, x509.IPAddress)]
        self.assertEqual(str(ip_addresses[0]), "192.168.1.1")

    def test_leaf_certificate_chain(self):
        """Test the complete certificate chain from root to leaf"""
        # Create the certificate chain
        root_cert = self.ca.create_root_certificate("Root CA", 365)
        intermediate = self.ca.create_intermediate_certificate(
            common_name="Intermediate CA",
            validity_days=365,
            root_public_key=root_cert["public_key"],
            root_private_key=root_cert["private_key"]
        )
        leaf = self.ca.create_leaf_certificate(
            common_name="test.example.com",
            san_list=["test.example.com"],
            validity_days=90,
            intermediate_public_key=intermediate["public_key"],
            intermediate_private_key=intermediate["private_key"]
        )

        # Load all certificates
        root_cert_obj = x509.load_pem_x509_certificate(
            root_cert["public_key"].encode())
        intermediate_cert_obj = x509.load_pem_x509_certificate(
            intermediate["public_key"].encode())
        leaf_cert_obj = x509.load_pem_x509_certificate(
            leaf["public_key"].encode())

        # Verify the chain
        self.assertEqual(leaf_cert_obj.issuer, intermediate_cert_obj.subject)
        self.assertEqual(intermediate_cert_obj.issuer, root_cert_obj.subject)

    def test_leaf_certificate_constraints(self):
        """Test that leaf certificates cannot be CA certificates"""
        root_cert = self.ca.create_root_certificate("Root CA", 365)
        intermediate = self.ca.create_intermediate_certificate(
            common_name="Intermediate CA",
            validity_days=365,
            root_public_key=root_cert["public_key"],
            root_private_key=root_cert["private_key"]
        )

        leaf = self.ca.create_leaf_certificate(
            common_name="test.example.com",
            san_list=["test.example.com"],
            validity_days=90,
            intermediate_public_key=intermediate["public_key"],
            intermediate_private_key=intermediate["private_key"]
        )

        # Load leaf certificate and check BasicConstraints
        leaf_cert_obj = x509.load_pem_x509_certificate(
            leaf["public_key"].encode())
        basic_constraints = leaf_cert_obj.extensions.get_extension_for_class(
            x509.BasicConstraints)
        self.assertFalse(basic_constraints.value.ca)

    def test_create_leaf_certificate_with_invalid_inputs(self):
        """Test leaf certificate creation with invalid inputs"""
        root_cert = self.ca.create_root_certificate("Root CA", 365)
        intermediate = self.ca.create_intermediate_certificate(
            common_name="Intermediate CA",
            validity_days=365,
            root_public_key=root_cert["public_key"],
            root_private_key=root_cert["private_key"]
        )

        # Test with empty common name
        with self.assertRaises(ValueError):
            self.ca.create_leaf_certificate(
                common_name="",
                san_list=["test.example.com"],
                validity_days=90,
                intermediate_public_key=intermediate["public_key"],
                intermediate_private_key=intermediate["private_key"]
            )

    def test_leaf_certificate_san_types(self):
        """Test different types of Subject Alternative Names"""
        root_cert = self.ca.create_root_certificate("Root CA", 365)
        intermediate = self.ca.create_intermediate_certificate(
            common_name="Intermediate CA",
            validity_days=365,
            root_public_key=root_cert["public_key"],
            root_private_key=root_cert["private_key"]
        )

        # Test various SAN types
        san_list = [
            "test.example.com",          # Regular domain
            "*.wildcard.example.com",    # Wildcard domain
            "192.168.1.1",              # IPv4
            "2001:db8::1",              # IPv6
        ]

        result = self.ca.create_leaf_certificate(
            common_name="test.example.com",
            san_list=san_list,
            validity_days=90,
            intermediate_public_key=intermediate["public_key"],
            intermediate_private_key=intermediate["private_key"]
        )

        cert = x509.load_pem_x509_certificate(result["public_key"].encode())
        san_extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName)
        sans = san_extension.value

        # Check all SAN types
        dns_names = [
            name.value for name in sans if isinstance(
                name, x509.DNSName)]
        ip_addresses = [str(ip.value)
                        for ip in sans if isinstance(ip, x509.IPAddress)]

        self.assertIn("test.example.com", dns_names)
        self.assertIn("*.wildcard.example.com", dns_names)
        self.assertIn("192.168.1.1", ip_addresses)
        self.assertIn("2001:db8::1", ip_addresses)


class ReverseProxyConfigurationTests(TestCase):
    """
    Test suite for reverse proxy configuration (SCRIPT_NAME support)
    """

    def test_settings_force_script_name_from_env(self):
        """Test that FORCE_SCRIPT_NAME is correctly read from environment"""
        # Test that the setting can be None (default) or set from environment
        # This verifies the configuration in settings.py is properly set up
        self.assertIn(settings.FORCE_SCRIPT_NAME, [None, '/localca'])

    def test_static_url_configuration(self):
        """Test that STATIC_URL is correctly configured based on FORCE_SCRIPT_NAME"""
        # When FORCE_SCRIPT_NAME is None, STATIC_URL should be '/static/'
        # When FORCE_SCRIPT_NAME is set, STATIC_URL should include the prefix
        if settings.FORCE_SCRIPT_NAME is None:
            self.assertEqual(settings.STATIC_URL, '/static/')
        elif settings.FORCE_SCRIPT_NAME == '/localca':
            self.assertEqual(settings.STATIC_URL, '/localca/static/')

    def test_url_patterns_exist(self):
        """Test that all expected URL patterns are defined"""
        # These URLs should always be resolvable regardless of SCRIPT_NAME
        # This ensures our URL configuration is correct
        from django.urls.exceptions import NoReverseMatch
        try:
            reverse('homepage')
            reverse('create_ca')
            reverse('create_leaf')
            reverse('login')
            reverse('logout')
        except NoReverseMatch as exc:
            self.fail(f"URL pattern resolution failed: {exc}")

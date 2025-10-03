'''
This module contains the CertificateAuthority class, which is used to generate
root, intermediate, and leaf certificates.
'''

import logging
import ipaddress
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12


logger = logging.getLogger(__name__)


class CertificateAuthority:
    """
    A class to manage certificate generation, CSR creation, and signing.
    """

    def generate_private_key(self):
        """
        Generate an RSA private key.
        """
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def create_root_certificate(
            self,
            common_name: str,
            validity_days: int) -> dict:
        """
        Create a self-signed root certificate.

        Args:
            common_name: The common name for the certificate
            validity_days: Number of days the certificate should be valid

        Raises:
            ValueError: If common_name is empty or validity_days is not positive
        """
        if not common_name or not common_name.strip():
            raise ValueError("Common name cannot be empty")
        if validity_days <= 0:
            raise ValueError("Validity days must be positive")

        private_key = self.generate_private_key()
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LocalCA"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA256(), default_backend())

        return {
            "serial_number": cert.serial_number,
            "public_key": cert.public_bytes(
                serialization.Encoding.PEM).decode(),
            "private_key": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()).decode(),
            "valid_until": cert.not_valid_after_utc,
        }

    def create_intermediate_certificate(
            self,
            common_name: str,
            validity_days: int,
            root_public_key: str,
            root_private_key: str) -> dict:
        """
        Create an intermediate certificate signed by a root certificate.
        """
        private_key = self.generate_private_key()

        csr = self.create_csr(common_name, private_key)

        root_cert = x509.load_pem_x509_certificate(
            root_public_key.encode(), default_backend())

        cert = self.sign_csr(csr, validity_days, root_cert, root_private_key)

        return {
            "serial_number": cert.serial_number,
            "public_key": cert.public_bytes(
                serialization.Encoding.PEM).decode(),
            "private_key": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()).decode(),
            "valid_until": cert.not_valid_after_utc,
        }

    def create_leaf_certificate(
            self,
            common_name: str,
            san_list: list,
            validity_days: int,
            intermediate_public_key: str,
            intermediate_private_key: str) -> dict:
        """
        Create a leaf certificate signed by an intermediate certificate.
        """
        private_key = self.generate_private_key()

        csr = self.create_leaf_csr(common_name, san_list, private_key)

        intermediate_cert = x509.load_pem_x509_certificate(
            intermediate_public_key.encode(),
            default_backend()
        )

        cert = self.sign_leaf_csr(
            csr,
            validity_days,
            intermediate_cert,
            intermediate_private_key)

        return {
            "serial_number": cert.serial_number,
            "public_key": cert.public_bytes(
                serialization.Encoding.PEM).decode(),
            "private_key": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()).decode(),
            "valid_until": cert.not_valid_after_utc,
        }

    def create_csr(
            self,
            common_name: str,
            key) -> x509.CertificateSigningRequest:
        """
        Create a CSR for a certificate.
        """
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LocalCA"),
        ])).sign(key, hashes.SHA256(), default_backend())

        return csr

    def create_leaf_csr(
            self,
            common_name: str,
            san_list: list,
            key) -> x509.CertificateSigningRequest:
        """
        Create a CSR for a leaf certificate with SANs.
        """
        # Create DNS names for all SANs
        san_objects = []

        # Process each SAN
        for san in san_list:
            san = str(san).strip()
            if not san:
                continue

            try:
                # Try to parse as IP address
                ip = ipaddress.ip_address(san)
                san_objects.append(x509.IPAddress(ip))
            except ValueError:
                # If not an IP, add as DNS name
                san_objects.append(x509.DNSName(san))

        # Create the CSR with SANs
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LocalCA"),
        ])).add_extension(
            x509.SubjectAlternativeName(san_objects),
            critical=False
        ).sign(key, hashes.SHA256(), default_backend())

        return csr

    def sign_csr(
            self,
            csr: x509.CertificateSigningRequest,
            validity_days: int,
            ca_cert: x509.Certificate,
            ca_private_key: str) -> x509.Certificate:
        """
        Sign a CSR with a CA's key to issue an intermediate certificate.
        """
        ca_private_key_obj = serialization.load_pem_private_key(
            ca_private_key.encode(), password=None)

        cert_builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )

        return cert_builder.sign(
            ca_private_key_obj,
            hashes.SHA256(),
            default_backend())

    def sign_leaf_csr(
            self,
            csr: x509.CertificateSigningRequest,
            validity_days: int,
            ca_cert: x509.Certificate,
            ca_private_key: str) -> x509.Certificate:
        """
        Sign a CSR with a CA's key to issue a leaf certificate.
        """
        ca_private_key_obj = serialization.load_pem_private_key(
            ca_private_key.encode(), password=None)

        builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        )

        # Add SAN extension if present in the CSR
        try:
            san_extension = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName)
            builder = builder.add_extension(
                san_extension.value, critical=san_extension.critical)
        except x509.ExtensionNotFound:
            logger.warning(
                "SAN extension not found in CSR; proceeding without it.")

        # Add BasicConstraints extension for a leaf certificate
        builder = builder.add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None),
            critical=True)

        return builder.sign(
            ca_private_key_obj,
            hashes.SHA256(),
            default_backend())

    def create_pkcs12(
            self,
            cert_pem: str,
            private_key_pem: str,
            ca_cert_pem: str = None,
            friendly_name: str = None) -> bytes:
        """
        Create a PKCS12 bundle containing the certificate and private key.
        
        Args:
            cert_pem: PEM-encoded certificate
            private_key_pem: PEM-encoded private key
            ca_cert_pem: Optional PEM-encoded CA certificate for chain
            friendly_name: Optional friendly name for the certificate
            
        Returns:
            PKCS12 bundle as bytes
        """
        # Load the certificate
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode(),
            default_backend()
        )

        # Load the private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )

        # Load CA certificate if provided
        ca_certs = []
        if ca_cert_pem:
            ca_cert = x509.load_pem_x509_certificate(
                ca_cert_pem.encode(),
                default_backend()
            )
            ca_certs.append(ca_cert)

        # Create PKCS12 bundle
        pkcs12_bundle = pkcs12.serialize_key_and_certificates(
            name=friendly_name.encode() if friendly_name else None,
            key=private_key,
            cert=cert,
            cas=ca_certs if ca_certs else None,
            encryption_algorithm=serialization.NoEncryption()
        )

        return pkcs12_bundle

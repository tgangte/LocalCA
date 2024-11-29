from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import User


class RootCertificate(models.Model):
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='root_certificates',
        null=True)
    name = models.CharField(max_length=255, unique=True)
    serial_number = models.CharField(
        max_length=255, unique=True)  # Unique serial number
    public_key = models.TextField()
    private_key_encrypted = models.TextField()  # Encrypted private key
    created_at = models.DateTimeField(auto_now_add=True)
    valid_until = models.DateTimeField()

    def __str__(self):
        return f"Root Certificate: {self.name}"


class IntermediateCertificate(models.Model):
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='intermediate_certificates',
        null=True)
    name = models.CharField(max_length=255, unique=True)
    serial_number = models.CharField(
        max_length=255, unique=True)  # Unique serial number
    public_key = models.TextField()
    private_key_encrypted = models.TextField()  # Encrypted private key
    signed_by_root = models.ForeignKey(
        RootCertificate, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    valid_until = models.DateTimeField()

    def __str__(self):
        return f"Intermediate Certificate: {self.name}"


class LeafCertificate(models.Model):
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='leaf_certificates',
        null=True)
    common_name = models.CharField(max_length=255)
    san = models.TextField()  # Comma-separated SANs
    valid_until = models.DateTimeField()
    serial_number = models.CharField(
        max_length=255, unique=True)  # Unique serial number
    public_key = models.TextField()
    private_key_encrypted = models.TextField()  # Encrypted private key
    signed_by_intermediate = models.ForeignKey(
        IntermediateCertificate, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Leaf Certificate: {self.common_name}"


class RevokedCertificate(models.Model):
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='revoked_certificates',
        null=True)
    certificate = models.OneToOneField(
        LeafCertificate, on_delete=models.CASCADE)
    reason = models.TextField()  # Reason for revocation
    revoked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Revoked: {self.certificate.common_name}"


class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('CREATE', 'Create'),
        ('REVOKE', 'Revoke'),
        ('DOWNLOAD', 'Download'),
        ('ACCESS', 'Access'),
    ]

    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    performed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField()

    def __str__(self):
        return f"{self.action} by {self.performed_by} at {self.timestamp}"

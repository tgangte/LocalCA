from django.contrib import admin

from .models import RootCertificate, IntermediateCertificate, LeafCertificate, RevokedCertificate, AuditLog

# Register your models here.
admin.site.register(RootCertificate)
admin.site.register(IntermediateCertificate)
admin.site.register(LeafCertificate)
admin.site.register(RevokedCertificate)
admin.site.register(AuditLog)
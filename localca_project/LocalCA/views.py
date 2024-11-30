"""Views for the LocalCA application handling certificate operations."""

from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, Http404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import logout
from .models import (
    RootCertificate,
    IntermediateCertificate,
    LeafCertificate,
    RevokedCertificate,
    AuditLog,
)
from .ca import CertificateAuthority


def homepage(request):
    """
    Public-facing homepage that lists all certificates (public keys only).
    For authenticated users, also shows their own certificates with private keys.
    """
    roots = RootCertificate.objects.all()
    certificate_tree = []

    for root in roots:
        # Get intermediates signed by this root
        intermediates = IntermediateCertificate.objects.filter(signed_by_root=root)
        intermediate_list = []

        for intermediate in intermediates:
            # Get leaves signed by this intermediate
            leaves = LeafCertificate.objects.filter(signed_by_intermediate=intermediate)
            intermediate_list.append(
                {
                    "intermediate": intermediate,
                    "is_owner": request.user.is_authenticated
                    and intermediate.created_by == request.user,
                    "leaves": [
                        {
                            "cert": leaf,
                            "is_owner": request.user.is_authenticated
                            and leaf.created_by == request.user,
                        }
                        for leaf in leaves
                    ],
                }
            )

        certificate_tree.append(
            {
                "root": root,
                "is_owner": request.user.is_authenticated
                and root.created_by == request.user,
                "intermediates": intermediate_list,
            }
        )

    return render(
        request,
        "LocalCA/homepage.html",
        {
            "certificate_tree": certificate_tree,
            "is_authenticated": request.user.is_authenticated,
        },
    )


def download(request, serial_number):
    """
    View to download the public key of a certificate.
    For leaf certificates, returns the full chain (Root -> Intermediate -> Leaf).
    """
    # Try to find the certificate in any of the certificate models
    cert = None
    for model in [RootCertificate, IntermediateCertificate, LeafCertificate]:
        try:
            cert = model.objects.get(serial_number=serial_number)
            break
        except model.DoesNotExist:
            continue

    if not cert:
        raise Http404("Certificate not found")

    # If it's a leaf certificate, create a chain
    if isinstance(cert, LeafCertificate):
        # Build the chain from leaf to root
        intermediate = cert.signed_by_intermediate
        root = intermediate.signed_by_root

        # Concatenate the certificates in order (root -> intermediate -> leaf)
        chain = (
            f"# Root CA Certificate\n{root.public_key}\n\n"
            f"# Intermediate CA Certificate\n{intermediate.public_key}\n\n"
            f"# Leaf Certificate\n{cert.public_key}"
        )

        response = HttpResponse(chain, content_type="text/plain")
        response["Content-Disposition"] = (
            f"attachment; filename={cert.common_name}_chain.pem"
        )

    # For root and intermediate certs, just return their public key
    else:
        cert_name = cert.name if hasattr(cert, "name") else cert.common_name
        response = HttpResponse(cert.public_key, content_type="text/plain")
        response["Content-Disposition"] = f"attachment; filename={cert_name}.pem"

    # Log the download
    AuditLog.objects.create(
        action="DOWNLOAD_PUBLIC_KEY",
        performed_by=request.user if request.user.is_authenticated else None,
        details=(
            f"Downloaded {'certificate chain' if isinstance(cert, LeafCertificate) else 'certificate'} "
            f"for: {cert_name if not isinstance(cert, LeafCertificate) else cert.common_name}"
        ),
    )

    return response


@login_required
def create_ca(request):
    """
    View to create both root and intermediate CAs.
    Only shows root certificates created by the current user for intermediate signing.
    """
    # Get existing certificates
    existing_roots = RootCertificate.objects.all().order_by("-created_at")
    existing_intermediates = IntermediateCertificate.objects.all().order_by(
        "-created_at"
    )

    # Get only the user's root certificates for the dropdown
    user_roots = RootCertificate.objects.filter(created_by=request.user).order_by(
        "-created_at"
    )

    if request.method == "POST":
        form_type = request.POST.get("form_type")

        if form_type == "root":
            # Handle root CA creation
            ca_name = request.POST.get("ca_name")
            validity_days = int(request.POST.get("validity_days"))

            try:
                ca_manager = CertificateAuthority()
                root_cert_data = ca_manager.create_root_certificate(
                    ca_name, validity_days
                )

                RootCertificate.objects.create(
                    name=ca_name,
                    serial_number=root_cert_data["serial_number"],
                    public_key=root_cert_data["public_key"],
                    private_key_encrypted=root_cert_data["private_key"],
                    valid_until=root_cert_data["valid_until"],
                    created_by=request.user,
                )

                AuditLog.objects.create(
                    action="CREATE",
                    performed_by=request.user,
                    details=f"Created root certificate: {ca_name}",
                )

                messages.success(request, f"Root CA '{ca_name}' created successfully!")
                return redirect("create_ca")

            except ValueError as e:
                messages.error(request, f"Error creating root CA: {str(e)}")

        elif form_type == "intermediate":
            # Handle intermediate CA creation
            intermediate_name = request.POST.get("intermediate_name")
            root_id = request.POST.get("root_id")

            # Verify the selected root belongs to the user
            if not RootCertificate.objects.filter(
                id=root_id, created_by=request.user
            ).exists():
                messages.error(
                    request,
                    "You can only sign intermediates with your own root certificates.",
                )
                return redirect("create_ca")

            validity_days = int(request.POST.get("validity_days"))

            try:
                root_cert = get_object_or_404(RootCertificate, id=root_id)
                ca_manager = CertificateAuthority()

                intermediate_cert_data = ca_manager.create_intermediate_certificate(
                    intermediate_name,
                    validity_days,
                    root_cert.public_key,
                    root_cert.private_key_encrypted,
                )

                # Save intermediate certificate to database with created_by
                # field
                IntermediateCertificate.objects.create(
                    name=intermediate_name,
                    serial_number=intermediate_cert_data["serial_number"],
                    public_key=intermediate_cert_data["public_key"],
                    private_key_encrypted=intermediate_cert_data["private_key"],
                    signed_by_root=root_cert,
                    valid_until=intermediate_cert_data["valid_until"],
                    created_by=request.user,
                )

                # Log the action
                AuditLog.objects.create(
                    action="CREATE",
                    performed_by=request.user,
                    details=f"Created intermediate certificate: {intermediate_name}",
                )

                messages.success(
                    request,
                    f"Intermediate CA '{intermediate_name}' created successfully!",
                )
                return redirect("create_ca")

            except ValueError as e:
                messages.error(request, f"Error creating intermediate CA: {str(e)}")

    return render(
        request,
        "LocalCA/create_ca.html",
        {
            "existing_roots": existing_roots,
            "existing_intermediates": existing_intermediates,
            "user_roots": user_roots,  # Pass only user's roots to template
        },
    )


@login_required
def create_intermediate(request):
    """
    View to create an intermediate certificate signed by a root CA.
    """
    roots = RootCertificate.objects.all()

    if request.method == "POST":
        intermediate_name = request.POST.get("intermediate_name")
        validity_days = int(request.POST.get("validity_days"))
        root_id = int(request.POST.get("root_id"))

        try:
            root_cert = get_object_or_404(RootCertificate, id=root_id)
            ca_manager = CertificateAuthority()

            intermediate_cert_data = ca_manager.create_intermediate_certificate(
                intermediate_name,
                validity_days,
                root_cert.public_key,
                root_cert.private_key_encrypted,
            )

            # Save intermediate certificate to database with created_by field
            IntermediateCertificate.objects.create(
                name=intermediate_name,
                serial_number=intermediate_cert_data["serial_number"],
                public_key=intermediate_cert_data["public_key"],
                private_key_encrypted=intermediate_cert_data["private_key"],
                signed_by_root=root_cert,
                valid_until=intermediate_cert_data["valid_until"],
                created_by=request.user,
            )

            # Log the action
            AuditLog.objects.create(
                action="CREATE",
                performed_by=request.user,
                details=f"Created intermediate certificate: {intermediate_name}",
            )

            messages.success(
                request, f"Intermediate CA '{intermediate_name}' created successfully!"
            )
            return redirect("homepage")

        except ValueError as e:
            messages.error(request, f"Error creating intermediate CA: {str(e)}")

    return render(request, "LocalCA/create_intermediate.html", {"roots": roots})


@login_required
def create_leaf(request):
    """
    View to create a leaf certificate signed by an intermediate CA.
    Shows only intermediate certificates and leaf certificates created by the user.
    """
    intermediates = IntermediateCertificate.objects.filter(
        created_by=request.user
    ).order_by("-created_at")

    existing_leaves = LeafCertificate.objects.filter(created_by=request.user).order_by(
        "-created_at"
    )

    if request.method == "POST":
        try:
            common_name = request.POST.get("common_name")
            san_input = request.POST.get("san", "").strip()
            validity_days = int(request.POST.get("validity_days"))
            intermediate_id = int(request.POST.get("intermediate_id"))

            # Process SANs
            san_list = [san.strip() for san in san_input.split(",") if san.strip()]
            # Always include common_name in the SAN list if not already present
            if common_name not in san_list:
                san_list.insert(0, common_name)

            intermediate_cert = get_object_or_404(
                IntermediateCertificate, id=intermediate_id, created_by=request.user
            )

            ca_manager = CertificateAuthority()
            leaf_cert_data = ca_manager.create_leaf_certificate(
                common_name=common_name,
                san_list=san_list,  # Pass the complete list of SANs
                validity_days=validity_days,
                intermediate_public_key=intermediate_cert.public_key,
                intermediate_private_key=intermediate_cert.private_key_encrypted,
            )

            # Create the leaf certificate
            LeafCertificate.objects.create(
                common_name=common_name,
                san=",".join(san_list),  # Store the complete SAN list
                valid_until=leaf_cert_data["valid_until"],
                serial_number=leaf_cert_data["serial_number"],
                public_key=leaf_cert_data["public_key"],
                private_key_encrypted=leaf_cert_data["private_key"],
                signed_by_intermediate=intermediate_cert,
                created_at=datetime.utcnow(),
                created_by=request.user,
            )

            messages.success(
                request, f"Leaf certificate '{common_name}' created successfully!"
            )
            # Log the action
            AuditLog.objects.create(
                action="CREATE",
                performed_by=request.user,
                details=f"Created leaf certificate: {common_name}",
            )
            return redirect("create_leaf")
        except ValueError as e:
            messages.error(request, f"Error creating leaf certificate: {str(e)}")

    return render(
        request,
        "LocalCA/create_leaf.html",
        {"intermediates": intermediates, "existing_leaves": existing_leaves},
    )


@login_required
def revoke_certificate(request, cert_id):
    """
    View to revoke a leaf certificate.
    """
    try:
        cert = get_object_or_404(LeafCertificate, id=cert_id)

        if RevokedCertificate.objects.filter(certificate=cert).exists():
            messages.warning(
                request, f"Certificate '{cert.common_name}' is already revoked."
            )
        else:
            RevokedCertificate.objects.create(
                certificate=cert, reason="Revoked by admin"
            )

            # Log the action
            AuditLog.objects.create(
                action="REVOKE",
                performed_by=request.user,
                details=f"Revoked leaf certificate: {cert.common_name}",
            )

            messages.success(
                request, f"Leaf certificate '{cert.common_name}' revoked successfully!"
            )

    except ValueError as e:
        messages.error(request, f"Error revoking certificate: {str(e)}")

    return redirect("homepage")


@login_required
def download_private(request, serial_number):
    """
    View to download the private key of a certificate.
    Only available to the certificate owner.
    """
    # Try to find the certificate in any of the certificate models
    cert = None
    for model in [RootCertificate, IntermediateCertificate, LeafCertificate]:
        try:
            cert = model.objects.get(serial_number=serial_number)
            break
        except model.DoesNotExist:
            continue

    if not cert:
        raise Http404("Certificate not found")

    # Check if the user is the owner of the certificate
    if cert.created_by != request.user:
        messages.error(request, "You don't have permission")
        raise PermissionDenied("You do not have permission")

    # Get the appropriate name based on certificate type
    if isinstance(cert, LeafCertificate):
        cert_name = cert.common_name
    else:
        cert_name = cert.name

    # Prepare the response with the private key
    response = HttpResponse(cert.private_key_encrypted, content_type="text/plain")
    response["Content-Disposition"] = f"attachment; filename={cert_name}_private.pem"

    # Log the private key download
    AuditLog.objects.create(
        action="DOWNLOAD_PRIVATE_KEY",
        performed_by=request.user,
        details=f"Downloaded private key for certificate: {cert_name} (Serial: {cert.serial_number})",
    )

    return response


@login_required
def change_password(request):
    """
    View to change the user's password.
    """
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Update the session to prevent logging out
            update_session_auth_hash(request, user)
            messages.success(request, "Your password was successfully updated!")
            return redirect("homepage")
    else:
        form = PasswordChangeForm(request.user)

    return render(request, "LocalCA/change_password.html", {"form": form})


def logout_view(request):
    """
    View to log out the user.
    """
    logout(request)
    messages.success(request, "You have been successfully logged out.")
    return redirect("login")

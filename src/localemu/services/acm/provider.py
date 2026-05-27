from moto import settings as moto_settings
from moto.acm import models as acm_models

from localemu.aws.api import RequestContext, handler
from localemu.aws.api.acm import (
    AcmApi,
    ListCertificatesRequest,
    ListCertificatesResponse,
    RequestCertificateRequest,
    RequestCertificateResponse,
)
from localemu.services import moto
from localemu.state import StateVisitor
from localemu.utils.patch import patch

# reduce the validation wait time from 60 (default) to 10 seconds
moto_settings.ACM_VALIDATION_WAIT = min(10, moto_settings.ACM_VALIDATION_WAIT)


@patch(acm_models.AWSCertificateManagerBackend.list_certificates)
def list_certificates(list_certificates_orig, self, statuses, includes):
    # Normalize keyTypes filter to match our describe() output format (hyphens).
    # Copy the includes dict first to avoid mutating the caller-supplied filter,
    # which can otherwise leak across requests (ACM-2).
    if includes and "keyTypes" in includes:
        includes = dict(includes)
        includes["keyTypes"] = [
            kt.replace("RSA_", "RSA-").replace("EC_", "EC-") for kt in includes["keyTypes"]
        ]
    return list_certificates_orig(self, statuses, includes)


@patch(acm_models.CertBundle.describe)
def describe(describe_orig, self):
    # Moto adds certain required fields only when status is PENDING_VALIDATION. Rather than
    # mutating `self.status` (which creates a race with concurrent describe() calls on the
    # same shared certificate — ACM-1), we invoke the original describe on a stand-in with
    # an overridden `status` attribute, so the shared instance is never modified.
    cert_status = self.status

    class _PendingStatusProxy:
        """Proxy that forwards attribute access to the underlying CertBundle
        but reports `status` as PENDING_VALIDATION."""

        __slots__ = ("_target",)

        def __init__(self, target):
            object.__setattr__(self, "_target", target)

        def __getattr__(self, item):
            if item == "status":
                return "PENDING_VALIDATION"
            return getattr(self._target, item)

        def __setattr__(self, key, value):
            setattr(self._target, key, value)

    proxy = _PendingStatusProxy(self)
    result = describe_orig(proxy)

    cert = result.get("Certificate", {})
    cert["Status"] = cert_status
    sans = cert.setdefault("SubjectAlternativeNames", [])
    sans_summaries = cert.setdefault("SubjectAlternativeNameSummaries", sans)

    # add missing attributes in ACM certs that cause Terraform to fail
    addenda = {
        "RenewalEligibility": "INELIGIBLE",
        "KeyUsages": [{"Name": "DIGITAL_SIGNATURE"}, {"Name": "KEY_ENCIPHERMENT"}],
        "ExtendedKeyUsages": [],
        "Options": {"CertificateTransparencyLoggingPreference": "ENABLED"},
    }
    addenda["DomainValidationOptions"] = options = cert.get("DomainValidationOptions")
    if not options:
        options = addenda["DomainValidationOptions"] = [
            {"ValidationMethod": cert.get("ValidationMethod")}
        ]

    for option in options:
        option["DomainName"] = domain_name = option.get("DomainName") or cert.get("DomainName")
        validation_domain = option.get("ValidationDomain") or f"test.{domain_name.lstrip('*.')}"
        option["ValidationDomain"] = validation_domain
        option["ValidationMethod"] = option.get("ValidationMethod") or "DNS"
        status = option.get("ValidationStatus")
        option["ValidationStatus"] = (
            "SUCCESS" if (status is None or cert_status == "ISSUED") else status
        )
        if option["ValidationMethod"] == "EMAIL":
            option["ValidationEmails"] = option.get("ValidationEmails") or [
                f"admin@{self.common_name}"
            ]
        test_record = {
            "Name": validation_domain,
            "Type": "CNAME",
            "Value": "test123",
        }
        option["ResourceRecord"] = option.get("ResourceRecord") or test_record
        option["ResourceRecord"]["Name"] = option["ResourceRecord"]["Name"].replace(".*.", ".")

    for key, value in addenda.items():
        if not cert.get(key):
            cert[key] = value
    cert["Serial"] = str(cert.get("Serial") or "")

    if cert.get("KeyAlgorithm") in ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096"]:
        cert["KeyAlgorithm"] = cert["KeyAlgorithm"].replace("RSA_", "RSA-")
    if cert.get("KeyAlgorithm") in ["EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]:
        cert["KeyAlgorithm"] = cert["KeyAlgorithm"].replace("EC_", "EC-")

    # add subject alternative names
    if cert["DomainName"] not in sans:
        sans.append(cert["DomainName"])
    if cert["DomainName"] not in sans_summaries:
        sans_summaries.append(cert["DomainName"])

    if "HasAdditionalSubjectAlternativeNames" not in cert:
        cert["HasAdditionalSubjectAlternativeNames"] = False

    if not cert.get("ExtendedKeyUsages"):
        cert["ExtendedKeyUsages"] = [
            {"Name": "TLS_WEB_SERVER_AUTHENTICATION", "OID": "1.3.6.1.0.1.2.3.0"},
            {"Name": "TLS_WEB_CLIENT_AUTHENTICATION", "OID": "1.3.6.1.0.1.2.3.4"},
        ]

    # remove attributes prior to validation
    if not cert.get("Status") == "ISSUED":
        attrs = ["CertificateAuthorityArn", "IssuedAt", "NotAfter", "NotBefore", "Serial"]
        for attr in attrs:
            cert.pop(attr, None)
        cert["KeyUsages"] = []
        cert["ExtendedKeyUsages"] = []

    return result


class AcmProvider(AcmApi):
    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(acm_models.acm_backends)

    @handler("RequestCertificate", expand=False)
    def request_certificate(
        self,
        context: RequestContext,
        request: RequestCertificateRequest,
    ) -> RequestCertificateResponse:
        response: RequestCertificateResponse = moto.call_moto(context)

        cert_arn = response["CertificateArn"]
        backend = acm_models.acm_backends[context.account_id][context.region]
        cert = backend._certificates[cert_arn]
        if not hasattr(cert, "domain_validation_options"):
            cert.domain_validation_options = request.get("DomainValidationOptions")

        return response

    @handler("ListCertificates", expand=False)
    def list_certificates(
        self,
        context: RequestContext,
        request: ListCertificatesRequest,
    ) -> ListCertificatesResponse:
        response = moto.call_moto(context)
        summaries = response.get("CertificateSummaryList") or []
        for summary in summaries:
            if "KeyUsages" in summary:
                summary["KeyUsages"] = [
                    k["Name"] if isinstance(k, dict) else k for k in summary["KeyUsages"]
                ]
            if "ExtendedKeyUsages" in summary:
                summary["ExtendedKeyUsages"] = [
                    k["Name"] if isinstance(k, dict) else k for k in summary["ExtendedKeyUsages"]
                ]
        return response

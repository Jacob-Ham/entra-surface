"""Authentication method policy extraction from collected policyDetail blobs."""
from __future__ import annotations

import re

from ..findings import make_finding
from ..policy import policy_detail_inner


METHOD_LABELS = {
    "fido2": "FIDO2 security key",
    "authenticator": "Microsoft Authenticator",
    "sms": "SMS",
    "tap": "Temporary Access Pass",
    "hardware_oath": "Hardware OATH token",
    "software_oath": "Software OATH token",
    "voice": "Voice call",
    "password": "Password",
    "email": "Email OTP",
    "qr": "QR code",
    "cba": "Certificate-based authentication",
    "verifiable_credentials": "Verifiable credentials",
    "qr_pin": "QR code PIN",
    "fic": "FIDO credential",
    "desktop_sso": "Seamless SSO (Desktop SSO)",
}

# Methods whose user authentication data can be sourced from on-premises AD.
# The method's tenant policy still lives in Entra, but the credential/identity
# data is changed on-prem and synchronized up.
ON_PREM_MANAGED_METHODS = {"password", "cba", "desktop_sso"}

METHOD_ORDER = {
    "fido2": 10,
    "authenticator": 20,
    "sms": 30,
    "tap": 40,
    "hardware_oath": 50,
    "software_oath": 60,
    "voice": 70,
    "password": 80,
    "email": 90,
    "cba": 100,
    "verifiable_credentials": 110,
    "qr_pin": 120,
    "desktop_sso": 130,
}

METHOD_ALIASES = {
    "fido": "fido2",
    "fido2": "fido2",
    "fido2securitykeys": "fido2",
    "phonesignin": "authenticator",
    "microsoftauthenticator": "authenticator",
    "authenticator": "authenticator",
    "sms": "sms",
    "accesspass": "tap",
    "temporaryaccesspass": "tap",
    "hardwareoathtoken": "hardware_oath",
    "softwareoathtoken": "software_oath",
    "voicecall": "voice",
    "password": "password",
    "email": "email",
    "qr": "qr",
    "x509certificate": "cba",
    "certificatebasedauthentication": "cba",
    "verifiablecredentials": "verifiable_credentials",
    "qrcodepin": "qr_pin",
    "fic": "fic",
    "desktopsso": "desktop_sso",
    "seamlesssso": "desktop_sso",
}

# Internal/legacy credential types that are not shown as authentication
# methods in the Entra admin center. The visible "QR code" method is QRCodePin.
_HIDDEN_METHODS = {"qrcode", "qr", "fic"}

_META_KEYS = {
    "@odata.context", "@odata.type", "id", "displayName", "description",
    "state", "policyVersion", "lastModifiedDateTime", "createdDateTime",
    "includeConditions", "excludeConditions", "includeTargets",
    "excludeTargets", "settings", "type", "additionalSettings",
}


def _normalize_method(value):
    text = str(value or "").strip()
    text = text.rsplit(".", 1)[-1]
    text = text.replace("AuthenticationMethodConfiguration", "")
    key = re.sub(r"[^a-z0-9]+", "", text.lower())
    return METHOD_ALIASES.get(key, key)


def _method_label(key, raw=""):
    if key in METHOD_LABELS:
        return METHOD_LABELS[key]
    text = str(raw or key).rsplit(".", 1)[-1]
    text = text.replace("AuthenticationMethodConfiguration", "")
    text = re.sub(r"(?<!^)(?=[A-Z])", " ", text).strip()
    return text or key.replace("_", " ").title()


def _state_label(value):
    low = str(value or "").strip().lower()
    if low in ("enabled", "enable", "on", "true", "1"):
        return "Enabled"
    if low in ("disabled", "disable", "off", "false", "0"):
        return "Disabled"
    return "Unknown"


def _target_label(target, graph):
    if not isinstance(target, dict):
        return str(target or "")
    target_id = str(target.get("id") or target.get("targetId") or "")
    if target_id.lower() in ("all_users", "allusers", "all"):
        return "All users"
    if target_id.lower() in ("admin_users", "adminusers"):
        return "Admin users"
    if target_id in graph.get("group", {}):
        return graph["group"][target_id].get("displayName") or target_id
    if target_id in graph.get("user", {}):
        return (graph["user"][target_id].get("userPrincipalName")
                or graph["user"][target_id].get("displayName") or target_id)
    if target_id in graph.get("sp", {}):
        return (graph["sp"][target_id].get("displayName")
                or graph["sp"][target_id].get("appDisplayName") or target_id)
    return target_id or str(target.get("type") or target.get("targetType") or "")


def _scope_label(include, exclude, graph):
    def labels(items):
        seen = []
        for item in items or ():
            label = _target_label(item, graph)
            if label and label not in seen:
                seen.append(label)
        return seen

    inc = labels(include)
    exc = labels(exclude)
    text = ", ".join(inc) if inc else "\u2014"
    if exc:
        text += " \u00b7 excl: " + ", ".join(exc)
    return text


def _registration(include, entry):
    for target in include or ():
        if isinstance(target, dict) and target.get("isRegistrationRequired") is not None:
            return bool(target.get("isRegistrationRequired"))
    if include:
        return False
    if isinstance(entry, dict) and entry.get("isRegistrationRequired") is not None:
        return bool(entry.get("isRegistrationRequired"))
    return None


def _settings(entry):
    settings = entry.get("settings") if isinstance(entry, dict) else None
    return settings if isinstance(settings, dict) else (entry if isinstance(entry, dict) else {})


def _desktop_sso_summary(sso):
    if not isinstance(sso, dict):
        return ""
    secrets = [s for s in (sso.get("Secrets") or []) if isinstance(s, dict)]
    machine = next((s.get("Machine") for s in secrets if s.get("Machine")), "")
    return f"machine: {machine}" if machine else "machine: \u2014"


def _settings_summary(key, entry):
    settings = _settings(entry)
    if key == "desktop_sso":
        return _desktop_sso_summary(entry)
    if key == "cba":
        mode = ((settings.get("authenticationModeConfiguration") or {})
                .get("x509CertificateAuthenticationDefaultMode") or "")
        mode = {
            "x509CertificateSingleFactor": "Single-factor",
            "x509CertificateMultiFactor": "Multi-factor",
        }.get(mode, mode)
        bindings = settings.get("certificateUserBindings") or []
        scopes = settings.get("certificateAuthorityScopes") or []
        crl = ((settings.get("crlValidationConfiguration") or {}).get("state") or "")
        hints = ((settings.get("issuerHintsConfiguration") or {}).get("state") or "")
        bits = []
        if mode:
            bits.append(mode)
        if bindings:
            bits.append(f"{len(bindings)} user binding(s)")
        bits.append(f"{len(scopes)} CA scope(s)" if scopes else "no CA scopes")
        if crl:
            bits.append("CRL " + str(crl).lower())
        if hints:
            bits.append("issuer hints " + str(hints).lower())
        return " \u00b7 ".join(bits)
    if key == "fido2":
        self_service = settings.get("allowSelfServiceSetup")
        if self_service is None:
            self_service = settings.get("isSelfServiceRegistrationAllowed")
        attestation = settings.get("enforceAttestation")
        if attestation is None:
            attestation = settings.get("isAttestationEnforced")
        restrictions = settings.get("keyRestrictions") or {}
        bits = []
        if self_service is not None:
            bits.append("self-service " + ("on" if self_service else "off"))
        if attestation is not None:
            bits.append("attestation " + ("required" if attestation else "not required"))
        if restrictions:
            bits.append("key restrictions "
                        + ("enforced" if restrictions.get("isEnforced") else "not enforced"))
        return " \u00b7 ".join(bits)
    if key == "tap":
        lifetime = settings.get("passLifetimeInMinutes")
        once = settings.get("isUsableOnce")
        length = settings.get("length")
        bits = []
        if lifetime:
            bits.append(f"{lifetime} min")
        if once is not None:
            bits.append("one-time" if once else "multi-use")
        if length:
            bits.append(f"{length} digits")
        return " \u00b7 ".join(bits)
    if key == "sms":
        use = settings.get("useForSignIn")
        if use is None:
            include = entry.get("includeConditions") or []
            if include and isinstance(include[0], dict):
                use = include[0].get("useForSignIn")
        return ("sign-in " + ("enabled" if use else "disabled")) if use is not None else ""
    if key == "voice":
        office = settings.get("allowOfficePhone")
        greeting = settings.get("isCustomGreetingEnabled")
        bits = []
        if office is not None:
            bits.append("office phone " + ("allowed" if office else "blocked"))
        if greeting is not None:
            bits.append("custom greeting " + ("on" if greeting else "off"))
        return " \u00b7 ".join(bits)
    if key == "email":
        external = settings.get("allowExternalIdEmailOtp")
        return ("external email OTP: " + str(external)) if external is not None else ""
    if key == "qr_pin":
        lifetime = settings.get("standardQRCodeLifetimeInDays")
        pin = settings.get("pinLength")
        bits = []
        if lifetime:
            bits.append(f"{lifetime} day lifetime")
        if pin:
            bits.append(f"{pin}-digit PIN")
        return " \u00b7 ".join(bits)
    if key == "authenticator":
        include = entry.get("includeConditions") or []
        if include and isinstance(include[0], dict):
            first = include[0]
            bits = []
            if first.get("authenticationMode"):
                bits.append("mode: " + str(first["authenticationMode"]))
            if first.get("isSoftwareTotpEnabled") is not None:
                bits.append("software OTP "
                            + ("on" if first["isSoftwareTotpEnabled"] else "off"))
            return " \u00b7 ".join(bits)
        return ""
    simple = []
    for name, value in settings.items():
        if name in _META_KEYS or not isinstance(value, (str, int, float, bool)):
            continue
        simple.append(f"{name}: {value}")
        if len(simple) >= 3:
            break
    return " \u00b7 ".join(simple)


def _merge_method(methods, key, entry):
    current = methods.get(key)
    if current is None or (entry["full"] and not current["full"]):
        methods[key] = entry


def _collect_methods(graph):
    methods = {}
    for policy_id, rec in (graph.get("policy") or {}).items():
        inner = policy_detail_inner(rec.get("policyDetail"))
        if not isinstance(inner, dict):
            continue
        flow = inner.get("OnPremAuthenticationFlowPolicy")
        if isinstance(flow, dict):
            sso = flow.get("DesktopSSO")
            if isinstance(sso, dict):
                secrets = [s for s in (sso.get("Secrets") or [])
                           if isinstance(s, dict)]
                domains = [s.get("Domain") for s in secrets if s.get("Domain")]
                enabled = str(sso.get("Enabled")).lower() in ("true", "1", "yes")
                _merge_method(methods, "desktop_sso", {
                    "full": False,
                    "raw": "DesktopSSO",
                    "state": "Enabled" if enabled else "Disabled",
                    "include": [{"id": d, "type": "Domain"} for d in domains],
                    "exclude": [],
                    "entry": sso,
                    "source": "On-premises authentication flow policy",
                    "source_id": policy_id,
                    "registration": None,
                })
            continue
        credentials = inner.get("credentials")
        if isinstance(credentials, list):
            for cred in credentials:
                if not isinstance(cred, dict):
                    continue
                key = _normalize_method(cred.get("type") or cred.get("id"))
                if not key or key in _HIDDEN_METHODS:
                    continue
                _merge_method(methods, key, {
                    "full": True,
                    "raw": cred.get("type") or key,
                    "state": cred.get("state"),
                    "include": cred.get("includeConditions") or [],
                    "exclude": cred.get("excludeConditions") or [],
                    "entry": cred,
                    "source": "Authentication methods policy",
                    "source_id": policy_id,
                })
            continue
        # Authentication-strength policies are not methods.
        if inner.get("allowedCombinations") and inner.get("requirementsSatisfied"):
            continue
        if inner.get("state") is None:
            continue
        raw = (inner.get("@odata.type") or inner.get("displayName")
               or inner.get("id") or "")
        key = _normalize_method(raw)
        if not key or key in ("defaultpolicy", "unknown") or key in _HIDDEN_METHODS:
            continue
        _merge_method(methods, key, {
            "full": False,
            "raw": raw,
            "state": inner.get("state"),
            "include": inner.get("includeTargets") or inner.get("includeConditions") or [],
            "exclude": inner.get("excludeTargets") or inner.get("excludeConditions") or [],
            "entry": inner,
            "source": "Authentication method configuration",
            "source_id": policy_id,
        })
    return methods


def check_authentication_methods(ctx):
    """One row per authentication method found in collected policy data.

    Handles the legacy full authentication-methods policy (a ``credentials``
    array) and newer per-method configuration blobs (for example FIDO2 or
    Temporary Access Pass). Authentication-strength policies are skipped: they
    describe what a CA policy accepts, not which methods the tenant enables.
    """
    graph = ctx["graph"]
    findings = []
    for key, entry in _collect_methods(graph).items():
        state = _state_label(entry["state"])
        include = entry["include"] or []
        exclude = entry["exclude"] or []
        registration = (entry["registration"] if "registration" in entry
                        else _registration(include, entry["entry"]))
        scope = _scope_label(include, exclude, graph)
        if state != "Enabled":
            scope = "\u2014"
            registration = None
        summary = _settings_summary(key, entry["entry"])
        label = _method_label(key, entry["raw"])
        evidence = " \u00b7 ".join(
            part for part in (state, scope, summary) if part)
        f = make_finding(
            check_id="authentication_methods", category="auth", severity="Info",
            title=f"Authentication method: {label}",
            evidence=evidence,
            remediation=("Review whether the method is still required and confirm "
                         "its assignment scope and registration settings."),
            primary_id=f"auth:{key}",
            target={"type": "Authentication method", "name": label, "id": key},
            status={"label": state, "enabled": state == "Enabled"},
        )
        f["auth_method_key"] = key
        f["auth_method_label"] = label
        f["auth_method_order"] = METHOD_ORDER.get(key, 999)
        f["auth_managed_on_prem"] = key in ON_PREM_MANAGED_METHODS
        f["auth_method_raw"] = entry["raw"]
        f["auth_state"] = state
        f["auth_enabled"] = state == "Enabled"
        f["auth_scope"] = scope
        f["auth_registration"] = registration
        f["auth_registration_label"] = (
            "Required" if registration is True
            else ("Not required" if registration is False else ""))
        f["auth_settings_summary"] = summary
        f["auth_settings"] = entry["entry"]
        f["auth_source"] = entry["source"]
        f["auth_source_id"] = entry["source_id"]
        findings.append(f)
    findings.sort(key=lambda f: (f.get("auth_method_order", 999),
                                 (f["auth_method_label"] or "").lower()))
    return findings

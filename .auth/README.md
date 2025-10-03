# Consent Documentation

Active or intrusive modules must not be executed unless the operator possesses a signed authorisation file named `active-scan-consent.json` in this directory. The file should contain:

- Scope of permitted testing (domains, IP ranges, duration).
- Signature of an authorised representative.
- Contact details for escalation.

Before running any `safe-active` or `pentest` command, validate the signature manually and ensure the operator confirms the consent string `I-CONFIRM-AUTH` as part of their runbook.

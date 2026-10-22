# Password Spraying Detection (T1110.003)

## Objective
Build and validate a Splunk detection rule for password spraying attacks
against a lab Active Directory domain, following a detection-engineering
workflow: hypothesis → rule → attack simulation → validation → tuning.

## Environment
- Lab AD domain: troika.com
- Target: Windows Server 2022 DC 
- Attack source: Kali Linux (NetExec/nxc)
- SIEM: Splunk, collecting Windows Security logs via Universal Forwarder

## Summary
A Splunk alert was built to detect password spraying based on the expected
attack pattern (many distinct accounts, few attempts each, single source,
short time window). The rule was validated against a simulated attack and
correctly triggered.

A second rule was then built to detect **successful compromise** following
a spray attempt (failed logons followed by a success from the same
source). Testing this rule surfaced two real weaknesses in the detection
logic itself — not in the attack simulation — each investigated, confirmed,
and fixed:

1. **False success on ANONYMOUS LOGON** — the query initially misread an
   SMB null session (established by the attack tool during reconnaissance)
   as a compromised account. Confirmed by isolating the tool's behavior
   with no credentials, then excluded from the detection logic.
2. **Missed detection on early success** — the rule required failures and
   success to fall within the same fixed time bin, which failed to detect
   a real compromise when the correct password was found early in the
   account list (fewer preceding failures than the threshold). Fixed by
   correlating the *latest* failure and *latest* success per source IP
   instead of relying on a fixed time bin.


## Key Takeaway
Building the detection rule was the easy part. Validating it against
realistic, messy attack behavior — not just a clean single test run — is
what surfaced two logic flaws that would have caused real missed
detections. Both were traced to a confirmed root cause before being fixed.

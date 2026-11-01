# Scheduled Task Persistence Detection (T1053.005)

## Objective
Build and validate a Splunk detection rule for PowerShell-based
persistence via scheduled tasks in a lab Active Directory environment.

## Environment
- Lab AD domain: troika.com
- Target: Windows Server 2022 DC (DC01)
- SIEM: Splunk, collecting Windows Security logs via Universal Forwarder

## Summary
Scheduled task creation (Event 4698) is not audited by default and had
to be enabled via GPO first. A task was then created that silently
re-executes a hidden PowerShell command on every logon — a common
persistence technique following a compromise.

The task's actual command and arguments weren't available as
ready-made Splunk fields (they're embedded as escaped XML inside the
raw event), so they were extracted manually before a detection rule
could be built at all.

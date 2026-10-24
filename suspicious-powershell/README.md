# Suspicious PowerShell Execution Detection (T1059.001, T1105)

## Objective
Build and validate Splunk detection rules for obfuscated and suspicious
PowerShell execution in a lab Active Directory environment.

## Environment
- Lab AD domain: troika.com
- Target: Windows Server 2022 DC (DC01)
- SIEM: Splunk, collecting Windows Security and PowerShell Operational
  logs (Event 4688, Event 4104) via Universal Forwarder

  ## Summary
Two complementary Splunk alerts were built around a single key
observation: the same PowerShell attack is visible differently
depending on the log source. Event 4688 (Process Creation) logs the
raw, still-encoded command line, while Event 4104 (Script Block
Logging) captures the command *after* PowerShell decodes it internally.

1. **Encoded Command Detection (4688)** — flags the use of
   `-EncodedCommand`/`-enc` itself, a technique commonly used by
   attackers to obscure commands, regardless of what the payload
   contains.
2. **Suspicious Decoded Content Detection (4104)** — flags
   download/execution indicators (`IEX`, `DownloadString`, `WebClient`,
   `Bypass`) in the decoded script block content, catching intent that
   would otherwise stay hidden inside an encoded 4688 command line.

Both rules were validated against simulated attacks and triggered
successfully.

## Key Takeaway
The same attack can look completely different depending on which log
source you're relying on. Relying on a single event source (4688 alone)
would have meant manually decoding Base64 to understand attacker
intent. Using Script Block Logging alongside Process Creation closed
that gap — a reminder that detection coverage often depends less on
the attack technique itself and more on understanding what each log
source actually captures.

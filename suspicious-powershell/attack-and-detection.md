# Attack Simulation & Detection Logic

## 1. Attack Simulations

**Technique:** Suspicious PowerShell Execution (MITRE ATT&CK T1059.001, T1105)

**Target Machine:** Windows Server 2022 DC01 (DC01.troika.com)

### Simulation 1: Encoded Command Execution

**Command used:**
```powershell
$cmd = "Get-Process"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $encoded
```

![Encoded command attack](evidence/attack1_command.png)

This simulates a common evasion technique where attackers encode
PowerShell commands in Base64 to avoid simple string-matching on the
raw command line.


### Simulation 2: Suspicious Content Execution (IEX)

**Command used:**
```powershell
IEX "Write-Host 'Simulated malicious payload executed'"
```
![IEX attack](evidence/attack2_command.png)

This simulates a simplified download-cradle pattern — using
`Invoke-Expression` to execute dynamically obtained code, a technique
commonly seen in real payload delivery (e.g.,
`IEX (New-Object Net.WebClient).DownloadString(...)`).

## 2. Key Observation: Encoding Visibility Differs by Log Source

The same attack command was logged differently depending on the event
source:

**Event 4688 (Process Creation)** logs the raw command line exactly as
invoked. The Base64 payload remains encoded and unreadable without
manual decoding







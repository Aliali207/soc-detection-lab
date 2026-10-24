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


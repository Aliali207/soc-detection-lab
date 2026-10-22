# Attack Simulation & Detection Logic

## 1. Attack Simulation

**Technique:** Password Spraying (MITRE ATT&CK T1110.003)

**Target_machine:**  Windows 11 (10.0.2.10)

**Attack_machine:** kali (10.0.2.15)

**Target accounts:** TestUser1–TestUser8, George.h, sara.ad, Administrator (11 accounts)

![Alert triggered](evidence/windows_server_ip.png)

![Alert triggered](evidence/kali_ip.png)

![Alert triggered](evidence/users_file_content.png)


**Command used:**

```nxc smb 10.0.2.10 -u users.txt -p "WrongPassword123"```

The attack attempted a single password against 11 different domain accounts
within the same minute, simulating a low-and-slow spraying attempt designed
to avoid account lockout thresholds while maximizing the chance of hitting
at least one weak password.

![Alert triggered](evidence/attack.png)


## 2. Detection Logic

### Hypothesis
A single source authenticating as multiple distinct accounts within a
short time window, each with few attempts per account, indicates password
spraying rather than ordinary user error (which typically involves one
account, repeated attempts).

### Splunk Query
```spl
index=wineventlog EventCode=4625
| bin _time span=10m
| stats dc(TargetUserName) as distinct_users, count as attempts, values(TargetUserName) as accounts by _time, src_ip
| where distinct_users>=5
```
![Alert triggered](evidence/constructed-alert.png)

**Threshold rationale:** `distinct_users>=5` within a 10-minute window was
chosen to filter out normal user mistakes (which involve 1 account) while
reliably catching spraying behavior. Validated against lab data showing
10 distinct accounts targeted from a single source within the same minute.

## 3. Validation

The alert was triggered successfully at `09:53`, around 10 minutes after the attack
was executed, confirming the detection logic correctly identifies the
simulated spraying pattern.


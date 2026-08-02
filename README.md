# ThreatCheck-Py

Started as a python port of [Rasta-Mouse's ThreatCheck](https://github.com/rasta-mouse/ThreatCheck).

A tool to find AV signatures in files.

## Requirements

- Python 3.8 or higher
- Windows OS (for Defender and AMSI scanners)

## Supported Scanners

### File Scanners

- Defender
- Amsi
- Clamav

### Process Scanners:

- Yara

## Installation

### From PyPi

```
pip install threatcheck-py
```

### From Source

```bash
git clone https://github.com/ruvolof/threatcheck-py.git
cd threatcheck-py
pip install -e .
```

## Usage

### Command Line Options

```
$ threatcheck --help
usage: threatcheck [-h] [-e {defender,amsi,clamav,yara}] (-f FILE | -u URL | -d DIRECTORY | -p PID) [-r RULES] [--debug] [--version]

Identify AV signatures in files

options:
  -h, --help            show this help message and exit
  -e, --engine {defender,amsi,clamav,yara}
                        Scanning engine (default: defender)
  -f, --file FILE       Analyze a file on disk
  -u, --url URL         Analyze a file from a URL
  -d, --directory DIRECTORY
                        Analyze all files in a directory
  -p, --pid PID         Analyze a process by PID
  -r, --rules RULES     Path to YARA rules directory. Will recursively search for all .yar and .yara files.
  --debug               Enable debug output
  --version             show program's version number and exit
```

### As a Python library

All scanners share a common interface: instantiate one, then call
`analyze(file_bytes=...)` (or `analyze(pid=...)` for YARA) and inspect the
returned `ScanResult`.

```python
from pathlib import Path
from threatcheck import DefenderScanner, ScanStatus

scanner = DefenderScanner()
result = scanner.analyze(file_bytes=Path('sample.exe').read_bytes())

if result.malicious:
    print(f'Threat: {result.signature}')
    print(f'Bad bytes end at offset 0x{result.end_offset:X}')
elif result.status == ScanStatus.ERROR:
    print(f'Scan failed: {result.error_message}')
else:
    print('Clean')
```

`AmsiScanner` and `ClamAVScanner` use the same pattern. `YaraScanner` takes
a `rules_path` and can scan a running process as well as file bytes:

```python
from threatcheck import YaraScanner

scanner = YaraScanner(rules_path='/path/to/rules')
result = scanner.analyze(pid=1234)

for match in result.matches or []:
    print(f'Rule: {match.rule}')
    for s in match.strings:
        print(f'  {s.identifier} @ 0x{s.offset:X}: {s.matched_data!r}')
```

`ScanResult` exposes:

- `status` — a `ScanStatus` (`NO_THREAT_FOUND`, `THREAT_FOUND`, `FILE_NOT_FOUND`, `TIMEOUT`, `ERROR`)
- `malicious` — `True` when `status == THREAT_FOUND`
- `success` — `True` when the scan completed (threat found or not)
- `signature` — signature name, when the engine reports one (Defender, ClamAV)
- `matches` — list of `YaraMatch` when using `YaraScanner`
- `offending_bytes` / `end_offset` — populated by split scanners (Defender, AMSI, ClamAV) that bisect the file to locate bad bytes
- `error_message` — set when `status == ERROR`

## Defender Test Environment Setup

It is recommended to force autosubmission of samples to never send them, or the amount of notification can be overwhelming. 

### Method 1: PowerShell

Open and administrative PowerShell session and type the following:

```
Set-MpPreference -SubmitSamplesConsent 2
```

### Method 2: Group Policies

This can be forced through group policies:

1) Open Local Group Policy Editor (gpedit.msc)
2) Navigate to Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > MAPS
3) Double click on "Send file samples when further analysis is required"
4) Set it to "Enabled" and in the bottom-left panel select "Never send"

### Exceptions

All other Defender settings can be left on as long:

1) There's a path exception in place for the original location of your samples (otherwise real-time protection will prevent the initial loading of the files).
2) (Maybe?) The original location has to be on your C drive. In my experience Defender ignores exception for external drives and I run in problem 1 above.

## Credits

- Original ThreatCheck by [Rasta-Mouse](https://github.com/rasta-mouse/ThreatCheck).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

# ThreatCheck-Py

Python port of [Rasta-Mouse's ThreatCheck](https://github.com/rasta-mouse/ThreatCheck), a tool to identify AV signatures in files.

## Requirements

- Python 3.8 or higher
- Windows OS (for Defender and AMSI scanners)

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

## Test Environment Setup

It is recommended to force autosubmission of samples to never send them, or the amount of notification can be overwhelming. This can be forced through group policies:

1) Open Local Group Policy Editor (gpedit.msc)
2) Navigate to Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > MAPS
3) Double click on "Send file samples when further analysis is required"
4) Set it to "Enabled" and in the bottom-left panel select "Never send"

All other Defender settings can be left as on as long:

1) There's a path exception in place for the original location of your samples (otherwise real-time protection will prevent the initial loading of the files).
2) (Maybe?) The original location has to be on your C drive. In my experience Defender ignores exception for external drives and I run in problem 1 above.

## Usage

### Command Line Options

```
> threatcheck --help
usage: threatcheck [-h] [-e {defender,amsi}] [-f FILE] [-u URL] [-d DIRECTORY] [--debug] [--version]

Identify AV signatures in files

options:
  -h, --help            show this help message and exit
  -e, --engine {defender,amsi}
                        Scanning engine (default: defender)
  -f, --file FILE       Analyze a file on disk
  -u, --url URL         Analyze a file from a URL
  -d, --directory DIRECTORY
                        Analyze all files in a directory
  --debug               Enable debug output
  --version             show program's version number and exit
```

## Credits

- Original ThreatCheck by [Rasta-Mouse](https://github.com/rasta-mouse/ThreatCheck)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

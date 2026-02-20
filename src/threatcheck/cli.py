import sys
import argparse
import requests
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List
from enum import Enum
from threatcheck import __version__
from threatcheck.console import Console
from threatcheck.scanners.defender import DefenderScanner
from threatcheck.scanners.amsi import AmsiScanner
from threatcheck.scanners.clamav import ClamAVScanner
from threatcheck.scanners.yara_scanner import YaraScanner

class ScanStatus(Enum):
  SUCCESS = 'success'
  NO_THREAT = 'no_threat'
  THREAT_FOUND = 'threat_found'
  ERROR = 'error'
  SKIPPED = 'skipped'

@dataclass
class ScanResult:
  file_path: Path
  status: ScanStatus
  error_message: Optional[str] = None
  file_size: Optional[int] = None

  @property
  def success(self) -> bool:
    return self.status in (ScanStatus.SUCCESS,
                           ScanStatus.NO_THREAT,
                           ScanStatus.THREAT_FOUND)

  @property
  def filename(self) -> str:
    return self.file_path.name


def download_file_bytes(url):
  try:
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.content
  except requests.RequestException as e:
    raise RuntimeError(f'Could not connect to URL: {e}')


def list_files_in_directory(directory: Path) -> List[Path]:
  if not directory.exists():
    Console.write_error('Directory not found')
    sys.exit(1)
  if not directory.is_dir():
    Console.write_error('Path is not a directory')
    sys.exit(1)
  files = [f for f in directory.iterdir() if f.is_file()]
  if not files:
    Console.write_error('No files found in directory')
    sys.exit(1)
  return files


def read_file_content(file_path: Path) -> bytes:
  with open(file_path, 'rb') as f:
    return f.read()


def initialize_scanner(engine: str,
                       debug: bool,
                       file_bytes: bytes = None,
                       pid: int = None,
                       rules_path: str = None):
  if engine == 'defender':
    return DefenderScanner(debug=debug, file_bytes=file_bytes, pid=pid)
  elif engine == 'amsi':
    return AmsiScanner(debug=debug, file_bytes=file_bytes, pid=pid)
  elif engine == 'clamav':
    return ClamAVScanner(debug=debug, file_bytes=file_bytes, pid=pid)
  elif engine == 'yara':
    return YaraScanner(debug=debug, file_bytes=file_bytes, pid=pid, rules_path=rules_path)
  else:
    raise ValueError(f'Unknown engine: {engine}')


def scan_process(pid: int, engine: str, debug: bool, rules_path: str = None):
  try:
    scanner = initialize_scanner(engine, debug, pid=pid, rules_path=rules_path)
    scanner.analyze()
    if scanner.malicious:
      status = ScanStatus.THREAT_FOUND
    else:
      status = ScanStatus.NO_THREAT
    return ScanResult(file_path=f'Process_{pid}',
                      status=status)
  except Exception as e:
    Console.write_error(f'Error scanning process {pid}: {e}')
    return ScanResult(
        file_path=f'Process_{pid}',
        status=ScanStatus.ERROR,
        error_message=str(e))


def scan_file_bytes(file_path: Path,
                    file_bytes: bytes,
                    engine: str,
                    debug: bool,
                    rules_path: str = None) -> ScanResult:
  try:
    scanner = initialize_scanner(
        engine, debug, file_bytes=file_bytes, rules_path=rules_path)
    scanner.analyze()
    if scanner.malicious:
      status = ScanStatus.THREAT_FOUND
    else:
      status = ScanStatus.NO_THREAT
    return ScanResult(file_path=file_path,
                      status=status,
                      file_size=len(file_bytes))
  except Exception as e:
    Console.write_error(f'Error scanning {file_path.name}: {e}')
    return ScanResult(
        file_path=file_path,
        status=ScanStatus.ERROR,
        error_message=str(e))


def process_files(file_list: List[Path], args) -> List[ScanResult]:
  results = []

  Console.write_output(f'Found {len(file_list)} file(s) to scan')

  for file_path in file_list:
    Console.write_output(f'Scanning file: {file_path.name}')
    content = read_file_content(file_path)
    result = scan_file_bytes(file_path,
                             content,
                             args.engine.lower(),
                             args.debug,
                             rules_path=args.rules)
    results.append(result)

  return results


def print_summary(results: List[ScanResult]):
  success = sum(1 for r in results if r.success)
  errors = len(results) - success
  threats = sum(1 for r in results if r.status == ScanStatus.THREAT_FOUND)
  Console.write_output('\n')
  Console.write_output('-' * 60)
  Console.write_output(f'Scan complete: {success} successful, {errors} errors')
  if threats:
    Console.write_threat(f'Found {threats} threats')
    for result in results:
      if result.status == ScanStatus.THREAT_FOUND:
        Console.write_threat(f'  - {result.file_path}')
  else:
    Console.write_output('No threats found')
  

def parse_arguments():
  parser = argparse.ArgumentParser(
      description='Identify AV signatures in files',
      prog='threatcheck')
  parser.add_argument(
      '-e', '--engine',
      type=str.lower,
      default='defender',
      choices=['defender', 'amsi', 'clamav', 'yara'],
      help='Scanning engine (default: defender)')
  parser.add_argument(
      '-f', '--file',
      help='Analyze a file on disk')
  parser.add_argument(
      '-u', '--url',
      help='Analyze a file from a URL')
  parser.add_argument(
      '-d', '--directory',
      help='Analyze all files in a directory')
  parser.add_argument('-p', '--pid', help='Analyze a process by PID')
  parser.add_argument(
      '-r', '--rules',
      help=('Path to YARA rules directory. Will recursively search for all '
            '.yar and .yara files.'))
  parser.add_argument(
      '--debug',
      action='store_true',
      help='Enable debug output')
  parser.add_argument(
      '--version',
      action='version',
      version=f'%(prog)s {__version__}')

  return parser.parse_args()


def main():
  args = parse_arguments()

  if args.directory:
    file_list = list_files_in_directory(Path(args.directory))
    results = process_files(file_list, args)
  elif args.file:
    file_list = [Path(args.file)]
    results = process_files(file_list, args)
  elif args.url:
    file_content = download_file_bytes(args.url)
    results = [scan_file_bytes(Path(args.url),
                               file_content,
                               args.engine.lower(),
                               args.debug,
                               rules_path=args.rules)]
  elif args.pid:
    results = [
        scan_process(int(args.pid),
                     args.engine.lower(),
                     args.debug,
                     rules_path=args.rules)]
  else:
    Console.write_error(
        'Specify either -d, -f, -u or -p as a source. Type --help for more.')
    sys.exit(1)

  print_summary(results)
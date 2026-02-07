import os
import sys
import subprocess
from pathlib import Path
from enum import Enum

from threatcheck.scanners.base import Scanner
from threatcheck.console import Console

class ScanResult(Enum):
  NO_THREAT_FOUND = 0
  THREAT_FOUND = 2
  FILE_NOT_FOUND = 3
  TIMEOUT = 4
  ERROR = 5

class DefenderScanResult:
  def __init__(self):
    self.result = None
    self.signature = None

class DefenderScanner(Scanner):
  def __init__(self, file_bytes=None, debug=False):
    super().__init__(file_bytes=file_bytes, debug=debug)
    
    if sys.platform != 'win32':
      raise RuntimeError(
          'Platform not supported: Defender scanner requires Windows')
    
    self.mpcmdrun_path = Path(r'C:\Program Files\Windows Defender\MpCmdRun.exe')
    if not self.mpcmdrun_path.exists():
      raise FileNotFoundError(
          f'MpCmdRun.exe not found at {self.mpcmdrun_path}')
  
  def _scan_bytes(self, data):
    """Scan a data split for threats"""
    # Defender needs to scan from disk, not memory.
    testfile_path = os.path.join(self.temp_dir, 'file.exe')
    with open(testfile_path, 'wb') as f:
      f.write(data)
    
    status = self._scan_file(testfile_path)
    return status.result == ScanResult.THREAT_FOUND

  def _scan_file(self, file_path, get_sig=False):
    result = DefenderScanResult()
    
    if not os.path.exists(file_path):
      result.result = ScanResult.FILE_NOT_FOUND
      return result
    
    try:
      cmd = [
        str(self.mpcmdrun_path),
        '-Scan',
        '-ScanType', '3',
        '-File', file_path,
        '-DisableRemediation',
        '-Trace',
        '-Level', '0x10'
      ]
      
      process = subprocess.Popen(
          cmd,
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE,
          creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32'
              else 0
      )
      
      try:
        stdout, stderr = process.communicate(timeout=30)
      except subprocess.TimeoutExpired:
        process.kill()
        result.result = ScanResult.TIMEOUT
        return result
      
      if get_sig:
        output = stdout.decode('utf-8', errors='ignore')
        for line in output.split('\n'):
          if 'Threat  ' in line:
            parts = line.split(' ')
            if len(parts) > 19:
              result.signature = parts[19]
            break
      
      if process.returncode == 0:
        result.result = ScanResult.NO_THREAT_FOUND
      elif process.returncode == 2:
        result.result = ScanResult.THREAT_FOUND
      else:
        result.result = ScanResult.ERROR
      
      return result
    
    except Exception as e:
      Console.write_error(f'Error scanning file: {e}')
      result.result = ScanResult.ERROR
      return result


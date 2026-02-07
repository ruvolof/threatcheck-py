import sys
import ctypes
from ctypes import c_void_p, c_uint, c_int, POINTER, byref
from enum import IntEnum
from threatcheck.scanners.base import Scanner
from threatcheck.console import Console

class AmsiResult(IntEnum):
  AMSI_RESULT_CLEAN = 0
  AMSI_RESULT_NOT_DETECTED = 1
  AMSI_RESULT_DETECTED = 32768

class AmsiScanner(Scanner):
  def __init__(self, file_bytes=None, debug=False,
      app_name='PowerShell_C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe_5.1.22621.2506'):
    super().__init__(file_bytes=file_bytes, debug=debug)
    
    self.amsi_context = None
    self.amsi_session = None
    
    if sys.platform != 'win32':
      raise RuntimeError(
          'Platform not supported: AMSI scanner requires Windows')
    
    try:
      self.amsi = ctypes.windll.amsi
    except Exception as e:
      raise RuntimeError(f'AMSI not available on this system: {e}')
    
    self._initialize_amsi(app_name)

    if not self._real_time_protection_enabled:
      raise RuntimeError('AMSI engine requires real-time protection enabled')

  @property
  def _real_time_protection_enabled(self):
    """Check if AMSI real-time protection is enabled"""
    amsi_uid = '7e72c3ce-861b-4339-8740-0ac1484c1386'
    sample = f'Invoke-Expression \'AMSI Test Sample: {amsi_uid}\''.encode()
    result = self._scan_buffer(sample, c_void_p())
    return result == AmsiResult.AMSI_RESULT_DETECTED

  def _initialize_amsi(self, app_name):
    self.amsi_context = c_void_p()
    self.amsi_session = c_void_p()
    
    result = self.amsi.AmsiInitialize(
        ctypes.c_wchar_p(app_name),
        byref(self.amsi_context)
    )
    
    if result != 0:
      raise RuntimeError(f'AmsiInitialize failed with code {result}')
    
    result = self.amsi.AmsiOpenSession(
        self.amsi_context,
        byref(self.amsi_session)
    )
    
    if result != 0:
      self.cleanup()
      raise RuntimeError(f'AmsiOpenSession failed with code {result}')
  
  def _scan_bytes(self, data):
    """Scan a data split for threats"""
    status = self._scan_buffer(data)
    return status == AmsiResult.AMSI_RESULT_DETECTED

  def _scan_buffer(self, buffer, session=None):
    if session is None:
      session = self.amsi_session
    
    result = c_int()
    
    buffer_array = (ctypes.c_ubyte * len(buffer)).from_buffer_copy(buffer)
    
    ret = self.amsi.AmsiScanBuffer(
        self.amsi_context,
        buffer_array,
        c_uint(len(buffer)),
        ctypes.c_wchar_p('test.ps1'),
        session,
        byref(result)
    )
    
    if ret != 0:
      Console.write_error(f'AmsiScanBuffer failed with code {ret}')
      return AmsiResult.AMSI_RESULT_CLEAN
    
    return AmsiResult(result.value)

  def cleanup(self):
    if self.amsi_session and self.amsi_context:
      try:
        self.amsi.AmsiCloseSession(self.amsi_context, self.amsi_session)
      except:
        pass
    
    if self.amsi_context:
      try:
        self.amsi.AmsiUninitialize(self.amsi_context)
      except:
        pass

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_val, exc_tb):
    self.cleanup()
    return False

  def __del__(self):
    self.cleanup()

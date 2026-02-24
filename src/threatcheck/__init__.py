__version__ = '0.3.0'
__author__ = 'Werebug security@werebug.com'
__license__ = 'GPL-3.0'

from threatcheck.scanners.defender import DefenderScanner
from threatcheck.scanners.amsi import AmsiScanner
from threatcheck.scanners.clamav import ClamAVScanner
from threatcheck.scanners.yara_scanner import YaraScanner

__all__ = [
  'DefenderScanner',
  'AmsiScanner',
  'ClamAVScanner',
  'YaraScanner'
]

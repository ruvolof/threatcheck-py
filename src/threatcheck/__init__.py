__version__ = '0.1.0'
__author__ = 'Werebug security@werebug.com'
__license__ = 'GPL-3.0'

from threatcheck.scanners.defender import DefenderScanner
from threatcheck.scanners.amsi import AmsiScanner

__all__ = ['DefenderScanner', 'AmsiScanner']

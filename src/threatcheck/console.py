import sys
from colorama import Fore, Style, init

init(autoreset=True)

class Console:
  @staticmethod
  def write_output(message):
    print(f'{Fore.GREEN}[+] {message}{Style.RESET_ALL}')

  @staticmethod
  def write_error(message):
    print(f'{Fore.RED}[x] {message}{Style.RESET_ALL}', file=sys.stderr)

  @staticmethod
  def write_debug(message):
    print(f'{Fore.YELLOW}[*] {message}{Style.RESET_ALL}')

  @staticmethod
  def write_threat(message):
    print(f'{Fore.RED}[!] {message}{Style.RESET_ALL}')

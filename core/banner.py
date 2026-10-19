import sys
from colorama import Fore, Style, init

init(autoreset=True)

def print_banner():
    banner = r"""
{red}    ___    {yellow}____   {cyan}______ {magenta}_  __
{red}   /   |  {yellow}/ __ \ {cyan}/ ____/{magenta}| |/ /
{red}  / /| | {yellow}/ /_/ /{cyan}/ __/   {magenta}|  /  
{red} / ___ \{yellow}/ ____/{cyan}/ /___  {magenta}/ /| |  
{red}/_/   \_/{yellow}/_/    {cyan}/_____/{magenta}/_/ |_|  
{reset}
{green}[+] Automated Phishing Executive Examiner v1.0
{dim}[+] Email Forensics & Executive PDF Reporting Engine
{dim}--------------------------------------------------
""".format(
        red=Fore.RED,
        yellow=Fore.YELLOW,
        cyan=Fore.CYAN,
        magenta=Fore.MAGENTA,
        green=Fore.GREEN,
        dim=Fore.LIGHTBLACK_EX,
        reset=Style.RESET_ALL
    )
    print(banner)

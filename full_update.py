import os
from subprocess import CompletedProcess
import time
import subprocess
import time
def full_update():
    #####################################################
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    RED='\033[0;31m'
    BLUE="\033[0;34m"
    NC='\033[0m' # No Color
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
    print(f"Time Taken: {time.time() - start_time:.2f} seconds")
    start_time=time.time()

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
        os.system("pwd")

    else:
        print(f"{YELLOW}[*]Installing CS - Outflanknl C2 Tool Collection...{NC}")
        os.system('git clone https://github.com/outflanknl/C2-Tool-Collection /opt/cobaltstrike/third-party/outflanknl-c2-tool-collection')
        print()
        os.system("pwd")

    if os.path.isdir('/opt/cobaltstrike/third-party/outflanknl-helpcolor/.git'):
        print(f"{BLUE}[*]Updating CS - Outflanknl HelpColor...{NC}")
        os.chdir('/opt/cobaltstrike/third-party/outflanknl-helpcolor/')
        os.system('git pull')
        print()
        os.system("pwd")

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
        os.system('pwd')
        
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
            os.system("pwd")

        if not os.path.isfile('/usr/bin/gobuster'):
            print(f"{BLUE}[*]Installing gobuster...{NC}")
            os.system("apt install -y gobuster")
            print()

        if os.path.isdir('/opt/Havoc/.git'):
            print(f"{BLUE}[*]Updating Havoc...{NC}")
            os.chdir('/opt/Havoc/')
            os.system('git pull')
            print()
            os.system('pwd')
            
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
        print(f" UPDATED DONE")
        exit()
        
def f_runlocally():
        pass

def f_banner():
    pass

def f_error():
    pass
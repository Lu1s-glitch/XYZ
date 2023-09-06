import os
from subprocess import CompletedProcess
import time
import time
def generate_targets():
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
                            GENERATE TARGETS 
            """)     
    print()
    start_time = time.time()
    if not os.path.exists("/opt/XYZ/active_recon"):
        os.chdir("/opt")
        os.system("mkdir XYZ")
        os.chdir("/opt/XYZ")
        os.system("mkdir generate_targets")
        os.chdir("/opt/XYZ/generate_targets")
        print()
        print(f"Time elapsed: {time.time() - start_time:.2f} seconds.\n\n")
    start_time = time.time()
    interface = input("Interface to scan: ")
    print(f"Time elapsed: {time.time() - start_time:.2f} seconds.\n\n")
    if not interface:
        f_error()
    else:
        os.system(f"arp-scan -l -I {interface} | egrep -v '(arp-scan|DUP:|Interface|packets)' > tmp")
        os.system("sed '/^$/d' tmp | sort -k3 > /opt/XYZ/generate_targets/arp-scan.txt")
        os.system("awk '{print $1}' tmp | $sip | sed '/^$/d' > /opt/XYZ/generate_targets/targets-arp-scan.txt")
        os.system("rm tmp")
        print("\n\n***Scan complete.***\n\n")
        print(f"The new report is located at {YELLOW}/opt/XYZ/generate_targets/targets-arp-scan.txt{NC}\n\n")
        exit()
        

    global location
    f_location()

    if not location:
        f_error()
    else:
        print(f"\n{BLUE}Type of input:{NC}\n")
        print("1.  List containing IPs, ranges, and/or CIDRs.")
        print("2.  Manual\n")
        choice = input("Choice: ")

        if choice == "1":
            os.system(f"nmap -sn -PS -PE --stats-every 10s -iL {location} > tmp")

        elif choice == "2":
            manual = input("Enter a CIDR or range: ")

            if not manual:
                f_error()

            os.system(f"nmap -sn -PS -PE --stats-every 10s {manual} > tmp")

        else:
            f_error()

        os.system("grep -oE '\\b([0-9]{1,3}\.){3}[0-9]{1,3}\\b' tmp > /opt/XYZ/generate_targets/targets-pingsweep.txt")
        os.system("rm tmp")
        print("\n\n***Scan complete.***\n\n")
        print(f"The new report is located at {YELLOW}/opt/XYZ/generate_targets/targets-pingsweep.txt{NC}\n\n")
        exit()


    def f_location():
        global location
        location = input("Enter a location: ")
        if not location:
            start_time = time.time()
            print(f"\n{YELLOW}NO LOCATION PROVIDED.{NC}\n")
            print(f"Time elapsed: {time.time() - start_time:.2f} seconds.\n\n")
            exit()


    def f_error():
        start_time = time.time()
        print(f"\n{YELLOW}INVALID CHOICE.{NC}\n")
        print(f"Time elapsed: {time.time() - start_time:.2f} seconds.\n\n")
        exit()
        
def f_runlocally():
        pass

def f_banner():
    pass

def f_error():
    pass
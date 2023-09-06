import os
from subprocess import CompletedProcess
import time
def person():
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
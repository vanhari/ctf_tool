#!/bin/bash

#Usage: first parameter is the ip-address and the second parameter will be the dns and it will be redirected to the /etc/hosts

ip_address=$1
dns=$2
http_ports=()

#Just a check to see if an IP-address was given
if [[ -z "$1" ]]; then
    echo "No IP-address was given exiting the program."
    exit
else
        :
fi

#colors for terminal output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

#Checks if the target is available.
checkPing() {
    ping ${ip_address} -c 1 >/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Target is available${NC}"
        return 0
    fi
    echo -e "${RED}Target is not available. Check if the ip address is correct${NC}"
    exit
}

#Scans the open ports and performs a more specific scan on those ports and puts that into a txt file. Also adds the http ports to an array which will later be used.
gatherPorts() {
    ports=($(nmap --min-rate=5000 $ip_address | grep -E "^[0-9]+/tcp\s+open\s" | awk '{print $1}' | cut -d'/' -f1))
    parsedPorts=$(IFS=,; echo "${ports[*]}")
    echo "The following ports were found $parsedPorts"
    echo "Performing a more specific scan. This may take a while."
    #Here the more specific scan is performed
    nmap -p "${parsedPorts}" -sC -sV $ip_address > nmap_results.txt
    echo -e "The nmap scan results were stored into a file named ${GREEN}[nmap_results.txt]${NC}"
}

#Function that takes the second parameter and puts the dns and the ip address to the /etc/hosts. If no dns given then it just skips this part pretty much
etcHosts() {
    if [[ -z "$dns" ]]; then
        echo -e "${RED}No dns given. Skipping${NC}"
    else
        echo -e "$ip_address    $dns" | sudo tee -a /etc/hosts >/dev/null
        echo -e "${GREEN}$ip_address    $dns has been added to the /etc/hosts file.${NC}"
    fi
}

#function that does a ffuf scan if http ports were found in the previous scan.
directoryScan() {
    #If the http_ports array is more than 0 it will do this else its just gonna skip it
    httpParse=($(grep -E "open\s+(http|ssl/http)" nmap_results.txt | awk '{print $1}' | cut -d'/' -f1))
    http_ports+=("${httpParse[@]}")
    if [[ ${#http_ports[@]} -gt 0 ]]; then
        echo -e "The following ports are possibly websites: $http_ports"
        read -p "Would you like to perform a directory and a subdomain scan on the website? (Y/n) " answer
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        echo "This will take a while"
            if [[ -z "$dns" ]]; then
                ffuf -w /usr/share/wordlists/dirb/big.txt -u http://$ip_address/FUZZ -e .php,.txt,.bak -t 200 -ac >ffuf_results.txt 2>&1
                echo -e "The ffuf scan results were stored into a file named ${GREEN}[ffuf_results.txt]${NC}"
                wfuzz -u http://$ip_address -H "Host: FUZZ.$ip_address" -w /usr/share/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 200 --hc 302 > subDomains.txt 2>&1
                echo -e "The subdomains scan results were stored into a file named ${GREEN}[subDomains.txt]${NC}"
            else
                ffuf -w /usr/share/wordlists/dirb/big.txt -u http://$dns/FUZZ -e .php,.txt,.bak -t 200 -ac >ffuf_results.txt 2>&1
                echo -e "The ffuf scan results were stored into a file named ${GREEN}[ffuf_results.txt]${NC}"
                wfuzz -u http://$dns -H "Host: FUZZ.$dns" -w /usr/share/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 200 --hc 302 > subDomains.txt 2>&1
                echo -e "The subdomains scan results were stored into a file named ${GREEN}[subDomains.txt]${NC}"
            fi
        else
            echo -e "Directory scan will not be performed."
        fi
    else
        echo -e "There were no http ports. Skipping directory scan."
    fi
}

check_command() {
    command -v "$1" &>/dev/null
}

install_package() {
    package_name="$1"
    read -p "The $package_name tool is missing. Would you like to install it? (Y/n): " answer
    if [[ "$answer" = "y" ]] || [[ "$answer" = "Y" ]]; then
        if [ "$package_name" == "nmap" ]; then
            sudo apt update
            sudo apt install -y nmap
            elif [ "$package_name" == "ffuf" ]; then
            sudo apt update
            sudo apt install -y ffuf
        fi
    else
        echo -e "${RED}Installation of $package_name skipped. Exiting.${NC}"
        exit 1
    fi
}

previewResults(){
        read -p "Would you like to see a compilation of all the results? (Y/n): " answer
        if [[ "$answer" = "y" ]] || [[ "$answer" = "Y" ]]; then
                cat nmap_results.txt
                echo ""
                cat ffuf_results.txt
                echo ""
                cat subDomains.txt
                echo ""
        else
                :
        fi
}

#Main osuus
# Checking for nmap
if ! check_command "nmap"; then
    echo -e "${RED}nmap is not installed. Exiting.${NC}"
    install_package "nmap"
else
    echo -e "nmap is installed.. continuing"
fi

# Checking for ffuf
if ! check_command "ffuf"; then
    echo -e "${RED}ffuf is not installed. Exiting.${NC}"
    install_package "ffuf"
else
    echo -e "ffuf is installed.. continuing"
fi

checkPing
etcHosts
gatherPorts
directoryScan
previewResults

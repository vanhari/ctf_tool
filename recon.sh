#!/bin/bash

#colors for terminal output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

ip_address=$1
http_ports=()

#Just a check to see if an IP-address was given
if [[ -z "$1" ]]; then
    echo "No IP-address was given exiting the program."
    exit
else
        :
fi

check_command() {
    command -v "$1" &>/dev/null
}

# Checking for nmap
if ! check_command "nmap"; then
    echo -e "${RED}nmap is not installed. Install it and re-run the script.${NC}"
    exit
else
    echo -e "${GREEN}nmap is installed.. continuing${NC}"
fi

# Checking for ffuf
if ! check_command "ffuf"; then
    echo -e "${RED}ffuf is not installed. Install it and re-run the script${NC}"
    exit
else
    echo -e "${GREEN}ffuf is installed.. continuing${NC}"
fi

# Checking for dirsearch
if ! check_command "dirsearch"; then
    echo -e "${RED}dirsearch is not installed. Install it and re-run the script${NC}"
    exit
else
    echo -e "${GREEN}dirsearch is installed.. continuing${NC}"
fi

#Function that curls the ip and to see if there is a dns that should be put into the /etc/hosts
checkDns(){
	dns=($(curl -sI http://$ip_address | awk -F'[/:]' '/^Location:/ {print $5}'))
	if [[ -z "$dns" ]]; then
        	echo -e "${RED}No redirect was detected. Skipping${NC}"
	else
		echo "Dns was found"
        	echo -e "$ip_address    $dns" | sudo tee -a /etc/hosts >/dev/null
		echo -e "${GREEN}$ip_address    $dns has been added to the /etc/hosts file.${NC}"
	fi
}

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
    echo -e "The following ports were found ${BLUE}$parsedPorts${NC}"
    echo "Performing a more specific scan. This may take a while."
    #Here the more specific scan is performed
    nmap -p "${parsedPorts}" -sC -sV $ip_address > ./results/nmap_results.txt
    echo -e "The nmap scan results were stored into a file named ${GREEN}[nmap_results.txt]${NC}"
}

#function that does a directory scan if http ports were found in the previous scan.
directoryScan() {
    #If the http_ports array is more than 0 it will do this else its just gonna skip it
    httpParse=($(grep -E "open\s+(http|ssl/http)" ./results/nmap_results.txt | awk '{print $1}' | cut -d'/' -f1))
    http_ports+=("${httpParse[@]}")
    if [[ ${#http_ports[@]} -gt 0 ]]; then
        echo -e "The following ports are possibly websites: $http_ports"
        read -p "Would you like to perform a directory scan on the website? (Y/n) " answer
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            if [[ -z "$dns" ]]; then
		for i in "${http_ports[@]}"; do
		echo "Performing a scan. This may take a while. [i]"
		dirsearch -u http://$ip_address -x 404 > results/directory_results.txt 2>&1
                echo -e "The directory scan results were stored into a file named ${GREEN}[directory_results.txt]${NC}"
		done
            else
		for i in "${http_ports[@]}"; do
		echo "Performing a scan. This may take a while. [d]"
		dirsearch -u http://$dns -x 404 > results/directory_results.txt 2>&1
		echo -e "The directory scan results were stored into a file named ${GREEN}[directory_results.txt]${NC}"
		done
            fi
        else
            echo -e "Directory scan will not be performed."
        fi
    else
        echo -e "${RED}There were no http ports. Skipping directory scan.${NC}"
    fi
}

#function that does a subdomain scan if http ports were found in the previous scan.
subdomainScan() {
    if [[ ${#http_ports[@]} -gt 0 ]]; then
        read -p "Would you like to perform a subdomain scan on the website? (Y/n) " answer
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            if [[ -z "$dns" ]]; then
		echo "Performing a scan. This may take a while. [i]"
                ffuf -s -u http://$ip_address -H "Host: FUZZ.$ip_address" -w ./wordlists/subdomains-top1million-20000.txt -t 200 -timeout 10 -ac --fc 301,302,403,404 > results/subDomains.txt 2>&1
                echo -e "The subdomains scan results were stored into a file named ${GREEN}[subDomains.txt]${NC}"
            else
		echo "Performing a scan. This may take a while. [d]"
		ffuf -s -u http://$dns -H "Host: FUZZ.$dns" -w ./wordlists/subdomains-top1million-20000.txt -t 200 -timeout 10 -ac --fc 301,302,403,404 > results/subDomains.txt 2>&1
		echo -e "The subdomains scan results were stored into a file named ${GREEN}[subDomains.txt]${NC}"
            fi
        else
            echo -e "Subdomain scan will not be performed."
        fi
    else
        echo -e "${RED}There were no http ports. Skipping scan.${NC}"
    fi
}

previewResults(){
        read -p "Would you like to see a compilation of all the results? (Y/n): " answer
        if [[ "$answer" = "y" ]] || [[ "$answer" = "Y" ]]; then
	for file in results/*.txt; do
        echo "________________________________________________"
        echo "File: $file"
        echo "________________________________________________"

        if [[ -r "$file" ]]; then
            cat "$file"
        else
            sudo cat "$file"
        fi
	done
	fi
	echo "________________________________________________"
}

checkPing
checkDns
gatherPorts
directoryScan
subdomainScan
previewResults

#!/bin/bash

#colors for terminal output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

ip_address=$1
http_ports=()

#Check to see if IP parameter was given
if [[ -z "$1" ]]; then
    echo "No IP-address was given exiting the program."
    exit
else
        :
fi

#Command to check if a tool is installed
check_command() {
    command -v "$1" &>/dev/null
}

# Checking for nmap
if ! check_command "nmap"; then
    echo -e "${RED}nmap is not installed.${NC} Install it and re-run the script.${NC}"
    exit
else
	:
fi

# Checking for ffuf
if ! check_command "ffuf"; then
    echo -e "${RED}ffuf is not installed.${NC} Install it and re-run the script${NC}"
    exit
else
	:
fi

# Checking for dirsearch
if ! check_command "dirsearch"; then
    echo -e "${RED}dirsearch is not installed.${NC} Install it and re-run the script${NC}"
    exit
else
	:
fi

#Function that curls the ip and to see if there is a dns that should be put into the /etc/hosts
checkDns(){
        dns=($(curl -sI http://$ip_address | awk -F'[/:]' '/^Location:/ {print $5}'))
        if [[ -z "$dns" ]]; then
                echo -e "${RED}No redirect was detected. Skipping${NC}"
        else
                echo "Dns was found"
		dnsExists=($(cat /etc/hosts | grep $dns))
		if [[ -n $dnsExists ]]; then
			echo -e "${RED}The $dns is already in the /etc/hosts changes will not be made${NC}"
		else
                	echo -e "$ip_address    $dns" | sudo tee -a /etc/hosts >/dev/null
                	echo -e "${GREEN}$ip_address    $dns has been added to the /etc/hosts file.${NC}"
		fi
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

#gathers the ports and does a specific scan on FOUND ports
gatherPorts() {
    ports=($(nmap -p- --min-rate=5000 -T4 $ip_address | grep -E "^[0-9]+/tcp\s+open\s" | awk '{print $1}' | cut -d'/' -f1))
    parsedPorts=$(IFS=,; echo "${ports[*]}")
    echo -e "The following ports were found ${BLUE}$parsedPorts${NC}"
    echo "Performing a more specific scan. This may take a while."
    #Here the more specific scan is performed
    nmap -p "${parsedPorts}" -sC -sV $ip_address > ./results/nmap_results.txt
    echo -e "The nmap scan results were stored into a file named ${GREEN}[nmap_results.txt]${NC}"
}

#Does a directory scan IF http ports were found in the previous scan.
directoryScan() {
    if [[ ${#http_ports[@]} -eq 0 ]]; then
		echo -e "${RED}There were no http ports. Skipping directory scan.${NC}"
		exit
	else
        echo -e "The following ports are possibly websites: $http_ports"
        read -p "Would you like to perform a directory scan on the website? (Y/n) " answer
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            if [[ -z "$dns" ]]; then
                for i in "${http_ports[@]}"; do
                echo "Performing a scan. This may take a while. [i]"
                dirsearch -u http://$ip_address:$i -x 404 -q --no-color --full-url --format=plain --user-agent "Mozilla/5.0" -o results/dirsearch_$i.txt 2>/dev/null
                echo -e "The directory scan results were stored into a file named ${GREEN}[dirsearch.txt]${NC}"
                done
            else
                for i in "${http_ports[@]}"; do
                echo "Performing a scan. This may take a while. [d]"
                dirsearch -u http://$dns:$i -q --no-color --full-url --user-agent "Mozilla/5.0" --format=plain -o results/dirsearch_$i.txt 2>/dev/null
                echo -e "The directory scan results were stored into a file named ${GREEN}[dirsearch_results.txt]${NC}"
                done
            fi
	#Here we perform the scan for subdomain(s) if any were found.
	if [[ -s results/subDomains.txt ]]; then
		echo -e "Performing a scan on the subdomain(s)."
		while IFS= read -r line; do
		dirsearch -u http://$line.$dns -x 404 -q --no-color --full-url --user-agent "Mozilla/5.0" --format=plain -o results/dirsearch_dns.txt 2>/dev/null
		done < results/subDomains.txt 
	else
		:
	fi
        else
            echo -e "Directory scan will not be performed."
        fi
    fi
    rmdir reports
}

#function that does a subdomain scan. Is done before the directory scan
subdomainScan() {
#If the http_ports array is more than 0 it will do this else its just gonna skip it
    httpParse=($(grep -Ei "open\s+.*http" ./results/nmap_results.txt | awk '{print $1}' | cut -d'/' -f1))
    http_ports+=("${httpParse[@]}")
    if [[ ${#http_ports[@]} -gt 0 && -n "$dns" ]]; then
        read -p "Would you like to perform a subdomain scan on the website? (Y/n) " answer
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            if [[ -n "$dns" ]]; then
                echo "Performing a subdomain scan. This may take a while."
		baselineFilter=$(curl -s -H "Host: random123.$dns" http://$dns | wc -c)
		ffuf -c -u http://$dns -H "Host: FUZZ.$dns" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs $baselineFilter -of csv -o results/subDomains.csv
		cut -d',' -f1 results/subDomains.csv | tail -n +2 > results/subDomains.txt
		rm results/subDomains.csv
		while IFS= read -r line; do
                	echo -e "$ip_address    $line.$dns" | sudo tee -a /etc/hosts >/dev/null
		done < results/subDomains.txt
		echo -e "The subdomains scan results were stored into a file named ${GREEN}[subDomains.txt]${NC} and was added to ${GREEN}/etc/hosts${NC}"
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
        for file in results/*; do
	echo -e "${RED}________________________________________________${NC}"
        echo "File: $file"
	echo -e "${RED}________________________________________________${NC}"
        if [[ -r "$file" ]]; then
            cat "$file"
        else
            :
        fi
        done
        fi
}


mainfunction(){
checkPing
checkDns
gatherPorts
subdomainScan
directoryScan
previewResults
}

mainfunction

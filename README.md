# ctf_tool

A recon automation script I built because the start of every CTF is the same pretty much. This handles all ofthat so I can skip to the actual interesting part.

It wraps existing tools rather than reimplementing them. nmap does the port scanning, ffuf does subdomain fuzzing, and feroxbuster handles directory scanning. 

## Dependencies

You need these installed before running it:

- `nmap` port scanning
- `ffuf` subdomain enumeration
- `feroxbuster` directory scanning
- `seclists` wordlists (used by ffuf and feroxbuster)

On Kali all of these are either pre-installed.

```bash
sudo apt install nmap ffuf feroxbuster seclists
```

## Usage

```bash
./recon.sh -t <ip> [options]
```

Run `./recon.sh -h` for the full flag list. The most useful ones:

```
-t   Target IP (required)
-y   Skip all prompts and run everything automatically
-q   Quiet mode, suppress verbose output
-ws  Custom subdomain wordlist
-wd  Custom directory wordlist
```

Basic run:
```bash
./recon.sh -t 10.10.10.10
```

Fully automated, no prompts:
```bash
./recon.sh -t 10.10.10.10 -y
```

Custom wordlists:
```bash
./recon.sh -t 10.10.10.10 -ws /opt/wordlists/subdomains.txt -wd /opt/wordlists/dirs.txt
```

## What it does

Runs in this order:

1. Checks the target is reachable
2. Looks for a DNS redirect and adds it to `/etc/hosts` if found
3. Runs a full port scan with nmap, then a detailed service scan on open ports
4. Probes each open port directly with curl to confirm whether it's HTTP or HTTPS — more reliable than trusting nmap's service guess
5. Subdomain scan with ffuf if a DNS name was found. Scans over both HTTP and HTTPS when both are available since some subdomains only respond on one protocol
6. Directory scan with feroxbuster on all discovered web ports and subdomains
7. Writes a summary file with everything found

Results are saved to `results/<target>/` relative to wherever the script lives, not wherever you run it from.

## /etc/hosts management

The script handles `/etc/hosts` automatically. If a hostname already exists but points to the wrong IP (happens a lot when you reset a box and get a new IP), it updates it rather than skipping it.

## Notes

This is a personal tool built for HackTheBox and similar CTF platforms. It is not meant for anything outside of legal, authorized environments.

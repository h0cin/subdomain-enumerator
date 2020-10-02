#!/usr/bin/env python3

import argparse
import requests
import json
import dns.resolver
import whois
import tldextract
import datetime
from datetime import datetime
from termcolor import colored

# Get subdomains for a certain domain name using the SecurityTrails API
def get_st_subdomains(domain):

    # Check border cases such as gub.uy
    subname = tldextract.extract(domain)
    print(colored("> Domain: " + subname.domain + " | Suffix: " + subname.suffix,"grey"))

    if domain == subname.suffix:
        apex_domain = subname.suffix

    # Setup securitytrails API environment
    url = "https://api.securitytrails.com/v1/domain/" + domain + "/subdomains"
    querystring = { "children_only": "true" }
    headers = { 'accept': "application/json",
                'apikey': "YOUR_API_KEY"
              }
    # Query securitytrails API and get the domain's subdomains
    response = requests.request("GET", url, headers=headers, params=querystring)
    result_json = json.loads(response.text)
    subdomains = [ i + '.' + domain for i in result_json['subdomains'] ]
    # Starting check message
    print(colored("   >> Checking " + str(len(subdomains)) + " subdomains for existing CNAME's <<\n","red"))
    # Find if there are CNAME's in every found subdomain
    cname_lists = []
    for subdomain in subdomains:
        #print("Checking: " + subdomain)
        cnames = check_cname(subdomain)
        cname_lists.append(cnames)
        if cnames != []:
            print("=---")

    #print(cname_list)
    return

def cname_diving(cname):
    cname = str(cname)
    cname_list = [cname]
    results = ""
    iterations = 1
    while results is not None:
        results = ask_dns_for_cnames(cname)
        if results is not None:
            for result in results:
                cname_list.append(str(result))
                print(colored("> CNAME[" + str(iterations) + "]:", "cyan"), cname + " =>", colored(str(result),"cyan"))
            cname = str(result)
            iterations += 1
        else:
            pass #print("Result is " + str(results))
    check_whois(cname_list)
    return cname_list

# Iterate CNAME discovery
def check_cname(subdomain):
    cnames = ask_dns_for_cnames(subdomain)
    cname_list = []
    cname_lists = []
    if cnames is not None:
        print(colored("> SUBDOMAIN: " + str(subdomain),"yellow"))
        for hostname in cnames:
            print(colored("> CNAME[0]: " + str(hostname),"white"))
            cname_dive = cname_diving(hostname)
            cname_lists.append(str(cname_dive))
        for cname in cnames:
            cname_lists.append(str(cname))

    # Flatten lists
    for cname_records in cname_lists:
        for cname_record in cname_records:
            if cname_record != "[]":
                cname_list.append(cname_record)

    return cname_list

# Ask DNS for CNAME's
def ask_dns_for_cnames(subdomain):
    cnames = ""
    try:
        cnames = dns.resolver.resolve(subdomain, 'CNAME')
    except:
        #print("DNS query didn't work for: " + str(subdomain))
        pass
    else:
        return cnames

# Get whois records and find expired domains
def check_whois(cname_list):
    apex_domains = []
    for cname_record in cname_list:
        subname = tldextract.extract(str(cname_record))
        apex_cname = subname.domain + '.' + subname.suffix
        apex_domains.append(apex_cname)

    # Recover original "-d domain" apex
    subname = tldextract.extract(domain)
    apex_subdomain = subname.domain + '.' + subname.suffix

    # Remove duplicated apex domains
    apex_dedup = list(dict.fromkeys(apex_domains))

    for apex_domain in apex_dedup:
        if apex_domain == apex_subdomain:
            print(colored("> Subdomain and CNAME using the same Apex domain, not following the CNAME.","magenta"))
        else:
            try:
                whois_record = whois.query(apex_domain)
            except whois.exceptions.UnknownTld:
                apex_subname = tldextract.extract(apex_domain)
                print(colored("> Error: Unknown TLD [." + apex_subname.suffix + "]", "magenta"))
                pass
            except:
                print(colored("> No WHOIS record, check this WHOIS server is working for this gTLD/TLD [." + apex_subname.suffix + "]", "magenta"))
                pass
            else:
                now = datetime.now()
                if (whois_record is None or whois_record.expiration_date is None):
                    print(colored("> WHOIS: " + apex_domain + "\n> Expiration: Expired or Invalid. Take a look!!","red", attrs=["blink"]))
                elif (whois_record.expiration_date < now):
                    print(colored("> Warning: domain name " + apex_domain + "expired by " + str(whois_record.expiration_date - now) + "!!","red", attrs=["blink"]))
                elif (whois_record.expiration_date > now):
                    print(colored("> WHOIS: " + apex_domain , "magenta") + colored("\n> Expiration: " + str(whois_record.expiration_date),"green"))
                    print(colored("> OK by " + str(whois_record.expiration_date - now) + " hours:minutes:seconds.","green"))
                else:
                    print(">> Missing WHOIS criteria!")

            #print("CNAME_APEX: " + str(apex_list))
    #print("WHOIS -> " + str(cname))

def splash():
    print(colored("""
   _____ _   _______    _____ _    _ _   ____  ___
  /  ___| | | | ___ \   |  ___| \ | | | | |  \/  |
  \ `--.| | | | |_/ /___| |__ |  \| | | | | .  . |
   `--. \ | | | ___ \___|  __|| . ` | | | | |\/| |
  /\__/ / |_| | |_/ /   | |___| |\  | |_| | |  | |
  \____/ \___/\____/    \____/\_| \_/\___/\_|  |_/

     > Subdomain > CNAME > CNAME > CNAME > WHOIS

     A passive DNS Stale records finder - Enjoy!!""","yellow"))
    return

##
# Main menu
##
if __name__ == "__main__":
    splash()
    ap = argparse.ArgumentParser(description='Expired CNAME\'s finder.',
           usage='Use "python3 %(prog)s --help" for more information',
           formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("-d", "--domain", required = True, type=str, help = "Domain name to analyze")
    args = vars(ap.parse_args())

    # Parser variables
    domain = args["domain"]

    # Filter out domain name
    subname = tldextract.extract(str(domain))
    domain = subname.domain + '.' + subname.suffix

    #Global variables
    #global domain
    get_st_subdomains(domain)

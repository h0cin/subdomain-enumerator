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

##
# Get subdomains for a certain domain name
##
def get_subdomains(domain):
	url = "https://api.securitytrails.com/v1/domain/" + domain + "/subdomains"

	querystring = {
			"children_only": "true"
	}

	headers = {
		'accept': "application/json",
		'apikey': ""
	}

	response = requests.request("GET", url, headers=headers, params=querystring)
	result_json = json.loads(response.text)
	subdomains = [ i + '.' + domain for i in result_json['subdomains'] ]
	print(colored("""\n#-----------------------------------------------------
# Checking """ + str(len(subdomains)) + """ subdomains for existing CNAME's
#-----------------------------------------------------""","yellow"),"\n\n=---")

	for subdomain in subdomains:
		try:
			result = dns.resolver.resolve(subdomain, 'CNAME')
		except:
			#print("No CNAME record for hostname: " + subdomain + '\n=---')
			pass
		else:
			print("Checking subdomain: " + subdomain)
			check_subdomain(result,subdomain)

	return

##
# Iterate on CNAME record
##
def check_cname(subdomain):
	try:
		result = dns.resolver.resolve(subdomain, 'CNAME')
	except:
		print("No additional CNAME records.")
	else:
		print("Additional subdomain: " + subdomain)
		check_subdomain(result,subdomain)
	return

##
# Check subdomains for expired CNAME's
##
def check_subdomain(result,subdomain):
    for cname_record in result:
        cname_record = str(cname_record)
        cname = tldextract.extract(cname_record)
        subname = tldextract.extract(subdomain)
        apex_subdomain = subname.domain + '.' + subname.suffix
        apex_domain = cname.domain + '.' + cname.suffix
        print('Apex: ' + apex_domain)
        if apex_domain == apex_subdomain:
            #print(colored("Subdomain and CNAME using the same Apex domain -> Following the CNAME.","magenta"))
            print("CNAME: " + cname_record)
            print(colored("Subdomain and CNAME using the same Apex domain.","yellow"))
        else:
            try:
                whois_record = whois.query(apex_domain)
            except:
                print("CNAME: " + cname_record)
                print(colored("No WHOIS record, check this WHOIS server is working for this gTLD/TLD [." + cname.suffix + "]", "magenta"))
            else:
                now = datetime.now()
                if (whois_record is None or whois_record.expiration_date is None):
                    print(colored("CNAME: " + cname_record + "\nWHOIS Expiration: Expired or Invalid. Take a look!!","red", attrs=["blink"]))
                elif (whois_record.expiration_date < now):
                    print(colored("Warning: domain name " + cname_record+ "expired by " + str(whois_record.expiration_date - now) + "!!","red", attrs=["blink"]))
                elif (whois_record.expiration_date > now):
                    print("CNAME: " + cname_record + "\nWHOIS Expiration: " + str(whois_record.expiration_date))
                    print(colored("OK by " + str(whois_record.expiration_date - now) + " hours:minutes:seconds.","cyan"))
                else:
                    print(">> Missing WHOIS criteria!")

    print('=---')


##
# Main menu
##
ap = argparse.ArgumentParser(description='Expired CNAME\'s finder.',
        usage='Use "python3 %(prog)s --help" for more information',
        formatter_class=argparse.RawTextHelpFormatter)
ap.add_argument("-d", "--domain", required = True, type=str,
  help = "Domain name to analyze")
ap.add_argument("-di", "--dont-ignore-same-apex", required = False, default=False, type=str,
  help = "Don't ignore subdomains' and CNAME's sharing the same apex domain.")
args = vars(ap.parse_args())

domain = args["domain"]
global ignore_apex
dont_ignore_apex = args["dont_ignore_same_apex"]

get_subdomains(domain)

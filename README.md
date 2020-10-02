# Subdomain Enumerator
A simple tool to enumerate subdomains, check for CNAME records inside them and find expired dns stale registries.

From a chosen target's domain name, it does the following:

+ subdomain discovery regarding the chosen domain
+ finds which subdomain points to a CNAME record
+ finds if there are additional CNAME's pointing to the found CNAME
+ finds nested CNAME records and checks them
+ conducts WHOIS queries to check the found CNAME's validity

Compatible with Python 3+

## Installation

### Downloading the software

Just git clone the repository like this:

````bash
git clone https://github.com/h0cin/subdomain-enumerator.git
```

Enter the newly created folder:

````bash
cd subdomain-enumerator
```

### Installing requirements

Install all required software for this script to run:

````bash
pip3 install -r requirements.txt
```

## Help menu

Available options are visible using the --help flag:

````bash
python3 sub-enum.py --help

usage: Use "python3 sub-enum.py --help" for more information

Expired CNAME's finder.

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain name to analyze
```

## Usage

Execution is pretty straightforward, just place your target's domain name after the -d flag:

```bash
python3 sub-enum.py -d your-domain.tld
```

## License
[To be determined]

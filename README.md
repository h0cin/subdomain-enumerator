# Subdomain Enumerator
A simple proof-of-concept tool to enumerate subdomains, check for CNAME records inside them and find expired dns stale registries.

From a chosen target's domain name, it does the following:

+ subdomain discovery regarding the chosen domain
+ finds which subdomain points to a CNAME record
+ finds if there are additional CNAME's pointing to the found CNAME
+ finds nested CNAME records and checks them
+ conducts WHOIS queries to check the found CNAME's validity

Compatible with Python 3+

![running](/pics/sub-enum-running.png)

![running2](/pics/running-screenshot.png)


## Installation

Installation is easy:

+ Download the files
+ Install software requirements
+ Get a SecurityTrails API key
+ Configure the API key
+ Have fun!

### Downloading the software

Just git clone the repository like this:

```bash
git clone https://github.com/h0cin/subdomain-enumerator.git
```

Enter the newly created folder:

```bash
cd subdomain-enumerator
```

### Installing requirements

Install all required software for this script to run:

```bash
pip3 install -r requirements.txt
```

### SecurityTrails API Key

You need to request an API Key from SecurityTrails in order
to list al available subdomains, you can use the free API: https://securitytrails.com/app/signup?plan=api-0

Limits of the free plan in here: https://securitytrails.com/corp/pricing#api

Once you sign up, and login API keys are available in the 
left menu at API > API Keys > Create New API Key

Just copy the key inside the sub-enum.py file:

```python
headers = { 'accept': "application/json",
            'apikey': "YOUR_API_KEY"
          }
```

You're ready!

## Help menu

Available options are visible using the --help flag:

```bash
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

![help](/pics/sub-enum-help.png)

## License
[To be determined]

# VMware Carbon Black Cloud and Proofpoint Emerging Threats Connector

## Overview 

This is an integration between VMware Carbon Black Cloud Enterprise EDR and Proofpoint Emerging threats. Using the command line arguments, a category (feed) of IOCs filtered by severity and type (IPs and/or domains) from Emerging Threats and pushed to a Watchlist in CBC. The watchlist is organized by severity and includes descriptions and tags on the IOCs. These watchlists allow for alerting on your Threat Intelligence throughout your enterprise endpoints.
## Requirements
Python 3.x
VMware Carbon Black Cloud Enterprise EDR
Proofpoint Emerging Threats

## Setup
Edit `config.conf` with your details (API keys, etc.)  
Install the requirements (`pip install -r requirements.txt`)

## Usage

To get a list of available threat feeds, provide `list` in the category argument (or no arguments)

`python app.py --category list`

or

`python app.py`

This will give you a list of feeds available for IPs or domains.

The script has 4 arguments:
```
  -h, --help           show this help message and exit
  --category CATEGORY  The list to pull from. To get a full list of options use 'list'
  --severity SEVERITY  Filter results based on IOC severity [1-10]
  --domains            Pull the domains list if available. (Either ips or domains are required)
  --ips                Pull the IPs list if available. (Either ips or domains are required)
```

To import the feed, use the following command:

`python app.py --category <category name> --severity [1-10] [--ips] [--domains]`

**Examples**

`python app.py --category Bitcoin_Related --severity 6 --ips --domains`

This will import IPs and domains from the Bitcoin_Related feed with a severity 6 or higher.

`python app.py --category TorNode --severity 3 --ips`

This will import IPs from the TorNode feed with a severity of 3 or higher
## Support

This is an open source integration and is not officially supported. Please open an issue on this repo and we will do our best to update as quickly as possible.
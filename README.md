# VMware Carbon Black Cloud and Proofpoint Emerging Threats Connector

## Overview 

This integration connects VMware Carbon Black Cloud Enterprise EDR with Proofpoint Emerging Threats to provide visibility into the latest threats through a filterable Watchlist in the Carbon Black Cloud console. Using the command line arguments, a category (or feed) of IOCs from Proofpoint Emerging Threats is pushed to a Watchlist in the Carbon Black Cloud. This Watchlist can be organized, filtered and alerted on based on severity and IOC type (IP or domain), and includes descriptions and tags for each IOC.

## Requirements
Python 3.x  
VMware Carbon Black Cloud Enterprise EDR  
Proofpoint Emerging Threats

## Setup

### Carbon Black Configuration
1. You will need to create 1 API Access Level and 1 API key (Custom type)

#### Custom Access Level Permissions

|    **Category**   | **Permission Name**   | **.Notation Name**       |        **Create**       |         **Read**        |        **Update**       | **Delete**              |       **Execute**       |
|:-----------------:|:---------------------:|:------------------------:|:-----------------------:|:-----------------------:|:-----------------------:|:-----------------------:|:-----------------------:|
| Custom Detections | Feeds                 | org.feeds                | :ballot_box_with_check: | :ballot_box_with_check: | :ballot_box_with_check: |                         |                         |

2. Install the requirements (`pip install -r requirements.txt`)
## Configuration

Edit [`config.conf`](https://github.com/cbcommunity/cbc-proofpoint-emerging-threats-connector/blob/main/app/config.conf) with your details (API keys, etc.)  

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
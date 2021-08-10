This is a proof of concept integration with VMware Carbon Black Cloud and Proofpoint Emerging Threats.

## Requirements
Python 3.x

## Setup
Edit `config.conf` with your details (API keys, etc.)
Install the requirements (`pip install -r requirements.txt`)

## Usage

To get a list of available threat feeds, provide `list` in the category argument

`python app.py --category list`

This will give you a list of feeds available for IPs or domains.

To import the feed, use the following command:

`python app.py --category Bitcoin_Related --severity 6 --ips --domains`

This will import the Bitcoin_Related feed with only IOCs of severity 6 or higher, and it will get IPs and domains.

## Support

This is an open source integration and is not officially supported.
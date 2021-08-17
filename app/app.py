# -*- coding: utf-8 -*-
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT

import os
import sys
import logging as log
import configparser
import argparse

from lib.helpers import CarbonBlackCloud, EmergingThreats, config2dict


# Globals
config = None
cb = None
et = None


def init():
    '''
        This is the initialization method which will import the settings from the config file
            and create objects of the Classes to work with the products.
    '''

    global config, cb, et

    # Make sure config file exists
    app_path = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(app_path, 'config.conf')
    exists = os.path.isfile(config_path)
    if exists is False:
        raise Exception('[APP.PY] Unable to find config.conf in {0}'.format(app_path))

    # Get setting from config.conf
    config = configparser.ConfigParser()
    config.read(config_path)
    config = config2dict(config)

    # Configure logging
    log_level = log.getLevelName(config['logging']['level'])
    log_path = os.path.join(app_path, config['logging']['filename'])
    log.basicConfig(filename=log_path, format='[%(asctime)s] %(levelname)s <pid:%(process)d> %(message)s', level=log_level)
    log.info('\n\n[APP.PY] Sarted {0} ({1}) v{2}'.format(config['general']['name'],
                                                         config['general']['description'],
                                                         config['general']['version']))

    # Configure CLI input arguments
    helpers = {
        'main': 'Pull an Emerging Threats feed',
        'severity': 'Filter results based on IOC severity [1-10]',
        'category': 'The list to pull from. To get a full list of options use \'list\'',
        'ips': 'Pull the IPs list if available. (Either ips or domains are required)',
        'domains': 'Pull the domains list if available. (Either ips or domains are required)'
    }
    parser = argparse.ArgumentParser(description=helpers['main'])
    parser.add_argument('--category', default='list', help=helpers['category'])
    parser.add_argument('--severity', default=5, help=helpers['severity'])
    parser.add_argument('--domains', action='store_true', default=False, help=helpers['domains'])
    parser.add_argument('--ips', action='store_true', default=False, help=helpers['ips'])
    args = parser.parse_args()

    # Update config with cli arguments
    config['category'] = args.category
    config['severity_limit'] = int(args.severity)
    config['get_domains'] = args.domains
    config['get_ips'] = args.ips

    # Initialize CBC
    cb = CarbonBlackCloud(config, log)

    # Initialize ET
    et = EmergingThreats(config, log)

    if args.domains is False and args.ips is False:
        print('\nNeither --ips nor --domains was provided. At least one is required.\n')
        sys.exit(1)

    return cb, et, config

def main():
    '''
        This integration will pull IOCs (IPs and/or domains) from the Emerging Threats feed.
        IOCs are restructured and pushed to VMware Carbon Black Cloud Enterprise EDR.
    '''
    
    # Intialize
    cb, et, config = init()

    # Get the IOCs from the feed
    iocs = et.get_feed()
    # Build the CB feed with the IOCs
    reports = cb.build_reports(iocs)
    
    # Update the name of the feed
    feed_name = 'Proofpoint Emerging Threats {0}'.format(config['category'])
    # Push the feed to CBC
    cb.push_feed(feed_name, reports)

if __name__ == '__main__':
    main()

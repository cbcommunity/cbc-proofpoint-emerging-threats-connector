# -*- coding: utf-8 -*-
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT

import os
import sys
import logging as log
import json
import requests
import hashlib
import configparser
import argparse
from datetime import datetime
import time

from cbc_sdk import CBCloudAPI
from cbc_sdk.enterprise_edr import Feed, Report
from cbc_sdk.helpers import eprint


def init():
    # Make sure config file exists
    app_path = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(app_path, 'config.conf')
    if os.path.isfile(config_path) is False:
        raise Exception('[APP.PY] Unable to find config.conf in {0}'.format(app_path))

    # Get setting from config.conf
    config = configparser.ConfigParser()
    config.read('config.conf')
    config = config2dict(config)

    # Configure logging
    log_level = log.getLevelName(config['logging']['level'])
    log_path = os.path.join(app_path, config['logging']['filename'])
    log.basicConfig(filename=log_path, format='[%(asctime)s] %(levelname)s <pid:%(process)d> %(message)s', level=log_level)
    log.info('\n\n[APP.PY] Sarted Proofpoint Emerging Threats Connector for VMware Carbon Black Cloud')

    # Configure CLI input arguments
    helpers = {
        'main': 'Pull an Emerging Threats feed',
        'severity': 'Filter results based on IOC severity',
        'category': 'The list to pull from. To get a full list of options use \'list\'',
        'ips': 'Pull the IPs list if available. (Either ips or domains are required)',
        'domains': 'Pull the domains list if available. (Either ips or domains are required)'
    }
    parser = argparse.ArgumentParser(description=helpers['main'])
    parser.add_argument('--category', default='list', help=helpers['category'])
    parser.add_argument('--severity', default=5, help=helpers['severity'])
    parser.add_argument('--ips', action='store_true', default=False, help=helpers['ips'])
    parser.add_argument('--domains', action='store_true', default=False, help=helpers['domains'])
    args = parser.parse_args()

    et_feeds = get_et_feeds()

    if args.category == 'list':
        eprint('\n\nNo category was provided. Provide a value from the list below:')
        eprint('\n  IP Feeds')
        for feed in et_feeds['ip_feeds']:
            eprint('    - {0}'.format(feed))
        eprint('\n  Domain Feeds')
        for feed in et_feeds['domain_feeds']:
            eprint('    - {0}'.format(feed))
        sys.exit(1)


    # Initialized Emerging Threats
    config['EmergingThreats']['category'] = args.category
    config['EmergingThreats']['severity'] = args.severity
    config['EmergingThreats']['ips'] = args.ips
    config['EmergingThreats']['domains'] = args.domains
    et = config['EmergingThreats']

    # Initialize Carbon Black
    api_url = config['CarbonBlack']['url']
    org_key = config['CarbonBlack']['org_key']
    api_id = config['CarbonBlack']['custom_api_id']
    api_key = config['CarbonBlack']['custom_api_key']
    cb = CBCloudAPI(
        url = api_url,
        token = '{0}/{1}'.format(api_key, api_id),
        org_key = org_key
    )

    return cb, et, config

def get_feed(cb, feed_id=None, feed_name=None):
    """Retrieve a feed by ID or name."""
    if feed_id:
        return cb.select(Feed, feed_id)
    elif feed_name:
        feeds = [feed for feed in cb.select(Feed) if feed.name == feed_name]

        if not feeds:
            log.warning("No feeds named '{}'".format(feed_name))
            return None
        elif len(feeds) > 1:
            log.warning("More than one feed named '{}'".format(feed_name))
            sys.exit(1)

        return feeds[0]
    else:
        raise ValueError("expected either feed_id or feed_name")

def get_et_feeds():
    return {
        'ip_feeds': {
            'AbusedTLD': 'AbusedTLD.txt',
            'Bitcoin_Related': 'Bitcoin_Related.txt',
            'Blackhole': 'Blackhole.txt',
            'Bot': 'Bot.txt',
            'Brute_Forcer': 'Brute_Forcer.txt',
            'ChatServer': 'ChatServer.txt',
            'CnC': 'CnC.txt',
            'Compromised': 'Compromised.txt',
            'DDoSAttacker': 'DDoSAttacker.txt',
            'DDoSTarget': 'DDoSTarget.txt',
            'DriveBySrc': 'DriveBySrc.txt',
            'Drop': 'Drop.txt',
            'DynDNS': 'DynDNS.txt',
            'EXE_Source': 'EXE_Source.txt',
            'FakeAV': 'FakeAV.txt',
            'IPCheck': 'IPCheck.txt',
            'Mobile_CnC': 'Mobile_CnC.txt',
            'Mobile_Spyware_CnC': 'Mobile_Spyware_CnC.txt',
            'OnlineGaming': 'OnlineGaming.txt',
            'P2P': 'P2P.txt',
            'P2PCnC': 'P2PCnC.txt',
            'Parking': 'Parking.txt',
            'Proxy': 'Proxy.txt',
            'RemoteAccessService': 'RemoteAccessService.txt',
            'Scanner': 'Scanner.txt',
            'SelfSignedSSL': 'SelfSignedSSL.txt',
            'Skype_SuperNode': 'Skype_SuperNode.txt',
            'Spam': 'Spam.txt',
            'SpywareCnC': 'SpywareCnC.txt',
            'TorNode': 'TorNode.txt',
            'Undesirable': 'Undesirable.txt',
            'Utility': 'Utility.txt',
            'VPN': 'VPN.txt',
            'Web_Crawler': 'Web_Crawler.txt'
        },
        'domain_feeds': {
            'AbusedTLD': 'domain-AbusedTLD.txt',
            'Bitcoin_Related': 'domain-Bitcoin_Related.txt',
            'Blackhole': 'domain-Blackhole.txt',
            'ChatServer': 'domain-ChatServer.txt',
            'CnC': 'domain-CnC.txt',
            'DriveBySrc': 'domain-DriveBySrc.txt',
            'Drop': 'domain-Drop.txt',
            'DynDNS': 'domain-DynDNS.txt',
            'EXE_Source': 'domain-EXE_Source.txt',
            'FakeAV': 'domain-FakeAV.txt',
            'IPCheck': 'domain-IPCheck.txt',
            'Mobile_CnC': 'domain-Mobile_CnC.txt',
            'Mobile_Spyware_CnC': 'domain-Mobile_Spyware_CnC.txt',
            'OnlineGaming': 'domain-OnlineGaming.txt',
            'P2P': 'domain-P2P.txt',
            'Proxy': 'domain-Proxy.txt',
            'RemoteAccessService': 'domain-RemoteAccessService.txt',
            'SpywareCnC': 'domain-SpywareCnC.txt',
            'Undesirable': 'domain-Undesirable.txt',
            'Utility': 'domain-Utility.txt'
        }
    }

def get_et(et, category, severity_limit=1, domains=False, ips=False):
    et_feeds = get_et_feeds()
    iocs = {
        'domains': {
            1: [], 2: [],
            3: [], 4: [],
            5: [], 6: [],
            7: [], 8: [],
            9: [], 10: []
        },
        'IPs': {
            1: [], 2: [],
            3: [], 4: [],
            5: [], 6: [],
            7: [], 8: [],
            9: [], 10: []
        }
    }

    if ips:
        if category not in et_feeds['ip_feeds']:
            log.warning('{0} is not a valid Emerging Threats IP feed. Skipping this request.'.format(category))

        else:
            url = '{0}/{1}/reputation/detailed_ip_cat_per_file/{2}'.format(et['url'], et['api_key'], et_feeds['ip_feeds'][category])
            r = requests.get(url)

            if r.status_code == 200:
                data = r.text.splitlines()
                for line in data:
                    line = line.split(',')
                    severity = get_severity(line[2])
                    if severity >= severity_limit:
                        iocs['IPs'][severity].append(line[0])
            else:
                log.error('Error {0}: {1}'.format(r.status_code, r.text))

    if domains:
        if category not in et_feeds['domain_feeds']:
            log.error('{0} is not a valid Emerging Threats domain feed. Skipping this request.'.format(category))

        else:
            url = '{0}/{1}/reputation/detailed_domain_cat_per_file/{2}'.format(et['url'], et['api_key'], et_feeds['domain_feeds'][category])
            r = requests.get(url)

            if r.status_code == 200:
                data = r.text.splitlines()
                for line in data:
                    line = line.split(',')
                    severity = get_severity(line[2])
                    if severity >= severity_limit:
                        iocs['domains'][severity].append(line[0])
            else:
                log.error('Error {0}: {1}'.format(r.status_code, r.text))

    return iocs

def build_iocs(iocs, ioc_type):
    if ioc_type == 'domains':
        field_value = 'netconn_domain'
    elif ioc_type == 'IPs':
        field_value = 'netconn_ipv4'

    ioc_list = []

    for ioc in iocs:
        unique_id = hashlib.md5('{0}'.format(ioc).encode('utf-8')).hexdigest()

        new_ioc = {
            'id': unique_id,
            'match_type': 'equality',
            'field': field_value,
            'values': [ioc],
            'link': 'https://emergingthreats.com'
        }

        ioc_list.append(new_ioc)
    
    return ioc_list

def build_reports(iocs, category):
    reports = []

    for ioc_type in iocs:
        for severity in iocs[ioc_type]:
            if len(iocs[ioc_type][severity]) > 0:
                report = build_report(iocs[ioc_type][severity], ioc_type, severity, category)
                reports.append(report)
    
    return reports

def build_report(iocs, ioc_type, severity, category):
    if ioc_type == 'domains':
        field_value = 'netconn_domain'
    elif ioc_type == 'IPs':
        field_value = 'netconn_ip'

    iocs = build_iocs(iocs, ioc_type)

    report = {
        'id': 'report-et_{0}_{1}_severity_{2}'.format(category, ioc_type, severity),
        'timestamp': convert_time(convert_time('now')),
        'title': '{0} {1} with severity {2}'.format(category, ioc_type, severity),
        'description': 'These IOCs were added from the Proofpoint Emerging Threats {0} {1} list and have a severity of {2}'.format(category, ioc_type, severity),
        'severity': severity,
        'link': 'https://emergingthreats.com',
        'tags': ['Emerging Threats', category],
        'iocs_v2': iocs,
        'visibility': None
    }

    return report

def get_severity(score):
    score = round(int(score) * 10 / 127)
    if score == 0:
        score = 1
    return score

def convert_time(timestamp):
    '''
        Converts epoch or ISO8601 formatted timestamp
        Inputs
            timestamp
                epoch time (int)
                ISO8601 time (str)
                'now' (str)
        Raises
            TypeError if timestamp is not a string or integer
        Output
            If timestamp was epoch, returns ISO8601 version of timestamp
            If timestamp was ISO8601, returns epoch version of timestamp
            If timestamp was 'now', returns ISO8601 of current time
        > Note: All times are treated as GMT
    '''

    if isinstance(timestamp, (str, int)) is False:
        raise TypeError('timestamp is expected to be an integer or string.')

    try:
        if isinstance(timestamp, int):
            if len(str(timestamp)) == 13:
                timestamp = int(timestamp / 1000)

            utc_dt = datetime(1970, 1, 1) + timedelta(seconds=timestamp)
            converted_time = utc_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')

        else:
            if timestamp == 'now':
                return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            utc_dt = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
            converted_time = int((utc_dt - datetime(1970, 1, 1)).total_seconds())

        return converted_time

    except Exception as err:
        eprint(err)

def import_feed(cb, reports, category):
    feed = {
        'feedinfo': {
            'name': 'Proofpoint Emerging Threats {0}'.format(category),
            'summary': 'A list of IOCs from the Emerging Threats {0} feed'.format(category),
            'owner': '7DESJ9GN',
            'provider_url': 'https://emergingthreats.com',
            'category': 'Partner',
            'access': 'private'
        },
        'reports': reports
    }

    feed = cb.create(Feed, feed)
    feed.save(public=False)

def config2dict(config):
    '''
        This method converts a configparser variable to a dict to
            enable addition of new values.
        Source: https://stackoverflow.com/a/57024021/1339829
    '''
    return { i: { i[0]: i[1] for i in config.items(i) } for i in config.sections() }

def main():
    cb, et, config = init()

    category = et['category']
    severity_limit = int(et['severity'])
    get_domains = et['domains']
    get_ips = et['ips']

    iocs = get_et(et, category, severity_limit=severity_limit, ips=get_ips, domains=get_domains)
    reports = build_reports(iocs, category)
    log.debug('{0}'.format(json.dumps(reports, indent=4)))
    
    feed_name = 'Proofpoint Emerging Threats {0}'.format(category)
    feed = get_feed(cb, feed_name=feed_name)
    if feed is None:
        log.info('Feed {0} does not exist. Creating feed.'.format(feed_name))

        feed = {
            'feedinfo': {
                'name': 'Proofpoint Emerging Threats {0}'.format(category),
                'summary': 'A list of IOCs from the Emerging Threats {0} feed'.format(category),
                'owner': '{0}'.format(config['CarbonBlack']['org_key']),
                'provider_url': 'https://emergingthreats.com',
                'category': 'Partner',
                'access': 'private'
            },
            'reports': reports
        }

        feed = cb.create(Feed, feed)
        feed.save(public=False)
        log.info('Feed {0} was created.'.format(feed_name))

    else:
        log.info('Feed {0} exists ({1}), replacing reports'.format(feed.name, feed.id))
        reports_obj = [Report(cb, initial_data=report, feed_id=feed.id) for report in reports]
        feed.replace_reports(reports_obj)
        log.info('Feed {0} ({1}) was updated.'.format(feed.name, feed.id))
    

if __name__ == '__main__':
    main()

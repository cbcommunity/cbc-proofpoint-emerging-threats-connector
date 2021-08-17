# -*- coding: utf-8 -*-
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT

import re
import sys
import time
import requests
import hashlib

from datetime import datetime, timedelta

from cbc_sdk import CBCloudAPI
from cbc_sdk.enterprise_edr import Feed, Report


class CarbonBlackCloud:
    '''
    '''

    def __init__(self, config, log):
        '''
        '''

        try:
            self.class_name = 'CarbonBlackCloud'
            self.log = log
            self.log.info('[%s] Initializing', self.class_name)

            self.config = config
            self.url = clean_url(config['CarbonBlack']['url'])
            self.org_key = config['CarbonBlack']['org_key']
            self.cust_api_id = config['CarbonBlack']['custom_api_id']
            self.cust_api_key = config['CarbonBlack']['custom_api_key']
            self.headers = {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache',
                'User-Agent': '{0} / {1} {2} / {3}'.format(config['general']['name'],
                                                           config['general']['description'],
                                                           config['general']['version'],
                                                           config['general']['author'])
            }
            self.sdk = CBCloudAPI(
                url = self.url,
                token = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id),
                org_key = self.org_key
            )
        
        except Exception as err:
            self.log(exception(err))

    def get_feed(self, feed_id=None, feed_name=None):
        '''
            Retrieve a feed by ID or name.
        '''

        if feed_id is not None:
            return self.sdk.select(Feed, feed_id)

        elif feed_name is not None:
            feeds = [feed for feed in self.sdk.select(Feed) if feed.name == feed_name]

            if not feeds:
                self.log.warning("No feeds named '{}'".format(feed_name))
                return None
            elif len(feeds) > 1:
                self.log.warning("More than one feed named '{}'".format(feed_name))
                sys.exit(1)

            return feeds[0]

        else:
            raise ValueError("expected either feed_id or feed_name")

    def build_iocs(self, iocs, ioc_type):
        '''
        '''
        if ioc_type == 'domains':
            field_value = 'netconn_domain'
        elif ioc_type == 'ips':
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

    def build_reports(self, iocs):
        '''
        '''
        reports = []

        for ioc_type in iocs:
            for severity in iocs[ioc_type]:
                if len(iocs[ioc_type][severity]) > 0:
                    report = self.build_report(iocs[ioc_type][severity], ioc_type, severity, self.config['category'])
                    reports.append(report)
        
        return reports

    def build_report(self, iocs, ioc_type, severity, category):
        '''
        '''
        iocs = self.build_iocs(iocs, ioc_type)

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

    def import_feed(self, reports, category):
        '''
        '''
        feed = {
            'feedinfo': {
                'name': 'Proofpoint Emerging Threats {0}'.format(category),
                'summary': 'A list of IOCs from the Emerging Threats {0} feed'.format(category),
                'owner': self.org_key,
                'provider_url': 'https://emergingthreats.com',
                'category': 'Partner',
                'access': 'private'
            },
            'reports': reports
        }

        feed = self.sdk.create(Feed, feed)
        feed.save(public=False)

    def push_feed(self, feed_name, reports):
        '''
        '''
        feed = self.get_feed(feed_name=feed_name)
        if feed is None:
            self._create_feed(feed_name, reports)

        else:
            self._update_feed(feed, reports)

    def _create_feed(self, feed_name, reports):
        '''
        '''
        self.log.info('Feed {0} does not exist. Creating feed.'.format(feed_name))

        feed = {
            'feedinfo': {
                'name': 'Proofpoint Emerging Threats {0}'.format(self.config['category']),
                'summary': 'A list of IOCs from the Emerging Threats {0} feed'.format(self.config['category']),
                'owner': '{0}'.format(self.config['CarbonBlack']['org_key']),
                'provider_url': 'https://emergingthreats.com',
                'category': 'Partner',
                'access': 'private'
            },
            'reports': reports
        }

        feed = self.sdk.create(Feed, feed)
        feed.save(public=False)
        self.log.info('Feed {0} was created.'.format(feed_name))

    def _update_feed(self, feed, reports):
        '''
        '''
        self.log.info('Feed {0} exists ({1}), replacing reports'.format(feed.name, feed.id))
        reports_obj = [Report(self.sdk, initial_data=report, feed_id=feed.id) for report in reports]
        feed.replace_reports(reports_obj)
        self.log.info('Feed {0} ({1}) was updated.'.format(feed.name, feed.id))



class EmergingThreats:
    '''
    '''
    
    def __init__(self, config, log):
        '''
        '''

        try:
            self.class_name = 'EmergingThreats'
            self.log = log
            self.log.info('[%s] Initializing', self.class_name)

            self.config = config
            self.url = clean_url(config['EmergingThreats']['url'])
            self.api_key = config['EmergingThreats']['api_key']
            self.headers = {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache',
                'User-Agent': '{0} / {1} {2} / {3}'.format(config['general']['name'],
                                                            config['general']['description'],
                                                            config['general']['version'],
                                                            config['general']['author'])
            }
            self.categories = self._get_categories()
            self.feeds = self._list_feeds()

            # If no category was provided, output a list of options
            if config['category'] == 'list':
                print('\n\nThese are the Emerging Threats feeds available broken down by type:')
                print('\n | {0:20} | {1:20} |'.format('IP Feeds', 'Domain Feeds'))
                print(' | {0:20} | {1:20} |'.format('-'*20, '-'*20))
                domain_feeds = [feed for feed in self.feeds['domain_feeds']]
                ip_feeds = [feed for feed in self.feeds['ip_feeds']]
                feeds = ip_feeds + [feed for feed in ip_feeds if feed not in ip_feeds]

                for feed in feeds:
                    ip = ""
                    domain = ""
                    if feed in domain_feeds:
                        domain = feed
                    if feed in ip_feeds:
                        ip = feed
                    print(' | {0:20} | {1:20} |'.format(ip, domain))
                
                print('\nExample: python app.py --category CnC --severity 7 --ips --domains\n\n')
                sys.exit(0)

            # If the category doesn't match any of the feed names, raise an error
            if config['category'] not in self.feeds['ip_feeds'] and args.category not in self.feeds['domain_feeds']:
                raise('{0} is not a valid feed name. Use --category list for a full list of feeds available.')

        except Exception as err:
            self.log.error(err)

    def _get_severity(self, score):
        '''
        '''

        score = round(int(score) * 10 / 127)
        if score == 0:
            score = 1
        return score

    def _get_categories(self):
        '''
        '''

        categories = {}
        url = '{0}/{1}/reputation/categories.txt'.format(self.url, self.api_key)
        
        r = requests.get(url)

        if r.status_code == 200:
            for line in r.text.splitlines():
                items = line.split(',')
                categories[items[0]] = items[1:]
            return categories
        
        else:
            self.log.error('[%s] Error: {0}'.format(r.text), self.class_name)
            return None

    def _list_feeds(self):
        '''
        '''

        feeds = {
            'ip_feeds': {},
            'domain_feeds': {}
        }
        regex = r"\"\.\/(((domain\-)?(.*?))\.txt)?\""

        # Get IP feed file locations
        r = requests.get('{0}/{1}/reputation/detailed_ip_cat_per_file/'.format(self.url, self.api_key))

        matches = re.finditer(regex, r.text, re.MULTILINE)
        for matchNum, match in enumerate(matches, start=1):
            feed_name = match.group(4)
            feed_file = match.group(1)
            feeds['ip_feeds'][feed_name] = feed_file

        # Get domain feed file locations
        r = requests.get('{0}/{1}/reputation/detailed_domain_cat_per_file/'.format(self.url, self.api_key))

        matches = re.finditer(regex, r.text, re.MULTILINE)
        for matchNum, match in enumerate(matches, start=1):
            feed_name = match.group(4)
            feed_file = match.group(1)
            feeds['domain_feeds'][feed_name] = feed_file

        return feeds        

    def get_feed(self):
        '''
        '''

        iocs = {
            'domains': {
                1: [], 2: [], 3: [], 4: [], 5: [],
                6: [], 7: [], 8: [], 9: [], 10: []
            },
            'ips': {
                1: [], 2: [], 3: [], 4: [], 5: [],
                6: [], 7: [], 8: [], 9: [], 10: []
            }
        }

        if self.config['get_ips']:
            if self.config['category'] not in self.feeds['ip_feeds']:
                self.log.warning('{0} is not a valid Emerging Threats IP feed. Skipping this request.'.format(self.config['category']))

            else:
                feed_file = self.feeds['ip_feeds'][self.config['category']]
                url = '{0}/{1}/reputation/detailed_ip_cat_per_file/{2}'.format(self.url, self.api_key, feed_file)
                headers = self.headers
                r = requests.get(url, headers=headers)

                if r.status_code == 200:
                    data = r.text.splitlines()
                    for line in data:
                        line = line.split(',')
                        severity = self._get_severity(line[2])
                        if severity >= self.config['severity_limit']:
                            iocs['ips'][severity].append(line[0])
                else:
                    self.log.error('Error {0}: {1}'.format(r.status_code, r.text))

        if self.config['get_domains']:
            if self.config['category'] not in self.feeds['domain_feeds']:
                self.log.error('{0} is not a valid Emerging Threats domain feed. Skipping this request.'.format(self.config['category']))

            else:
                feed_file = self.feeds['domain_feeds'][self.config['category']]
                url = '{0}/{1}/reputation/detailed_domain_cat_per_file/{2}'.format(self.url, self.api_key, feed_file)
                headers = self.headers
                r = requests.get(url, headers=headers)

                if r.status_code == 200:
                    data = r.text.splitlines()
                    for line in data:
                        line = line.split(',')
                        severity = self._get_severity(line[2])
                        if severity >= self.config['severity_limit']:
                            iocs['domains'][severity].append(line[0])
                else:
                    self.log.error('Error {0}: {1}'.format(r.status_code, r.text))

        return iocs

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

def config2dict(config):
    '''
        This method converts a configparser variable to a dict to
            enable addition of new values.
        Source: https://stackoverflow.com/a/57024021/1339829
    '''
    
    return { i: { i[0]: i[1] for i in config.items(i) } for i in config.sections() }    

def clean_url(url):
    '''
    '''

    # if missing protocol, add https
    url = 'https://' + url if url[:8] != 'https://' else url
    # if it has a / at the end, remove it
    url = url[0:-1] if url[-1] == '/' else url
    return url
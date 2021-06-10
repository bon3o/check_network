#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import redis
import base64
import argparse
import requests
from bs4 import BeautifulSoup

REDIS_TTL = 14400 # 4 hours of ttl for dns keys
REDIS_KEY_PREFIX = 'TEMPLATE_APP_IP_CONFIG_MONITOR'

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--radd', help='Redis address', default='')
    parser.add_argument('--rport', help='Redis port', default=6379)
    parser.add_argument('--jurl', help='jira api link', default='')
    parser.add_argument('--jpid', help='jira page id', default='')
    parser.add_argument('--jlog', help='jira login', required=True)
    parser.add_argument('--jpwd', help='jira password', required=True)
    return parser.parse_args()
    
def parse_jira(args):
    error = ''
    fullJiraUrl = args.jurl.format(args.jpid)
    authString = '{0}:{1}'.format(args.jlog, args.jpwd)
    red = redis.StrictRedis(host=args.radd, port=args.rport, db=6)
    authStringEncoded = base64.b64encode(authString.encode()).decode()
    headers = {
        "Authorization" : "Basic {}".format(authStringEncoded),
        "Content-Type" : "application/json"
    }
    table = None
    facilityData = {}
    try:
        r = requests.get(fullJiraUrl, headers=headers)
    except Exception as e:
        error = 'Не удалось получить данные от Jira. Описание ошибки: \n{}'.format(e)
        return error
    try:
        soup = BeautifulSoup(json.loads(r.text)['body']['storage']['value'], features="lxml")
        table = soup.find("table")
    except Exception as e:
        error = 'Не удалось распарсить данные, полученные от Jira со страницы с ID={0}. Описание ошибки: {1}\nОтвет от сервера: \n{2}'.format(args.jpid, e, r.text)
        return error
    if table:
        for tableRow in (table.findAll('tr'))[1:]:
            facilityLoc = tableRow.find('th').text
            dns = [dns.text for dns in tableRow.findAll('td')[0:2]]
            facilityData[facilityLoc] = ','.join(dns)
        for facility, dns in facilityData.items():
            try:
                red.set('{0}_{1}'.format(REDIS_KEY_PREFIX, facility.upper()), dns, ex=REDIS_TTL)
            except Exception as e:
                error = 'Во время попытки записать данные о DNS серверах в Redis произошла ошибка. Описание ошибки: \n{}'.format(e)
    else:
        error = 'Во время получения данных о DNS серверах из Jira со страницы с ID={0} \
произошла ошибка. Ответ от сервера: \n{1}'.format(args.jpid, r.text)
    return error

def main():
    args = parse_args()
    result = parse_jira(args)
    print(result)

if __name__ == "__main__":
    main()

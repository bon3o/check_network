#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import configparser
import argparse
import requests
import socket
import struct
import json
import os
import re

REDIS_ADDRESS = ''
REDIS_PORT = 7379
REDIS_INSIGHT_DB = 3
REDIS_DNS_DB = 6
REDIS_KEY_PREFIX = 'TEMPLATE_APP_IP_CONFIG_MONITOR_'
CONFIG_FILE =  (os.path.abspath(__file__)[:-2] + 'conf')
ZABBIX_CONFIG_FILE = "/etc/zabbix/zabbix_agentd.conf"
DNS_WORDS = {0 :'первичного', 1 : 'вторичного'}
DEFAULT_ROUTES = [
    {
        'destination' : '10.0.0.0',
        'mask' : '255.0.0.0'
    },
    {
        'destination' : '192.168.0.0',
        'mask' : '255.255.0.0'
    }
]
#CIDR ARRAY
CIDR_ARRAY = [
    0, 2147483648, 3221225472, 3758096384, 4026531840, 4160749568, 4227858432,
    4261412864, 4278190080, 4286578688, 4290772992, 4292870144, 4293918720,
    4294443008, 4294705152, 4294836224, 4294901760, 4294934528, 4294950912,
    4294959104, 4294963200, 4294965248, 4294966272, 4294966784, 4294967040,
    4294967168, 4294967232, 4294967264, 4294967280, 4294967288, 4294967292,
    4294967294, 4294967295
    ]

def get_zabbix_addr():
    redisAddress = REDIS_ADDRESS
    try:
        with open(ZABBIX_CONFIG_FILE, 'r') as conf:
            confLines = conf.readlines()
            for line in confLines:
                if "ServerActive" in line:
                    r = re.match(r'^\s*ServerActive\s*=\s*([A-Za-z0-9.-]*):?(\d*)', line)
                    if r:
                        address = r.groups()
                        redisAddress = address[0].strip()
                        break
    except:
        pass
    return redisAddress

def get_default_gateway():
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            return socket.inet_ntoa(
                    struct.pack("<L", int(fields[2], 16))
                    ), fields[0]

def get_nameservers():
    nameservers = []
    content = ''
    with open('/etc/resolv.conf', 'r') as f:
        content = f.read()

    for line in content.split('\n'):
        if line.startswith('nameserver'):
            nameservers.append(line.split()[1])
    return nameservers

def hex2addr(hexVal):
    ipString = [
                str(int((hexVal[i:i+2]), 16)) for i in range(0, len(hexVal), 2)
               ]
    ipString.reverse()

    return '.'.join(ipString)

def ip2int(ipAddress):
    a, b, c, d = ipAddress.split('.')

    return ((int(a) << 24) + (int(b) << 16) + (int(c) << 8) + int(d))

def get_dns_config():
    redisAddress = get_zabbix_addr()
    insightData = ''
    exclusions = []
    configFailed = False
    errors = []
    DNS = []
    config = configparser.ConfigParser()
    try:
        c = config.read(CONFIG_FILE)
    except:
        configFailed = True
        errors.append(
                'REDIS: Не удалось прочитать файл '
                'конфигурации \'{}\'.'.format(CONFIG_FILE)
                )
    if configFailed:
        pass
    elif not c:
        errors.append(
                'REDIS: Не найден файл конфигурации {}.'.format(CONFIG_FILE)
                )
    else:
        try:
            exclusions = config['EXCLUSIONS']
        except:
            errors.append('REDIS: не найдена секция \'EXCLUSIONS\' '
                    'в файле конфигурации.')
    hostContours = []
    #hostName = os.uname().nodename.split('.')[0].upper()
    hostName = os.uname()[1].split('.')[0].upper()
    hostNamePrefix = hostName.split('-')[0]
    insightRedisUrl = "http://{0}:{1}/{2}/get/insight".format(redisAddress, REDIS_PORT, REDIS_INSIGHT_DB)
    try:
        insightJson = json.loads((json.loads(requests.get(insightRedisUrl).text))['get'])
        insightData = insightJson.get('hosts_sites').get(hostName)
    except:
        pass
    if insightData:
        hostContours = [
                contour.get('name') for contour in insightData.get('Env')
                ]

    for contour in hostContours:
        for key, value in exclusions.items():
            contours = [v.strip() for v in value.split(';')]
            if contour in contours:
                hostNamePrefix = '{0}{1}'.format(
                        key.upper(), hostNamePrefix
                        )
    redisDNSKey = '{0}{1}'.format(REDIS_KEY_PREFIX, hostNamePrefix)
    redisDNSUrl = "http://{0}:{1}/{2}/get/{3}".format(redisAddress, REDIS_PORT, REDIS_DNS_DB, redisDNSKey)
    try:
        DNS = json.loads(requests.get(redisDNSUrl).text).get('get').split(',')
    except Exception as e:
        errors.append('REDIS: Ошибка получения данных из Redis. '
                'Описание проблемы: {}.'.format(str(e)))
    return DNS, errors

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
            '--bypass', help='True if you need to bypass this check and '
            'return 0, otherwise - False',
            type=str, default=False
            )
    parser.add_argument(
            '--dnsoverride', help='Pass a list of DNS servers comma separated '
            'if you need custom values. Otherwise - None',
            type=str, default='None'
            )

    return parser.parse_args()

def check_configuration(correctDns, errors):
    currentDns = get_nameservers()

#Check if nameservers configuration is correct
    for index, address in enumerate(currentDns):
        try:
            if address != correctDns[index]:
                errors.append('IPError: Ошибка конфигурации {0} сервера DNS. '
                        'Должен быть \'{1}\', но указан \'{2}\''.format(
                            DNS_WORDS.get(index),
                            correctDns[index], address)
                            )
        except:
            errors.append('IPError: Ошибка конфигурации {0} сервера DNS. '
                        'Должен быть \'{1}\', но не указан вовсе.'.format(
                            DNS_WORDS.get(index),
                            correctDns[index])
                            )

#Check if we have correct nameservers count
    if correctDns and (len(correctDns) < len(currentDns)):
        setCurrent = set(currentDns)
        setCorrect = set(correctDns)
        errors.append('На сервере задано более двух адресов DNS. Следующие '
                    'записи лишние: {}'.format(setCurrent - setCorrect))

#Check if we have necessary routes
    defaultGateWay, defaultIf = get_default_gateway()
    defaultGateWayInt = ip2int(defaultGateWay)
    if defaultGateWay.split('.')[3] != '1':
        routesList = []
        with open('/proc/net/route') as f:
            routes = f.read().split('\n')[1:]
        for r in routes:
            if r:
                routeSplitted = r.split('\t')
                routesList.append(
                            {
                                'interface' : routeSplitted[0],
                                'destination' : hex2addr(routeSplitted[1]),
                                'gateway' : hex2addr(routeSplitted[2]),
                                'mask' : hex2addr(routeSplitted[7])
                            }
                            )
        for route in routesList:
            routeFormatted = {
                'destination' : route['destination'],
                'mask' : route['mask']
                }
            if routeFormatted in DEFAULT_ROUTES:
                DEFAULT_ROUTES.remove(routeFormatted)
        if DEFAULT_ROUTES:
            errors.append('IPError: У одного из сетевых адаптеров задан шлюз '
                        'по умолчанию, в адресе которого последний октет не '
                        'равен 1, но маршруты {} не были найдены в таблице '
                        'маршрутизации. \n'.format(json.dumps(DEFAULT_ROUTES)))

    addresses = os.popen(
            'ip addr show | grep {} | grep -o "inet '
            '[0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*/[0-9]*" |'
            ' cut -d\' \' -f2'.format(
                defaultIf)
                ).read().split('\n')

#Check if address of iface and gateway are in the same subnet
    for address in addresses:
        if address:
            addr, cidr = address.split('/')
            maskInt = CIDR_ARRAY[int(cidr)]
            addressInt = ip2int(addr)
            if (addressInt & maskInt) != (defaultGateWayInt & maskInt):
                errors.append('IPError: Адрес \'{0}\' интерфейса \'{1}\' и'
                    'его шлюз \'{2}\' не в пределах подсети префикса '
                    '{3}'.format(
                        addr, defaultIf, defaultGateWay, cidr))

    return errors

def main():
    errors = []
    correctDns = []
    result = 0
    args = parse_args()
    if args.bypass == 'True':
        result = 0
    else:
        if args.dnsoverride == 'None':
            correctDns, errors = get_dns_config()
        else:
            correctDns = [f.strip() for f in args.dnsoverride.split(',')]
    if correctDns:
        result = check_configuration(correctDns, errors)
    else:
        result = errors

    if len(result) > 0:
        print('\n'.join(result))
    else:
        print(0)

if __name__ == "__main__":
    main()

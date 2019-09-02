#!/usr/bin/env python3
import shodan
import argparse
from ipaddress import ip_network, ip_address

SHODAN_API_KEY = "***YOUR KEY HERE***"
api = shodan.Shodan(SHODAN_API_KEY)

parser = argparse.ArgumentParser(epilog="EXAMPLE: newHosts.py -s \"org:\\\"Test Company\\\"\" -l ranges.txt")
parser.add_argument("-s", "--search", action='store',
                    help="shodan search syntax. Escape quotes inside of search!")
parser.add_argument("-l", "--list", type=argparse.FileType('r'),
                    help="list of subnets to exclude from results")
args = parser.parse_args()

print("[*] Search: " + args.search)

subnet = []
ips = []

if args.list:
    ranges = args.list.readlines()
    subnet = [ip_network(i.strip()) for i in ranges]

pageNum = 1
morePages = True
while morePages:
    try:
        # search Shodan
        results = api.search(args.search, page=pageNum, limit=None)
        pageResults = len(results['matches'])
        # show the results
        # print('Results found: %s\n' % results['total'])
        # print('Results returned: %d' % pageResults)
        print('[+] getting page %d results' % pageNum)
        if pageResults is 0:
            morePages = False
            break
        for result in results['matches']:
            match = False
            for net in subnet:
                if ip_address(result['ip_str']) in net:
                    match = True
                    break
            if match is False:
                    ips.append(result['ip_str'])
        # continue to next page of results
        pageNum += 1
    except shodan.APIError as e:
        print('Error: %s' % e)

# prints ips sorted by subnets
for ip in sorted(ips, key = lambda ip: [int(ip) for ip in ip.split(".")]):
    print(ip)

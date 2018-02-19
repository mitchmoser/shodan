#!/usr/bin/env python3
import shodan
import sys
from retry import retry

SHODAN_API_KEY = ""
api = shodan.Shodan(SHODAN_API_KEY)

# retry decorator to handle timeouts searching vulns
@retry()
def exploit(query):
    return api.exploits.search(query)

query = sys.argv[1]
try:
    # search Shodan
    results = api.host(query)

    # print host details
    for k in results:
        if str(k) != 'data': # data is verbose
            print(str(k).rjust(15) + ' - ' + str(results[k]))

    # get site titles from 'data' dictionary
    for k in results['data']:
        if 'title' in k:
            print('\nPort %-5s Title: %s' % (k['port'], k['title']))
    # vulnerabilities
    if 'vulns' in results:
        for i in results['vulns']:
            # some return !CVE-* for explicilty not vulnerable
            if not i.startswith('!'):
                vulns = exploit(i)
                print('\033[1m' # bold
                      + '\n**********\tVULNERABILE to '
                      + i
                      + '\t**********\n'
                      + '\033[0m'# end bold
                     )
                # return Descriptions & Related CVE's
                for v in reversed(vulns['matches']):
                    if v['cve'][0] == i:
                        print('\033[1m%s\033[0m' % v['cve'][0])
                    else:
                        print('\033[1mRelated\033[0m - %s' % v['cve'][0])
                    print(str(v['description']).replace('. ', '.\n'))
                    print()
except shodan.APIError as e:
    print('Error: %s' % e)

#!/usr/bin/env python3
import shodan
import sys
from retry import retry

SHODAN_API_KEY = "***YOUR KEY HERE***"

api = shodan.Shodan(SHODAN_API_KEY)

# retry decorator to handle timeouts line 56
@retry()
def search(query):
    return api.search(query)

# List of properties in summary
# default limit of top 5
# ('property', 3) would return top 3
FACETS = [
    'org',
    'domain',
    'port',
    'asn',
    ('country', 3) #top 3 countries
    ]
FACET_TITLES = {
    'org':'Top 5 Organizations',
    'domain':'Top 5 Domains',
    'port':'Top 5 Ports',
    'asn':'Top 5 Autonomous Systems',
    'country':'Top 3 Countries'
    }

# input validation
if len(sys.argv) ==1:
    print('Usage: %s "<search query>"' % sys.argv[0])
    sys.exit(1)

try:
    query = sys.argv[1]
    #search Shodan
    #count() doesn't return results and runs faster than search()
    summary = api.count(query, facets=FACETS)
    #print summary info from the facets
    print('\nShodan Summary Information')
    print('Query: %s' % query)
    print('Total Results: %s\n' % summary['total'])
    for facet in summary['facets']:
        print('\n\t'+FACET_TITLES[facet])
        print('Count |')
        for term in summary['facets'][facet]:
            print('%-5s | %s' % (term['count'], term['value']))

    # return top 5 hosts for each company
    for company in summary['facets']['org']:
        subQuery = query + ' org:' + str(company['value']).replace(' ', '\ ')
        # sanity check
        # print('\nSearch: '+subQuery)
        results = search(subQuery)
        print('\n5 freshest results from %s:' % company['value'])
        print('Date\tTime\tHost:Port')
        for result in results['matches'][0:5]:
            dateTime = result['timestamp'][5:10] + '\t' + result['timestamp'][11:16]
            if result['hostnames']:
                print('%s\t%s:%s' % (dateTime,
                                     result['hostnames'][0],
                                     result['port']))
            else:
                print('%s\t%s:%s' % (dateTime,
                                     result['ip_str'],
                                     result['port']))

except shodan.APIError as e:
    print('Error: %s' % e)
    sys.exit(1)

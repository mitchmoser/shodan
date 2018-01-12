import shodan
import sys

SHODAN_API_KEY = "***ADD YOUR KEY HERE***"
api = shodan.Shodan(SHODAN_API_KEY)

# use ' '.join(sys.argv[1:]) to avoid using quotes
query = sys.argv[1]
try:
    #search Shodan
    results = api.search(query)
    #show the results
    print('Results found: %s\n' % results['total'])
    for result in results['matches']:
        if result['hostnames']:
            print('%s:%s' % (result['hostnames'][0], result['port']))
        else:
            print('%s:%s' % (result['ip_str'], result['port']))
except shodan.APIError as e:
    print('Error: %s' % e)

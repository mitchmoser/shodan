# Shodan
These are scripts I've created that interact with the Shodan API

Script | Function
-----: | :-------
`newHosts.py` | Takes a search and a list of IPs and/or CIDR ranges as a filter. Only returns search results that are not in the provided list.
`host.py` | Takes an ip address as an argument and returns Shodan information including relevant CVE details
`newTrojans.py` | Returns a summary of the latest Trojan/Malware results from Shodan
`searchShodan.py` |	Takes a search as an argument and returns the results from Shodan
`top5.py` | Takes a search as an argument and returns Top 5 Domains, Countries, Products, Ports, Organizations, and Autonomous Systems as well as the newest 5 hosts from each Organization

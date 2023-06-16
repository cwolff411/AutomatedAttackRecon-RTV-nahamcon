import shodan
import os
import yaml
import requests


# Open config file
with open('config.yml', 'r') as config_file:
    config = yaml.safe_load(config_file)

# Shodan API Setup
shodan_api_key = os.environ.get("SHODAN_API")
api = shodan.Shodan(shodan_api_key)

# Fancy functions for core functionality
def shodan_fingerprint_search(fingerprint):
    results = api.search("ssl.cert.fingerprint:{}".format(fingerprint))

    if results['total'] > 0:
        return results['matches']
    # TO DO: Someone setup try/catch for error handling and become a real developer


def shodan_common_name_search(common_name):
    results = api.search("ssl.cert.subject.cn:{}".format(common_name))

    if results['total'] > 0:
        return results['matches']
    # TO DO: Someone setup try/catch for error handling

def chaos_search(domain):

    url = "https://dns.projectdiscovery.io/dns/{}/subdomains".format(domain)
    chaos_key = os.environ.get("CHAOS_API_KEY")

    headers = {
        "Content-Type": "application/json",
        "Authorization": chaos_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()

# MAIN
ip_list = []
found_subdomains = []

for hash in config['cert_hashes']:
    print("Searching for hash {}".format(hash))

    fingerprint_results = shodan_fingerprint_search(hash)
    if fingerprint_results is not None:
        [ ip_list.append(i['ip_str']) for i in fingerprint_results if i['ip_str'] not in ip_list ]

for name in config['common_names']:
    print ("Searching for common name: {}".format(name))

    common_name_results = shodan_common_name_search(name)
    if common_name_results is not None:
        [ ip_list.append(i['ip_str']) for i in common_name_results if i['ip_str'] not in ip_list ]

for domain in config['domain_names']:
    print("Asking Chaos for subdomains for domain: {}".format(domain))

    chaos_results = chaos_search(domain)

    if chaos_results is not None:
        [ found_subdomains.append(d) for d in chaos_results['subdomains'] if d not in found_subdomains ]

print(found_subdomains)

for domain in found_subdomains:
    results_again = shodan_common_name_search(domain)

ip_file = open('ip_list.txt', 'w')
ip_file.writelines(ip + '\n' for ip in ip_list)
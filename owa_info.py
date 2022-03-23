#! /usr/bin/env python

from email import header
import socket
from time import time
import requests
import re
import ssl
import ipaddress
import json
import idna
import argparse
from OpenSSL import SSL
from cryptography import x509
from urllib.parse import urlparse
from cryptography.x509.oid import NameOID
from collections import namedtuple
from base64 import b64decode
from struct import unpack

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')

class owa_info():
    def __init__(self, target, debug=False, timeout=5):
        self.target   = target
        self.debug    = debug
        self.ssl      = False
        self.timeout  = timeout
        self.url      = ""
        self.host     = None
        self.port     = None
        self.paths    = ["Autodiscover/", "Autodiscover/Autodiscover.xml",
                         "Microsoft-Server-ActiveSync", "Microsoft-Server-ActriveSync/default.eas",
                         "ECP", "EWS", "EWS/Exchange.asmx","Exchange", "OWA"]
        self.versions = self.get_versions_map()

    
    def get_versions_map(self):
        # get versions dict
        with open("./ms-exchange-unique-versions-dict.json", "r") as file:
            raw_versions = file.read()
        versions = json.loads(raw_versions)

        return versions

    def req(self, url, data=None, headers=None):
        if not headers:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36',
            }
        if data:
            resp = requests.post(url, data=data,timeout=self.timeout, verify=False, headers=headers)
        else:
            resp = requests.get(url, timeout=self.timeout, verify=False, headers=headers)
        return resp

    def buildnumber_to_version(self, BuildNumber):
        #Reference:https://docs.microsoft.com/en-us/Exchange/new-features/build-numbers-and-release-dates?redirectedfrom=MSDN&view=exchserver-2019
        strlist = BuildNumber.split('.')
        if int(strlist[0]) == 4:
            return 'Exchange Server 4.0'

        elif int(strlist[0]) == 5:
            if int(strlist[1]) == 0:
                return 'Exchange Server 5.0'
            elif int(strlist[1]) == 5:
                return 'Exchange Server 5.5'

        elif int(strlist[0]) == 6:
            if int(strlist[1]) == 5:
                if int(strlist[2]) == 6944:
                    return 'Exchange Server 2003'
                elif int(strlist[2]) == 7226:
                    return 'Exchange Server 2003 SP1'
                elif int(strlist[2]) == 7683:
                    return 'Exchange Server 2003 SP2'
                elif int(strlist[2]) == 7653:
                    return 'Exchange Server 2003 post-SP2'
                elif int(strlist[2]) == 7654:
                    return 'Exchange Server 2003 post-SP2'
            elif int(strlist[1]) == 0:
                return 'Exchange 2000 Server'

        elif int(strlist[0]) == 8:
            if int(strlist[1]) == 0:
                return 'Exchange Server 2007'
            elif int(strlist[1]) == 1:
                return 'Exchange Server 2007 SP1'
            elif int(strlist[1]) == 2:
                return 'Exchange Server 2007 SP2'
            elif int(strlist[1]) == 3:
                return 'Exchange Server 2007 SP3'

        elif int(strlist[0]) == 14:
            if int(strlist[1]) == 0:
                return 'Exchange Server 2010'
            elif int(strlist[1]) == 1:
                return 'Exchange Server 2010 SP1'
            elif int(strlist[1]) == 2:
                return 'Exchange Server 2010 SP2'
            elif int(strlist[1]) == 3:
                return 'Exchange Server 2010 SP3'

        elif int(strlist[0]) == 15:        
            if int(strlist[1]) == 0:
                return 'Exchange Server 2013'
            elif int(strlist[1]) == 1:
                return 'Exchange Server 2016'
            elif int(strlist[1]) == 2:
                return 'Exchange Server 2019'
        else:
            return None


    def get_build_via_exporttool(self, url, build):
        r = self.req(
            f'{url}/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application')
        if r.status_code == 200:
            result = re.search(
                "<assemblyIdentity.*version=\"(\d+.\d+.\d+.\d+)\"", r.text)
            if(result):
                return result.group(1)

        # get build via exporttool
        if r.status_code == 200:
            #for version in self.versions:
            r2 = self.req(
                f'{url}/ecp/{build}/exporttool/microsoft.exchange.ediscovery.exporttool.application')
            result = re.search(
                "<assemblyIdentity.*version=\"(\d+.\d+.\d+.\d+)\"", r2.text)
            if(result):
                return result.group(1)

        return None

    def get_owa_build(self, url):
        r = self.req(f'{url}/owa/')

        # x-owa-version header method
        if r.headers.get("x-owa-version"):
            return self.versions[r.headers["x-owa-version"]]

        # get partial build from urls
        build = None
        result = re.search("/owa/auth/(\d+.\d+.\d+)", r.text)
        if(result):
            build = result.group(1)
        else:
            result = re.search("/owa/auth/(\d+.\d+.\d+)", r.text)
            if(result):
                build = result.group(1)
        if build is not None:
            ecp_build = self.get_build_via_exporttool(url, build)
            if ecp_build is not None:
                try:
                    return self.versions[ecp_build]
                except:
                    return {'build': build, 'name': self.buildnumber_to_version(build)} 
            else:
                return {'build': build, 'name': self.buildnumber_to_version(build)} 
        return None

    def testUrl(self):
        """
        Let's make sure the supplied host is reachable and looks like an OWA page
        """
        if self.target.startswith("http"):
            o = urlparse(self.target)
            if o.scheme == "https":
                self.ssl = True
            self.hostname = o.netloc
            self.url = f'{o.scheme}://{o.netloc}/'
            return True
        else:
            print("[-] Target must be an HTTP(S) URL")
            return False

    def sslHost(self):
        """
        OWA will almost always be via SSL so this should be the most common function
        """
        data = None
        results = [] # We may encounter a situation where we get IPs and hostnames
        for path in self.paths:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssl_sock = ssl.wrap_socket(s, ca_certs=None)
                if ":" in self.hostname:
                    host, port = self.hostname.split(":")
                    self.host = host
                    self.port = port
                    ssl_sock.connect((host, int(port)))
                else:
                    self.host = self.hostname
                    self.port = 443
                    ssl_sock.connect((self.hostname, 443))
                fetch = f"GET /{path} HTTP/1.0\r\n\r\n"
                if self.debug:
                    print(f"[*] Fetching: {self.url}{path}")
                ssl_sock.write(fetch.encode())
                data = ssl_sock.read()
                ssl_sock.close()
                if data:
                    ret = re.search(r"realm=\"(.*)\"", data.decode())
                    if ret and ret.groups()[0] not in results:
                        results.append(ret.groups()[0])
            except Exception as e:
                continue
        return results

    def plainHost(self):
        """
        Hopefully there's no OWA running without SSL exposed to the internet, but you never know
        """
        data = None
        results = []
        for path in self.paths:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if ":" in self.hostname:
                    host, port = self.hostname.split(":")
                    self.host = host
                    self.port = port
                    s.connect((host, int(port)))
                else:
                    self.host = self.hostname
                    self.port = 80
                    s.connect((self.hostname, 80))
                fetch = f"GET /{path} HTTP/1.0\r\n\r\n"
                if self.debug:
                    print(f"[*] Fetching: {self.url}{path}")
                s.write(fetch.encode())
                data = s.read()
                s.close()
                if data:
                    ret = re.search(r"realm=\"(.*)\"", data.decode())
                    if ret and ret.groups()[0] not in results:
                        results.append(ret.groups()[0])
            except Exception as e:
                continue
        return results


    def get_common_name(self, cert):
        try:
            names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if len(names) == 0:
                return None
            return names[0].value
        except x509.ExtensionNotFound:
            return None


    def get_alt_names(self, cert):
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return None

    def get_issuer(self, cert):
        try:
            names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            if len(names) == 0:
                return None
            return names[0].value
        except x509.ExtensionNotFound:
            return None


    def get_certificate(self, hostname, port):
        hostname_idna = idna.encode(hostname)
        sock = socket.socket()

        sock.connect((hostname, port))
        peername = sock.getpeername()
        ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE

        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()

        return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

    def print_basic_info(self, hostinfo):
        common_name = self.get_common_name(hostinfo.cert)
        issuer = self.get_issuer(hostinfo.cert)
        s = '''\n[*] Certinfo:
\tcommonName: {commonname}
\tSAN: {SAN}
\tissuer: {issuer}
\tnotBefore: {notbefore}
\tnotAfter:  {notafter}      
'''.format(
                hostname=hostinfo.hostname,
                peername=hostinfo.peername,
                commonname=common_name if common_name else "None",
                SAN=self.get_alt_names(hostinfo.cert),
                issuer=issuer if issuer else "None",
                notbefore=hostinfo.cert.not_valid_before,
                notafter=hostinfo.cert.not_valid_after
        )
        print(s)


    def _unpack_str(self, byte_string):
        return byte_string.decode('UTF-8').replace('\x00', '')

    def _unpack_int(self, format, data):
        return unpack(format, data)[0]

    def parse_challenge(self, auth):
        target_info_fields  = auth[40:48]
        target_info_len     = self._unpack_int('H', target_info_fields[0:2])
        target_info_offset  = self._unpack_int('I', target_info_fields[4:8])
        target_info_bytes = auth[target_info_offset:target_info_offset+target_info_len]

        domain_name   = ''
        computer_name = ''
        info_offset   = 0
        while info_offset < len(target_info_bytes):
            av_id = self._unpack_int('H', target_info_bytes[info_offset:info_offset+2])
            av_len = self._unpack_int('H', target_info_bytes[info_offset+2:info_offset+4])
            av_value = target_info_bytes[info_offset+4:info_offset+4+av_len]
            
            info_offset = info_offset + 4 + av_len
            if av_id == 2:   # MsvAvDnsDomainName
                domain_name = self._unpack_str(av_value)
            elif av_id == 3: # MsvAvDnsComputerName
                computer_name = self._unpack_str(av_value)

        assert domain_name, 'DomainName not found'
        assert computer_name, 'ComputerName not found'

        return domain_name, computer_name

    def get_domain_info(self):
        headers = {
            'Authorization': 'Negotiate TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKALpHAAAADw==',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.517 Safari/537.36'
        }
        r = self.req(f'{self.url}/rpc/', headers=headers)
        assert r.status_code == 401, "Error while getting ComputerName"
        auth_header = r.headers['WWW-Authenticate']
        auth = re.search('Negotiate ([A-Za-z0-9/+=]+)', auth_header).group(1)
        domain_name, computer_name = self.parse_challenge(b64decode(auth))
        LOCAL_NAME = computer_name
        FQDN = ".".join(LOCAL_NAME.split(".")[1:])
        if self.debug:
            print("[*] DomainName: {}".format(domain_name))
        print(f'''[*] Domain info:
\tDomain FQDN   = {FQDN}
\tExchagne Computer Name = {computer_name}
''')

    def run(self):
        if self.testUrl():
            print(f"[*] Checking {self.target}")
            ex_version = self.get_owa_build(self.url)
            if not ex_version:
                print("[-] Could not determine OWA version")
                return
            build_number = ex_version['build']
            print(f'''[*] Version info:
\tBuild Number: {build_number}
\tOWA Version:  👉   {ex_version['name']}''')
            if ex_version.get('build_long'):
                print(f"\tBuild Number long: {ex_version['build_long']}")
            if ex_version.get("release_date"):
                print(f"\tRelease Date: {ex_version['release_date']}")
            if ex_version.get("url"):
                print(f"\tDownload URL: {ex_version['url']}")
            self.get_domain_info()
            
            if self.ssl:
                results = self.sslHost()        
            else:
                results = self.plainHost()
            if len(results) > 0:
                for ip in results:
                    try:
                        if ipaddress.ip_address(ip).is_private:
                            print(f"[+] Internal ip:\n\t👉  {ip}")
                    except:
                        continue
            if self.ssl and self.host:
                hostinfo = self.get_certificate(self.host, self.port)
                self.print_basic_info(hostinfo)  
            
            
        else:
            return

def main():
    parser = argparse.ArgumentParser(description="OWA Info Scanner")
    parser.add_argument('-u','--url', help='Exchange OWA URL', required=True)
    parser.add_argument('-t','--timeout', help='Timeout', default=10, required=False)
    parser.add_argument('-d','--debug', action='store_true',help='Print Debug info', default=False, required=False)
    args = parser.parse_args()
    ex = owa_info(args.url, args.debug, args.timeout)
    ex.run()
    
if __name__ == "__main__":
    main()

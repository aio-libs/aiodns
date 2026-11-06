import json
import aiodns
import asyncio


# import wizard_whois
# from datetime import date, datetime
# import requests
# from requests.exceptions import Timeout, ConnectionError
# from requests.packages.urllib3.util.retry import Retry
# from requests.adapters import HTTPAdapter
#
#
# # https://findwork.dev/blog/advanced-usage-python-requests-timeouts-retries-hooks/
# class TimeoutHTTPAdapter(HTTPAdapter):
#     def __init__(self, *args, **kwargs):
#         DEFAULT_TIMEOUT = 1
#         self.timeout = DEFAULT_TIMEOUT
#         if "timeout" in kwargs:
#             self.timeout = kwargs["timeout"]
#             del kwargs["timeout"]
#         super().__init__(*args, **kwargs)
#
#     def send(self, request, **kwargs):
#         timeout = kwargs.get("timeout")
#         if timeout is None:
#             kwargs["timeout"] = self.timeout
#         return super().send(request, **kwargs)
#
#
# http = requests.Session()
# # Mount  TimeoutHTTP adapter with retries it for both http and https usage
# adapter = TimeoutHTTPAdapter(timeout=2.5)
# retries = Retry(total=1, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
# http.mount("https://", TimeoutHTTPAdapter(max_retries=retries))
# http.mount("http://", TimeoutHTTPAdapter(max_retries=retries))
#
# TIMEOUT = 1.0  # timeout in seconds
# wizard_whois.net.socket.setdefaulttimeout(TIMEOUT)


# def check_http(name):
#     """Is the domain reachable via http?"""
#     try:
#         url = 'http://' + name
#         http.get(url)
#         return True
#     except requests.exceptions.ConnectionError:
#         print(f"URL {url} not reachable")
#         return False


class DomainInfo:
    # http = requests.Session()
    # # Mount  TimeoutHTTP adapter with retries it for both http and https usage
    # adapter = TimeoutHTTPAdapter(timeout=2.5)
    # retries = Retry(total=1, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    # http.mount("https://", TimeoutHTTPAdapter(max_retries=retries))
    # http.mount("http://", TimeoutHTTPAdapter(max_retries=retries))
    #
    # DEFAULT_TIMEOUT = 1  # seconds
    # rdapbootstrapurl = 'https://www.rdap.net/'
    # wizard_whois.net.socket.setdefaulttimeout(DEFAULT_TIMEOUT)

    def __init__(self, domain):
        self.name = domain
        self.domain = domain
        # Setup dictionary and defaults
        self.domain = domain.lower()
        self.url = 'http://' + self.domain
        self.domain_dict = {}
        self.domain_whois = {}
        self.registrar = ''
        self.registration = ''
        self.expiration = ''
        self.status = []
        self.soa = {}
        # Setup lists variables
        # Namservers with A record lookups
        self.whois_nameservers = []
        self.domain_nameservers = []
        # Domain WWW: A, AAA, CNAME values
        self.domain_www = []
        # Domain MX Records list
        self.domain_mx = []
        # Domain TXT type records
        self.domain_txt = []
        # Nameserver lists without IP's
        self.whois_ns = []
        self.ns = []
        # Abort DNS lookups when no valid DNS NS found to prevent lockups
        self.dns_lookup_continue = ''
        # Domain Expired
        self.expired = ''
        # Domain DNS Dictionary
        self.dns = {}
        # Whois and DNS NS agree on Nameserver names
        self.auth_ns_match = ''
        # Sender Policy Framework
        self.spf = ''
        # DomainKeys Identified Mail (DKIM)
        self.dkim = []
        # Domain-based Message Authentication, Reporting & Conformance (DMARC)
        self.dmarc = ''
        # Holds values for detected WAF's/CDN/Proxy like Sucuri/Cloudflare/Quic.cloud
        self.waf = ''
        # DNSSEC aka SecureDNS status of domain
        self.dnssec = {}
        # Setup asyncio
        self.loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=self.loop)

        # Initialize Whois and DNS
        self.domain_dict['domain'] = self.domain
        # self.get_whois_domain()
        # self.check_expiration()
        self.get_domain_dns()
        # self.check_auth_nameservers_match()

    async def query(self, name, query_type):
        return await self.resolver.query(name, query_type)

    def get_hostname_from_ip(self, ip):
        try:
            reverse_name = '.'.join(reversed(ip.split("."))) + ".in-addr.arpa"
            coro = self.query(reverse_name, 'PTR')
            result = self.loop.run_until_complete(coro)
            return result.name
        except:
            return ""

    def get_rdns_from_ip(self, ip):
        try:
            coro = self.resolver.gethostbyaddr(ip)
            result = self.loop.run_until_complete(coro)
            return result.name
        except:
            return ""

    # def get_domain_whois_info(self):
    #     # "domain": "google.com"
    #     # self.domain_dict['domain'] = self.domain
    #     # domain_dict['WHOIS'] = {'nameservers': None}
    #
    #     try:
    #         self.domain_whois = wizard_whois.get_whois(self.domain)
    #         # print(self.domain_whois)
    #     except:
    #         return False
    #         # pass
    #
    #     # "WHOIS": {"registrar": "MarkMonitor Inc."}
    #     try:
    #         # domain_dict['WHOIS']['registrar'] = str(self.domain_whois['registrar'][0])
    #         # print('Registrar is :' + str(self.domain_whois['registrar'][0]))
    #         update_dict = {"WHOIS": {'registrar': str(self.domain_whois['registrar'][0])}}
    #         self.domain_dict.update(update_dict)
    #         self.registrar = str(self.domain_whois['registrar'][0])
    #     except:
    #         pass
    #
    #     # "WHOIS": {"status": "['client delete prohibited', 'server transfer prohibited', 'server update prohibited']"
    #     try:
    #         # print(str(self.domain_whois['status'][0]).rsplit())
    #         whois_statuses = []
    #         whois_status = self.domain_whois['status']
    #         for status in whois_status:
    #             status = status.rsplit()
    #             # print(status[0])
    #             whois_statuses.append(status[0])
    #         # print(str(whois_statuses))
    #         self.domain_dict['WHOIS']['status'] = whois_statuses
    #
    #     except:
    #         pass
    #
    #     # Source "WHOIS": {"registration": "1997-09-15T04:00:00Z", "expiration": "2028-09-14T04:00:00Z"}
    #     try:
    #         self.domain_dict['WHOIS']['registration'] = str(self.domain_whois['creation_date'][0])
    #         self.registration = str(self.domain_whois['creation_date'][0])
    #     except:
    #         pass
    #
    #     try:
    #         self.domain_dict['WHOIS']['expiration'] = str(self.domain_whois['expiration_date'][0])
    #         self.expiration = str(self.domain_whois['expiration_date'][0])
    #     except:
    #         update_dict = {"WHOIS": {'expiration': 'No Expiration Found'}}
    #         self.domain_dict.update(update_dict)
    #         self.expiration = 'No Expiration Found'
    #         pass
    #
    #     # "WHOIS": {"secureDNS": {"delegationSigned": false}}
    #     try:
    #         domainwhois_dnssec_raw = str(self.domain_whois['raw']).split('DNSSEC: ', 1)[1]
    #         # print(domainwhois_dnssec_raw)
    #         if "signedDelegation" in domainwhois_dnssec_raw:
    #             # print('signedDelegation')
    #             # domain_dict['WHOIS']['secureDNS'] = 'signedDelegation'
    #             self.domain_dict['WHOIS']['secureDNS'] = {"delegationSigned": 'true'}
    #             self.dnssec = {"secureDNS": {"delegationSigned": 'true'}}
    #         elif "unsigned" in domainwhois_dnssec_raw:
    #             # print('unsigned')
    #             # domain_dict['WHOIS']['secureDNS'] = 'unsigned'
    #             self.domain_dict['WHOIS']['secureDNS'] = {"delegationSigned": 'false'}
    #             self.dnssec = {"secureDNS": {"delegationSigned": 'false'}}
    #     except:
    #         pass
    #
    #     #  "WHOIS": {"nameservers": [["NS1.GOOGLE.COM", "216.239.32.10"], ["NS2.GOOGLE.COM", "216.239.34.10"]]}
    #     try:
    #
    #         for nameserver in self.domain_whois['nameservers']:
    #             # print(ns)
    #             ns = nameserver.lower()
    #             coro = self.query(ns, 'A')
    #             result = self.loop.run_until_complete(coro)
    #             # print(result)
    #             ip = str(result[0].host)
    #             # print(ns, ip)
    #             self.whois_nameservers.append([str(ns), str(ip)])
    #             self.whois_ns.append(ns)
    #         self.domain_dict['WHOIS']['nameservers'] = self.whois_nameservers
    #     except:
    #         pass
    #
    # def check_expiration(self):
    #     """Is the domain active?. Also catches when tld does not have an expiration. Returns True if not expired or has
    #     no expiration date """
    #     try:
    #         past = datetime.strptime(str(self.domain_dict['WHOIS']['expiration']), "%Y-%m-%d %H:%M:%S")
    #         present = datetime.now()
    #         if past.date() < present.date():
    #             # self.DomainExpiresLabel.setText("Expired:")
    #             # self.DomainExpiresValue.setText('')
    #             # self.DomainExpiresValue.setStyleSheet("QLabel { background-color : red}")
    #             print('Domain is expired or unregistered')
    #             return False
    #         else:
    #             print('Domain is not expired')
    #             return True
    #     except:
    #         var = KeyError == 'WHOIS'
    #         print('No Expiration Found')
    #         # domain_dict['WHOIS']['expiration'] = 'No Expiration Found'
    #         return True
    #         pass
    #
    # def get_domain_rdap_info(self):
    #     request = self.rdapbootstrapurl + 'domain/' + self.domain
    #     try:
    #         domain_response = http.get(request).text
    #         # print(request)
    #         # print(domain_response)
    #         self.domain_whois = json.loads(str(domain_response))
    #         # print(json.dumps(self.domain_whois, indent=4))
    #         return self.domain_whois
    #     except:
    #         print('RDAP Lookup Failed')
    #         return False
    #
    # def create_domain_dict_rdap(self):
    #     # "domain": "google.com"
    #     # self.domain_dict['domain'] = self.domain
    #
    #     # rdapsource
    #     self.domain_dict['rdapurl'] = self.rdapbootstrapurl + 'domain/' + self.domain
    #
    #     # "WHOIS": {"status": "['client delete prohibited', 'server transfer prohibited', 'server update prohibited']"
    #     try:
    #         self.domain_dict['WHOIS'] = {'status': str(self.domain_whois['status'])}
    #     except:
    #         pass
    #
    #     # "WHOIS": {"registrar": "MarkMonitor Inc."}
    #     try:
    #         self.domain_dict['WHOIS']['registrar'] = str(self.domain_whois["entities"][0]['vcardArray'][1][1][3])
    #         self.registrar = str(self.domain_whois["entities"][0]['vcardArray'][1][1][3])
    #     except:
    #         pass
    #
    #     # "WHOIS": {"registration": "1997-09-15T04:00:00Z", "expiration": "2028-09-14T04:00:00Z"}
    #     try:
    #         for event in self.domain_whois['events']:
    #             # print(event)
    #             event_action = event['eventAction']
    #             event_date = event['eventDate']
    #             if event_action == 'registration':
    #                 self.domain_dict['WHOIS']['registration'] = event_date.replace("T", " ").replace("Z", "")
    #                 self.registration = self.domain_dict['WHOIS']['registration']
    #             elif event_action == 'expiration':
    #                 self.domain_dict['WHOIS']['expiration'] = event_date.replace("T", " ").replace("Z", "")
    #                 self.expiration = self.domain_dict['WHOIS']['expiration']
    #                 # print(event_action, event_date)
    #             # print(event.eventAction, event.eventDate)
    #     except:
    #         pass
    #
    #     # "WHOIS": {"secureDNS": {"delegationSigned": false}}
    #     try:
    #         self.domain_dict['WHOIS']['secureDNS'] = str(self.domain_whois['secureDNS'])
    #         self.dnssec = self.domain_dict['WHOIS']['secureDNS']
    #     except:
    #         pass
    #
    #     #  "WHOIS": {"nameservers": [["NS1.GOOGLE.COM", "216.239.32.10"], ["NS2.GOOGLE.COM", "216.239.34.10"]]}
    #     try:
    #         for nameserver in self.domain_whois['nameservers']:
    #             # print(nameserver['ldhName'])
    #             ns = nameserver['ldhName'].lower()
    #             coro = self.query(ns, 'A')
    #             result = self.loop.run_until_complete(coro)
    #             # print(result)
    #             ip = str(result[0].host)
    #             # print(ns, ip)
    #             self.whois_nameservers.append([ns, ip])
    #             self.whois_ns.append(ns)
    #
    #         self.domain_dict['WHOIS']['nameservers'] = self.whois_nameservers
    #     except:
    #         pass

    def get_domain_dns(self):
        site = self.domain
        try:
            res_ns = self.loop.run_until_complete(self.resolver.query(site, 'NS'))
            for elem in res_ns:
                # print(elem.host)
                ns = str(elem.host)
                coro = self.query(ns, 'A')
                result = self.loop.run_until_complete(coro)
                # print(result)
                ip = str(result[0].host)
                self.ns.append(ns)
                self.domain_nameservers.append([ns, ip])
                if "cloudflare" in elem.host:
                    print("Cloudflare: FullZone detected")
                    self.waf = 'Cloudflare: FullZone detected'
            self.dns_lookup_continue = True
        except:
            self.dns_lookup_continue = False
            pass

        if self.dns_lookup_continue:
            try:
                # SOA query the host's DNS
                res_soa = self.loop.run_until_complete(self.resolver.query(site, 'SOA'))
                # print(res_soa)
                # for elem in res_soa:
                # print(str(res_soa.nsname) + " " + str(res_soa.hostmaster) + " " + str(res_soa.serial))
                domain_soa_dict = {"DNS": {
                    "SOA": {"nsname": str(res_soa.nsname), "hostmaster": str(res_soa.hostmaster),
                            "serial": str(res_soa.serial),
                            "refresh": str(res_soa.refresh), "retry": str(res_soa.retry),
                            "expires": str(res_soa.expires),
                            "minttl": str(res_soa.minttl), "ttl": str(res_soa.ttl)}}}
                self.domain_dict.update(domain_soa_dict)
                # print(domain_dict)
                self.soa = self.domain_dict['DNS']['SOA']
                if "cloudflare" in res_soa.nsname:
                    self.waf = 'Cloudflare: FullZone detected'
            except:
                pass

            try:
                # Here we are checking all the popular and common DKIM selector names in a loop
                dkim_selectors = ['default', 'dkim', 'dkim1', 'google', 'k1', 'k2', 'mail', 'selector1', 'selector2',
                                  'zoho']
                for selector in dkim_selectors:
                    # default._domainkey.domain.com
                    # DKIM query the host's DNS
                    dkim_name = selector + '._domainkey.' + site
                    res_dkim = self.loop.run_until_complete(self.resolver.query(dkim_name, 'TXT'))
                    # print(res_dkim[0].text)
                    # print(dkim_name + ' ==> ' + str(res_dkim.text))
                    for elem in res_dkim:
                        # print(str(elem.text))
                        self.domain_txt.append(['TXT', str(dkim_name), str(elem.text)])
                        if 'v=DKIM' in str(elem.text):
                            self.dkim.append([str(dkim_name), str(elem.text)])
            except:
                pass

            try:
                # _dmarc.domain.com
                # DMARC query the host's DNS
                dmarc_name = '_dmarc.' + site
                res_dmarc = self.loop.run_until_complete(self.resolver.query(dmarc_name, 'TXT'))
                # print(res_dkim[0].text)
                # print(dkim_name + ' ==> ' + str(res_dkim.text))
                for elem in res_dmarc:
                    # print(str(elem.text))
                    self.domain_txt.append(['TXT', str(dmarc_name), str(elem.text)])
                    if 'v=DMARC' in str(elem.text):
                        self.dmarc = str(elem.text)
            except:
                pass

            try:
                # WWW query the host's DNS
                res_cname = self.loop.run_until_complete(self.resolver.query('www.' + site, 'CNAME'))
                www_name = 'www.' + site
                # print(www_name + ' ==> ' + res_cname.cname)
                self.domain_www.append(['CNAME', str(www_name), str(res_cname.cname)])
                if "cloudflare" in res_cname.cname:
                    self.waf = 'Cloudflare: CNAME detected'
                if "quic.cloud" in res_cname.cname:
                    self.waf = "QUIC.cloud CDN: CNAME detected"
            except:
                pass

            try:
                res_www = self.loop.run_until_complete(self.resolver.query('www.' + site, 'A'))
                for elem in res_www:
                    # print(elem)
                    www_name = 'www.' + site
                    # print('www.' + site + ' ==> ' + elem.host)
                    self.domain_www.append(['A', str(www_name), str(elem.host)])
            except:
                pass

            try:
                res_a = self.loop.run_until_complete(self.resolver.query(site, 'A'))
                for elem in res_a:
                    # print(elem.host)
                    domain_a = elem.host
                    self.domain_www.append(['A', str(site), str(domain_a)])
            except:
                pass

            try:
                res_aaaa = self.loop.run_until_complete(self.resolver.query(site, 'AAAA'))
                for elem in res_aaaa:
                    # print(elem.host)
                    domain_aaaa = elem.host
                    self.domain_www.append(['AAAA', str(site), str(domain_aaaa)])
            except:
                pass

            try:
                # MX query the host's DNS
                res_mx = self.loop.run_until_complete(self.resolver.query(site, 'MX'))
                for elem in res_mx:
                    # print(res_mx)
                    # print(str(elem.host) + ' has preference ' + str(elem.priority))
                    self.domain_mx.append(['MX', str(elem.host), str(elem.priority)])
            except:
                pass

            try:
                res_txt = self.loop.run_until_complete(self.resolver.query(site, 'TXT'))
                for elem in res_txt:
                    # print(str(elem.text))
                    self.domain_txt.append(['TXT', str(site), str(elem.text)])
                    if 'v=spf' in str(elem.text):
                        self.spf = str(elem.text)
            except:
                pass

            try:
                self.domain_dict['DNS']['NS'] = self.domain_nameservers
            except:
                print('NS lookups failed')
                pass
            try:
                self.domain_dict['DNS']['WWW'] = self.domain_www
            except:
                print('WWW lookup failed')
                pass

            try:
                self.domain_dict['DNS']['MX'] = self.domain_mx
            except:
                print('MX lookup failed')
                pass

            try:
                self.domain_dict['DNS']['TXT'] = self.domain_txt
            except:
                print('TXT lookup failed')
                pass

        self.dns = self.domain_dict['DNS']

    # def get_whois_domain(self):
    #     if self.get_domain_rdap_info():
    #         self.create_domain_dict_rdap()
    #     else:
    #         self.get_domain_whois_info()
    #
    # def check_auth_nameservers_match(self):
    #     if sorted(self.whois_ns) == sorted(self.ns):
    #         # print('Authoratative NS and DNS nameservers match')
    #         self.auth_ns_match = True
    #     else:
    #         self.auth_ns_match = False

# get_domain_whois_info(domain)

# domain_whois = wizard_whois.get_whois(domain)
# for key, value in domain_whois.items():
#    print(key, ':', value)

# print('')
# print('DNS Records JSON:')
# # print(json.dumps(domain_dict, default=str))
# print(json.dumps(DomainInfo('google.com').domain_dict))
#
# print('')
# print('DNS Records JSON Pretty Print:')
# print(json.dumps(DomainInfo('google.com').domain_dict, indent=4, sort_keys=False))


# How to use class by attributes
# def check_domaininfo(name):
#     domain = DomainInfo(name)
#     print(f"{domain.domain}'s registrar is {domain.registrar} ")
#     print(f"Whois Namservers: {domain.whois_nameservers} ")
#     print('')
#     print(f"WWW records: {domain.domain_www}")
#     print(f"SOA record: {domain.soa}")
#     print(f"MX records: {domain.domain_mx}")
#     print(f"DNS Nameservers: {domain.ns} ")
#     print(f"Domain's SPF: {domain.spf} ")
#     print(f"Domain's DKIM: {domain.dkim} ")
#     print(f"Domain's DMARC: {domain.dmarc} ")
#     print(f"Domain Expiration: {domain.expiration} ")
#     print(f"Whois Namservers: {domain.whois_ns} ")
#     print(f"DNS Namservers: {domain.ns} ")
#     print(f"Auth and DNS Namservers match: {domain.auth_ns_match} ")
#     print(f"WAF check: {domain.waf} ")
#     # for key, value in domain.dns.items():
#     #    print(key, ':', value)
#
#
# check_domaininfo('sucuri.net')

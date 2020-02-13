import os
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
import threading
from shodan import Shodan
from subenum import SubEnum
import dns.resolver
from tqdm import tqdm
import csv
import ipwhois
import time
from termcolor import colored

class sak:
    #class initialisation, declares instance variables and calls main()
    def __init__(self,target,threads,asn,shodan,output,shodankey,subdomains,subonly):
        self.datadict = {}
        self.target = target
        self.threads = threads
        self.asn = asn
        self.shodan = shodan
        self.output = output
        self.shodankey = shodankey
        self.subdomains = subdomains
        self.subonly = subonly

    def main(self):
        try:
            #subdomain input check
            if not self.subdomains:
                enum = SubEnum(self.target)
                sublist = enum.main()
                if self.subonly:
                    if self.output:
                        with open(self.output, 'w') as f:
                            for s in sublist:
                                f.write(s+'\n')
                        print(colored('Results saved to: '+self.output, 'green'))
                    return
            else:
                sublist = self.target
                self.target = 'N/A'
            #threading for i/o heavy tasks, fetches dns records and asn data for each asset
            with ThreadPoolExecutor(max_workers=int(self.threads)) as pool:
                print(colored('\nGetting DNS records...', 'magenta'))
                list(tqdm(pool.map(self.getrecords, sublist), total=len(sublist)))
                if self.asn:
                    print(colored('\nGetting ASN data...', 'magenta'))
                    aslist = list(self.datadict.values())
                    list(tqdm(pool.map(self.getasn, aslist), total=len(aslist)))
            #shodan option check, limited to 1 ip per second by api
            if self.shodan:
                api = Shodan(self.shodankey)
                print(colored('\nGetting Shodan data...', 'magenta'))
                for asset in tqdm(self.datadict.values()):
                    self.getshodan(api,asset)
                    time.sleep(1)
            #output option check, writes to csv also checks for existing file to prevent duplicating header
            if self.output:
                dictlist = list(self.datadict.values())
                if not os.path.isfile(self.output):
                    with open(self.output, 'w') as f:
                        w = csv.DictWriter(f, dictlist[0].keys())
                        w.writeheader()
                        w.writerows(dictlist)
                    print(colored('Results saved to: '+self.output, 'green'))
                else:
                    with open(self.output, 'a') as f:
                        w = csv.DictWriter(f, dictlist[0].keys())
                        w.writerows(dictlist)
                    print(colored('Results saved to: '+self.output, 'green'))
            else:
                dictlist = list(self.datadict.values())
                for item in dictlist:
                    print(item)



        except Exception as e:
            print('\nError in sak.main:')
            print(e)
            sys.exit(2)

    def getrecords(self,subdomain):
        #handles getting the records for each subdomain, dns server(s) is specified below
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['1.1.1.1', '1.0.0.1']
            resolver.timeout = 3
            resolver.lifetime = 3
            #gets A records and starts populating main dict, drops CNAME
            try: 
                A = resolver.query(subdomain, 'A')
                for rec in A.response.answer:
                    if 'CNAME' not in rec.to_text():
                        for x in rec.items:
                            self.datadict[subdomain+x.to_text()] = {'tld':self.target, 'subdomain':subdomain, 'record':'A', 'ip':x.to_text()}
            except:
                pass
            #gets AAAA records, drops CNAME
            try: 
                AAAA = resolver.query(subdomain, 'AAAA')
                for rec in AAAA.response.answer:
                    if 'CNAME' not in rec.to_text():
                        for x in rec.items:
                            self.datadict[subdomain+x.to_text()] = {'tld':self.target, 'subdomain':subdomain, 'record':'AAAA', 'ip':x.to_text()}
            except:
                pass
            #gets MX records, note these are also a subdomain rather than IP.
            try: 
                MX = resolver.query(subdomain, 'MX')
                for rec in MX.response.answer:
                    for x in rec.items:
                        self.datadict[subdomain+x.to_text()] = {'tld':self.target, 'subdomain':subdomain, 'record':'MX', 'ip':x.to_text().split(' ')[1]}
            except:
                pass
        except Exception as e:
            print('\nError in sak.getrecords:')
            print(e)
            sys.exit(2)
    
    def getasn(self,asset):
        #gets ASN data using ipwhois module and RDAP lookup
        try:
            whois = ipwhois.IPWhois(asset['ip'])
            asdata = whois.lookup_rdap()
            asn = asdata['asn']
            asndesc = asdata['asn_description']
            try:
                name = asdata['network']['name']
                cidr = asdata['network']['cidr']
            except:
                try:
                    name = asdata['nets'][len(asdata['nets']-1)]['name']
                    cidr = asdata['nets'][len(asdata['nets']-1)]['cidr']
                except:
                    name = 'Not Found'
                    cidr = asdata['adn_cidr']
                    pass
                pass
            self.datadict[asset['subdomain']+asset['ip']].update({'asn':asn, 'asn_description':asndesc, 'asn_netblock':cidr, 'asn_netname':name}) 
        except Exception as e:
            #print('\nError in sak.getasn:')
            #print(e)
            #sys.exit(2)
            pass

    def getshodan(self,api,asset):
        #get Shodan data per IP, rate limited to 1 per second
        try:
            try:
                results = api.host(asset['ip'])
                ports = sorted(results['ports'])
                isp = results['isp']
                org = results['org']
                country = results['country_code']
                try:
                    tags = results['tags']
                except:
                    tags = ''
                    pass
                try:
                    os = results['os']
                except:
                    os = ''
                    pass
                try:
                    vulns = results['vulns']
                except:
                    vulns = ''
                    pass

            except Exception as e:
                ports = ''
                tags = ''
                isp = ''
                org = ''
                country = ''
                os = ''
                vulns = ''
                pass
            self.datadict[asset['subdomain']+asset['ip']].update({'shodan_os':os, 'shodan_tags':tags, 'shodan_ports':ports, 'shodan_vulns':vulns, 'shodan_isp':isp, 'shodan_org':org, 'shodan_country':country})
        except Exception as e:
            #print('\nError in sak.getshodan:')
            #print(e)
            #sys.exit(2)
            pass

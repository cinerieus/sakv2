import os
import sys
import argparse
import configparser
from sak import sak
import csv

def main():
    parser = argparse.ArgumentParser(description='The OSINT swiss army knife, Fetches data for TLDs.', usage='sakv2 -t example.com -11')
    parser._action_groups.pop()
    required = parser.add_argument_group('Required arguments (-t or -f)')
    optional = parser.add_argument_group('Optional arguments')
    required.add_argument('-t', action='store', dest='target', help='A target TLD or subdomain.')
    required.add_argument('-f', action='store', dest='targetfile', help='A target file that contains a list of TLDs or subdomains.')
    required.add_argument('-o', action='store', dest='output', help='Outputs to a csv.')
    optional.add_argument('-s', action='store_true', dest='subdomains', help='Use for inputing a list of subdomains.')
    optional.add_argument('-so', action='store_true', dest='subonly', help='If specified, will only perform subdomain enumeration.')
    optional.add_argument('-td', action='store', dest='threads', help='Specify number of threads used (defaults to 40).', default=40)
    optional.add_argument('-11', action='store_true', dest='eleven', help='Choose this option to enable all modules.')
    optional.add_argument('-as', action='store_true', dest='asn', help='This option enables the ASN data module.')
    optional.add_argument('-sh', action='store_true', dest='shodan', help='This option enables the Shodan data module.')
    #optional.add_argument('-ssl', action='store_true', dest='ssl', help='This option enables the SSL data module.')
    args = parser.parse_args()
    
    # checks for empty/incompatible args
    if not args.target and not args.targetfile or args.target and args.targetfile:
        print('\n')
        parser.print_help(sys.stderr)
        print('\n')
        sys.exit(0)
    
    #check for 11 option
    if args.eleven:
        args.asn = True
        args.shodan = True
    
    # format input
    if args.target:
        target = [args.target]
    else:
        target = []
        with open(args.targetfile, 'r') as csvin:
            reader = csv.reader(csvin)
            rawlist = list(reader)
            for x in rawlist:
                target.append(x[0])
    
    #config file check
    try:
        path = os.path.dirname(os.path.abspath(__file__))+'/config.ini'
        config = configparser.ConfigParser()
        config.read(path)
        shodankey = config.get('config', 'shodankey')
        if shodankey == '':
            print('\nShodan API key not present, disabling Shodan module...\n')
            args.shodan = False      
    except:
        print('\nConfig file not present, disabling Shodan module...\n')
        shodankey = ''
        args.shodan = False
        pass
    
    #checks for list of subdomains or tlds
    if not args.subdomains:
        for t in target:
            try:
                sakc = sak(t,args.threads,args.asn,args.shodan,args.output,shodankey,args.subdomains,args.subonly)
                sakc.main()
            except Exception as e:
                print('\nError in __main__:')
                print(e)
                sys.exit(1)
    else:
        try:
            sakc = sak(target,args.threads,args.asn,args.shodan,args.output,shodankey,args.subdomains,args.subonly)
            sakc.main()
        except Exception as e:
            print('\nError in __main__:')
            print(e)
            sys.exit(1)

if __name__ == '__main__':
    main()


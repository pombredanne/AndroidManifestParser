#!/usr/bin/python

import argparse
import collections
import logging
import re
import sys
import xml.etree.ElementTree as ET

# Logging
lg = logging.getLogger('parser')
con = logging.StreamHandler()
formatter = logging.Formatter('%(name)s:%(levelname)-8s %(message)s')
con.setFormatter(formatter)
lg.addHandler(con)


# Strip NS
def sanitize(d):

    r = {}

    for k,v in d:
        nk = re.sub('^{.+}(.+)$',r'\1', k)
        r[nk] = v

    return r


# Formatter
def formatTable(results):

    oResults = collections.OrderedDict(sorted(results.items()))

    for category, dicts in oResults.items():

        print '%s:' % category
        for i in range(0, len(dicts)):

            for k, v in dicts[i].items():

                if type(v) == list:
                    s =  ', '.join(v)
                else:
                    s = str(v).replace('\n', ' - ')

                print '\t[%.2d] %s= %s' % (i, k, s)

        print ''


# Parser
def parse(xmlString):

    # Results is dict of lists
    # Each sublist is [{'a':1, 'b':2}, {'a':1, ....]
    results = {}


    # Parse XML
    lg.info('Parsing XML')
    try:
        root = ET.fromstring(xmlString)
    except Exception,e:
        lg.error('Error during parsing "%s"' % e.message)
        return


    # Checking manifest tag
    if root.tag.lower() != 'manifest':
        lg.error('XML File does not seem to be an Android Manifest')
        return


    ### GENERAL
    attr = sanitize(root.items())
    GENERAL = '0. General'
    results[GENERAL] = [{'Package': attr['package']}]


    # Target SDK Version
    targetFound = False

    lg.info('Searching targetSdkVersion')
    for child in root.findall('./uses-sdk'):

        attr = sanitize(child.items())
        if 'targetSdkVersion' in attr.keys():

            targetSDKVersion = int(attr['targetSdkVersion'])
            lg.info('Target SDK Version is %d' % targetSDKVersion)
            targetFound = True
            break


    # No target, search for min
    if not targetFound:

        lg.info('No targetSdkVersion found, seaching for minSdkVersion')

        for child in root.findall('./uses-sdk'):

            attr = sanitize(child.items())
            if 'minSdkVersion' in attr.keys():

                targetSDKVersion = int(attr['minSdkVersion'])
                lg.info('Target SDK Version is set to minSdkVersion %d' % targetSDKVersion)
                targetFound = True
                break


    # No min, set to 1
    if not targetFound:

        targetSDKVersion = 1
        lg.info('No minSdkVersion found, Target SDK Version set to default value "1"')

    results[GENERAL][0]['TargetSDKVersion'] = targetSDKVersion


    ### PERMISSIONS

    CUSTOM_PERMISSIONS = '1.1 Custom permissions'
    results[CUSTOM_PERMISSIONS] = []
    for child in root.findall('./permission'):

        attr = sanitize(child.items())
        results[CUSTOM_PERMISSIONS].append({'Name': attr['name'], 'Protection': attr['protectionLevel']})


    PERMISSIONS = '1.2. Permissions required'
    results[PERMISSIONS] = []
    for child in root.findall('./uses-permission'):

        attr = sanitize(child.items())
        results[PERMISSIONS].append({'Name': attr['name']})



    ###NORMAL EXIT
    return results


# Main invocation
if __name__=='__main__':

    # Argument parser
    ap = argparse.ArgumentParser()
    ap.add_argument('-i', '--input', metavar='FILE', dest='input', default=None, help='Input file, stdin if none')


    # Verbosity
    ap.add_argument('-v', action='count', dest='verbose', default=0, help='Increase output verbosity (default=ERROR)')
    ap.add_argument('-q', action='count', dest='quiet', default=0, help='Decrease output verbosity')

    args = ap.parse_args()


    # Verbosity
    verbosityLevel = logging.ERROR - 10*(args.verbose) + 10*(args.quiet)
    verbosityLevel = max(logging.DEBUG, verbosityLevel)
    verbosityLevel = min(logging.CRITICAL, verbosityLevel)
    lg.setLevel(verbosityLevel)


    # Retrieve file contents
    try:

        lg.info('Opening input file')
        infile = sys.stdin if args.input is None else open(args.input, 'rb')
        xmlString = infile.read()
        infile.close()
    except Exception, e:

        lg.error('Input file error "%s"' % e.strerror)
        sys.exit(1)


    # Parsing
    results = parse(xmlString)

    if results is None:
        lg.critical('Error during parsing, exiting')
        sys.exit(2)


    # Formatting
    formatTable(results)

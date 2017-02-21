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


# Writeline + flush
def write(f, l):

    f.write('%s\n' % l)
    f.flush()


### Formatters

# Text
def formatText(results, outfile):

    oResults = collections.OrderedDict(sorted(results.items()))

    for category, dicts in oResults.items():

        if len(dicts):
            write(outfile, '%s:' % category)
            for i in range(0, len(dicts)):

                oDict = collections.OrderedDict(sorted(dicts[i].items()))
                for k, v in oDict.items():

                    if type(v) == list:
                        s =  ', '.join(v)
                    else:
                        s = str(v).replace('\n', ' - ')

                    write(outfile, '\t[%.2d] %s: %s' % (i, k.replace('!',''), s))
                write(outfile, '\t--')
            write(outfile, '')


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


    ## Package
    results[GENERAL] = [{'!Package': attr['package']}]


    ## Backup
    application = root.findall('./application')
    if len(application)==0:
        lg.error('No <application> tag found, exiting')
        return

    application = application[0]
    attr = sanitize(application.items())
    backup = not ('allowBackup' in attr.keys() and attr['allowBackup'].lower()=='false')
    debug = ('debuggable' in attr.keys() and attr['debuggable'].lower()=='true')

    results[GENERAL][0]['Backup allowed'] = backup
    results[GENERAL][0]['Debuggable'] = debug

    if not 'name' in attr.keys():
        attr['name'] = '__UNDEFINED__'
        lg.warning('Application did not specifify main class')

    results[GENERAL][0]['!Main class'] = attr['name']


    ## Target SDK Version
    targetFound = False

    lg.info('Searching targetSdkVersion')
    for child in root.findall('./uses-sdk'):

        attr = sanitize(child.items())
        if 'targetSdkVersion' in attr.keys():

            targetSDKVersion = int(attr['targetSdkVersion'])
            lg.debug('Found target SDK Version %d' % targetSDKVersion)
            targetFound = True
            break

    # No target, search for min
    if not targetFound:

        lg.debug('No targetSdkVersion found, seaching for minSdkVersion')

        for child in root.findall('./uses-sdk'):

            attr = sanitize(child.items())
            if 'minSdkVersion' in attr.keys():

                targetSDKVersion = int(attr['minSdkVersion'])
                lg.debug('Target SDK Version is set to minSdkVersion %d' % targetSDKVersion)
                targetFound = True
                break

    # No min, set to 1
    if not targetFound:

        targetSDKVersion = 1
        lg.debug('No minSdkVersion found, Target SDK Version set to default value "1"')

    results[GENERAL][0]['TargetSDKVersion'] = targetSDKVersion


    ### PERMISSIONS

    lg.info('Listing permissions')
    CUSTOM_PERMISSIONS = '1.1 Custom permissions'
    results[CUSTOM_PERMISSIONS] = []
    for child in root.findall('./permission'):

        attr = sanitize(child.items())
        results[CUSTOM_PERMISSIONS].append({'!Name': attr['name'], 'Protection': attr['protectionLevel']})
        lg.debug('Custom permission found %s' % attr['name'])


    PERMISSIONS = '1.2. Permissions required'
    results[PERMISSIONS] = []
    for child in root.findall('./uses-permission'):

        attr = sanitize(child.items())
        results[PERMISSIONS].append({'Name': attr['name']})
        lg.debug('Permission found %s' % attr['name'])


    ### ACTIVITIES
    ACTIVITIES = '2. Activities'
    results[ACTIVITIES] = []

    lg.info('Listing activities')
    for child in application.findall('./activity'):

        attr = sanitize(child.items())

        hasIntentFilter = len(child.findall('./intent-filter'))>0
        exported = ("%s (default)" % str(hasIntentFilter)) if 'exported' not in attr.keys() else (attr['exported'].lower()=='true')

        aDict = {
            '!Class': attr['name'],
            'Exported': exported,
        }
        lg.debug('Found activity %s' % attr['name'])

        if hasIntentFilter:

            intentFilters = []
            for intent in child.findall('./intent-filter'):
                actions = intent.findall('./action')

                if len(actions)==0:
                    lg.warning('Intent filter with no action in activity %s' % attr['name'])
                    continue

                for action in actions:
                    actionAttr = sanitize(action.items())
                    intentFilters.append(actionAttr['name'])

                    lg.debug('Found intent-filter action %s' % actionAttr['name'])

            intentFilters = list(set(intentFilters))
            aDict['Intent filters'] = ', '.join(intentFilters)

        results[ACTIVITIES].append(aDict)


    ### PROVIDERS
    PROVIDERS = '3. Content Providers'
    results[PROVIDERS] = []

    lg.info('Listing content providers')
    for child in application.findall('./provider'):

        attr = sanitize(child.items())

        if targetSDKVersion < 17:
            exported = 'True by default because API<17'
        else:
            if 'exported' in attr.keys():
                exported = '%s' % attr['exported']
            else:
                exported = 'False (default)'

        pDict = {
            '!Name': attr['name'],
            '!Authorities': attr['authorities'],
            'Exported': exported,
        }

        lg.debug('Found provider %s' % attr['name'])
        results[PROVIDERS].append(pDict)


    ### RECEIVERS
    RECEIVERS = '4. Receivers'
    results[RECEIVERS] = []

    lg.info('Listing receivers')
    for child in application.findall('./receiver'):

        attr = sanitize(child.items())

        hasIntentFilter = len(child.findall('./intent-filter'))>0
        exported = ("%s (default)" % str(hasIntentFilter)) if 'exported' not in attr.keys() else (attr['exported'].lower()=='true')

        rDict = {
            '!Class': attr['name'],
            'Exported': exported,
        }
        lg.debug('Found receiver %s' % attr['name'])

        if hasIntentFilter:

            intentFilters = []
            for intent in child.findall('./intent-filter'):
                actions = intent.findall('./action')

                if len(actions)==0:
                    lg.warning('Intent filter with no action in receiver %s' % attr['name'])
                    continue

                for action in actions:
                    actionAttr = sanitize(action.items())
                    intentFilters.append(actionAttr['name'])

                    lg.debug('Found intent-filter action %s' % actionAttr['name'])

            intentFilters = list(set(intentFilters))
            rDict['Intent filters'] = ', '.join(intentFilters)

        results[RECEIVERS].append(rDict)


    ### SERVICES
    SERVICES = '5. Services'
    results[SERVICES] = []

    lg.info('Listing services')
    for child in application.findall('./service'):

        attr = sanitize(child.items())

        hasIntentFilter = len(child.findall('./intent-filter'))>0
        exported = ("%s (default)" % str(hasIntentFilter)) if 'exported' not in attr.keys() else (attr['exported'].lower()=='true')

        sDict = {
            '!Class': attr['name'],
            'Exported': exported,
        }
        lg.info('Found service %s' % attr['name'])

        if hasIntentFilter:

            intentFilters = []
            for intent in child.findall('./intent-filter'):
                actions = intent.findall('./action')

                if len(actions)==0:
                    lg.warning('Intent filter with no action in service %s' % attr['name'])
                    continue

                for action in actions:
                    actionAttr = sanitize(action.items())
                    intentFilters.append(actionAttr['name'])

                    lg.debug('Found intent-filter action %s' % actionAttr['name'])

            intentFilters = list(set(intentFilters))
            sDict['Intent filters'] = ', '.join(intentFilters)

        results[SERVICES].append(sDict)

    ###NORMAL EXIT
    return results


# Main invocation
if __name__=='__main__':

    # Argument parser
    ap = argparse.ArgumentParser()
    ap.add_argument('-i', '--input', metavar='FILE', dest='input', default=None, help='Input file, stdin if none')
    ap.add_argument('-o', '--output', metavar='FILE', dest='output', default=None, help='Output file, stdout if none')

    formats = {
            'TEXT': formatText,
    }
    ap.add_argument('-f', '--format', metavar='FMT', dest='format', default='TEXT', help='Output format, default is TEXT, allowed %s' % ', '.join(formats.keys()))

    # Verbosity
    ap.add_argument('-v', action='count', dest='verbose', default=0, help='Increase output verbosity (default=ERROR)')
    ap.add_argument('-q', action='count', dest='quiet', default=0, help='Decrease output verbosity')

    args = ap.parse_args()


    # Output format
    if not args.format in formats.keys():
        ap.print_help()
        sys.exit(1)

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
        sys.exit(2)


    # Output destination
    outfile = sys.stdout if args.output is None else open(args.output, 'wb')

    # Parsing
    results = parse(xmlString)

    if results is None:
        lg.critical('Error during parsing, exiting')
        sys.exit(3)


    # Formatting
    formats[args.format](results, outfile)
    outfile.close()

# usage : ./qualyscli.py hostname selenium-script.file
# if no selenium script is supplied the default qualys crawler would be used

import requests
import sys
import re
import time
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
from xml.etree import ElementTree
from xml.dom import minidom


DEBUG = False

# Process arg.
#assert len(sys.argv) == 2
host = sys.argv[1]
sScript = 0
if len(sys.argv) == 3:
    sScript = sys.argv[2]

# Base URL
BASEURL = ''
CREDENTIALS = ('', '')
HEADERS = {'content-type': 'text/xml', 'Accept-Charset': 'UTF-8'}
DEFAULT_SCANNER_APPLIANCE = ""

# Constant Web App ID
# At this point we can only use one web app ID
#
# WEBAPP_ID = Web Application ID from your Qualys webserver

# Function   : generate_start_scan_service_request
# Purpose    : generate the XML to be used for the API post call
# Parameters :
#   scanName - name for the scan to be run
#   webAppID - the web application ID you wish to scan
#   customProfileID - the custom profile you made to scan for custom crieterias
#   **keyword_parameters - Optional - Provide a different authentication record
#                          by providing auth=ID
# Return : XML in string


def generate_start_scan_service_request(scanName, webAppID, customProfileID, **keyword_parameters):
    ServiceRequest = Element('ServiceRequest')
    data = SubElement(ServiceRequest, 'data')
    WasScan = SubElement(data, 'WasScan')
    WasScanName = SubElement(WasScan, 'name')
    WasScanName.text = scanName
    WasScanType = SubElement(WasScan, 'type')
    WasScanType.text = "VULNERABILITY"
    WasScanTarget = SubElement(WasScan, 'target')
    WasScanTargetWebApp = SubElement(WasScanTarget, 'webApp')
    WasScanTargetWebAppID = SubElement(WasScanTargetWebApp, 'id')
    WasScanTargetWebAppID.text = str(webAppID)
    WasScanTargetWebAppAuth = SubElement(WasScanTarget, 'webAppAuthRecord')

    # Optional different authentication record can be provided if the default
    # web application authentication record does not suffice
    if 'auth' in keyword_parameters:
        WasScanTargetWebAppAuthID = SubElement(WasScanTargetWebAppAuth, 'id')
        WasScanTargetWebAppAuthID.text = str(keyword_parameters['auth'])
    else:
        WasScanTargetWebAppAuthDefault = SubElement(
            WasScanTargetWebAppAuth, 'isDefault')
        WasScanTargetWebAppAuthDefault.text = "true"

    # Scanner Appliance section in XML
    WasScanTargetScannerAppliance = SubElement(
        WasScanTarget, 'scannerAppliance')
    WasScanTargetScannerApplianceType = SubElement(
        WasScanTargetScannerAppliance, 'type')
    WasScanTargetScannerApplianceType.text = "INTERNAL"
    WasScanTargetScannerApplianceName = SubElement(
        WasScanTargetScannerAppliance, 'friendlyName')
    WasScanTargetScannerApplianceName.text = DEFAULT_SCANNER_APPLIANCE

    # Profile Section in XML
    WasScanProfile = SubElement(WasScan, 'profile')
    WasScanProfileID = SubElement(WasScanProfile, 'id')
    WasScanProfileID.text = str(customProfileID)

    return tostring(ServiceRequest)

# Function   : generate_webapp_update_service_request
# Purpose    : generate the XML to be used for the API post call
# Parameters :
#   newWebApp - new web app url to scan
#   keyword_parameters - accepts - SeleniumScript with the file name
#
# Sample :
#   generate_webapp_update_service_request("http://exampleendpoint")
#   generate_webapp_update_service_request("http://exampleendpoint", SeleniumScript="test-script.html")
#
# Return : XML in string


def generate_webapp_update_service_request(new_webapp, **keyword_parameters):
    ServiceRequest = Element('ServiceRequest')
    data = SubElement(ServiceRequest, 'data')
    WebApp = SubElement(data, 'WebApp')
    url = SubElement(WebApp, 'url')
    url.text = new_webapp

    # Optional - Provide a selenium script
    if 'SeleniumScript' in keyword_parameters:
        # As of now this is the best method I can think off
        fileName = str(keyword_parameters['SeleniumScript'])

        # Readfile
        SeleniumScriptString = open(fileName, 'r').read()

        CrawlingScript = SubElement(WebApp, 'crawlingScripts')
        CrawlingScriptSet = SubElement(CrawlingScript, 'set')
        SeleniumScript = SubElement(CrawlingScriptSet, 'SeleniumScript')

        SeleniumScriptName = SubElement(SeleniumScript, 'name')
        SeleniumScriptName.text = fileName

        SeleniumScriptStartingUrl = SubElement(SeleniumScript, 'startingUrl')
        SeleniumScriptStartingUrl.text = new_webapp

        SeleniumScriptData = SubElement(SeleniumScript, 'data')
        SeleniumScriptData.text = "<![CDATA[{}]]>".format(SeleniumScriptString)

        SeleniumScriptAuthentication = SubElement(
            SeleniumScript, 'requiresAuthentication')
        SeleniumScriptAuthentication.text = "false"

        SeleniumScriptStartingUrlRegex = SubElement(
            SeleniumScript, 'startingUrlRegex')
        SeleniumScriptStartingUrlRegex.text = "false"

    resultOne = re.sub(r'\&lt;', "<", str(tostring(ServiceRequest)))
    resultOne = re.sub(r'\\n', "", resultOne)
    result = re.sub(r'\&gt;', ">", resultOne)

    return result

# Function   : generate_search_service_request
# Purpose    : generate the XML to be used for the API post call
# Parameters :
#   filterToUse : Refer to the API Quickstart Guide for your call
#   operation   : Refer to Allowed Operators (page 70, quick reference)
#   customData  : Data to to compare against (Refer to Quick Reference guide for specifics)
# Sample :
#   generate_search_service_request("name", "CONTAINS", "API")
# Return :XML in string


def generate_search_service_request(filterToUse, operation, customData):
    ServiceRequest = Element('ServiceRequest')
    filters = SubElement(ServiceRequest, 'filters')
    crieteria = SubElement(filters, 'Criteria',
                           field=filterToUse, operator=operation)
    crieteria.text = customData
    return tostring(ServiceRequest)


# Function   : generate_auth_service_request
# Purpose    : generate the XML to be used for the API post call
# Parameters :
#   filterToUse : Refer to the API Quickstart Guide for your call
#   operation   : Refer to Allowed Operators (page 70, quick reference)
# Return :XML in string
def generate_auth_service_request(name, customData):
    ServiceRequest = Element('ServiceRequest')
    data = SubElement(ServiceRequest, 'data')
    webAppAuthRecord = SubElement(data, 'WebAppAuthRecord')
    authRecordName = SubElement(webAppAuthRecord, 'name')
    authRecordName.text = name
    formRecord = SubElement(webAppAuthRecord, 'formRecord')
    authType = SubElement(formRecord, 'type')
    authType.text = "CUSTOM"
    fields = SubElement(formRecord, 'fields')
    fieldsSet = SubElement(fields, 'set')

    for item in customData:
        WebAppAuthFormRecordField = SubElement(
            fieldsSet, 'WebAppAuthFormRecordField')
        WebAppAuthFormRecordFieldName = SubElement(
            WebAppAuthFormRecordField, 'name')
        WebAppAuthFormRecordFieldName.text = str(item[0])
        WebAppAuthFormRecordFieldValue = SubElement(
            WebAppAuthFormRecordField, 'value')
        WebAppAuthFormRecordFieldValue.text = str(item[1])

    return tostring(ServiceRequest)


# Function   : check_success
# Purpose    : validates if the call went through successfully or not
# Parameters :
#   xml : response from call in xml
#
# Return : Exception
def check_success(xml):
    if xml.getElementsByTagName("responseCode"):
        if xml.getElementsByTagName("responseCode")[0].firstChild.nodeValue != "SUCCESS":
            raise Exception(xml.toxml())


# Validate input is int
def is_input_valid(input, dataType, err):
    if not isinstance(input, dataType):
        raise Exception(err)


# Function   : get_total_scan_count
# Purpose    : get total cout of webapp scans
# Parameters : n/a
# Return : int scan count
def get_total_scan_count():
    call = "/count/was/wasscan"
    r = requests.post(
        BASEURL + call,
        data=generate_search_service_request("status", "EQUALS", "FINISHED"),
        headers=HEADERS,
        auth=CREDENTIALS)
    return ET.fromstring(r.content).find('count').text

# Function   : update_existing_webapp
# Purpose    : change the static webapp we are using for a new target
# Parameters :
#   new_webapp : new target to update existing webapp with (for scannign later on)
# Return : Response XML


def update_existing_webapp(new_webapp, **keyword_parameters):
    is_input_valid(new_webapp, str, "{} is not of type str".format(new_webapp))
    call = "/update/was/webapp/{}".format(WEBAPP_ID)

    if 'SeleniumScript' in keyword_parameters:
        postData = generate_webapp_update_service_request(
            new_webapp, SeleniumScript=str(keyword_parameters['SeleniumScript']))[2:][:-1]
    else:
        postData = generate_webapp_update_service_request(new_webapp)[2:][:-1]

    response = minidom.parseString(requests.post(
        BASEURL + call,
        data=postData,
        headers=HEADERS,
        auth=CREDENTIALS).content)

    check_success(response)
    return response

# Function   : get_webapp_details
# Purpose    : get more details a webapp
# Parameters :
#   id : web app ID
# Return : Response XML


def get_webapp_details(id):
    is_input_valid(id, int, "ID used was not type int")

    call = "/get/was/webapp/{}".format(str(id))

    r = requests.post(
        BASEURL + call,
        data=generate_search_service_request("status", "EQUALS", "FINISHED"),
        headers=HEADERS,
        auth=CREDENTIALS)

    return r


# Function   : start_scan
# Purpose    : start scan against webapp
# Parameters :
#   webapp_id : webapp ID
#   keyword_parameters : optionally provide a different custom profile ID for scanning
# Return : Scan ID
def start_scan(webapp_id, **keyword_parameters):
    is_input_valid(webapp_id, int, "{} is not of type int".format(webapp_id))

    call = "/launch/was/wasscan"
    new_scan_name = "[QA] API Test %s" % str(time.time())[:-3]
    
    if 'profile' in keyword_parameters:
        is_input_valid(keyword_parameters['profile'], int,"%s is not of type int" % keyword_parameters['profile'])
        profile_id = int(keyword_parameters['profile'])
    else:
        # Default scan (for quick scan)
        # If you have a custom scan profile, choose the ID here
        profile_id = 000000
        
    if 'auth' in keyword_parameters:
        auth_id = int(keyword_parameters['auth'])
        postData = generate_start_scan_service_request(
            new_scan_name, webapp_id, profile_id, auth=auth_id)
    else:
        postData = generate_start_scan_service_request(
            new_scan_name, webapp_id, profile_id)
        

    xml = minidom.parseString(requests.post(
        BASEURL + call,
        data=postData,
        headers=HEADERS,
        auth=CREDENTIALS).content)
    check_success(xml)
    return xml.getElementsByTagName("id")[0].firstChild.nodeValue

# Function   : get_custom_profiles
# Purpose    : get the custom profiles we had created
# Parameters : n/a
# Return : n/a


def get_custom_profiles():
    call = "/search/was/optionprofile"
    xml = minidom.parseString(requests.post(
        BASEURL + call,
        headers=HEADERS,
        auth=CREDENTIALS).content)

    check_success(xml)

    count = int(xml.getElementsByTagName("count")[0].firstChild.nodeValue)
    if (count):
        for idx in range(0, int(count)):
            #import pdb; pdb.set_trace()
            profileID = xml.getElementsByTagName("OptionProfile")[
                idx].getElementsByTagName('id')[0].firstChild.nodeValue
            profileName = xml.getElementsByTagName(
                "OptionProfile")[idx].getElementsByTagName('name')[0].firstChild.nodeValue
            print("ID: %s  Name: %s " % (profileID, profileName))


# Function   : is_scan_running
# Purpose    : check whether a scan is running
# Parameters :
#   scan_id : scan ID
# Return : boolean
def is_scan_running(scan_id):
    is_input_valid(scan_id, int, "{} is not of type int".format(scan_id))
    call = "/search/was/wasscan"
    while True:
        try:
            xml = minidom.parseString(requests.post(
                BASEURL + call,
                data=generate_search_service_request(
                    "id", "EQUALS", str(scan_id)),
                headers=HEADERS,
                auth=CREDENTIALS,
                timeout=10).content)
            break
        except:
            pass

    check_success(xml)
    toxml = xml.toxml()
    return ("SUBMITTED" in toxml or "RUNNING" in toxml or "PROCESSING" in toxml)

# Function   : get_scan_results
# Purpose    : get more details about a scan (for results)
# Parameters :
#   scan_id : scan ID
# Return : count
# TODO: Better return value (more object oriented)


def get_scan_results(scan_id):
    is_input_valid(scan_id, int, "{} is not of type int".format(scan_id))
    call = "/download/was/wasscan/{}".format(str(scan_id))

    while True:
        try:
            xml = minidom.parseString(requests.get(
                BASEURL + call,
                headers=HEADERS,
                auth=CREDENTIALS,
                timeout=60).content)
            break
        except:
            pass

    check_success(xml)

    if (xml.getElementsByTagName("vulns")):
        count = int(xml.getElementsByTagName("vulns")[
                    0].getElementsByTagName("count")[0].firstChild.nodeValue)
    else:
        count = 0

    if count:
        for vuln in xml.getElementsByTagName("WasScanVuln"):
            qid = vuln.getElementsByTagName('qid')[0].firstChild.nodeValue
            title = vuln.getElementsByTagName('title')[0].firstChild.nodeValue
            uri = vuln.getElementsByTagName('uri')[0].firstChild.nodeValue
            print("[QID %s] Failed: %s (url: %s)" % (qid, title, uri))

    return count

# Function   : get_auth_records
# Purpose    : pull all existing authentication records
# Parameters : n/a
# Return : count
# TODO: Better return value (more object oriented)


def get_auth_records():
    call = "/search/was/webappauthrecord/"
    while True:
        try:
            xml = minidom.parseString(requests.post(
                BASEURL + call,
                headers=HEADERS,
                auth=CREDENTIALS,
                timeout=1).content)
            break
        except:
            pass

    check_success(xml)
    count = int(xml.getElementsByTagName("count")[0].firstChild.nodeValue)
    if (count):
        for authRec in xml.getElementsByTagName("WebAppAuthRecord"):
            userid = authRec.getElementsByTagName('id')[0].firstChild.nodeValue
            title = authRec.getElementsByTagName(
                'name')[0].firstChild.nodeValue
            print("ID: %s  Username: %s " % (userid, title))
    return count

# Function   : get_auth_record_details
# Purpose    : pull more details about a specifc authentication record
# Parameters :
#   authID : Authentication record ID
# Return : count
# TODO: Better return value (more object oriented)


def get_auth_record_details(authID):
    is_input_valid(authID, int, "{} is not of type int".format(authID))
    call = "/get/was/webappauthrecord/%s" % (authID)

    while True:
        try:
            xml = minidom.parseString(requests.get(
                BASEURL + call,
                headers=HEADERS,
                auth=CREDENTIALS,
                timeout=10).content)
            break
        except:
            pass

    check_success(xml)

    count = int(xml.getElementsByTagName("count")[0].firstChild.nodeValue)
    if (count):
        for authRec in xml.getElementsByTagName("WebAppAuthRecord"):

            userid = authRec.getElementsByTagName('id')[0].firstChild.nodeValue
            title = authRec.getElementsByTagName(
                'name')[0].firstChild.nodeValue

            for authFormRecord in authRec.getElementsByTagName("formRecord")[0].getElementsByTagName("fields"):
                authRecordCount = authFormRecord.getElementsByTagName("count")[
                    0].firstChild.nodeValue
                authRecordList = authFormRecord.getElementsByTagName("list")[0]

                print("ID: %s  Username: %s " % (userid, title))

                for idx in range(0, int(authRecordCount)):
                    item1 = authRecordList.getElementsByTagName("WebAppAuthFormRecordField")[
                        idx].getElementsByTagName("name")[0].firstChild.nodeValue
                    item2 = authRecordList.getElementsByTagName("WebAppAuthFormRecordField")[
                        idx].getElementsByTagName("value")[0].firstChild.nodeValue
                    print("Form Name: %s  Value: %s" % (item1, item2))

    return count


# Function   : create_auth_record
# Purpose    : create a custom authentication record
# Parameters :
#   customName : New authentication record name
#   customData : a nested n by 2 list for new record details (below)
#   Sample customData : [["formIDforUsername","user"],["formIDforPassword","lmao"]..etc]
#           Note : formIDfor* could be anything depending on the target textbox ID
#                   i.e for gateway its companyID, uid, and pwd
#
# Return : response in xml string
def create_auth_record(customName, customData):
    call = "/create/was/webappauthrecord/"

    while True:
        try:
            xml = minidom.parseString(requests.post(
                BASEURL + call,
                data=generate_auth_service_request(customName, customData),
                headers=HEADERS,
                auth=CREDENTIALS,
                timeout=10).content)
            break
        except:
            pass

    check_success(xml)

    # TODO: Parse the XML to be human friendly

    return xml

################################################################################
# ArgParse Area for command-line commands
################################################################################
class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)


parser = MyParser()
parser.add_argument('-gP', '--getprofiles',
                    help="Get exisiting option profiles",
                    action="store_true",
                    dest='getoptionprofiles')

parser.add_argument('-gA', '--getauthrecords',
                    help="Get exisiting option profiles",
                    action="store_true",
                    dest='getauthrecords')

parser.add_argument('-t', '--targethost',
                    help="Specify a new host as the target to be scanned",
                    action="store",
                    dest='targethost')

parser.add_argument('-a', '--authentication',
                    help="Authentication ID you would like to use to authenticate the scan",
                    action="store",
                    dest='authID')

parser.add_argument('-p', '--profile',
                    help="Option Profile ID you want to use to scan the target with",
                    action="store",
                    default=000000,
                    dest='profileID')

parser.add_argument('-s', '--seleniumscript',
                    help="Provide a Qualys Selenium script for better crawling",
                    action="store",
                    dest='seleniumscript')

# 
args = parser.parse_args()


sScript = ""
cAuthID = 0
cProfileID = 0
host = ""


if args.getauthrecords:
    get_auth_records()
    quit()

if args.getoptionprofiles:
    get_custom_profiles()
    quit()

if args.authID:
    uAuthID = int(args.authID)

if args.profileID:
    cProfileID = int(args.profileID)

if args.seleniumscript:
    sScript = str(args.seleniumscript)

if args.targethost :
    host = str(args.targethost)
    print(host)
else:
    print("You need to specifiy a host. Type --help for help")
    quit()


if (sScript):
    update_existing_webapp(host, SeleniumScript=sScript)
else:
    update_existing_webapp(host)

if (cAuthID):
    scan_id = int(start_scan(WEBAPP_ID, profile=cProfileID, auth=cAuthID))
else:
    scan_id = int(start_scan(WEBAPP_ID, profile=cProfileID))

time.sleep(60)

while is_scan_running(scan_id):
    if DEBUG:
        print(","),
    time.sleep(30)

print("%s vulnerabilities detected." % get_scan_results(scan_id))

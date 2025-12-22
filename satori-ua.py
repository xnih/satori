import os
import sys
import argparse
import untangle
import satoriCommon
import user_agents
from pathlib import Path

def main():
  [useragentExactList, useragentPartialList] = BuildHTTPUserAgentFingerprintFiles()

  if (useragent != ''):
    httpUserAgentProcess(useragent, useragentExactList, useragentPartialList)

  elif (readfile != ''):
    try:
      processfile(readfile, useragentExactList, useragentPartialList)
    except:
      print('File was not pcap format', end='\n', flush=True)
      sys.exit(1)



def version():
  dateReleased='satori-ua.py - 2025-12-22'
  print(dateReleased)


def httpUserAgentProcess(ua, useragentExactList, useragentPartialList):
  fingerprintHdrUserAgent = None
  ua = ua.replace("\n", "").replace("\r", "").strip()

  if (ua != ''):

    #user_agent.parser FP
    user_agent = user_agents.parse(ua)
    os = user_agent.os.family + ' ' + user_agent.os.version_string
    browser = user_agent.browser.family + ' ' + user_agent.browser.version_string
    device = device_string(user_agent)
    os = checkMacOSX(os, browser)

    #satori FP
    httpUserAgentFingerprint = fingerprintLookup(useragentExactList, useragentPartialList, ua)

    #not ideal but converting any ; to | for parsing reasons!
    fingerprintHdrUserAgent = ua + '|' + os + '|' + browser + '|' + device + '|' + httpUserAgentFingerprint

    print(fingerprintHdrUserAgent)


def BuildHTTPUserAgentFingerprintFiles():
  # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
  useragentExactList = {}
  useragentPartialList = {}

  satoriPath = str(Path(__file__).resolve().parent)

  obj = untangle.parse(satoriPath + '/fingerprints/webuseragent.xml')
  fingerprintsCount = len(obj.WEBUSERAGENT.fingerprints)
  for x in range(0,fingerprintsCount):
    os = obj.WEBUSERAGENT.fingerprints.fingerprint[x]['name']
    testsCount = len(obj.WEBUSERAGENT.fingerprints.fingerprint[x].webuseragent_tests)
    test = {}
    for y in range(0,testsCount):
      test = obj.WEBUSERAGENT.fingerprints.fingerprint[x].webuseragent_tests.test[y]
      if test is None:  #if testsCount = 1, then untangle doesn't allow us to iterate through it
        test = obj.WEBUSERAGENT.fingerprints.fingerprint[x].webuseragent_tests.test
      matchtype = test['matchtype']
      webuseragent = test['webuseragent']
      weight = test['weight']
      if matchtype == 'exact':
        if webuseragent in useragentExactList:
          oldValue = useragentExactList.get(webuseragent)
          useragentExactList[webuseragent] = oldValue + ';' + os + ':' + weight
        else:
          useragentExactList[webuseragent] = os + ':' + weight
      else:
        if webuseragent in useragentPartialList:
          oldValue = useragentPartialList.get(webuseragent)
          useragentPartialList[webuseragent] = oldValue + ';' + os + ':' + weight
        else:
          useragentPartialList[webuseragent] = os + ':' + weight

  return [useragentExactList, useragentPartialList]


def fingerprintLookup(exactList, partialList, value):
  exactValue = ''
  partialValue = ''

  if value in exactList:
    exactValue = exactList.get(value)

  for key, val in partialList.items():
    if value.find(key) > -1:
      partialValue = partialValue + ';' + val

  if partialValue.startswith(';'):
    partialValue = partialValue[1:]
  if partialValue.endswith(';'):
    partialValue = partialValue[:-1]

  fingerprint = exactValue + ';' + partialValue
  if fingerprint.startswith(';'):
    fingerprint = fingerprint[1:]
  if fingerprint.endswith(';'):
    fingerprint = fingerprint[:-1]

  fingerprint = satoriCommon.sortFingerprint(fingerprint)
  return fingerprint


#10.15.7 is hardcoded in some useragent strings, specifically Chrome and Safari, maybe others, but only Safari provides more info on what the OS may really be
#this part will have to be updated periodically
def checkMacOSX(os, browser):
  if os == 'Mac OS X 10.15.7':
    if 'Chrome' in browser:
      os = os + ';Mac OS X 11.x;Mac OS X 12.x;Mac OS X 13.x;Mac OS X 14.x;Mac OS X 26.x'

    if 'Safari' in browser:
      version = browser.split(' ')[1]

      if '14' in version:
        if '14.1' in version:
          os = os + ';Mac OS X 11.3+'
        else:
          os = os + ';Mac OS X 11.0 - 11.2'

      elif '15' in version:
        if '15.6' in version:
          os = os + ';Mac OS X 12.5+'
        elif '15.5' in version:
          os = os + ';Mac OS X 12.4'
        elif '15.4' in version:
          os = os + ';Mac OS X 12.3'
        elif '15.3' in version: #guess, not documented
          os = os + ';Mac OS X 12.2'
        elif '15.2' in version:
          os = os + ';Mac OS X 12.1'
        else:
          os = os + ';Mac OS X 12.0'

      elif '16' in version:
        if '16.6' in version:
          os = os + ';Mac OS X 11.x;Mac OS X 12.x;Mac OS X 13.x'
        elif '16.5' in version:
          os = os + ';Mac OS X 11.x;Mac OS X 12.x;Mac OS X 13.x'
        elif '16.4' in version:
          os = os + ';Mac OS X 11.x;Mac OS X 12.x;Mac OS X 13.x'
        elif '16.3' in version:
          os = os + ';Mac OS X 11.x;Mac OS X 12.x;Mac OS X 13.x'
        elif '16.2' in version:
          os = os + ';Mac OS X 11.x;Mac OS X 12.x;Mac OS X 13.x'
        elif '16.1' in version:
          os = os + ';Mac OS X 11.x;Mac OS X 12.x;Mac OS X 13.x'
        else:
          os = os + ';Mac OS X 11.x;Mac OS X 12.x'

      elif '17' in version:
        os = os + ';Mac OS X 12.x;Mac OS X 13.x;Mac OS X 14.x'

      elif '18' in version:
        if '18.6' in version:
          os = os + ';Mac OS X 13.x;Mac OS X 14.x;Mac OS X 15.6'
        elif '18.5' in version:
          os = os + ';Mac OS X 13.x;Mac OS X 14.x;Mac OS X 15.5'
        elif '18.4' in version:
          os = os + ';Mac OS X 13.x;Mac OS X 14.x;Mac OS X 15.4'
        elif '18.3' in version:
          os = os + ';Mac OS X 13.x;Mac OS X 14.x;Mac OS X 15.3'
        elif '18.2' in version:
          os = os + ';Mac OS X 13.x;Mac OS X 14.x;Mac OS X 15.2'
        elif '18.1' in version:
          os = os + ';Mac OS X 13.x;Mac OS X 14.x;Mac OS X 15.1'
        elif '18.0.1' in version:
          os = os + ';Mac OS X 13.x;Mac OS X 14.x;Mac OS X 15.0.1'
        else:
          os = os + ';Mac OS X 13.x;Mac OS X 14.x;Mac OS X 15'

      elif '26' in version:
        if '26.3' in version:
          os = os + ';Mac OS X 14.x;Mac OS X 15.x;Mac OS X 26.3'
        elif '26.2' in version:
          os = os + ';Mac OS X 14.x;Mac OS X 15.x;Mac OS X 26.2'
        elif '26.1' in version:
          os = os + ';Mac OS X 14.x;Mac OS X 15.x;Mac OS X 26.1'
        else:
          os = os + ';Mac OS X 14.x;Mac OS X 15.x;Mac OS X 26'

  return os



def device_string(user_agent):
  try:
    family = str(user_agent.device.family)
    if family == 'None':
      family = ''
  except:
    family = ''

  try:
    brand = str(user_agent.device.brand)
    if brand == 'None':
      brand = ''
  except:
    brand = ''

  try:
    model = str(user_agent.model)
    if model == 'None':
      model = ''
  except:
    model = ''

  val = family + ';' + brand + ';' + model
  return val



def processfile(filepath, useragentExactList, useragentPartialList):
  try:
    with open(filepath, "r") as file:
      for line in file:
        if len(line.strip()) > 5:
          httpUserAgentProcess(line, useragentExactList, useragentPartialList)
  except FileNotFoundError:
    print(f"Error: The file '{file_path}' was not found.")
  except Exception as e:
    print(f"An error occurred: {e}")




## Parse Arguments
try:
  proceed = False

  parser = argparse.ArgumentParser(prog='Satori-UserAgent')
  parser.add_argument('-u', '--useragent', action="store", dest="useragent", help='process a single useragent; example: -u "WeChat/8.0.66.34 CFNetwork/3860.300.31 Darwin/25.2.0"', default="")
  parser.add_argument('-r', '--read', action="store", dest="readfile", help="read in text file; example: -r useragents.txt", default="")
  parser.add_argument('-v', '--version', action="store_true", dest="version", help="print version; example: -v", default="")

  args = parser.parse_args()

  if args.readfile != '':
    if not os.path.isfile(args.readfile):
      print('\nFile "%s" does not appear to exist, please verify file name.' % args.readfile)
      sys.exit()
    else:
      proceed = True
      useragent = ''
      readfile = args.readfile
  if args.useragent != '':
      proceed = True
      useragent = args.useragent
  if args.version:
    version()
    sys.exit()

  if (__name__ == '__main__') and proceed:
    main()
  else:
    print('Need to provide a file to read in or a useragent to parse!', end='\n', flush=True)
    parser.print_help()

except argparse.ArgumentError:
  print(self)




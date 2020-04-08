import sys
import argparse
import json

# Used to parse nmap XML file
import xml.etree.ElementTree as ET

# Used to interact with Nucleus API
import requests

# Get the nmap XML file to parse
def parse_xml(inputPath):
  try:
    tree = ET.parse(inputPath)
    root = tree.getroot()
  except ET.ParseError as e:
    print("Parse error(%s): %s" % e.errno, e.strerror)
    sys.exit(2)
  except IOError as e:
    print("IO error(%s): %s" % e.errno, e.strerror)
    sys.exit(2)
  except:
    print("Unexpected error: %s" % sys.exc_info()[0])
    sys.exit(2)

  return root

# Used to parse the vuln data from the json file
def build_asset_list(root, args):
  assets = []

  for host in root.findall('host'):
    # ET.dump(host)

    asset = {}

    for os in host.findall('os'):
      os_score = 0

      for osmatch in os.findall('osmatch'):
        for osclass in osmatch.findall('osclass'):
          try:
            if int(osclass.get('accuracy')) > os_score:
              os_score = int(osclass.get('accuracy'))
              asset['operating_system_name'] = osmatch.get('name')
              # asset['operating_system_version'] = ET.tostring(osclass, encoding="utf8", method="text").decode('utf8')
          except:
            pass

    asset['ip_address'] = ''

    for address in host.findall('address'):

      if address.get('addrtype') == 'ipv4' or address.get('addrtype') == 'ipv6':
        asset['ip_address'] = address.get('addr')
      elif address.get('addrtype') == 'mac':
        asset['mac_address'] = address.get('addr')

    for hostname in host.findall('hostnames'):
      for hname in hostname.findall('hostname'):
        try:
          asset['asset_name'] = hname.get('name')
        except:
          pass

    asset['asset_groups'] = args.groups.split(',')
    asset['asset_users'] = args.users.split(',')
    asset['asset_location'] = args.location
    asset['asset_type'] = args.type
    asset['asset_notes'] = args.notes
    asset['domain_name'] = args.domain
    asset['asset_complianced_score'] = args.complianceScore
    asset['asset_public'] = args.public
    asset['asset_criticality'] = args.criticality
    asset['asset_data_sensitivity_score'] = args.dataSensitivityScore
    asset['asset_criticality_score'] = args.criticalityScore

    # print("%s" % json.dumps(asset, indent=2))

    assets.append(asset)

  return (assets)

def get_existing_project_assets(args):
  nucleus_url = str('https://' + args.nucleusHost + '/nucleus/api/projects/' + str(args.projectId) + '/assets')

  assets = []

  try:
    more_assets_to_come = True
    starting_at = 0

    while more_assets_to_come == True:
      print("Requesting assets %d to %d" % (starting_at, starting_at + 100))
      payload = {'start': starting_at, 'limit': 100}
      response = requests.get(nucleus_url, headers = {'accept': 'application/json', 'x-apikey': args.nucleusApiKey}, params=payload)
      if response.status_code == 200:
        print("Status Code = %d, Asset Count = %d" % (response.status_code, len(response.json())))
      else:
        print("Status Code = %d" % (response.status_code))

      if response.status_code == 200:
        assets = assets + response.json()
        starting_at += 100

        if len(response.json()) < 100:
          more_assets_to_come = False
          break

  except Exception as e:
    print("Unable to get assets via Nucleus API. Try checking your Nucleus URL and project ID.")
    print("Error as follows:", e)
    return [False]

  return assets

def handle_assets(assets, existing_assets, args):


  for asset in assets:
    # print("%s" % json.dumps(asset, indent=2))

    if asset.get('asset_name'):
      asset_name = asset['asset_name']
    else:
      asset_name = asset['ip_address']

    already_exists = False
    existing_asset_id = 0

    for existing_asset in existing_assets:
      existing_asset_name = existing_asset['asset_name']

      # compare asset name
      if asset.get('asset_name') and existing_asset.get('asset_name') and asset['asset_name'] != '' and existing_asset['asset_name'] != '' and asset['asset_name'] == existing_asset['asset_name']:
        already_exists = True
        existing_asset_id = int(existing_asset['asset_id'])
        break

      # compare asset IP address
      if asset.get('ip_address') and existing_asset.get('ip_address') and asset['ip_address'] != '' and existing_asset['ip_address'] != '' and asset['ip_address'] == existing_asset['ip_address']:
        already_exists = True
        existing_asset_id = int(existing_asset['asset_id'])
        break

    try:
      if already_exists == False:
        nucleus_url = str('https://' + args.nucleusHost + '/nucleus/api/projects/' + str(args.projectId) + '/assets')
        print("Creating asset %s via POST to %s" % (asset_name, nucleus_url))
        response = requests.post(nucleus_url, data = json.dumps(asset), headers = {'content-type': 'application/json', 'accept': 'application/json', 'x-apikey': args.nucleusApiKey})
        print("Status Code = %d, Body = %s" % (response.status_code, response.json()))
      else:
        if existing_asset_name != '':
          print("Asset %s appears to already exist as '%s' with ID %d, ignoring." % (asset_name, existing_asset_name, existing_asset_id))
        else:
          print("Asset %s appears to already exist without a name but with ID %d, ignoring." % (asset_name, existing_asset_id))

    except Exception as e:
      print("Exception when trying to communicate with Nucleus API. Try checking your Nucleus URL and project ID.")
      print("Asset name: %s" % asset['asset_name'])
      print("Error as follows:", e)

def get_args():
  parser = argparse.ArgumentParser(description="For parsing nmap XML files to create assets in Nucleus.")

  # List arguments. Should only include input file and output file
  parser.add_argument('-o', '--hostname', dest='nucleusHost', metavar='FQDN', help="Nucleus instance hostname", required=True)
  parser.add_argument('-a', '--api-key', dest='nucleusApiKey', metavar='API_KEY', help="Nucleus instance API key", required=True)
  parser.add_argument('-i', '--input-file', dest='inputFile', metavar='PATH/TO/FILE.xml', help="Path to nmap xml file to parse", required=True)
  parser.add_argument('-p', '--project-id', dest="projectId", metavar='PROJECT_ID', help="Project ID to associate assets with", type=int, required=True)
  parser.add_argument('-u', '--users', dest='users', metavar='USER1@DOMAIN.TLD,USER2', help="Common delimited list of asset users to associate with new assets", default='', required=False)
  parser.add_argument('-l', '--location', dest='location', metavar='LOCATION', help="Location string to set for new assets", default='', required=False)
  parser.add_argument('-t', '--type', dest='type', metavar='TYPE', help="Asset type to use for new assets", choices=['Database','Host','Container Image','Application'], default='Host', required=False)
  parser.add_argument('-n', '--notes', dest='notes', metavar='NOTES', help="Notes to set for new assets", default='', required=False)
  parser.add_argument('-d', '--domain', dest='domain', metavar='DOMAIN', help="Domain to set for new assets", default='', required=False)
  parser.add_argument('-c', '--compliance-score', dest='complianceScore', metavar='SCORE', help="Compliance score to set for new assets (1=no/non-compliant, 10=yes/compliant)", type=int, default=1, required=False)
  parser.add_argument('-b', '--public', dest='public', help="Mark new assets as public", action='store_true', required=False)
  parser.add_argument('-r', '--criticality', dest='criticality', metavar='CRITICALITY', help="Criticality for new assets", choices=['Critical','High','Moderate','Low'], default='Low', required=False)
  parser.add_argument('-s', '--data-sensitivity-score', dest='dataSensitivityScore', metavar='SCORE', help="Data sensitivity score for new assets", type=int, default=5, required=False)
  parser.add_argument('-e', '--criticality-score', dest='criticalityScore', metavar='SCORE', help="Criticality score for new assets", type=int, default=5, required=False)
  parser.add_argument('-g', '--groups', dest='groups', metavar='GROUP1,GROUP2', help="Common delimited list of asset groups to associate with new assets", default='', required=False)

  args = parser.parse_args()

  return args

if __name__ == "__main__":
  arguments = get_args()
  inputPath = arguments.inputFile
  xml_root = parse_xml(inputPath)
  asset_list = build_asset_list(xml_root, arguments)
  existing_asset_list = get_existing_project_assets(arguments)

  if len(existing_asset_list) == 1 and existing_asset_list[0] == False:
    print("Error trying to get existing asset list, will not continue.")
    exit(1)
  else:
    handle_assets(asset_list, existing_asset_list, arguments)

# EOF

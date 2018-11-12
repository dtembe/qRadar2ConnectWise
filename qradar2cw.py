#!/usr/bin/env python3

import urllib3
import requests
import json
import logging
import urllib.request
from datetime import datetime, timedelta
import base64


# ctx = ssl.create_default_context()
# ctx.check_hostname = False
# ctx.verify_mode = ssl.CERT_NONE

# Variables for Connectwise Manage -

cwurl = "https://<link_to_your_CW_instance/v4_6_release/apis/3.0/service/tickets"
userPass = '<yourCompany>+<yourUserName>:<yourApiKey>'
date = datetime

#encode and decode your Token using Base64
cwtoken = (base64.b64encode(userPass.encode())).decode()
#CW Headers for POST
cwHeaders = {"Authorization":"Basic " + cwtoken,
             "Content-Type":"application/json",
             "cache-control": "no-cache",
             }

#qRadar Security Token

security_token = 'SEC_TOKEN'
#qRadar needs EPOCH time passed to the start_time filter in the URL so passing that now via the code below.


now = datetime.now()

nowinepoch = int(now.timestamp())

nowepochtime = nowinepoch * 1000
#possible to change to a different time in seconds
fiveminutesago = now - timedelta(minutes=600)

etime = int(fiveminutesago.timestamp())

epochtime = etime * 1000





# Creating Logger Environment
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# create a file handler
handler = logging.FileHandler('/tmp/qRadarCW.log')
handler.setLevel(logging.INFO)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)

logger.info('\n')
logger.info('Starting Script')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger.info(epochtime)
#status of offense
open = "OPEN"
# Qradar -
#url_base = "<URL_TO_qRADAR"

#formatted URL looking for offenses that are open adn for the past 5 minutes (or different lookback time depending on your epochtime variable.

url = "https://<urlToqRadar>/api/siem/offenses?filter=status%20%3D%20%22{open}%22%20and%20start_time%20%3E%20{etime}".format(open=open, etime=epochtime)

#querystring = {"status": "OPEN"}

headers = {
    'Accept': "application/json",
    'SEC': security_token,
    'cache-control': "no-cache",
}

response = requests.request("GET", url, headers=headers, verify=False)


data = response.json()

# http = urllib3.PoolManager()

if data == []:
    logger.info("No Data")
else:
    logger.info('Number of offenses retrived: ' + str(len(data)))
    #write below to log file.
    for rows in data:
        logger.info('\n')
        logger.info("*****")
        logger.info('Offense ID: ' + str(rows['id']))
        logger.info('Description: ' + str(rows['description']))
        logger.info('Rules -  ID: ' + str(rows['rules'][0]['id']))
        logger.info('Rules -  Type: ' + str(rows['rules'][0]['type']))
        logger.info('Category : ' + str(rows['categories'][0]))
        logger.info('Severity:' + str(rows['severity']))
        logger.info("*****")
        logger.info('\n')



        #qRadar Field Maps from event. to post into Initial Description.
        q_username_count = ("username count:  " + str(rows['username_count']))
        q_description = ("Description: " + str(rows['description']))
        q_rules_id = ('Rules -  ID: ' + str(rows['rules'][0]['id']))
        q_rules_type = ('Rules -  Type: ' + str(rows['rules'][0]['type']))
        q_event_count = ('Event Count: ' + str(rows['event_count']))
        q_flow_count = ('Flow Count:' + str(rows['flow_count']))
        q_assigned_to = ('Assigned To in qRadar:' + str(rows['assigned_to']))
        q_security_category_count = ('Security Category Count:' + str(rows['security_category_count']))
        q_follow_up = ('Follow Up:' + str(rows['follow_up']))
        q_source_address_ids = ('Source ID - First: ' + str(rows['source_address_ids'][0]))
        q_categories = ('Category: ' + str(rows['categories'][0]))
        q_offense_id = ('Offense ID: ' + str(rows['id']))
        q_offense_type = ('Offense Type: ' + str(rows['offense_type']))
        initialDesc = q_username_count + '\n' + q_description + '\n' + q_rules_id + '\n' + q_rules_type + '\n' +  q_event_count + '\n' +  q_flow_count + '\n' + q_assigned_to + '\n' + q_security_category_count + '\n' + q_follow_up + '\n' + q_source_address_ids+ '\n' +  q_categories + '\n' + q_offense_id + '\n' + q_offense_type
        intialsummary = q_offense_id + ' qRadar Alert - ' + q_categories

        # ALL - qRadarFields
        # 'username_count': 1,
        # 'description': 'Multiple Login Failures for the Same User\n containing Failure Audit: The domain controller failed to validate the credentials for an account\n',
        # 'rules': [{'id': 100056, 'type': 'CRE_RULE'}],
        # 'event_count': 9,
        # 'flow_count': 0,
        # 'assigned_to': None,
        # 'security_category_count': 2,
        # 'follow_up': False,
        # 'source_address_ids': [3335],
        # 'source_count': 1,
        # 'inactive': False,
        # 'protected': False,
        # 'category_count': 2,
        # 'source_network': 'other',
        # 'destination_networks': ['other'],
        # 'closing_user': None,
        # 'close_time': None,
        # 'remote_destination_count': 1,
        # 'start_time': 1541771059904,
        # 'last_updated_time': 1541771070947,
        # 'credibility': 2,
        # 'magnitude': 2,
        # 'id': 3435,
        # 'categories': ['User Login Failure', 'General Authentication Failed'],
        # 'severity': 5,
        # 'policy_category_count': 0,
        # 'device_count': 2,
        # 'closing_reason_id': None,
        # 'offense_type': 3,
        # 'relevance': 1,
        # 'domain_id': 4,
        # 'offense_source': 'RPS-TS02', 'local_destination_address_ids': [],
        # 'local_destination_count': 0,
        # 'status': 'OPEN'

        #CW ticket Fields to map to

        #Type = "SIEM Security Information & Event Management"

        #Create JSON Mapping - nede to clean this as this is from SNOW mapping I created before with a similar script.
        o_source = str("qRadar-API")
        o_node = str("SIEM")
        o_metric_name = str(rows['rules'][0]['id'])
        o_type = str(rows['rules'][0]['type'])
        o_resource = str(rows['id'])
        o_severity = str(rows['severity'])
        o_description = intialsummary
        o_event_class = str(rows['categories'][0])
        o_additional_info = str(rows)
        o_initial_description = initialDesc

        data = {"summary": o_description,
         "board": {
             "name": "<your board name>"
         },
         "company": {
             "identifier": "<your client name in string>"
         },
         "type":{
             "name": "<your type name>"
         },
         "initialDescription": o_initial_description,
         "recordType": "ServiceTicket"
        }

        try:
            r = requests.post(cwurl, data=bytes(json.dumps(data), encoding="utf-8"), headers=cwHeaders)
            logger.info(r.raise_for_status())

        except IOError as e:
            logger.info(e)

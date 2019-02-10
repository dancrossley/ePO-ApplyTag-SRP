"""
McAfee ePO Apply Tag SmartResponse for LogRhythm
Dan Crossley | daniel.crossley@logrhythm.com
Jan 2019

This example should be considered a proof of concept only, and does not necessarily represent best practices recommended by LogRhythm.

Actions:
 - Applies a tag to the a system in McAfee ePO
 - Issues an agent wakeup to the system
 - Searches for a LogRhythm case associated Alarm ID. If a case is found:
    - Annotate the case
    - Adds the ePO system information to the LogRhythm case
    - Change case status to 'Mitigated'
 - If no associated case is found, exit

"""

from mcafee_epo import Client #https://pypi.org/project/mcafee-epo/
import json
import argparse
import urllib3
import requests
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #Disable certificate validation warnings

'''
Global Variables
'''
#ePO Credentials
EPO_URL = '<ePO URL goes here>'
EPO_UN = '<ePO Username goes here>'
EPO_PASS = '<ePO Password goes here>'
LR_URL = '<PM IP goes here>' #IP of the LogRhythm Platform Manager

#Bearer token for authenticating with LogRhythm API
BEARER_TOKEN = ''
OUTPUT_PATH = 'C:/Program Files/LogRhythm/LogRhythm System Monitor/VT-SRP/' #Path to read/write the case id for chained SRPs
HEADERS = { #Headers required for LogRhythm API calls. Do not modify
    'Content-Type': "application/json",
    'Authorization': "Bearer " + BEARER_TOKEN,
    'cache-control': "no-cache",
    }

def epo_apply_tag(c, sysname, tag):
    """Applies a tag to an endpoint in ePO

    Args:
        c: mcafee_epo client object
        sysname: the system name to apply the tag
        tag: tag to apply. Must be pre-defined in ePO.
    """
    c('system.applyTag', sysname, tag)
    print('ePO tag: \'{}\' applied to system: {}'.format(tag, sysname))

def epo_wakeup_agent(c, sysname):
    """Performs agent wakeup on the endpoint in ePO

    Args:
        c: mcafee_epo client object
        sysname: the system name to apply the tag
    """
    print('Performing agent wakeup..')
    c('system.wakeupAgent', sysname)
    print('Agent wakeup sent to system: {}'.format(sysname))

def epo_find_system(c, sysname):
    """Search for a hostname or IP address of a system within ePO and return pertinent information

    Args:
        c: mcafee_epo client object
        sysname: the system name to apply the tag

    Returns:
        a string containing summary system information from ePO.
    """
    system = c('system.find', sysname)
    #print(json.dumps(system, indent=4)) #Uncomment to print full epo information
    casenote = 'Name: {} '.format(system[0]["EPOComputerProperties.ComputerName"])
    casenote += 'Hostname: {} '.format(system[0]["EPOComputerProperties.IPHostName"])
    casenote += 'IP Address: {} '.format(system[0]["EPOComputerProperties.IPAddress"])
    casenote += 'OS: {} '.format(system[0]["EPOComputerProperties.OSType"])
    casenote += 'OS Version: {} '.format(system[0]["EPOComputerProperties.OSVersion"])
    casenote += 'OS Platform: {} '.format(system[0]["EPOComputerProperties.OSPlatform"])
    casenote += 'Agent GUID: {} '.format(system[0]["EPOLeafNode.AgentGUID"])
    casenote += 'To view system in ePO: ' + EPO_URL + '/core/orionTableDetail.do?nodeType=4&selectedTab=SYSTEMS&nodeIDs=&id=ComputerMgmt.computer.datasource&datasourceAttr=ComputerMgmt.computer.datasource&uid='+ str(system[0]["EPOComputerProperties.ParentID"]) + '&index=0&absoluteIndex=0&rt=epo.rt.computer'
    return casenote

def add_case_note(caseid, note):
    """Adds note to the case in LogRhythm

    Args:
        caseid: the LogRhythm case ID
        note: string containing note to add to case
    """
    url = "https://" + LR_URL + ":8501/lr-case-api/cases/" + caseid + "/evidence/note/"
    payload = "{\n  \"text\": \"" + note + "\"\n}"
    requests.request("POST", url, data=payload, headers=HEADERS, verify=False)

def change_case_status(caseid, status):
    """Updates a case status
        - Permissible status codes are:
            1 = Created
            2 = Completed
            3 = Incident
            4 = Mitigated
            5 = Resolved
    Args:
        caseid: ID of the case to be updated.
        status: new status of the case.
    """
    url = "https://" + LR_URL + ":8501/lr-case-api/cases/" + caseid + "/actions/changeStatus/"
    payload = "{\n  \"statusNumber\": " + status + "\n}"
    requests.request("PUT", url, data=payload, headers=HEADERS, verify=False)

def run_smartresponse(c, sysname, tag, alarmid):
    """Runs the main SRP actions.
    - Adds the given tag to the given system in ePO
    - Issues an agent wakeup to the system
    - Annotates the LogRhythm case with the above actions
    - Adds the ePO system information to the LogRhythm case

    Args:
        c: mcafee_epo client object
        sysname: the system name to apply the tag
        tag: tag to apply. Must be pre-defined in ePO.
        alarmid: The ID of the triggering alarm.
    """
    print('Adding tag to system in McAfee ePO..')
    epo_apply_tag(c, sysname, tag)
    #epo_wakeup_agent(c, sysname) #Uncomment to peform this action - currently it waits for confirmation (around 1 min)
    directory = os.path.join(OUTPUT_PATH, alarmid)
    if not os.path.exists(directory): #check for alarmid folder, exit if there is none
        print('No LogRhythm case found, exiting..')
        exit()
    fullpath = os.path.join(directory, 'case.txt')
    fhand = open(fullpath)
    caseid = fhand.read() #Get the LogRhythm dcaseid from file
    note = 'Tag applied to endpoint in McAfee ePO & agent wake up issued..' #Add note to case confirming actions performed
    add_case_note(caseid, note)
    casenote = epo_find_system(c, sysname)
    add_case_note(caseid, casenote) #Add note to case with ePO system information
    change_case_status(caseid, '4') #Change case status to mitigated   

def main():
    """Main execution code
    """
    client = Client(EPO_URL, EPO_UN, EPO_PASS) #Create epo client object wrapper
    parser = argparse.ArgumentParser(description='McAfee ePO ApplyTag SRP')
    parser.add_argument("-applytag", help="ePO tag to apply", required=True)
    parser.add_argument("-sysname", help="System name", required=True)
    parser.add_argument("-alarmid", help="LogRhythm Alarm ID", required=True)
    args = parser.parse_args()
    if (args.applytag) and (args.sysname):
        hostname = args.sysname.split(' ') #LR Alarm passed Host(Origin) as '<hostname> *', need to remove the * so ePO can find it
        run_smartresponse(client, hostname[0], args.applytag, args.alarmid)
    else:
        print('Usage: ePO-ApplyTag-SRP.py [-h] -applytag TAG -sysname SYSNAME -alarmid ALARMID')

if __name__ == "__main__":
    main()

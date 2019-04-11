#!/usr/bin/env python3


#Pprint is a good tool for printing dictionaries
import pprint
#Requests needed for API call
import requests
#Json needed for getting API repsonse info
import json
#Getpass used as backup to enter API username/secret
import getpass
#Os used to read local password file
import os
#pandas to convert api output to excel
import pandas as pd
#for different getpass commands
import sys
#time stuff
import time
import datetime

def API_creds():
    #Check is a `credentials.json` exists in local directory for the Client id/secret needed to get the bearer token.
    if os.path.isfile('./credentials.json'):
        with open('credentials.json', 'r') as vf_file_creds:
            vf_json_creds = json.load(vf_file_creds)
        try:
            vf_str_username = vf_json_creds['CLIENT_ID']
            vf_str_password = vf_json_creds['CLIENT_SECRET']
        except:
            print('Credentials file found but not in correct format.  Falling back to manual entry')
    #If there is no local credentials file, it prompts you.  FYI, getpass doesn't seem to work well in Windows.
    else:
        vf_str_username = input('email: ')
        if  sys.platform.lower()=="win32":
            vf_str_password = getpass.win_getpass(prompt='key: ')
        else:
            vf_str_password = getpass.getpass(prompt='key: ')
    vf_dict_headers = {
        'X-Auth-Email': vf_str_username,
        'X-Auth-Key': vf_str_password,
        'Content-Type': "application/json",
        }
    return(vf_dict_headers)

def get_zones(vf_dict_headers):
    url = "https://api.cloudflare.com/client/v4/zones/"
   
    response = requests.request("GET", url, headers=vf_dict_headers)

    vf_dict_data = json.loads(response.text)

    #pprint.pprint(vf_dict_data)
    #print(vf_dict_data['result'])
    list_of_zones = vf_dict_data['result']
    result_dict = {}
    x = 1
    for item in list_of_zones:
        result_dict[x]={'name':item['name'],'id':item['id']}
        x = x + 1
    #pprint.pprint(result_dict)

    print('Menu - Please select one of the following (or `q` to quit):')
    for item in result_dict.keys():
        #print(type(item))
        print(item,'.',result_dict[item]['name'])
    vf_str_select = input('Selection: ')
    #print(type(vf_str_select))
    while not(vf_str_select in str(result_dict.keys())):
        if vf_str_select == 'q':
            print('BYE FOR NOW!')
            exit()
        vf_str_select = input('Please select a valid number above or `q` to quit: ')
    vf_int_select = int(vf_str_select)
    zone_id_select = result_dict[vf_int_select]['id']
    #print(zone_id_select)
    #Find out if you want to parse by rule-id as well.
    vf_str_ruleid = input('Filter by ruleid? Y/N: ')
    good_answer = ['Y','y','n','N']
    while not(vf_str_ruleid in good_answer):
        vf_str_ruleid = input('Please respond Y/N/y/n: ')
    vf_dict_headers={}
    return(zone_id_select,vf_str_ruleid)

def get_FW_rules(vf_dict_headers,vf_str_zone_id):

    url = 'https://api.cloudflare.com/client/v4/zones/' + vf_str_zone_id + '/firewall/rules'
    response = requests.request("GET", url, headers=vf_dict_headers)

    vf_dict_data = json.loads(response.text)

    list_of_rules = vf_dict_data['result']
    result_dict = {}
    x = 1
    for item in list_of_rules:
        result_dict[x]={'name':item['description'],'id':item['id']}
        x = x + 1
    #pprint.pprint(result_dict)

    print('Menu - Please select one of the following (or `q` to quit):')
    for item in result_dict.keys():
        #print(type(item))
        print(item,'.',result_dict[item]['name'])
    vf_str_select = input('Selection: ')
    #print(type(vf_str_select))
    while not(vf_str_select in str(result_dict.keys())):
        if vf_str_select == 'q':
            print('BYE FOR NOW!')
            exit()
        vf_str_select = input('Please select a valid number above or `q` to quit: ')
    vf_int_select = int(vf_str_select)
    rule_id_select = result_dict[vf_int_select]['id']
    #print(rule_id_select)
    vf_dict_headers={}
    return(rule_id_select)

#will add time vs log number filter later
def time_vs_number():
    #Find out if you want to get logs by date or number.
    vf_str_type = input('Do you want log by recent (H)ours or (N)umber of logs: ')
    good_answer = ['H','h','N','n']
    while not(vf_str_type in good_answer):
        vf_str_type = input('Please respond H/N/h/n: ')
    if ((vf_str_type == 'N') or (vf_str_type == 'n')):
        vf_int_decision = 0
    else:
        vf_str_hours = input('How many hours of logs do you want to collect? (1-48): ')
        while not(vf_str_hours.isnumeric()):
            vf_str_hours = input('Please respond with number of hours b/w 1-48: ')
            while not((int(vf_str_hours) <= 48) and (int(vf_str_hours) != 0)):
                vf_str_hours = input('Please respond with number of hours b/w 1-48: ')
        vf_int_decision = int(vf_str_hours)
    return(vf_int_decision)

def get_logs_simple(vf_dict_headers,vf_str_zone_id,querystring):
    url = 'https://api.cloudflare.com/client/v4/zones/' + vf_str_zone_id + '/security/events'
    #print(url)
    response = requests.request("GET", url, headers=vf_dict_headers, params=querystring)
    vf_dict_data = json.loads(response.text)
    #pprint.pprint(vf_dict_data['result'])
    vf_dict_headers={}
    return(vf_dict_data['result'])

def get_logs_loop(vf_dict_headers,vf_str_zone_id,querystring):
    vf_list_logs = []
    cursor = '1'
    while (cursor != '' and cursor != None):
        if cursor == '1':
            cursor = ''
        else:
            querystring['cursor']=cursor
        url = 'https://api.cloudflare.com/client/v4/zones/' + vf_str_zone_id + '/security/events'
        #print(url)
        response = requests.request("GET", url, headers=vf_dict_headers, params=querystring)
        vf_dict_data = json.loads(response.text)
        if vf_dict_data['errors']:
            print(type(vf_dict_data['errors']))
            print(vf_dict_data['errors'])
            return(vf_list_logs)
        print('------')
        #pprint.pprint(vf_dict_data)
        #pprint.pprint(vf_dict_data['result'])
        vf_list_temp = vf_dict_data['result']
        #pprint.pprint(vf_dict_data)
        for item in vf_list_temp:
            vf_list_logs.append(item)
        dict_temp = vf_dict_data['result_info']['cursors']
        if 'before' in dict_temp.keys():
            cursor = vf_dict_data['result_info']['cursors']['before']
        else:
            cursor = ''
        print('cursor:',cursor)
        print('------------')
        print(len(vf_list_logs))
    vf_dict_headers={}    
    return(vf_list_logs)

def do_pandas(vf_list_logs):
    try:
        columns = ['ip', 'rule_id', 'ray_id', 'action', 'occured_at']
        vf_pand_logs = pd.DataFrame(columns=columns)
        for item in vm_list_logs:
            #print(item['ip'])    
            vf_pand_logs.loc[len(vf_pand_logs)] = [item['ip'], item['rule_id'], item['ray_id'], item['action'], item['occurred_at']]
        #print(vf_pand_logs)
        return(vf_pand_logs)
    except:
        print(sys.exc_info())
        exit()

def write_excel(vf_pand_logs):
    vf_str_filename = time.strftime('%Y%m%d%H%M%S',time.localtime())+'-CFlog.xlsx'
    vf_pand_logs.to_excel(vf_str_filename)
  
#Main program.       
if __name__ == '__main__':
    vm_dict_headers = API_creds()
    vm_str_zone_id,vm_str_ruleid = get_zones(vm_dict_headers)
    if (vm_str_ruleid == 'Y') or (vm_str_ruleid == 'y'):
        vm_str_rule_id = get_FW_rules(vm_dict_headers,vm_str_zone_id)
    vm_int_type = time_vs_number()
    if ('vm_str_rule_id' in vars()) and (vm_int_type == 0):
        querystring = {"limit":"1000","rule_id":vm_str_rule_id}
        vm_list_logs = get_logs_simple(vm_dict_headers,vm_str_zone_id,querystring)
        vm_pand_logs = do_pandas(vm_list_logs)
    elif vm_int_type == 0:
        querystring = {"limit":"1000"}
        vm_list_logs = get_logs_simple(vm_dict_headers,vm_str_zone_id,querystring)
        vm_pand_logs = do_pandas(vm_list_logs)
    elif 'vm_str_rule_id' not in vars():
        time3 = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - datetime.timedelta(hours=vm_int_type)
        time4 = time3.isoformat()
        time4 = time4[:-13] + 'Z'
        querystring = {"limit":"1000","since":time4}
        vm_list_logs = get_logs_loop(vm_dict_headers,vm_str_zone_id,querystring)
        #print(vm_list_logs)
        print('-----------')
        print(datetime.datetime.utcnow())
        vm_pand_logs = do_pandas(vm_list_logs)
        print(datetime.datetime.utcnow())
    else:
        time3 = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - datetime.timedelta(hours=vm_int_type)
        #time3 = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - datetime.timedelta(days=3)
        time4 = time3.isoformat()
        time4 = time4[:-13] + 'Z'
        print(time4)
        querystring = {"limit":"1000","rule_id":vm_str_rule_id,"since":time4}
        #querystring = {"limit":"1000","since":time4}
        vm_list_logs = get_logs_loop(vm_dict_headers,vm_str_zone_id,querystring)
        #print(vm_list_logs)
        print('-----------')
        print(datetime.datetime.utcnow())
        vm_pand_logs = do_pandas(vm_list_logs)
        print(datetime.datetime.utcnow())
    print(datetime.datetime.utcnow())
    write_excel(vm_pand_logs)
    print(datetime.datetime.utcnow())
    vm_dict_headers = {}

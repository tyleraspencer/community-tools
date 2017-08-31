#!/usr/bin/env python

## Purpose: 
##  	add/remove specified privileges from list of groups
## Authors:
##  	tyler.spencer@thoughtspot.com
## Created:
##  	30-August-2017


import sys, requests, json, time, collections, socket, argparse

#suppress warnings for insecure HTTP connection
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#session cookies
session = requests.session()


## Safeguards:
	## verify privileges are valid
	## remove duplicate privilege inputs
	## validate groups
	## prevent update of any system groups (this returns 403 anyways)
	## don't update timestamp if no privileges change
	## adding a privilege trumps deleting a privilege

################################################################
## GLOBAL VARIABLES TO MODIFY
thoughtspot_host = "http://"
username = ""
password = ""
groups_to_modify = ["1","2","3","4","5","6","7"]
privileges_to_remove = ["USERDATAUPLOADING","DATADOWNLOADING","DATAMANAGEMENT"]
privileges_to_add = ["ADMINISTRATION"]
################################################################

## PRIVILEGE OPTION:
	## "DATAMANAGEMENT"
	## "DATADOWNLOADING"
	## "USERDATAUPLOADING"
	## "ADMINISTRATION"
	## "SHAREWITHALL"
	## "JOBSCHEDULING"


def main():
	if login():
		if validate_privileges():
			groups = get_groups()
			for group in groups:
				group_detailes = get_group_details(group)
				group_name = group_detailes["header"]["name"]
				current_privileges = group_detailes["privileges"]
				try:
					group_detailes["privileges"] = list(set(group_detailes["privileges"]) - set(privileges_to_remove))
					group_detailes["privileges"] = group_detailes["privileges"] + (list(set(privileges_to_add) - set(group_detailes["privileges"])))
					if set(current_privileges) != set(group_detailes["privileges"]):
						group_detailes["header"]["modified"] = int(round(time.time() * 1000))
						status_code = update_privileges(group_detailes["header"]["id"], convert(group_detailes))
						if status_code == 204:
							print "Privileges successfully updated for " + group_name
						else:
							print "Update failed for " + group_name + " - status code: " + str(status_code)
					else:
						print group_name + " is already up to date"
				except:
					print "Update failed for " + group_name + " - Unknown error"
		else:
			print "Invalid privilege(s) detected"


def login():
	#send connection credentials
	credentials = {"username": username, "password": password, "rememberme": True}
	login = session.post(thoughtspot_host + '/callosum/v1/session/login', data=credentials, verify=False)
	if login.status_code != 200:
		print "Server connection failed. Status code: " + str(login.status_code)
		return False
	else:
		return True


def validate_privileges():
	URL = thoughtspot_host + '/callosum/v1/session/privileges'
	response = session.get(URL, verify=False)
	valid_privileges = json.loads(response.text)
	if set(privileges_to_remove).issubset(valid_privileges) and set(privileges_to_add).issubset(valid_privileges):
		return True
	else:
		return False


def get_groups():
	groups = []	
	URL = thoughtspot_host + '/callosum/v1/metadata/list?type=USER_GROUP'
	response = session.get(URL, verify=False)
	data = json.loads(response.text)
	system_groups = ["System","Administrator","All"] #these are the system groups that should never be modified
	groups = {}
	for i in data["headers"]:
		if i["name"] in groups_to_modify and i["name"] not in system_groups:
			groups[i["id"]] = i["name"]
	return groups


def get_group_details(guid):
	URL = thoughtspot_host + '/callosum/v1/metadata/detail/' + guid + '?type=USER_GROUP'
	response = session.get(URL)
	results = json.loads(response.text)
	return results


def update_privileges(guid, content):
	URL = thoughtspot_host + '/callosum/v1/session/group/update'
	data = {"groupid": guid, "content": str(content)}
	response = session.post(URL, data=data)
	return response.status_code


def convert(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data


if __name__ == "__main__":
	main()



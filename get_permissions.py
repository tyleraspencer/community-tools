#!/usr/bin/env python

"""
Copyright 2017 ThoughtSpot

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, 
modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS 
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT 
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

## Purpose: 
##  	determine ownership and permissions for all system objects
## Authors:
##  	tyler.spencer@thoughtspot.com
## Created:
##  	16-June-2017

import sys, requests, json, socket, csv, argparse, re
from collections import defaultdict

#suppress warnings for insecure HTTP connection
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


#session cookies
session = requests.session()

def parse_args():
    """Parses the arguments from the command line."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--thoughtspot_host", required=True,
                        help="domain or ip.  E.g. http://1.1.1.1")
    parser.add_argument("-u", "--username", required=True,
                        help="username - must have administrative privileges")
    parser.add_argument("-p", "--password", required=True,
                        help="password - must have administrative privileges")
    parser.add_argument("-d", "--delimiter", default=',',
                        help="character to seperate values by.  Default to comma")
    parser.add_argument("-c", "--csv", action="store_true",
                        help="create csv file called permissions.csv")
    parser.add_argument("-s", "--share", action="store_true",
                        help="output usable format for share api")
    return parser.parse_args()

args = parse_args()

def main():
	if login():
		users = get_ug("USER")
		groups = get_ug("USER_GROUP")
		users_in_groups = get_users_in_groups()

		answer="QUESTION_ANSWER_SHEET" ## SHEET will eventually be depricated and I will have to switch to BOOK
		pinboard="PINBOARD_ANSWER_SHEET"
		data="LOGICAL_TABLE"
	

		if args.share:
			permissionsList = [["Object ID", "Object Type", "User ID", "Permission Type"]]
		else:
			permissionsList = [["Object Name", "Object Owner", "Object Type", "User with Permission", "Permission Group", "Group Source"]]
	
		## Get data for all Answers
		answerMetadata = get_metadata(answer)
		answerPermissions = get_permissions(answer, answerMetadata)
	
		permissionsList = process_permissions(users, groups, users_in_groups, permissionsList, answer, answerMetadata, answerPermissions)
	
	
		## Get data for all Pinboards
		pinboardMetadata = get_metadata(pinboard)
		pinboardPermissions = get_permissions(pinboard, pinboardMetadata)
	
		permissionsList = process_permissions(users, groups, users_in_groups, permissionsList, pinboard, pinboardMetadata, pinboardPermissions)
	
	
		## Get data for all Data objects
		dataMetadata = get_metadata(data)
		dataPermissions = get_permissions(data, dataMetadata)
	
		permissionsList = process_permissions(users, groups, users_in_groups, permissionsList, data, dataMetadata, dataPermissions)
	
		## print output
		if args.csv:
			with open('permissions.csv', 'w') as csvFile:
				csv_writer = csv.writer(csvFile, delimiter=args.delimiter)
				csv_writer.writerows(permissionsList)
		else:
			for row in permissionsList:
				print args.delimiter.join(row)



def login():
	#send connection credentials
	credentials = {"username": args.username, "password": args.password, "rememberme": True}
	login = session.post(args.thoughtspot_host + '/callosum/v1/session/login', data=credentials, verify=False)
	if login.status_code != 200:
		print "Server connection failed. Status code: " + str(login.status_code)
		return False
	else:
		return True


#run this check on a name if you suspect there may be foreign characters
def is_ascii(string):
	if (re.sub('[ -~]', '', string)) != "":
		string = "non-ascii characters detected"
	return string


#output: [{guid:name},{guid:name} ...].  ugType should be USER or USER_GROUP
def get_ug(ugType):
	URL = args.thoughtspot_host + '/callosum/v1/metadata/list?type=' + ugType
	
	response = session.get(URL)
	data = json.loads(response.text)

	UGs = {}
	for UG in data["headers"]:
		UGs[UG["id"]] = UG["name"]
	return UGs


#output: raw metadata
def get_metadata(objType):
	URL = args.thoughtspot_host + '/callosum/v1/metadata/list?type=' + objType
	response = session.get(URL)
	results = json.loads(response.text)
	return results


#output: raw metadata
def get_permissions(objType, metadata):
	GUIDs = []
	for GUID in metadata["headers"]:
		GUIDs.append(str(GUID["id"]))

	permissionURL = args.thoughtspot_host + '/callosum/v1/security/definedpermission'
	
	permissionParameters = {"type": objType, "id": str(GUIDs), "dependentshare": True}
	permissionResponse = session.post(permissionURL, data=permissionParameters)
	permissions = json.loads(permissionResponse.text)
	
	return permissions


def get_users_in_groups():
	URL = args.thoughtspot_host + '/callosum/v1/tspublic/v1/user/list'
	response = session.get(URL)
	group_data = json.loads(response.text)

	groups = defaultdict(list)
	for obj in group_data:
		if "_USER" in str(obj["principalTypeEnum"]):
			for group in obj["groupNames"]:
				groups[group].append(obj["name"])

	return groups


def process_permissions(users, groups, users_in_groups, permissionsList, raw_objType, objMetadata, objPermissions):
	if raw_objType == "QUESTION_ANSWER_SHEET":
		objType = "answer"
	elif raw_objType == "PINBOARD_ANSWER_SHEET":
		objType = "pinboard"

	for obj in objMetadata["headers"]:
		if raw_objType == "LOGICAL_TABLE":
			if obj["type"] == "ONE_TO_ONE_LOGICAL":
				objType = "table"
			elif obj["type"] == "WORKSHEET":
				objType = "worksheet"
			elif obj["type"] == "AGGR_WORKSHEET":
				objType = "aggregated worksheet"
			elif obj["type"] == "USER_DEFINED":
				objType = "uploaded table"
			else:
				objType = "unknown data object"
		objGUID = obj["id"]
		objectPermissions = objPermissions[objGUID]["permissions"]
		
		## all share users
		for ugGUID in objectPermissions:
			if args.share:
				permissionsList.append([is_ascii(obj["id"]), is_ascii(raw_objType), ugGUID, is_ascii(objectPermissions[ugGUID]["shareMode"])])
			else:
				if ugGUID in groups: # this GUID is a group
					for user in users_in_groups[str(groups[ugGUID])]:
						permissionsList.append([is_ascii(obj["name"]), is_ascii(obj["authorName"]), objType, is_ascii(user), is_ascii(objectPermissions[ugGUID]["shareMode"]), is_ascii(groups[ugGUID])])
				else: # this GUID is a user
					permissionsList.append([is_ascii(obj["name"]), is_ascii(obj["authorName"]), objType, is_ascii(users[ugGUID]), is_ascii(objectPermissions[ugGUID]["shareMode"]), "N/A"])
		
		## all owners
		if args.share:
			permissionsList.append([is_ascii(obj["id"]), is_ascii(raw_objType), obj["author"], "MODIFY"])
		else:
			permissionsList.append([is_ascii(obj["name"]), is_ascii(obj["authorName"]), objType, is_ascii(obj["authorName"]), "MODIFY", "N/A"])


	return permissionsList


if __name__ == "__main__":
	main()



"""
Copyright <year> ThoughtSpot

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


## Author: tyler.spencer@thoughtspot.com
## Date: 11/17/2016
## Purpose: sum total number of rows, estimated table size, and actual data volume 
##		for all imported data.  Only factors in user-uploaded data.  Base table data
##		and Data Connect data are not accounted for.


## Steps:
##	1) establish connection to ThoughtSpot server
##	2) collect server statistics from falcon
##	3) collect logical table GUIDs and associated authors for all user defined tables
##	4) match logical table GUIDs to physical table GUIDs
##	5) use physical table GUIDs to find desired falcon server stats
##	6) sum server stats per user
##
##	Path to match Author to Database Stats:
##		Author --> Logical Table GUID --> Physical Table GUID --> Server Stats



##  QUESTIONS:
##  	Is there are way to match author to Physical Table GUID?


## 	TODO:
##  	Accept argument to look only at specific User/Group
##		Add CSV as output option
##		Automatically pass shell password


import sys
import requests
import json
import csv
import subprocess
from collections import defaultdict
import argparse
import time

#suppress warnings for insecure HTTP connection
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# HOST_NAME = "thoughtspot1.rizepoint.com"
HOST_NAME = ""
THOUGHTSPOT_HOST = "http://"+HOST_NAME

USERNAME = ""
PASSWORD = ""

SHELL_PASSWORD = ""

session = requests.session()

def main():
	if login():
		args = parse_args() # put this in table metadata - if no results then check
		userTableMetrics = get_server_stats()
		get_table_metadata(args, userTableMetrics)


def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("--csv", action='store_true')
	parser.add_argument("-u", "--user",
						default="",
						help="name of user to search for")
	parser.add_argument("-g", "--group",
						default="",
						help="name of group to search for")
	return parser.parse_args()


def login():
	print "connecting to ThoughtSpot ..."
	credentials = {"username": USERNAME, "password": PASSWORD, "rememberme": True}
	login = session.post(THOUGHTSPOT_HOST + '/callosum/v1/session/login', data=credentials, verify=False)
	if login.status_code == 200:
		return True
	else:
		print "ThoughtSpot connection failed. Status code: '" + str(login.status_code) + "'"
		time.sleep(2)
		return False

#I should only check to see if a user exists after I run the calculation and discover that there is no data.  This will make the who thing seem faster.
def verify_user(user): 
	if user is not None:
		users_response = session.get(THOUGHTSPOT_HOST+"/callosum/v1/session/user/list", verify=False)
		users = json.loads(users_response.text)
		for i in users['authorName']: #figure out what the path to authorName is
			if i == user:
				return True

		print "User not found. Please verify user and try again"
		time.sleep(2)
		return False
		# instead of return false - terminate script


def find_users_in_group(group_name):
	print 


#TODO: add logic to only look for specific author using value passed in 'args'
def get_table_metadata(args, userTableMetrics):
	print "retrieving user defined table metadata ..."
	#get a list of all user defined tables
	url=THOUGHTSPOT_HOST+"/callosum/v1/metadata/list?type=LOGICAL_TABLE&subtypes=%5BUSER_DEFINED%5D&sort=AUTHOR"
	response = session.get(url, verify=False)

	logical_table_metadata = json.loads(response.text)
	
	currentAuthorName = ""
	authorTableArray = []
	authorMetricsDict = defaultdict(lambda: [0,0,0]) # unncessary when i actually get a running version of the script
	
	print "calculating ..."
	for column in logical_table_metadata['headers']:
		#find specific physical GUIDs based on given list of logical GUIDs
		response = session.get(THOUGHTSPOT_HOST+"/callosum/v1/metadata/detail/"+column['id']+"?type=LOGICAL_TABLE")
		physical_table_metadata = json.loads(response.text)
		physicalGUID = physical_table_metadata['physicalTableGUID']
		#perform calculation
		for i, val in enumerate(userTableMetrics[physicalGUID]): #will loop once for each metric in the array
			authorMetricsDict[column["authorName"]][i] += float(val) #defaultDict starts each new author at [0,0,0] then values summed from there

		# authorTableArray.append([column["authorName"],column["name"]]) #list of authors and tables
		output = column["authorName"] + "	" + str([format(i, '.4f') for i in authorMetricsDict[column["authorName"]]]) #round all values in Metrics Dictionary to 4 decimal places

		#print each output
		if currentAuthorName == column["authorName"]: #add
			sys.stdout.write("\x1b[2K\r" + output)
			sys.stdout.flush()
			# sys.stdout.write("\n" + output)
		else:
			sys.stdout.write("\n" + output)
		currentAuthorName = column["authorName"]
	sys.stdout.write("\n\n")

	# for row in authorTableArray:
	# 	print row

def get_server_stats():
	print "retrieving server statistics ..."
	command = "ssh admin@"+HOST_NAME+" \"echo 'show detailed statistics for server;' | /usr/local/scaligent/bin/tql\""
	proc = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = proc.communicate()
	# columnHeaders = err.replace('show detailed statistics for server;\n', '').replace('\nStatement executed successfully. ', '').split('\n', 1)[0]
	out = out[:-1].replace(' ', '').split('\n')
	data = {}
	for row in out:
		if "USERDATA" in row:
			userdata = row.split('|')
			# Table Guid : [ Total Row Count, Estimated Size (MB), Cluster Space Used (MB) ]
			data[userdata[3]] = [userdata[6],userdata[8],userdata[11]]
	return data


if __name__ == "__main__":
	main()


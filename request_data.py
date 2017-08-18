#!/usr/bin/python


## Purpose: 
##  	request data from pinboard in ThoughtSpot
## Authors:
##  	tyler.spencer@thoughtspot.com
## Created:
##  	29-June-2016


import sys, requests, json, socket, csv, argparse
from collections import defaultdict

#thoughtspot_host = 'http://' + socket.gethostname()
thoughtspot_host = 'http://172.31.24.136'
username = 'portal'
password = 'portal'
pinboardId = "6017d81a-e33f-48ab-b943-1538a5b8526c"


#session cookies
session = requests.session()
session.get(thoughtspot_host)

def main():
	if login() == True:
		args = parse_args()
		getData(args)

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("--csv", action='store_true')
	args = parser.parse_args()
	return args

def login():
	#send connection credentials
	credentials = {"username": username, "password": password, "rememberme": True}
	login = session.post(thoughtspot_host + '/callosum/v1/session/login', data=credentials)
	if login.status_code != 200:
		print "Server connection failed. Status code: " + str(login.status_code)
		return False

	#check for successful connection
	checklogin = session.get(thoughtspot_host + '/callosum/v1/session/info')
	response = json.loads(checklogin.text)
	if username == response['userName']:
		return True
	else:
		print "Server connection failed. Status code: " + str(checklogin.status_code)
		return False

def getData(args):
	myURL = thoughtspot_host + "/callosum/v1/tspublic/v1/pinboarddata?id=" + pinboardId
	
	#output in json
	response = session.post(myURL)
	data = json.loads(response.text)

	if args.csv:
		nameDict = {}
		countDict = defaultdict(lambda: 1, cd = {})
		for viz in data:
			#check for duplicate names
			name = data[viz]['name']
			if name in nameDict.values():
				nameDict[viz] = name + '(' + str(countDict[name]) + ')'
				countDict[name] += 1
			else:
				nameDict[viz] = name
			#write to csv
			print "writing " + nameDict[viz] + " ..."
			with open(nameDict[viz] + '.csv', 'w') as csvFile:
				csv_writer = csv.writer(csvFile)
				csv_writer.writerow(data[viz]['columnNames'])
				csv_writer.writerows(data[viz]['data'])
	else:
		print data

if __name__ == "__main__":
	main()

	
#!/usr/bin/python

"""
Copyright 2018 ThoughtSpot

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
##  	request data from pinboard in ThoughtSpot
## Authors:
##  	tyler.spencer
## Created:
##  	29-June-2016
## Usage:
##	modify variables on lines 34-40
##	python request_data.py
##	default output is JSON
##	optionally add "--csv" flag for CSV output


import sys, requests, json, socket, csv, argparse
from collections import defaultdict

##################VARIABLES TO MODIFY##################
thoughtspot_host = 'https://' + ''
username = ''
password = ''
pinboardId = ''
vizId = '' ## leave blank to get all data in pinboard
#######################################################

#session cookies
session = requests.session()
session.headers = {"X-Requested-By": "ThoughtSpot"}  ## needed for 4.5 and above

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
	login = session.post(thoughtspot_host + '/callosum/v1/tspublic/v1/session/login', data=credentials)
	if login.status_code != 204:
		print "Server connection failed. Status code: " + str(login.status_code)
		return False
	else:
		return True

def getData(args):
	myURL = thoughtspot_host + "/callosum/v1/tspublic/v1/pinboarddata?id=" + pinboardId
	
	if vizId:
		myURL = myURL + '&vizid=%5B' + vizId + '%5D'
	
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

	

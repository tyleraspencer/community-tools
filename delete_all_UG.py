#!/usr/bin/python

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


import sys, requests, json, csv, argparse, socket, time
from collections import defaultdict

#suppress warnings for insecure HTTP connection
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

thoughtspot_host = ''
username = ''
password = ''

session = requests.session()

args = parse_args()

def main():
	if login():
		if args.users:
			delete_users()
		if args.groups:
			delete_groups()
		if args.users == False and args.groups == False:
			print "please add a '--users' and/or '--groups' flag"

#site analytics report pinboard
def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("--users", action='store_true')
	parser.add_argument("--groups", action='store_true')
	parser.add_argument("-t", "--thoughtspot_host", required=True,
                        help="domain or ip.  E.g. http://1.1.1.1")
    parser.add_argument("-u", "--username", required=True,
                        help="username - must have administrative privileges")
    parser.add_argument("-p", "--password", required=True,
                        help="password - must have administrative privileges")

	return parser.parse_args()


def login():
	print "connecting to server ..."
	credentials = {"username": args.username, "password": args.password, "rememberme": True}
	login = session.post(args.thoughtspot_host + '/callosum/v1/session/login', data=credentials, verify=False)
	if login.status_code == 200:
		return True
	else:
		print "Server connection failed. Status code: '" + str(login.status_code) + "'"
		time.sleep(1)
		return False


def delete_users():
	userURL = args.thoughtspot_host + '/callosum/v1/metadata/list?type=USER'
	
	response = session.get(userURL, verify=False)
	data = json.loads(response.text)

	number_of_users = len(data["headers"])
	user_count = 0
	for user in data["headers"]:
		user_count += 1
		sys.stdout.write("\x1b[2K\r" + str(user_count) + " of " + str(number_of_users) + " users deleted ...")
		sys.stdout.flush()
		deleteURL = args.thoughtspot_host + '/callosum/v1/session/user/delete/' + user["id"]
		session.delete(deleteURL, verify=False)
	sys.stdout.write("\n")


def delete_groups():
	groupURL = args.thoughtspot_host + '/callosum/v1/metadata/list?type=USER_GROUP'
	
	response = session.get(groupURL, verify=False)
	data = json.loads(response.text)

	number_of_groups = len(data["headers"])
	group_count = 0
	for group in data["headers"]:
		group_count += 1
		sys.stdout.write("\x1b[2K\r" + str(group_count) + " of " + str(number_of_groups) + " groups deleted ...")
		sys.stdout.flush()
		deleteURL = args.thoughtspot_host + '/callosum/v1/session/group/delete/' + group["id"]
		session.delete(deleteURL, verify=False)
	sys.stdout.write("\n")



if __name__ == "__main__":
	main()


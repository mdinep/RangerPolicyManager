#!/usr/bin/python3
import os
import sys
import time
import getopt
import configparser
import json
import ast
import logging
from PolicyObject import *
from apache_ranger.model.ranger_service import *
from apache_ranger.client.ranger_client import *
from apache_ranger.model.ranger_policy import *

'''logging configuration and instantiation of global config object'''
logging.basicConfig(filename=os.getcwd() + '/RangerPolicyManager' + str(time.time()).replace(".", "") + '.log', encoding='utf-8', level=logging.DEBUG)
config = configparser.ConfigParser()

'''
Method to iterate over services in config file marked for processing
These are defined as a list under the 'componentClasses' property in hte Auth section of the config file
For each service to be processed, the full set of policy properties is read and each one is processed individually
'''
def processPolicies(ranger, componentName):
	if len(componentName) == 0:
		logging.error("No services defined. Please check config file and update 'componentClasses' before rerunning")
		sys.exit()

	for key in config[componentName]:
		try:
			parsedKey = json.loads(config[componentName][key])
			policyObj = PolicyObject(key, parsedKey['resource'])
			policyDetails = parsedKey['policy']
			createPolicy(ranger, key, config[componentName], policyObj, policyDetails)
		except Exception as ex:
			logging.error("Exception in processPolicies while trying to parse policy information: %s" % ex)
			sys.exit()

'''
Method to process individual policies defined as properties under a service section in the config file
Keys are used as the policy name to be written to Ranger, and values are the allowed and denied properties of a polocy
Values are stored as JSON in the config.
For more complex policies that appliy to a single resource, this does support array objects for the 'policy' section of the JSON
'''
def createPolicy(ranger, key, serviceName, policyObj, policyDetails):
	policy = RangerPolicy()
	policy.service = serviceName
	policy.name = key
	policy.resources = policyObj.policyResources
	allowedItem = RangerPolicyItem()
	deniedItem = RangerPolicyItem()

	if "[" in policyDetails:
		try:
			policyList = ast.literal_eval(policyDetails)
			allowUsers, allowItems, denyUsers, denyItems = processPolicyList(policyList, policyObj)
			allowedItem.users = allowUsers
			allowedItem.accesses = allowItems
			deniedItem.users = denyUsers
			deniedItem.accesses = denyItems
		except Exception as ex:
			logging.error("Error processing policy array: %s" % ex)
			sys.exit()
	else:
		try:
			objectDetails = policyObj.processPolicy(policyDetails)
			allowedItem.users = objectDetails["allowedUsers"]
			allowedItem.accesses = objectDetails["allowedAccess"]
			deniedItem.users = objectDetails["deniedUsers"]
			deniedItem.accesses = objectDetails["deniedAccess"]
		except Exception as ex:
			logging.error("Error processing policy info: %s" % ex)
			sys.exit()

	policy.policyItems = [allowedItem]
	policy.denyPolicyItems = [deniedItem]

	try:
		created_policy = ranger.create_policy(policy)
		logging.info("created policy: name=" + created_policy.name + ", id=" + str(created_policy.id))
	except Exception as ex:
		logging.error("Failed to create policy: name=%s" % policy.name)

'''
Method to handle list objects for the 'policy' portion of a policy's JSON
This iterates over the items in the policy and builds the user and access collections used to write a policy
'''
def processPolicyList(policyList, policyObj):
	allowUsers = []
	allowItems = []
	denyUsers = []
	denyItems = []
	itemCounter = 0
	for pol in policyList:
		try:
			objectDetails = policyObj.processPolicy(pol)
			itemCounter += 1
			logging.info("Processing policy item %d of %d" % (itemCounter,len(policyList)))
			allowUsers.append([objectDetails["allowedUsers"]])
			allowItems.append([objectDetails["allowedAccess"]])
			denyUsers.append([objectDetails["deniedUsers"]])
			denyItems.append([objectDetails["deniedAccess"]])
		except Exception as ex:
			logging.error("Unable to process policy object: %s" % ex)
			sys.exit()
	return allowUsers, allowItems, denyUsers, denyItems

'''
Method to programatically delete policies
This iterares over the services defined in the 'componentClasses' property of the Auth section in the config
For each service, a list of policy names is built from the keys present in the config
The service in Ranger is then queried to get a collection of all currently existing policies
The values of both lists is normalized and then compared to build a sublist of polcies present in Ranger but not in the config
All polices absent from the config are then deleted based on policy id
'''
def deletePolicy(ranger, serviceName):
	configKeySet = []
	rangerKeySet = []
	policies = ranger.get_policies_in_service(serviceName)
	if len(policies) > 0:
		for plcy in policies:
			rangerKeySet.append(plcy.name.strip().lower())
		for key in config[serviceName]:
			configKeySet.append(key.strip().lower())
		configKeySet.sort()
		rangerKeySet.sort()
		itemsToDelete = [x for x in rangerKeySet if x not in configKeySet]
		for item in itemsToDelete:
			for plcy in policies:
				if plcy.name.strip().lower() == item:
					try:
						ranger.delete_policy_by_id(plcy.id)
						logging.info("deleted policy: id=%s, name=%s" % (plcy.id, plcy.name.strip))
					except Exception as ex:
						logging.error("Unable to delete policy: id=%s, name=%s" % (plcy.id, plcy.name.strip))
	else:
		logging.warning("Service %s does not appear to have any policies currently set. Nothing to delete." % serviceName)

'''Main method'''
def main(argv):
	processType = ""
	cfgProvided = False
	opts, args = getopt.getopt(argv,"hadc:",["help","config=","add","del","delete"])
	if len(argv) < 4 and "h" not in opts:
		logging.error("Not enough arguments supplied. Try running with -h or --help for more info")
		sys.exit()
	if len(argv) > 4:
		logging.error("Too many arguments supplied. Try running with -h or --help for more info")
		sys.exit()

	for opt, arg in opts:
		if opt in ("c", "--config"):
			cfgProvided = True
			config.read(arg)
		elif opt in ("-a","--add"):
			processType = "add"
		elif opt in ("-d", "--del", "--delete"):
			processType = "del"
		elif opt in ("-h","--help"):
			print("\nto add policies from config: python3 " + __file__ + " -c <configFile> -a")
			print("\nto delete policies by config: python3 " + __file__ + " -c <configFile> -d")

	if processType == "" and cfgProvided == False:
		logging.error("No run type or config file provided. Try running with -h or --help for more info")
		sys.exit()
	elif processType == "" and cfgProvided == True:
		logging.warning("No run type privided. Defaulting to add policies.")
		processType = "add"


	ranger_url = config['Auth']['rangerURL']
	ranger_auth = (config['Auth']['rangerAuthUser'], config['Auth']['rangerAuthPW'])
	rangerComponents = config['Auth']['componentClasses'].split(",")

	ranger = RangerClient(ranger_url, ranger_auth)

	for componentName in rangerComponents:
		if processType == "add":
			processPolicies(ranger, componentName.strip())
		elif processType == "del":
			deletePolicy(ranger, componentName.strip())
		else:
			logging.error("Invalid processing type defined. Please specify at runtime")
			sys.exit()

if __name__ == "__main__":
		main(sys.argv[1:])
#!/usr/bin/python3

import configparser
import json
from PolicyObject import *
from apache_ranger.model.ranger_service import *
from apache_ranger.client.ranger_client import *
from apache_ranger.model.ranger_policy  import *

config = configparser.ConfigParser()

ranger_url  = config['Auth']['rangerURL']
ranger_auth = (config['Auth']['rangerAuthUser'],config['Auth']['rangerAuthPW'])

rangerComponents = config['Auth']['componentClasses'].split(,).strip()

for component in rangerComponents:
	processPolicies(component)
	
def processPolicies(componentName):
	for key in config[componentName]:
		parsedKey = json.loads(config[componentName][key])
		policyObj = PolicyObject(key, parsedKey['resource'])
		policyDetails = policyObj.processPolicy(parsedKey['policy'])
		createPolicy(key, config[componentName], policyObj, policyDetails)
		
def createPolicy(key, serviceName, policyObj, policyDetails):
	policy = RangerPolicy()
	policy.service = serviceName
	policy.name = key
	policy.resources = policyObj.policyResources
	
class PolicyObject: 

    def __init__(self, policyName, resourceString):
        self.policyName = policyName
        self.policyResources = self.processResource(resourceString)
        self.policyDetails = {}
    
    def processResource(self, resourceString):
        policyObjects = resourceString.split(",")
        policyResources = {}
        for policyItem in policyObjects:
            pKey, pVal = policyItem.split(":")
            policyResources[pKey.strip()] = pVal.strip()
        return policyResources
     

    def processPolicy(self, policyString):
        allowedUser, allowedString, denyUser, denyString = policyString.split("|")
        policyDetails = {}
        aUser, aAccess = self.parsePolicy(allowedUser, allowedString)
        dUser, dAccess = self.parsePolicy(denyUser, denyString)
        policyDetails["allowedUsers"] = aUser
        policyDetails["allowedAccess"] = aAccess
        policyDetails["deniedUsers"] = dUser
        policyDetails["deniedAccess"] = dAccess
        return policyDetails
        
    def parsePolicy(self, allowedUser, allowedString):
        pUsers = allowedUser.split(",")
        pAccess = allowedString.split(",")
        return pUsers, pAccess
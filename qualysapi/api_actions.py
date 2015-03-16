from lxml import objectify
import qualysapi.api_objects
from qualysapi.api_objects import *

class QGActions(object):  
    def getHost(host):
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'ips': host, 'details': 'All'}
        hostData = objectify.fromstring(self.request(call, parameters)).RESPONSE
        try:
            hostData = hostData.HOST_LIST.HOST
            return Host(hostData.DNS, hostData.ID, hostData.IP, hostData.LAST_VULN_SCAN_DATETIME, hostData.NETBIOS, hostData.OS, hostData.TRACKING_METHOD)
        except AttributeError:
            return Host("", "", host, "never", "", "", "")
        
    def getHostRange(self, start, end):
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'ips': start+'-'+end}
        hostData = objectify.fromstring(self.request(call, parameters))
        hostArray = []
        for host in hostData.RESPONSE.HOST_LIST.HOST:
            hostArray.append(Host(host.DNS, host.ID, host.IP, host.LAST_VULN_SCAN_DATETIME, host.NETBIOS, host.OS, host.TRACKING_METHOD))
            
        return hostArray
        
    def listAssetGroups(self, groupName=''):
        call = '/api/2.0/fo/asset/group/'
        if groupName == '':
            agData = objectify.fromstring(self.request(call))
        else:
            agData = objectify.fromstring(self.request(call, 'title='+groupName)).RESPONSE
            
        groupsArray = []
        scanipsArray = []
        scannersArray = []
        for group in agData.ASSET_GROUP:
            try:
                for scanip in agData.ASSET_GROUP.SCANIPS:
                    scanipsArray.append(scanip.IP)
            except AttributeError:
                scanipsArray = [] # No IPs defined to scan.
                
            for scanner in agData.ASSET_GROUP.SCANNER_APPLIANCES.SCANNER_APPLIANCE:
                scannersArray.append(scanner.SCANNER_APPLIANCE_NAME)
                
            groupsArray.append(AssetGroup(group.BUSINESS_IMPACT, group.ID, group.LAST_UPDATE, scanipsArray, scannersArray, group.TITLE))
            
        return groupsArray
        
        
    def notScannedSince(self, days):
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'details': 'All'}
        hostData = objectify.fromstring(self.request(call, parameters))
        hostArray = []
        today = datetime.date.today()
        for host in hostData.RESPONSE.HOST_LIST.HOST:
            last_scan = str(host.LAST_VULN_SCAN_DATETIME).split('T')[0]
            last_scan = datetime.date(int(last_scan.split('-')[0]), int(last_scan.split('-')[1]), int(last_scan.split('-')[2]))
            if (today - last_scan).days >= days:
                hostArray.append(Host(host.DNS, host.ID, host.IP, host.LAST_VULN_SCAN_DATETIME, host.NETBIOS, host.OS, host.TRACKING_METHOD))
        
        return hostArray
        
    def addIP(self, ips, vmpc):
        #'ips' parameter accepts comma-separated list of IP addresses.
        #'vmpc' parameter accepts 'vm', 'pc', or 'both'. (Vulnerability Managment, Policy Compliance, or both)
        call = '/api/2.0/fo/asset/ip/'
        enablevm = 1
        enablepc = 0
        if vmpc == 'pc':
            enablevm = 0
            enablepc = 1
        elif vmpc == 'both':
            enablevm = 1
            enablepc = 1
            
        parameters = {'action': 'add', 'ips': ips, 'enable_vm': enablevm, 'enable_pc': enablepc}
        self.request(call, parameters)
        
    def listScans(self, launched_after="", state="", target="", type="", user_login=""):
        #'launched_after' parameter accepts a date in the format: YYYY-MM-DD
        #'state' parameter accepts "Running", "Paused", "Canceled", "Finished", "Error", "Queued", and "Loading".
        #'title' parameter accepts a string
        #'type' parameter accepts "On-Demand", and "Scheduled".
        #'user_login' parameter accepts a user name (string)
        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'list'}
        if launched_after != "":
            parameters['launched_after_datetime'] = launched_after
            
        if state != "":
            parameters['state'] = state
            
        if target != "":
            parameters['target'] = target
            
        if type != "":
            parameters['type'] = type
        
        if user_login != "":
            parameters['user_login'] = user_login
            
        scanlist = objectify.fromstring(self.request(call, parameters))
        scanArray = []
        for scan in scanlist.RESPONSE.SCAN_LIST.SCAN:
            scanArray.append(Scan(scan.DURATION, scan.LAUNCH_DATETIME, scan.PROCESSED, scan.REF, scan.STATUS, scan.TARGET, scan.TITLE, scan.TYPE, scan.USER_LOGIN))
            
        return scanArray
        


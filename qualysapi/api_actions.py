from lxml import objectify, etree
import qualysapi.api_objects
from qualysapi.api_objects import *
from qualysapi.exceptions import NoConnectionError, ParsingBufferException
from qualysapi.api_methods import api_methods
import logging
import pprint


def defaultCompletionHandler(IB):
    logging.info('Import buffer completed.')
    logging.info(repr(IB))


class QGActions(object):

    import_buffer = None
    request = None
    stream_request = None

    conn = None


    def __init__(self, *args, **kwargs):
        '''
        Set up the Actions connection wrapper class

        @Params
        cache_connection -- either this option or the connection option are
        required, but this one takes precedence.  If you specify a cache
        connection then the connection is inferred from the cache
        configuration.
        connection -- required if no cache_connection is specified, otherwise
        it is ignored in favor of the cache connection.
        import_buffer -- an optional parse buffer which handles parsing using
        both an object instance factory and a multiprocess/thread parse
        handler.  This is efficient for enterprise applications which have
        large numbers of maps and scans with very large result sets and custom
        handling attached to the qualys objects.
        '''
        self.conn = kwargs.get('cache_connection', None)
        if self.conn:
            self.request = self.conn.cache_request
            self.stream_request = self.conn.stream_cache_request
        else:
            self.conn = kwargs.get('connection', None)
            if not self.conn:
                raise NoConnectionError('You attempted to make an \
                api requst without specifying an API connection first.')
            self.request = self.conn.request
            self.stream_request = self.conn.stream_request

        self.import_buffer = kwargs.get('import_buffer', None)

    def parseResponse(self, **kwargs):
        '''
        An internal utility method that implements an lxml parser capable of
        handling streams and mapping objects to elements.

        Please note that this utiliy is only capable of parsing known Qualys
        API DTDs properly.

        @Params
        source -- a filename or url to an xml file or an open stream.
        block -- an optional parameter which binds the caller to the parse
        buffer for consumption.  It is generally assumed by the design that
        parse consumers will handle themselves internally and that this method
        can return once it kicks off an action.  When block is set to True,
        however, this method will join the parse buffer and wait for the
        consumers to clear the queue before returning.
        result_handler -- an optional method that gets called when consumption
        of a parse completes.  This method will receive all of the objects
        handled by the buffer consumers as a callback rather than a threaded
        parse consumer.
        '''
        source = kwargs.pop('source', None)
        if source is None:
            raise QualysException('No source file or URL or raw stream found.')


        block = kwargs.pop('block', False)
        callback = kwargs.pop('callback', None)

        response = self.stream_request(source, **kwargs)
        context = etree.iterparse(response, events=('end',))

        if self.import_buffer is None:
            self.import_buffer = ImportBuffer()
        clear_ok = False
        for event, elem in context:
            #Use QName to avoid specifying or stripping the namespace, which we don't need
            if etree.QName(elem.tag).localname.upper() in obj_elem_map:
                self.import_buffer.add(obj_elem_map[etree.QName(elem.tag).localname.upper()](elem=elem))
                clear_ok = True
            if clear_ok:
                elem.clear() #don't fill up a dom we don't need.
                clear_ok = False
        return self.import_buffer.finish()


    def getHost(host):
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'ips': host, 'details': 'All'}
        hostData = objectify.fromstring(self.request(call, data=parameters)).RESPONSE
        try:
            hostData = hostData.HOST_LIST.HOST
            return Host(hostData.DNS, hostData.ID, hostData.IP, hostData.LAST_VULN_SCAN_DATETIME, hostData.NETBIOS, hostData.OS, hostData.TRACKING_METHOD)
        except AttributeError:
            return Host("", "", host, "never", "", "", "")

    def getHostRange(self, start, end):
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'ips': start+'-'+end}
        hostData = objectify.fromstring(self.request(call, data=parameters))
        hostArray = []
        for host in hostData.RESPONSE.HOST_LIST.HOST:
            hostArray.append(Host(host.DNS, host.ID, host.IP, host.LAST_VULN_SCAN_DATETIME, host.NETBIOS, host.OS, host.TRACKING_METHOD))

        return hostArray


    def listAssetGroups(self, groupName=''):
        call = 'asset_group_list.php'
        if groupName == '':
            agData = objectify.fromstring(self.request(call))
        else:
            agData = objectify.fromstring(self.request(call, 'title='+groupName)).RESPONSE

        groupsArray = []
        scanipsArray = []
        scandnsArray = []
        scannersArray = []
        for group in agData.ASSET_GROUP:
            try:
                for scanip in group.SCANIPS:
                    scanipsArray.append(scanip.IP)
            except AttributeError:
                scanipsArray = [] # No IPs defined to scan.

            try:
                for scanner in group.SCANNER_APPLIANCES.SCANNER_APPLIANCE:
                    scannersArray.append(scanner.SCANNER_APPLIANCE_NAME)
            except AttributeError:
                scannersArray = [] # No scanner appliances defined for this group.

            try:
                for dnsName in group.SCANDNS:
                    scandnsArray.append(dnsName.DNS)
            except AttributeError:
                scandnsArray = [] # No DNS names assigned to group.

            groupsArray.append(AssetGroup(group.BUSINESS_IMPACT, group.ID, group.LAST_UPDATE, scanipsArray, scandnsArray, scannersArray, group.TITLE))

        return groupsArray


    def listReportTemplates(self):
        call = 'report_template_list.php'
        rtData = objectify.fromstring(self.request(call))
        templatesArray = []

        for template in rtData.REPORT_TEMPLATE:
            templatesArray.append(ReportTemplate(template.GLOBAL, template.ID, template.LAST_UPDATE, template.TEMPLATE_TYPE, template.TITLE, template.TYPE, template.USER))

        return templatesArray

    def listReports(self, id=0):
        call = '/api/2.0/fo/report'

        if id == 0:
            parameters = {'action': 'list'}

            repData = objectify.fromstring(self.request(call, data=parameters)).RESPONSE
            reportsArray = []

            for report in repData.REPORT_LIST.REPORT:
                reportsArray.append(Report(report.EXPIRATION_DATETIME, report.ID, report.LAUNCH_DATETIME, report.OUTPUT_FORMAT, report.SIZE, report.STATUS, report.TYPE, report.USER_LOGIN))

            return reportsArray

        else:
            parameters = {'action': 'list', 'id': id}
            repData = objectify.fromstring(self.request(call, data=parameters)).RESPONSE.REPORT_LIST.REPORT
            return Report(repData.EXPIRATION_DATETIME, repData.ID, repData.LAUNCH_DATETIME, repData.OUTPUT_FORMAT, repData.SIZE, repData.STATUS, repData.TYPE, repData.USER_LOGIN)


    def notScannedSince(self, days):
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'details': 'All'}
        hostData = objectify.fromstring(self.request(call, data=parameters))
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
        self.request(call, data=parameters)

    def asyncListMaps(self, bind=False):
        '''
        An asynchronous call to the parser/consumer framework to return a list
        of maps.
        '''
        raise QualyException('Not yet implemented')

    def listMaps(self, *args, **kwargs):
        '''
        Initially this is a api v1 only capability of listing available map
        reports.
        '''
        call = 'map_report_list.php'
        data = {}
        return self.parseResponse(source=call, data=data)
        #result = self.request(call, data = data)
        #logging.debug(pprint.pformat(result))
        #maplist = objectify.fromstring(result)
        #logging.debug(pprint.pformat(maplist.__dict__))
        #return [mapr.TITLE for mapr in maplist.MAP_REPORT]
#        for mapr in maplist.RESPONSE.MAP_REPORT_LIST.MAP_REPORT:
#            logging.debug(pprint.pformat(mapr))


    def listScans(self, launched_after="", state="", target="", type="", user_login=""):
        #'launched_after' parameter accepts a date in the format: YYYY-MM-DD
        #'state' parameter accepts "Running", "Paused", "Canceled", "Finished", "Error", "Queued", and "Loading".
        #'title' parameter accepts a string
        #'type' parameter accepts "On-Demand", and "Scheduled".
        #'user_login' parameter accepts a user name (string)
        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'list', 'show_ags': 1, 'show_op': 1, 'show_status': 1}
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

        scanlist = objectify.fromstring(self.request(call, data = parameters))
        scanArray = []
        for scan in scanlist.RESPONSE.SCAN_LIST.SCAN:
            try:
                agList = []
                for ag in scan.ASSET_GROUP_TITLE_LIST.ASSET_GROUP_TITLE:
                    agList.append(ag)
            except AttributeError:
                agList = []

            scanArray.append(Scan(agList, scan.DURATION, scan.LAUNCH_DATETIME, scan.OPTION_PROFILE.TITLE, scan.PROCESSED, scan.REF, scan.STATUS, scan.TARGET, scan.TITLE, scan.TYPE, scan.USER_LOGIN))

        return scanArray

    def launchScan(self, title, option_title, iscanner_name, asset_groups="", ip=""):
        # TODO: Add ability to scan by tag.
        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'launch', 'scan_title': title, 'option_title': option_title, 'iscanner_name': iscanner_name, 'ip': ip, 'asset_groups': asset_groups}
        if ip == "":
            parameters.pop("ip")

        if asset_groups == "":
            parameters.pop("asset_groups")

        scan_ref = objectify.fromstring(self.request(call, data=parameters)).RESPONSE.ITEM_LIST.ITEM[1].VALUE

        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'list', 'scan_ref': scan_ref, 'show_status': 1, 'show_ags': 1, 'show_op': 1}

        scan = objectify.fromstring(self.request(call, data=parameters)).RESPONSE.SCAN_LIST.SCAN
        try:
            agList = []
            for ag in scan.ASSET_GROUP_TITLE_LIST.ASSET_GROUP_TITLE:
                agList.append(ag)
        except AttributeError:
            agList = []

        return Scan(agList, scan.DURATION, scan.LAUNCH_DATETIME, scan.OPTION_PROFILE.TITLE, scan.PROCESSED, scan.REF, scan.STATUS, scan.TARGET, scan.TITLE, scan.TYPE, scan.USER_LOGIN)

    def addBuffer(self, parse_buffer):
        '''
        Add an ImportBuffer to this action object.
        '''
        self.import_buffer = parse_buffer

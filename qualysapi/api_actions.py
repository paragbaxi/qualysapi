from lxml import objectify, etree
import qualysapi.api_objects
from qualysapi.api_objects import *
from qualysapi.exceptions import *
from qualysapi.api_methods import api_methods
import logging
import pprint
import json

from multiprocessing import pool

from threading import Thread, Event


# two essential methods here include creating a semaphore-based local threading
# or multiprocessing pool which is capable of monitoring and dispatching
# callbacks to calling instances when both parsing and consumption complete.

# In the default implementation the calls are blocking and perform a single
# request, parse the response, and then wait for parse consumption to finish.
# This isn't ideal, however, as there are often cases where multiple requests
# could be sent off at the same time and handled asynchronously.  The
# methods below wrap thread pools or process pools for asynchronous
# multi-request parsing/consuming by a single calling program.


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
        source -- An api endpoint (mapped using the api_methods sets) or an IO
        source.  If this is an instance of str it is treated as an api
        endpoint, otherwise it is treated as a file-like object yielding binary
        xml data.  This should be sufficient to allow any kind of
        processing while still being convenient for standard uses.
        block -- an optional parameter which binds the caller to the parse
        buffer for consumption.  It is generally assumed by the design that
        parse consumers will handle themselves internally and that this method
        can return once it kicks off an action.  When block is set to True,
        however, this method will join the parse buffer and wait for the
        consumers to clear the queue before returning.  By default this is true
        for ease of implementation.
        completion_callback -- an optional method that gets called when consumption
        of a parse completes.  This method will receive all of the objects
        handled by the buffer consumers as a callback rather than a threaded
        parse consumer.
        '''

        source = kwargs.pop('source', None)
        if source is None:
            raise QualysException('No source file or URL or raw stream found.')

        block = kwargs.pop('block', True)
        callback = kwargs.pop('completion_callback', None)
        #TODO: consider passing in an import_buffer for thread management reuse
        #of this object
        #TODO: consider replacing this requirement
        if not block and not callback:
            raise exceptions.QualysFrameworkException("A callback outlet is \
            required for nonblocking calls to the parser/consumer framework.")

        #select the response file-like object
        response = None
        if isinstance(source, str):
            response = self.stream_request(source, **kwargs)
        else:
            response = source

        if self.import_buffer is None:
            self.import_buffer = ImportBuffer(callback=callback)
        else:
            self.import_buffer.setCallback(callback)

        block = kwargs.pop('block', True)
        callback = kwargs.pop('completion_callback', None)
        if not block and not callback:
            raise exceptions.QualysFrameworkException("A callback outlet is \
            required for nonblocking calls to the parser/consumer framework.")

        clear_ok = False
        context = etree.iterparse(response, events=('end',))
        for event, elem in context:
            #Use QName to avoid specifying or stripping the namespace, which we don't need
            if etree.QName(elem.tag).localname.upper() in obj_elem_map:
                self.import_buffer.add(obj_elem_map[etree.QName(elem.tag).localname.upper()](elem=elem))
                clear_ok = True
            if clear_ok:
                elem.clear() #don't fill up a dom we don't need.
                clear_ok = False
        return self.import_buffer.finish() if block else self.import_buffer


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


    def queryQKB(self, **kwargs):
        '''
        Pulls down a set of Qualys Knowledge Base entries in XML and hands them
        off to the parser/consumer framework.

        Params:

        qids -- a list of Qualys QIDs to pull QKB entries for.  Limits the
        result set.  Can be empty or none if pulling all.
        all -- boolean.  Causes quids to be ignored if set.  Pulls the entire
        knowledge base.
        changes_since -- an inclusive subset of new and modified entries since
        a specific date.  Can be a datetime (which will be converted to a
        string query parameter) or a string formatted as Qualys expects
        .  It is up to the calling function to ensure strings are correct if
        you choose to use them.  This brackets all of the XX_after variables.
        changes_before -- an inclusive subset old entries.  This brackets all
        of the XX_before variables.
        details -- defaults to 'All' but you can specify 'Basic' or 'None'.
        range -- A tuple of qids.  (Min,Max).  Shorthand for a specific list.
        only_patchable -- Boolean.  Limits the results to only QKB entries that
        have known patches.
        show_pci_reasons -- False by default.  You have to have this in your
        sub for it to be safe.
        file -- a special (but useful) case in which a file should be used to
        load the input.  In this case the entire file is parsed, regardless of
        the other parameters.
        discovery_method -- 'RemoteAndAuthenticated' by default, but valid
        options are:
            *'Remote'
            *'Authenticated'
            *'RemoteOnly'
            *'AuthenticatedOnly'
            *'RemoteAndAuthenticated'

        Retuns of this function depend on the parse consumers.  A list of
        objects or None.
        '''
        if 'quids' in kwargs:
            raise exceptions.QualysFrameworkException('Not yet implemented.')
        elif 'all' in kwargs:
            raise exceptions.QualysFrameworkException('Not yet implemented.')
        elif 'changes_since' in kwargs:
            raise exceptions.QualysFrameworkException('Not yet implemented.')
        else:
            if 'file' not in kwargs:
                raise exceptions.QualysFrameworkException('You must provide at\
                least some parameters to this function.')
            sourcefile = open(kwargs.pop('file'), 'rb')
            result = self.parseResponse(source=sourcefile)
            sourcefile.close()

        return result


    def launchMapReports(self, **kwargs):
        '''
        This is a type of automation function that should really be used in a
        process server or manager context.  Consider yourself warned.

        This function gatheres a list of finished maps, turns them into json
        strings, stores them in redis and then performs a series of automation
        tasks on them.

        Steps followed:
        * get a list of finished maps from Qualys.  Serialize
        each map object as a json string to redis using a key generated from
        the map name.  This means that only the most recent run of a map with a
        given name is cached or operated on by default.
        * after the maps have been cached, a filter is applied to the map
        objects including or excluding name patterns or date ranges.
        * the resulting filtered list of maps is handed off to a report running
        multiprocessing queue which will ensure that reports are started for
        each of the maps.  Each process will respond to qualys indications of
        concurrent report quests by sleeping and periodically checking to see
        if qualys is ready to begin another report.  After a report is started,
        the process will periodically check to see if the report is finished
        and then download the report.  IDs will be stored with and associated
        with the map and report.
        * each process will update the cache with the current state of the map
        and report each time it wakes up.  This allows processes which want to
        consume available or specific map reports to simply check if the report is
        available for processing against the cache and continue sleeping.
        * Consumption of specific map reports is outside the purview of this
        process manager.

        @params
        include_pattern -- an optional pattern by which to include map names.
        exclude_pattern -- an optional pattern by which to exclude map names.
        map_refs -- an optional list of map references to operate on.
        map_names -- an optional list of map names to operate on.
        sleep_period -- override the default sleep period for map report
        checking.  Each processes will sleep for 30 minutes by default.

        @returns -- a list of @see qualysapi.api_objects.Maps that this processes
        is or was operating on when called.  If this call is non-blocking then
        anything other than the name, ref, and map date will almost certainly
        be out of date with the cache (map report ids will need to be refreshed from
        the cache, so think of the results returned as useful for reference to
        state rather than completed states.)

        '''

        # verify we have a cache connection since a cache is required for this
        from qualysapi import qcache
        if not isinstance(self.conn, qcache.APICacheInstance):
            raise exceptions.QualysFrameworkException('This method requires \
                that you use the redis cache.')
        maps = self.listMaps()
        # filter the list to only include those we want
        if include_pattern in kwargs:
            #TODO: compile regex and filter matches
            pass
        if exclude_pattern in kwargs:
            #TODO: compile regex and filter matches
            pass

        if 'map_refs' in kwargs:
            maps[:] = [mapr for mapr in maps if mapr.map_ref in \
                    kwargs.get('map_refs', []) ]

        if 'map_names' in kwargs:
            maps[:] = [mapr for mapr in maps if mapr.name in \
                kwargs.get('map_names', []) ]

        # we should now have a specific subset to generate reports on...


    def startMapReportOnMap(self, mapr, **kwargs):
        '''Generates a report on a map.
        Parameters:
        mapr -- the map result to generate a report against.  Can be a string
        map_ref but a map result object is really preferred.
        domain -- one of domain or ip_restriction are required for map reports.
        You can use the asset domain list for this parameter.  If this
        parameter is excluded 'none' is substituted but a lack of an IP range
        list will result in an api exception.
        ip_restriction -- Either a string of ips acceptable to qualys or a list
        of IP range objects.  These objects provide a reasonably uniform way to
        specify ranges.
        at least one of:
            template_id -- (Optional) the report template ID to use.  Required.
            template_name -- (Optional) the name of the template to use. (look
            up ID)
            use_default_template -- (Optional) boolean.  Look up the
            default map report template and load the template_id from it.

        report_title -- (Optional) Specify a name for this report.
        output_format -- (Optional) Default is xml.  Options are pdf, html,
        mht, xml or csv.  This API only supports parsing of xml format, the
        rest must be downloaded and saved or viewed.
        hide_header -- (Optional) Tell the API to remove report header info.
        Optional.  By default this isn't set at all.
        comp_mapr -- (Optional) A map result to compare against.

        Return tuple (mapr, report_id):
            if mapr is a map result object, the report_id property will be set.
            Either way, a tuple is returned with mapr and report_id at 0,1
            respectively.
        '''

        # figure out our template_id
        template_id = 0
        if 'template_id' in kwargs:
            template_id = kwargs.get('template_id', 0)
        elif 'template_name' in kwargs or kwargs.get('use_default_template',
                False):
            # get the list of tempaltes
            template_list = self.listReportTemplates()
            for template in template_list:
                if template.report_type == 'Map':
                    if template.title == kwargs.get('template_title', None):
                        template_id = template.template_id
                    elif template.is_default and kwargs.get('use_default_template',
                            False):
                        tempalte_id = template.template_id
                    if not template_id: # false if not 0
                        break
        else:
            raise exceptions.QualysFrameworkException('You need one of a \
                    template_id, template_name or use_default_template to \
                    generate a report from a map result.')

        report_title = kwargs.pop('report_title', None)
        comp_mapr = kwargs.pop('comp_mapr', None)
        if not report_title:
            mapr_name = mapr.name if not isinstance(mapr, str) else str(mapr)
            comp_mapr_name = None
            if comp_mapr:
                comp_mapr_name = comp_mapr.name if not isinstance(comp_mapr, \
                        str) else str(comp_mapr)

            report_title = '%s - api generated' % (mapr_name)
            if comp_mapr_name:
                report_title = '%s vs. %s' % (comp_mapr_name, report_title)

        output_format = kwargs.pop('output_format', 'xml')

        call = '/api/2.0/fo/report/'
        params = {
            'action'      : 'launch',
            'template_id' : template_id,
            'report_title' : report_title,
            'output_format' : output_format,
            'report_type' : 'Map',
            'domain' : kwargs.pop('domain', 'none'),
        }

        if 'hide_header' in kwargs:
            # accept boolean type or direct parameter
            if isinstance(kwargs.get('hide_header'), str):
                params['hide_header'] = kwargs.get('hide_header')
            else:
                params['hide_header'] = '0' if not kwargs.get('hide_header') \
                        else '1'

        if 'ip_restriction' in kwargs:
            if isinstance(kwargs.get('ip_restriction'), str):
                params['ip_restriction'] = kwargs.pop('ip_restriction')
            else:
                params['ip_restriction'] = ','.join((
                    str(iprange) for iprange in
                    kwargs.pop('ip_restriction')))
        elif params['domain'] == 'none':
            raise exceptions.QualysException('Map reports require either a \
            domain name or an ip_restriction collection of IPs and/or ranges. \
            You specified no domain and no ips.')

        params['report_refs'] = mapr.ref if not isinstance(mapr, str) else \
            str(mapr)

        if comp_mapr:
            params['report_refs'] = '%s,%s' % (params['report_refs'], \
                    comp_mapr.ref if not isinstance(comp_mapr, str) else \
                    str(comp_mapr))

        response = self.parseResponse(source=call, data=params)
        if not len(response) and isinstance(response[0], SimpleReturnResponse):
            response = response[0]
            if response.hasItem('ID'):
                report_id = response.getItemValue('ID')
                if not isinstance(mapr, str):
                    mapr.report_id = report_id
                return (mapr, report_id)
        # if we get here, something is wrong.
        raise exceptions.QualysFrameworkException('Unexpected API \
            response.\n%s' % (pprint.pformat(response)))


    def fetchReport(self, **kwargs):
        '''
        Uses the cache to quickly look up the report associated with a specific
        map ref.
        '''
        call = '/api/2.0/fo/report/'
        params = {
            'action' : 'launch',
            ''     : kwargs.get('id', 0)
        }
#        map_reports = kwargs.get('map_reports', None)
#        if map_reports:
#            params['id'] = map_reports[0]
#        else:
#            raise QualysException('Need map refs as report ids to continue.')
        return self.parseResponse(source=call, data=params)


    def listReportTemplates(self):
        '''Load a list of report templates'''
        call = 'report_template_list.php'
        return self.parseResponse(source=call, data=None)

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

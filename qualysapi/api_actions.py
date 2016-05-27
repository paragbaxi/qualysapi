from lxml import objectify, etree
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
        :parameter cache_connection:
            either this option or the connection option are
        required, but this one takes precedence.  If you specify a cache
        connection then the connection is inferred from the cache
        configuration.
        :parameter connection:
            required if no cache_connection is specified, otherwise
        it is ignored in favor of the cache connection.
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

    def clone(self, proto=None):
        #TODO: this is wrong...  fix it.
        if proto == None:
            conf = self.conn.getConfig()
            return QGActions(
                conf.get_auth(),
                hostname=conf.get_hostname(),
                proxies=conf.proxies,
                max_retries=conf.max_retries)
        else:
            if not isinstance(QGActions, proto):
                raise exceptions.QualysFrameworkException('Cannot clone, \
prototype is not an instance.')
            else:
                return proto(
                    conf.get_auth(),
                    hostname=conf.get_hostname(),
                    proxies=conf.proxies,
                    max_retries=conf.max_retries)


    def parseResponse(self, **kwargs):
        '''single-thread/process parseResponse.'''
        # TODO: when you implement this, remember to incldue the improved
        # response checker
        # self.checkResults(results)
        raise exceptions.QualysFrameworkException('Not yet implemented.')

    def checkResults(self, results):
        '''check for actionable response errors'''
        api_response = None
        if not results:
            raise exceptions.QualysFrameworkException('Got a NoneType from the \
parser.')
        if isinstance(results, list) and \
            len(results) > 0 and \
            issubclass(type(results[0]),SimpleReturn):
            api_response = results[0]
        elif issubclass(type(results), SimpleReturn):
            api_response = results

        if api_response:
            api_response.raiseAPIExceptions()
        return results

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


    # single-thread/process specific 1-off query for starting a map report
    def startMapReportOnMap(self, mapr, **kwargs):
        '''Generates a report on a map.
        Parameters:
        :parameter mapr:
            the map result to generate a report against.  Can be a string
        map_ref but a map result object is really preferred.
        :parameter domain:
            one of domain or ip_restriction are required for map reports.
        You can use the asset domain list for this parameter.  If this
        parameter is excluded 'none' is substituted but a lack of an IP range
        list will result in an api exception.
        :parameter ip_restriction:
            Either a string of ips acceptable to qualys or a list
        of IP range objects.  These objects provide a reasonably uniform way to
        specify ranges.
        :parameter template_id:
            (Optional) the report template ID to use.  Required.
        :parameter template_name:
            (Optional) the name of the template to use. (look
        up ID)
        :parameter use_default_template:
            (Optional) boolean.  Look up the
        default map report template and load the template_id from it.
        Note: If none of the above are sent then the configuration option
        default template is used.  That will either be 'Unknown Device Report'
        or whatever you have in your config for the map_template configuration
        option under the report_templates configuration section.

        :parameter report_title:
            (Optional) Specify a name for this report.
        :parameter output_format:
            (Optional) Default is xml.  Options are pdf, html,
        mht, xml or csv.  This API only supports parsing of xml format, the
        rest must be downloaded and saved or viewed.
        :parameter hide_header:
            (Optional) Tell the API to remove report header info.
        Optional.  By default this isn't set at all.
        :parameter comp_mapr:
            (Optional) A map result to compare against.

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
            use_default_template = kwargs.get('use_default_template', False)
            template_title = kwargs.get('template_title',
                    self.conn.getConfig().getReportTemplate())
            for template in template_list:
                if use_default_template and \
                    template.is_default and \
                    template.report_type == 'Map':
                    template_id = template.template_id
                elif template.title == template_title:
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
        if not len(response) and isinstance(response[0], SimpleReturn):
            response = response[0]
            if response.hasItem('ID'):
                report_id = response.getItemValue('ID')
                if not isinstance(mapr, str):
                    mapr.report_id = report_id
                return (mapr, report_id)
        # if we get here, something is wrong.
        raise exceptions.QualysFrameworkException('Unexpected API '
            'response.\n%s' % (pprint.pformat(response)))

    def fetchReport(self, rid=None, report=None, consumer_prototype=None,
            **kwargs):
        '''
        Uses the cache to quickly look up the report associated with a specific
        map ref.
        This API only handles XML.  Anything else you're on your own other than
        using this API to download the report.

        :param rid:
            the report_id for the report to fetch
        :param report:
            the report header info/skeleton (Report object).  This can contain
            the report id rather than the rid named argument.
        :param consumer_prototype:
            Optional.  A subclass prototype of BufferConsumer which will act on
            each report item in parallel with the downloading of the report.
        :param **kwargs:
            expansion arguments
        '''
        if rid is None and report is None:
            raise exceptions.QualysException('A report id is required.')
        elif rid is None:
            rid = report.id

        call = '/api/2.0/fo/report/'
        params = {
            'action'        : 'fetch',
            'id'            : rid
        }
        # return 1 or None.  API doesn't allow multiple.  Also make sure it's a
        # report and not a SimpleReturn (which can happen)
        results = self.parseResponse(source=call, data=params, report=report,
                consumer_prototype=consumer_prototype)
        for result in results:
            if isinstance(result, Report):
                return result
        #None result

    def queryQKB(self, **kwargs):
        '''
        Pulls down a set of Qualys Knowledge Base entries in XML and hands them
        off to the parser/consumer framework.

        Params:

        :parameter qids:
            a list of Qualys QIDs to pull QKB entries for.  Limits the
            result set.  Can be empty or none if pulling all.
        :parameter all:
            boolean.  Causes quids to be ignored if set.  Pulls the entire
            knowledge base.
        :parameter changes_since:
            an inclusive subset of new and modified entries since
            a specific date.  Can be a datetime (which will be converted to a
            string query parameter) or a string formatted as Qualys expects
            .  It is up to the calling function to ensure strings are correct if
            you choose to use them.  This brackets all of the XX_after variables.
        :parameter changes_before:
            an inclusive subset old entries.  This brackets all
            of the XX_before variables.
        :parameter details:
            defaults to 'All' but you can specify 'Basic' or 'None'.
        :parameter range:
            A tuple of qids.  (Min,Max).  Shorthand for a specific list.
        :parameter only_patchable:
            Boolean.  Limits the results to only QKB entries that
            have known patches.
        :parameter show_pci_reasons:
            False by default.  You have to have this in your
            sub for it to be safe.
        :parameter file:
            a special (but useful) case in which a file should be used to
            load the input.  In this case the entire file is parsed, regardless
            of the other parameters.
        :parameter discovery_method:
            'RemoteAndAuthenticated' by default, but valid
            :options:
                -'Remote'
                -'Authenticated'
                -'RemoteOnly'
                -'AuthenticatedOnly'
                -'RemoteAndAuthenticated'

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


    def listReportTemplates(self):
        '''Load a list of report templates'''
        call = 'report_template_list.php'
        return self.parseResponse(source=call, data=None)

    def listReports(self, *args, **kwargs):
        '''Executes a list of available reports.  Filtering parameters allowed
        (from the API Documentation):

        :parameter id:
            request info on a sepecific report id
        :parameter state:
            only include reports witha a given state (such as finished)
        :parameter user_login:
            only include reports launched by a specific user
        :parameter expires_before_datetime:
            A date/time by which any reports returned
            would have.  String format.  Qualys format.
            expired.
        :parameter filter:
            A dictionary used to filter the result set.  The result set can be
            filter on any property/value pair for a Report object
        .. seealso:: :class:`qualysapi.api_objects.Report`
        '''
        call = '/api/2.0/fo/report/'
        parameters = {
            'action' : 'list',
        }
        for param in ('id', 'state', 'user_login', 'expires_before_datetime'):
            if param in kwargs:
                parameters[param] = kwargs[param]

        results = self.parseResponse(source=call, data=parameters)
        if 'filter' in kwargs:
            fdict = kwargs['filter']
            return filterObjects(kwargs['filter'], results)
        else:
            return results


    def notScannedSince(self, days):
        call = '/api/2.0/fo/asset/host/'
        parameters = {'action': 'list', 'details': 'All'}
        hostData = objectify.fromstring(self.request(call, data=parameters))
        hostArray = []
        today = datetime.date.today()
        for host in hostData.RESPONSE.HOST_LIST.HOST:
            last_scan = str(host.LAST_VULN_SCAN_DATETIME).split('T')[0]
            last_scan = datetime.date(int(last_scan.split('-')[0]),
                    int(last_scan.split('-')[1]), int(last_scan.split('-')[2]))
            if (today - last_scan).days >= days:
                hostArray.append(Host(host.DNS, host.ID, host.IP,
                    host.LAST_VULN_SCAN_DATETIME, host.NETBIOS, host.OS,
                    host.TRACKING_METHOD))

        return hostArray

    def addIP(self, ips, vmpc):
        #'ips' parameter accepts comma-separated list of IP addresses.
        #'vmpc' parameter accepts 'vm', 'pc', or 'both'. (Vulnerability
        #Managment, Policy Compliance, or both)
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

    def listScans(self, launched_after="", state="", target="", type="",
            user_login=""):
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

            scanArray.append(Scan(agList, scan.DURATION, scan.LAUNCH_DATETIME,
                scan.OPTION_PROFILE.TITLE, scan.PROCESSED, scan.REF,
                scan.STATUS, scan.TARGET, scan.TITLE, scan.TYPE,
                scan.USER_LOGIN))

        return scanArray

    def launchScan(self, title, option_title, iscanner_name, asset_groups="",
            ip=""):
        # TODO: Add ability to scan by tag.
        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'launch', 'scan_title': title, 'option_title':
                option_title, 'iscanner_name': iscanner_name, 'ip': ip,
                'asset_groups': asset_groups}
        if ip == "":
            parameters.pop("ip")

        if asset_groups == "":
            parameters.pop("asset_groups")

        scan_ref = objectify.fromstring(self.request(call,
            data=parameters)).RESPONSE.ITEM_LIST.ITEM[1].VALUE

        call = '/api/2.0/fo/scan/'
        parameters = {'action': 'list', 'scan_ref': scan_ref, 'show_status': 1,
                'show_ags': 1, 'show_op': 1}

        scan = objectify.fromstring(self.request(call,
            data=parameters)).RESPONSE.SCAN_LIST.SCAN
        try:
            agList = []
            for ag in scan.ASSET_GROUP_TITLE_LIST.ASSET_GROUP_TITLE:
                agList.append(ag)
        except AttributeError:
            agList = []

        return Scan(agList, scan.DURATION, scan.LAUNCH_DATETIME,
                scan.OPTION_PROFILE.TITLE, scan.PROCESSED, scan.REF,
                scan.STATUS, scan.TARGET, scan.TITLE, scan.TYPE,
                scan.USER_LOGIN)

    def addBuffer(self, parse_buffer):
        '''
        Add an ImportBuffer to this action object.
        '''
        self.import_buffer = parse_buffer

    def getConnectionConfig(self):
        return self.conn.getConfig()

    def reportFromFile(self, filename, **kwargs):
        """reportFromFile
        load and parse a report from an xml file.

        :param filename:
        The name of the file to open and pass to the parser.
        :param kwargs:
        Passed through to other functions
        """
        with open(filename, 'rb') as source:
            # make sure we only return the report (since it's possible for the
            # result to be 'dirty'
            results = self.parseResponse(source=source, **kwargs)
            for item in results:
                if isinstance(item, Report):
                    return item

    def hostDetectionQuery(self, **kwargs):
        """hostDetectionQuery

        :param **kwargs: keyword arguments for api call
        """
        pass

    def assetGroupQuery(self, consumer_prototype=None, **kwargs):
        """assetGroupQuery

        Implements the list functions from the qualys Asset Group API.

        :Note: show_attributes=ALL can take a very long time

        """
        # p;ckle name/default pairs for kwargs
        optional_params = [
            ('action',           'list'),
            ('echo_request',     '0' ),
            ('ids',              None ),
            ('id_min',           None ),
            ('id_max',           None ),
            ('truncation_limit', None ), # default is 1000
            ('network_ids',      None ),
            ('unit_id',          None ),
            ('user_id',          None ),
            ('title',            None ),
            ('show_attributes',  'TITLE' ), # see docs for list
        ]
        call = '/api/2.0/fo/asset/group/'
        params = {
            key:kwargs.get(key, default) for (key, default) in
            optional_params if kwargs.get(key, default) is not None
        }
        # return 1 or None.  API doesn't allow multiple.  Also make sure it's a
        # report and not a SimpleReturn (which can happen)
        return self.parseResponse(source=call, data=params,
                consumer_prototype=consumer_prototype)

    def hostListQuery(self, consumer_prototype=None, **kwargs):
        """hostListQuery

        :param consumer_prototype: Optional multiprocess consumer
        :param **kwargs: optional api parameters and keyword args
        """
        # p;ckle name/default pairs for kwargs
        optional_params = [
            ('action',                   'list'),
            ('truncation_limit',         None ), # default is 1000
            ('details',                  'Basic'), # see docs for list
            ('ips',                      None ),
            ('ids',                      None ),
            ('ag_ids',                   None ),
            ('ag_titles',                None ),
            ('id_min',                   None ),
            ('id_max',                   None ),
            ('network_ids',              None ),
            ('no_vm_scan_since',         None ), #: {date}
            ('no_compliance_scan_since', None ), #: {date}]
            ('vm_scan_since',            None ), #: {date}
            ('compliance_scan_since',    None ), #: {date}
            ('compliance_enabled',       None ), #: {0|1}
            ('os_pattern',               None ), #: {expression}
            ('use_tags',                 None ), #: {0|1}
            ('tag_set_by',               None ), #: {id|name}
            ('tag_include_selector',     None ), #: {any|all}
            ('tag_exclude_selector',     None ), #: {any|all}
            ('tag_set_include',          None ), #: {value}
            ('tag_set_exclude',          None ), #: {value}
            ('show_tags',                None ), #: {0|1}
        ]
        call = '/api/2.0/fo/asset/host/'
        params = {
            key:kwargs.get(key, default) for (key, default) in
            optional_params if kwargs.get(key, default) is not None
        }
        # return 1 or None.  API doesn't allow multiple.  Also make sure it's a
        # report and not a SimpleReturn (which can happen)
        return self.parseResponse(source=call, data=params,
                consumer_prototype=consumer_prototype)

    def hostDetectionQuery(self, consumer_prototype=None, **kwargs):
        """hostListQuery

        :param consumer_prototype: Optional multiprocess consumer
        :param **kwargs: optional api parameters and keyword args
        """
        # p;ckle name/default pairs for kwargs
        optional_params = [
            ('action',                            'list'),
            ('echo_request',                      '0' ), #: optional but default
            ('output_format',                     None ), #: {XML|CSV| CSV_NO_METADATA}
            ('truncation_limit',                  None ), # default is 1000
            ('ids',                               None ),
            ('id_min',                            None ),
            ('id_max',                            None ),
            ('ips',                               None ),
            ('ag_ids',                            None ),
            ('ag_titles',                         None ),
            ('network_ids',                       None ),
            ('vm_scan_since',                     None ), #: {date}
            ('no_vm_scan_since',                  None ), #: {date}
            ('no_compliance_scan_since',          None ), #: {date}]
            ('os_pattern',                        None ), #: {expression}
            ('active_kernels_only',               None ), #: {0|1}
            ('truncation_limit',                  None ), #: {value}
            ('status',                            None ), #: {value} compliance_enabled={0|1}
            ('qids',                              None ), #: {value}
            ('severities',                        None ), #: {value}
            ('show_igs',                          None ), #: {0|1}
            ('include_search_list_titles',        None ), #: {value}
            ('exclude_search_list_titles',        None ), #: {value}
            ('include_search_list_ids',           None ), #: {value,value...}
            ('exclude_search_list_ids',           None ), #: {value,value...}
            ('use_tags',                          None ), #: {0|1} tag_set_by={id|name}
            ('tag_include_selector',              None ), #: {any|all}
            ('tag_exclude_selector',              None ), #: {any|all}
            ('tag_set_include',                   None ), #: {value}
            ('tag_set_exclude',                   None ), #: {value}
            ('show_tags',                         None ), #: {0|1}
            ('suppress_duplicated_data_from_csv', None ), #: {0|1}
            ('max_days_since_last_vm_scan',       None ), #: {value}
        ]
        call = '/api/2.0/fo/asset/host/'
        params = {
            key:kwargs.get(key, default) for (key, default) in
            optional_params if kwargs.get(key, default) is not None
        }
        # return 1 or None.  API doesn't allow multiple.  Also make sure it's a
        # report and not a SimpleReturn (which can happen)
        return self.parseResponse(source=call, data=params,
                consumer_prototype=consumer_prototype)

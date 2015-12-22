# redis cache for qualys api results
import redis
from .. import api_methods, connect
import traceback
import pprint
import logging
import json
from io import BytesIO 

from qualysapi import util

from qualysapi import exceptions

connection_args = {
    'host' : 'localhost',
    'port' : 6379,
    'db' : 1,
}


# this is to reliably build the redis cache key by api parameter ordering. (combined v1 and v2 api args, covers most of WAS too AFAICT right now
api_param_key_order = [
    'access_key',
    'action',
    'active',
    'active_kernels_only',
    'add_asset_groups',
    'add_comment',
    'add_host_ips',
    'add_ips',
    'add_new_controls',
    'add_new_technologies',
    'add_task',
    'address1',
    'address2',
    'ag_ids',
    'ag_title',
    'ag_titles',
    'agentless_tracking_path',
    'all_asset_groups',
    'all_or_nothing',
    'appliance_id',
    'appliance_ids',
    'asset_group',
    'asset_group_ids',
    'asset_groups',
    'assignee_type',
    'auth_alg',
    'auto_discover_databases',
    'auto_discover_instances',
    'auto_discover_ports',
    'business_impact',
    'business_unit',
    'busy',
    'ca_api_username',
    'ca_ssl_verify',
    'ca_url',
    'ca_web_password',
    'ca_web_username',
    'change_assignee',
    'change_state',
    'city',
    'cleartext_password',
    'client_cert',
    'client_key',
    'comment',
    'comments',
    'community_strings',
    'compliance_enabled',
    'compliance_scan_since',
    'connector_name',
    'connector_uuid',
    'context',
    'context_engine_id',
    'control_ids',
    'country',
    'created_after_datetime',
    'criticality_labels',
    'criticality_values',
    'csv_data',
    'cvss_enviro_ar',
    'cvss_enviro_cdp',
    'cvss_enviro_cr',
    'cvss_enviro_ir',
    'cvss_enviro_td',
    'database',
    'date_from',
    'date_to',
    'day_of_month',
    'day_of_week',
    'db_local',
    'default_appliance_id',
    'default_scanner',
    'default_scanner_appliance',
    'deleted_before_datetime',
    'deleted_since_datetime',
    'detailed_history',
    'detailed_no_results',
    'detailed_results',
    'details',
    'dg_names',
    'discovery_auth_types',
    'discovery_method',
    'division',
    'dns',
    'dns_contains',
    'dns_names',
    'domain',
    'domains',
    'drop_task',
    'dsa_private_key',
    'ec2_endpoint',
    'ec2_only_classic',
    'echo_request',
    'email',
    'enable',
    'enable_password',
    'enable_pc',
    'enable_vm',
    'encrypt_password',
    'end_after',
    'end_after_hours',
    'exclude_ip_per_scan',
    'exclude_search_list_ids',
    'exclude_search_list_titles',
    'expires_before_datetime',
    'expiry_days',
    'external_id',
    'external_id_assigned',
    'external_id_contains',
    'fax',
    'first_name',
    'fqdn',
    'frequency_days',
    'frequency_months',
    'frequency_weeks',
    'function',
    'general_info',
    'hide_header',
    'host_dns',
    'host_id',
    'host_ids',
    'host_ip',
    'host_ips',
    'host_netbios',
    'host_os',
    'hosts',
    'id',
    'id_max',
    'id_min',
    'ids',
    'ig_severity',
    'include_license_info',
    'include_search_list_ids',
    'include_search_list_titles',
    'installation_path',
    'instance',
    'instance_path',
    'instance_string',
    'invalid',
    'ion',
    'ip',
    'ip_network_id',
    'ip_not_targeted_list',
    'ip_restriction',
    'ip_targeted_list',
    'ips',
    'ips_network_id',
    'ipv4_filter',
    'ipv6_network',
    'is_patchable',
    'iscanner_id',
    'iscanner_name',
    'last',
    'last_modified_after',
    'last_modified_before',
    'last_modified_by_service_after',
    'last_modified_by_service_before',
    'last_modified_by_user_after',
    'last_modified_by_user_before',
    'last_name',
    'last_scan',
    'launched_after_datetime',
    'launched_before_datetime',
    'limit',
    'loadbalancer',
    'location',
    'login',
    'map_title',
    'max_days_since_last_vm_scan',
    'merchant_username',
    'merge_policy_id',
    'missing_qids',
    'mode',
    'modified',
    'modified_since_datetime',
    'name',
    'netbios',
    'netbios_contains',
    'netbios_names',
    'netblock',
    'network_id',
    'network_ids',
    'new_title',
    'no_compliance_scan_since',
    'no_vm_scan_since',
    'ntlm',
    'observe_dst',
    'occurrence',
    'offset',
    'on',
    'option',
    'option_id',
    'option_profile_title',
    'option_title',
    'orderby',
    'organisation_name1',
    'organisation_name2',
    'organisation_name3',
    'os_pattern',
    'output_format',
    'output_mode',
    'overdue',
    'owner',
    'password',
    'patch_quids',
    'path',
    'pause_after_hours',
    'pc_only',
    'pci_only',
    'pdf_password',
    'perform_unix_opatch_checks',
    'perform_unix_os_checks',
    'perform_windows_os_checks',
    'phone',
    'policy_id',
    'policy_ids',
    'polling_interval',
    'port',
    'ports',
    'potential_vuln_severities',
    'potential_vuln_severity',
    'preview_merge',
    'priv_alg',
    'published_after',
    'published_before',
    'qids',
    'realm',
    'recipient_group',
    'recipient_group_id',
    'recurence',
    'recurrence',
    'ref',
    'remove_host_ips',
    'remove_ips',
    'reopen_ignored_days',
    'replace_asset_groups',
    'replace_cover_page',
    'report_refs',
    'report_title',
    'report_type',
    'resume_in_days',
    'root_tool',
    'rsa_private_key',
    'runtime_http_header',
    'safe',
    'save_report',
    'scan_detail',
    'scan_id',
    'scan_ref',
    'scan_target',
    'scan_title',
    'scandeadhosts',
    'scanner_appliances',
    'scanners_in_ag',
    'security_engine_id',
    'send_email',
    'server_address',
    'servicename',
    'set_appliance_ids',
    'set_business_impact',
    'set_comments',
    'set_cvss_enviro_ar',
    'set_cvss_enviro_cdp',
    'set_cvss_enviro_cr',
    'set_cvss_enviro_ir',
    'set_cvss_enviro_td',
    'set_default_appliance_id',
    'set_division',
    'set_dns_names',
    'set_domains',
    'set_function',
    'set_ips',
    'set_location',
    'set_netbios_names',
    'set_routes',
    'set_title',
    'set_vlans',
    'severities',
    'show_ags',
    'show_attributes',
    'show_cvss_submetrics',
    'show_igs',
    'show_last',
    'show_op',
    'show_pci_flag',
    'show_pci_reasons',
    'show_status',
    'show_tags',
    'show_vuln_details',
    'sid',
    'since_datetime',
    'since_ticket_number',
    'sortorder',
    'source',
    'specific_vulns',
    'ssl',
    'ssl_verify',
    'start_date',
    'start_hour',
    'start_minute',
    'state',
    'states',
    'status',
    'status_changes_since',
    'sub_type',
    'suppress_duplicated_data_from_csv',
    'tag_exclude_selector',
    'tag_include_selector',
    'tag_set_by',
    'tag_set_exclude',
    'tag_set_include',
    'target',
    'target_asset_groups',
    'target_from',
    'target_ips',
    'task_id',
    'template_id',
    'template_title',
    'ticket_assignee',
    'ticket_details',
    'ticket_numbers',
    'time_zone',
    'time_zone_code',
    'title',
    'tracking_method',
    'truncation_limit',
    'type',
    'ud1',
    'ud2',
    'ud3',
    'ui_interface_style',
    'unit_id',
    'unix_apache_config_file',
    'unix_apache_control_command',
    'unix_config_file',
    'unix_db2dir',
    'unix_init_ora_path',
    'unix_install_dir',
    'unix_invptrloc',
    'unix_listener_ora_path',
    'unix_mirlogfile',
    'unix_ora_home_path',
    'unix_prilogfile',
    'unix_seclogfile',
    'unix_spfile_ora_path',
    'unix_sqlnet_ora_path',
    'unix_terlogfile',
    'unix_tnsnames_ora_path',
    'until_ticket_number',
    'update_existing_controls',
    'update_section_heading',
    'updated_after_datetime',
    'url',
    'use_agentless_tracking',
    'use_ip_nt_range_tags',
    'use_tags',
    'user_id',
    'user_login',
    'user_logins',
    'user_role',
    'username',
    'vendor_ref_contains',
    'version',
    'vhost',
    'vm_scan_since',
    'vuln_details',
    'vuln_details_contains',
    'vuln_id',
    'vuln_port',
    'vuln_qid',
    'vuln_results',
    'vuln_service',
    'vuln_severities',
    'vuln_severity',
    'vuln_title_contains',
    'week_of_month',
    'weekdays',
    'win_db2dir',
    'win_init_ora_path',
    'win_listener_ora_path',
    'win_mirlogfile',
    'win_ora_home_name',
    'win_ora_home_path',
    'win_prilogfile',
    'win_seclogfile',
    'win_spfile_ora_path',
    'win_sqlnet_ora_path',
    'win_terlogfile',
    'win_tnsnames_ora_path',
    'windows_config_file',
    'windows_domain',
    'xml_data',
    'zip_code',
]

class RedisConfig():
    '''
    Default configuration options such as endpoint-specific and
    argument-specific cache expirations

    __defaults__ -- a dictionary of endpoints by default applied
    to the qualysapi.api_methods from the parent module.  Use the
    keyword arguments in the constructor to override or customize the
    cache timeouts.
    '''
    # pull in the parent library stuff and then set on rules
    __defaults__ = dict.fromkeys(api_methods.api_methods['1'] |
            api_methods.api_methods['1 get'] |
            api_methods.api_methods['2'],
            7200)
    logging.debug(pprint.pformat(__defaults__))
    qconfig = None
    qusername = None
    qpassword = None
    rhost = None
    rport = None
    rdb = None
    def __init__(
            self,
            qconfig,
            **kwargs):
        '''
        Accepts.configure cache settings

        Required:
        qconfig -- the qualysapi configuration

        Optional/keyword:
        redis_user -- the redis usernmae
        redis_password -- the redis password
        default_expire -- set the default api endpoint expiration
        custom_expire -- a dictionary of endpoints with a dictionary of
        possible api parameters on which to set expiration timeout

        Note: for custom_expire values cannot be included at this time.
        If a qualys api parameter has a custom expiration, it is set
        *per value parameter* so that a request for a particular map
        will not expire or be reset if a different map is requested.

        Thus including values here discouraged.  you can do it, and it
        will work, but behavior will be a bit unpredictable.

        -- required api endpoint to apply any expiration to.

        note: you may set any amount of keyword arguments here.  the
        cache api isn't responsible for making sure that they are
        valid qualys api arguments.
        '''
        self.qconfig = qconfig
        qauth = qconfig.get_auth()

        # Debug output of qualys config stuff...
        logging.debug('***************** Cache Qualys config ***************')
        logging.debug(pprint.pformat(qauth))
        logging.debug('*****************************************************')

        self.qusername = qauth[0]
        self.qpassword = qauth[1]
        default_expire = kwargs.pop('default_expire', 7200)
        custom_expire = kwargs.pop('custom_expire', {})
        self.__defaults__.update(custom_expire)


class APICacheInstance(object):
    ''' A unary cache instance.

    Required:
    qualysconfig = a QualysConnectConfig instance set up however you
    wish.  (required to fetch keys not in the cache)
    '''

    __connection = None
    __config = None

    def __init__(self, qualysconfig, **kwargs):
        ''' initialize a cache instance

        pool -- a redis.ConnectionPool instance
        config - an APIRedisConfig instance
        '''
        self.__config = kwargs.pop(
                'redis_config',
                RedisConfig(qualysconfig))
        self.__pool = kwargs.pop('pool', None)
        if self.__pool:
            pass

    def getConnection(self,**kwargs):
        '''
        Minimal connection method

        host -- host specification

        port -- port specification

        db -- override default redis database index (default: 1)

        use_pipe -- boolean for using the pipe by default

        pipe_path -- override the redis pipe location.  sets use_pipe to
        True

        '''
        if not self.__connection:
            redis_config  = self.__config.qconfig.get_redis_options()
            # get the redis config options and update the defaults if the
            # options are NoneType
            for key in redis_config.keys():
                value = redis_config[key]
                if value is None and connection_args.get(key, None) is not None:
                    redis_config[key] = connection_args[key]
                    if key == 'ruser' or key == 'rpass':
                        debug.warn('redis user/pass are not yet implemented.')
            self.__connection = redis.StrictRedis(
                    kwargs.get('host', redis_config['host']),
                    kwargs.get('port', redis_config['port']),
                    kwargs.get('db', redis_config['db'])
                    )
        return self.__connection


    def build_redis_key(self, endpoint, **kwargs):
        '''
        builds the key fingerprint
        '''
        intersect = sorted(set(kwargs.keys()), key = api_param_key_order.index)
        return endpoint + ''.join(['|%s=%s' % (key,kwargs[key]) for key in intersect])


    def cache_flush(self, *args, **kwargs):
        '''
        Deletes a key or the entire database specified by the configuration
        '''
        conn = kwargs.get('connection', None)
        if not conn: conn = self.getConnection(**kwargs)

        if kwargs.get('all', False):
            return conn.flushdb()
        else:
            endpoint = None
            if len(args):
                endpoint = util.preformat_call(args[0])
                if self.__config.__defaults__.get(endpoint, None) is None:
                    raise exceptions.QCacheException('first argument for args \'' + endpoint \
                            + '\' not a valid qualys api endpoint.')
            else:
                endpoint = kwargs.pop('endpoint', None)
            if not endpoint:
                raise exceptions.QCacheException('can\'t find your endpoint in args or keyword args')
            data = kwargs.get('data', None)
            key = self.build_redis_key(endpoint, **data)
            return conn.delete(key)


    def cache_request(self,*args,**kwargs):
        '''
        Just build a redis key from the endpoint + arguments and
        check the cache.  If not found cache.

        if an endpoint is included as the first argument that is fine
        (backwards compatible with old qualysapi style) but the preferred
        method is to use the keyword endpoint = 'api-endpoint' as in the below
        example.
        '''
        conn = kwargs.pop('connection', None)
        if not conn:
            conn = self.getConnection(**kwargs)
        if len(args):
            endpoint = util.preformat_call(args[0])
            if self.__config.__defaults__.get(endpoint, None) is None:
                raise exceptions.QCacheExceptio('first argument for args \'' + endpoint \
                        + '\' not a valid qualys api endpoint.')
        else:
            endpoint = kwargs.pop('endpoint', None)
            if not endpoint:
                raise exceptions.QCacheException('can\'t find your endpoint in args or keyword args')

        #check the cache
        data = kwargs.get('data', None)
        if data is None: data = {}
        key = self.build_redis_key(endpoint, **data)
        result = None
        if kwargs.pop('force_cache_refresh', False):
            conn.delete(key)
        else:
            result = conn.get(key)

        #not in cache or force refresh then go to qualys
        if not result:
            logging.debug('Connecting with username \'' + \
                    self.__config.qusername + '\'')
            qgs = connect(
                    username = self.__config.qusername,
                    password = self.__config.qpassword)

            result = qgs.request(endpoint, data=data)
            conn.set(key,result)

            # set the default expiration on the cache
            if key in self.__config.__defaults__:
                conn.expire(key, self.__config.__defaults__[key])
            else:
                conn.expire(key, self.__config.__defaults__[endpoint])

        return result


    def cache_api_object(self, *args, **kwargs):
        '''
        Each type of api object returns a key and defines a representation
        of itself which can be serialized to the cache.  This function uses
        those hooks to shove the object into the cache.
        Params:
            obj -- required, the object to serialize and cache
            expiration -- optional.  override the default expiration of 5 days.
        '''
        if len(args):
            obj = args[0]
        else:
            obj = kwargs.pop('obj', None)
        if obj is None:
            raise exceptions.QCacheException('Can\'t cache NoneType')

        expiration = kwargs.pop('expiration', None)
        if expiration is None:
            expiration = 432000 # 5 days in seconds
        elif isinstance(expiration, str):
            expiration = int(expiration)

        conn = self.getConnection(**kwargs)
        # conn.setex(obj.getKey(), json.JSONEncoder(obj), expiration)
        conn.set(obj.getKey(), repr(obj))
        conn.expire(obj.getKey(), expiration)

    def load_api_object(self, *args, **kwargs):
        '''Uses json to serialize and deserialize api objects based ona  key.

        Params:
        obj -- a prototype api object to be refreshed or loaded from the cache
        objkey -- required if a prototype is not specified
        objtype -- an api object type to be used if a prototype is not
        provided.
        '''
        if len(args):
            shell = args[0]
        else:
            objkey = kwargs.pop('objkey', None)
            objtype = kwargs.pop('objtype', None)
            obj = kwargs.pop('obj', None)
            if obj is None and (objtype is None or objkey is None):
                raise exceptions.QCacheException('You must include an object, \
                    or a key and object type in order to load an API object.')
        conn = self.getConnection(**kwargs)
        if obj is not None:
            obj.refresh(json=conn.get(obj.key))
        else:
            try:
                obj = objtype(**(json.loads(str(conn.get(objkey), 'utf-8'))))
            except TypeError as e:
                obj = None
        return obj


    def map_to_report_helper(self, *args, **kwargs):
        '''
        This special helper is designed for use with multiprocessing,
        launching scans, and map references.

        The map_ref is used as a key, and stores information in the cache about
        the report ID allowing a processes to request the status of a report
        and update the cache when it is finished.

        Thus there are multiple keys used in this case, built as follows:

        map_name:
            returns the map reference (most recent specifc map result for a
            name)
        map_ref:
            returns the REPORT ID associted with this map reference.
        report_id:
            combines with map_name to link to the most recent report for a
            given map_name and the STATUS of that report.  (Running, Stopped,
            Finished, etc...)
        map:
            If the caller has a full map it can be passed in as an object

        So the above can be specified individually or a list of maps can be
        sent into this function and the status on all of them will be returned
        by this function.

        A polling processes is started and periodicially checks on the status
        of a map report and updates the cache.  This is how you check the
        status of a map report in process for the status.
        '''

        map_name = kwargs.pop('map_name', None)
        map_ref = kwargs.get('map_ref', None)
        report_id = kwargs.get('report_id', None)
        themap = kwargs.pop('map', None)

        if map_name is None and map_ref is None and themap is None:
            raise exceptions.QCacheException( \
                    'A map name or map reference is required.')
        conn = self.getConnection(**kwargs)


    def stream_cache_request(self, *args, **kwargs):
        ''' This implements a stream wrapper around redis, which doesn't handle
        streams.  Eventually this should be handled differently (because of XML
        sizes).
        '''
        result = self.cache_request(*args, **kwargs)
        return BytesIO(result)



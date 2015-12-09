# redis cache for qualys api results
import redis
from .. import api_methods, connect
import traceback
import pprint
import logging

logging.basicConfig()
# Setup module level logging.
logger = logging.getLogger(__name__)

connection_args = {
    'host' : 'localhost',
    'port' : 6379,
    'db' : 1,
}


import unittest

# this is to reliably build the redis cache key by api parameter ordering. (combined v1 and v2 api args, covers most of WAS too AFAICT right now
api_param_key_order = [
    'action',
    'active',
    'add_comment',
    'add_task',
    'address1',
    'address2',
    'ag_ids',
    'ag_title',
    'appliance_ids',
    'asset_group',
    'asset_group_ids',
    'asset_groups',
    'business_impact',
    'business_unit',
    'ca_url',
    'change_assignee',
    'change_state',
    'city',
    'comment',
    'comments',
    'control_ids',
    'country',
    'cvss_enviro_ar',
    'cvss_enviro_cdp',
    'cvss_enviro_cr',
    'cvss_enviro_ir',
    'cvss_enviro_td',
    'date_from',
    'date_to',
    'day_of_month',
    'day_of_week',
    'db_local',
    'default_scanner',
    'default_scanner_appliance',
    'deleted_before_datetime',
    'deleted_since_datetime',
    'detailed_history',
    'detailed_no_results',
    'detailed_results',
    'details',
    'division',
    'dns',
    'dns_contains',
    'dns_names',
    'domain',
    'drop_task',
    'echo_request',
    'email',
    'enable',
    'enable_pc',
    'exclude_ip_per_scan',
    'external_id',
    'external_id_contains',
    'fax',
    'first_name',
    'function',
    'general_info',
    'host_dns',
    'host_ids',
    'host_ip',
    'host_ips',
    'host_netbios',
    'host_os',
    'id',
    'id_max',
    'id_min',
    'ids',
    'ig_severity',
    'installation_path',
    'instance',
    'invalid',
    'ip',
    'ip_not_targeted_list',
    'ip_restriction',
    'ip_targeted_list',
    'ips',
    'ips_network_id',
    'is_patchable',
    'iscanner_name',
    'last',
    'last_name',
    'last_scan',
    'location',
    'login',
    'map_title',
    'merge_policy_id',
    'modified',
    'modified_since_datetime',
    'name',
    'netbios',
    'netbios_contains',
    'netblock',
    'network_id',
    'observe_dst',
    'occurrence',
    'option',
    'option_profile_title',
    'orderby',
    'output_format',
    'owner',
    'password',
    'pc_only',
    'phone',
    'policy_id',
    'port',
    'ports',
    'potential_vuln_severities',
    'potential_vuln_severity',
    'qids',
    'recurrence',
    'ref',
    'reopen_ignored_days',
    'report_refs',
    'report_title',
    'report_type',
    'save_report',
    'scan_id',
    'scan_ref',
    'scan_target',
    'scan_title',
    'scandeadhosts',
    'scanner_appliances',
    'scanners_in_ag',
    'send_email',
    'server_address',
    'servicename',
    'set_comments',
    'set_division',
    'set_function',
    'set_location',
    'set_title',
    'show_attributes',
    'show_cvss_submetrics',
    'show_pci_flag',
    'show_tags',
    'sid',
    'since',
    'since_datetime',
    'since_ticket_number',
    'siness_unit',
    'sortorder',
    'specific_vulns',
    'start_hour',
    'start_minute',
    'state',
    'states',
    'sub_type',
    'tag_set_by',
    'target',
    'target_asset_groups',
    'target_ips',
    'task_id',
    'ticket_details',
    'ticket_numbers',
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
    'unix_install_dir',
    'unmodified_since_datetime',
    'until_ticket_number',
    'url',
    'use_tags',
    'user_id',
    'user_logins',
    'user_role',
    'username',
    'vendor_ref_contains',
    'vuln_details',
    'vuln_details_contains',
    'vuln_id',
    'vuln_port',
    'vuln_qid',
    'vuln_results',
    'vuln_service',
    'vuln_severity',
    'vuln_title_contains',
    'week_of_month',
    'weekdays',
    'windows_domain',
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
    logger.debug(pprint.pformat(__defaults__))
    qusername = None
    qpassword = None
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
        qauth = qconfig.get_auth()
        self.qusername = qauth[0]
        self.qpassword = qauth[1]
        default_expire = kwargs.pop('default_expire', 7200)
        custom_expire = kwargs.pop('custom_expire', {})
        for (key, args) in custom_expire:
            pass


class QCacheException(Exception):
    '''
    Simple cache exception wrapper
    '''
    pass


class APICacheInstance():
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
            self.__connection = redis.StrictRedis(
                    kwargs.get('host', connection_args['host']),
                    kwargs.get('port', connection_args['port']),
                    kwargs.get('db', connection_args['db'])
                    )
        return self.__connection


    def build_redis_key(self, endpoint, **kwargs):
        '''
        builds the key fingerprint
        '''
        intersect = sorted(set(kwargs.keys()), key = api_param_key_order.index)
        return endpoint + ''.join(['|%s=%s' % (key,kwargs[key]) for key in intersect])


    def cache_request(self,*args,**kwargs):
        '''
        Just build a redis key from the endpoint + arguments and
        check the cache.  If not found cache.
        '''
        connection = kwargs.pop('connection', None)
        if not connection:
            connection = self.getConnection(**kwargs)
        if len(args):
            endpoint = args[0]
            if self.__config.__defaults__.get(endpoint, None) is None:
                raise QCacheException('first argument for args not a valid qualys api endpoint.')
        else:
            endpoint = kwargs.pop('endpoint', None)
            if not endpoint:
                raise QCacheException('can\'t find your endpoint in args or keyword args')

        #check the cache
        key = self.build_redis_key(endpoint, **kwargs)
        result = None
        conn = self.getConnection()
        if kwargs.pop('force_cache_refresh', False):
            conn.delete(key)
        else:
            result = conn.get(key)

        #not in cache or force refresh then go to qualys
        if not result:
            qgs = connect(
                    endpoint,
                    self.__config.qusername,
                    self.__config.qpassword)

            result = qgs.request(endpoint, **kwargs)
            conn.set(key,result)

            # set the default expiration on the cache
            if key in self.__config.__defaults__:
                conn.expire(key, self.__config.__defaults__[key])
            else:
                conn.expire(key, self.__config.__defaults__[endpoint])

        return result





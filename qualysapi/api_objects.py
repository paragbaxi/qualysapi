import datetime
import lxml
import logging
import pprint
import json
from multiprocessing import Process, Pool, Manager, get_context
from multiprocessing.queues import Queue

import threading
from qualysapi import exceptions


def jsonify(obj):
    return obj.__dict__


class CacheableQualysObject(object):
    '''
    A base class implementing the api framework
    '''
    def __init__(self, **kwargs):
        '''Superclass init function that handles json serializaiton'''
        if 'json' in kwargs:
            jsondict = json.loads(kwargs['json'])
            [setattr(self, key, jsondict[key]) for key in jsondict]


    def getKey(self):
        raise exceptions.QualysFrameworkException('You must implement this \
            function in your base class(es).')

    def __repr__(self):
        '''Represent y0'''
        return json.dumps(self.__dict__, default=jsonify)

    def __eq__(self, other):
        '''Instance equality (simple dict key/value comparison'''
        return self.__dict__ == other.__dict__


class Host(CacheableQualysObject):
    def __init__(self, dns, id, ip, last_scan, netbios, os, tracking_method):
        self.dns = str(dns)
        self.id = int(id)
        self.ip = str(ip)
        last_scan = str(last_scan).replace('T', ' ').replace('Z', '').split(' ')
        date = last_scan[0].split('-')
        time = last_scan[1].split(':')
        self.last_scan = datetime.datetime(int(date[0]), int(date[1]), int(date[2]), int(time[0]), int(time[1]), int(time[2]))
        self.netbios = str(netbios)
        self.os = str(os)
        self.tracking_method = str(tracking_method)

class AssetGroup(CacheableQualysObject):
    def __init__(self, business_impact, id, last_update, scanips, scandns, scanner_appliances, title):
        self.business_impact = str(business_impact)
        self.id = int(id)
        self.last_update = str(last_update)
        self.scanips = scanips
        self.scandns = scandns
        self.scanner_appliances = scanner_appliances
        self.title = str(title)

    def addAsset(conn, ip):
        call = '/api/2.0/fo/asset/group/'
        parameters = {'action': 'edit', 'id': self.id, 'add_ips': ip}
        conn.request(call, parameters)
        self.scanips.append(ip)

    def setAssets(conn, ips):
        call = '/api/2.0/fo/asset/group/'
        parameters = {'action': 'edit', 'id': self.id, 'set_ips': ips}
        conn.request(call, parameters)
# replaced
# class ReportTemplate(CacheableQualysObject):
#     def __init__(self, isGlobal, id, last_update, template_type, title, type, user):
#         self.isGlobal = int(isGlobal)
#         self.id = int(id)
#         self.last_update = str(last_update).replace('T', ' ').replace('Z', '').split(' ')
#         self.template_type = template_type
#         self.title = title
#         self.type = type
#         self.user = user.LOGIN

class Report(CacheableQualysObject):
    '''
    An object wrapper around qualys report handles.

    Properties:

    NOTE: previously used ordered arguments are depricated.  Right now the
    class is backwards compatible, but you cannot mix and match.  You have to
    use the previous named order or keyword arguments, not both.

    expiration_datetime -- required expiration time of the report
    id -- required id of the report
    launch_datetime -- when the report was launched
    output_format -- the output format of the report
    size -- 
    status -- current qualys state of the report (scheduled, completed, paused,
    etc...)
    type -- report type
    user_login -- user who requested the report
    '''
    expiration_datetime = None
    id = None
    launch_datetime = None
    output_format = None
    size = None
    status = None
    type = None
    user_login = None
    def __init__(self, *args, **kwargs):
        # backwards-compatible ordered argument handling
        arg_order = [
            'expiration_datetime',
            'id',
            'launch_datetime',
            'output_format',
            'size',
            'status',
            'type',
            'user_login',
        ]
        # because of the old style handling where STATE is an etree element and
        # not a string the assumption must be handled before anyhting else...
        if len(args):
            [self.setattr(arg, args[n]) for (n,arg) in enumerate(n, arg_order)]
            # special handling for a single retarded attribute...
            if self.status is not None:
                self.status = status.STATE

        # set keyword values, prefer over ordered argument values if both get
        # supplied
        for key in arg_order:
            value = kwargs.pop(key, None)
            if value is not None:
                self.setattr(key, value)

        elem = kwargs.pop('elem', None)
        if elem is not None:
            # parse an etree element into string arguments
            self.status = status.STATE
            #TODO: implement
            pass

        json = kwargs.pop('json', None)
        if json is not None:
            # parse a json dict into arguments
            #TODO: implement
            pass

        # post attribute assignment processing
        self.expiration_datetime = str(self.expiration_datetime).replace('T', ' ').replace('Z', '').split(' ')
        self.launch_datetime = str(self.launch_datetime).replace('T', ' ').replace('Z', '').split(' ')
        # if id is a string change it to an int (used by other api objects)
        if isinstance(self.id, str):
            self.id = int(self.id)

    def download(self, conn):
        call = '/api/2.0/fo/report'
        parameters = {'action': 'fetch', 'id': self.id}
        if self.status == 'Finished':
            return conn.request(call, parameters)


class QKBVuln(CacheableQualysObject):
    '''
    A class respresentation of a Qualys Knowledge Base entry.
    Params:
    qid -- the qualys id
    vtype -- the qualys vuln type identifier
    severity -- the qualys severity
    title -- a human readable title-length description of the vulnerability
    vcat -- a qualys-specific category for the vulnerability
    usermod_date -- the most recent date that this vuln was modified by the auth account manager
    servicemod_date -- the most recent date that this vuln was modified by the service
    publ_date -- the date that this vuln was published
    bugtraq_listing -- mozilla bugtraq information. A list of Bugtraq objects
    patch_avail -- Boolean conversion of QKB 0/1 value.  Indicates a known patch is available.
    diagnosis -- The Qualys service-provided evalution.
    diagnosis_notes -- Admin/user account diagnosis recommendation notes.
    consequence -- Service provided projected exploit fallout description.
    consequence_notes -- Admin/user account notes on consequences.
    solution -- Qualys/Service recommended remediation.
    solution_notes -- Admin/user solution notes.
    pci_mustfix -- PCI compliance fix mandated (boolean)
    pci_reasons -- optional depending on query argument to provide pci pass/fail reasons.
    a list of PCIReason objects.
    cvss -- a CVSS object.
    affected_software -- An ordered list (KQB ordering) of specific affected
    software (VulnSoftware class instances)
    assoc_vendors -- An unordered dictionary of software vendors associated
    with any software associated with this vulnerability.  The dictionary is
    key=vendor_id, value=VulnVendor
    compliance_notice_list -- A service-provided list of SLA/Standards that are
    or may be affected by this vulnerability.  Ordered list of Compliance
    objects, ordered as sent from qualys.
    known_exploits -- a list of correlated known exploits (Exploit obj)
    known_malware -- a list of known malware using exploits (Malware obj)
    remote_detectable -- boolean
    auth_type_list -- a list of auth types that can be used to detect
    vulnerability.  Strings.
    '''
    qid                    = None
    vtype                  = None
    severity               = None
    title                  = None
    vcat                   = None
    usermod_date           = None
    servicemod_date        = None
    publ_date              = None
    patch_avail            = False
    diagnosis              = None
    diagnosis_notes        = None
    consequence            = None
    consequence_notes      = None
    solution               = None
    solution_notes         = None
    pci_mustfix            = False
    cvss                   = None
    remote_detectable      = False
    # lists
    bugtraq_listing        = []
    cve_list               = []
    pci_reasons            = []
    affected_software      = []
    vendor_list            = []
    compliance_notice_list = []
    known_exploits         = []
    known_malware          = []
    auth_type_list         = []

    class PCIReason(CacheableQualysObject):
        '''
        Class to hold information for PCI compliance failure associated with a
        vulnerability.
        '''
        pass

    class CVE(CacheableQualysObject):
        '''
        CVE metadata encoding wrapper object and helpers.
        '''
        cve_id = None
        url    = None

        def __init__(self, *args, **kwargs):
            elem = None
            if 'elem' in kwargs:
                elem = kwargs.pop('elem')
            elif len(args) or 'xml' in kwargs:
                # we assume xml binary string
                xml    = args[0] if len(args) else kwargs.pop('xml')
                elem = lxml.objectify.fromstring(xml)

            if elem:
                self.cve_id = getattr(elem, 'ID', None)
                self.url    = getattr(elem, 'URL', None)
            else:
                self.cve_id = kwargs.pop('ID', None)
                self.url    = kwargs.pop('URL', None)

    class CVSS(CacheableQualysObject):
        '''
        CVSS metadata encoding wrapper object and helpers.
        ##CVSS element DTD:
        ```xml
        <!ELEMENT CVSS (BASE, TEMPORAL?, ACCESS?, IMPACT?,
                        AUTHENTICATION?, EXPLOITABILITY?,
                        REMEDIATION_LEVEL?, REPORT_CONFIDENCE?)>
          <!ELEMENT BASE (#PCDATA)>
            <!ATTLIST BASE source CDATA #IMPLIED>
          <!ELEMENT TEMPORAL (#PCDATA)>
          <!ELEMENT ACCESS (VECTOR?, COMPLEXITY?)>
            <!ELEMENT VECTOR (#PCDATA)>
            <!ELEMENT COMPLEXITY (#PCDATA)>
          <!ELEMENT IMPACT (CONFIDENTIALITY?, INTEGRITY?, AVAILABILITY?)>
            <!ELEMENT CONFIDENTIALITY (#PCDATA)>
            <!ELEMENT INTEGRITY (#PCDATA)>
            <!ELEMENT AVAILABILITY (#PCDATA)>
          <!ELEMENT AUTHENTICATION (#PCDATA)>
          <!ELEMENT EXPLOITABILITY (#PCDATA)>
          <!ELEMENT REMEDIATION_LEVEL (#PCDATA)>
          <!ELEMENT REPORT_CONFIDENCE (#PCDATA)>
        ```
        Parameters:

        base -- BASE element.  CVSS base score.  (A CVSS base score assigned to
        the vulnerability. (This element appears only when the CVSS Scoring
        feature is turned on in the user’s subscription and the API request is
        for “Basic” details or “All” details.)
        temporal_score -- TEMPORAL element.  A CVSS temporal score. (This
        element appears only when the CVSS Scoring feature is turned on in the
        user’s subscription and the API request is for “Basic” details or “All”
        details.)
        access -- ACCESS element/class.
        impact -- IMPACT element/class.
        authentication    -- AUTHENTICATION child element.  A CVSS
        authentication metric. This metric measures the number of times an
        attacker must authenticate to a target in order to exploit a
        vulnerability. The value is: Undefined, Non required, Require single
        instance, or Require multiple instances. See “CVSS V2 Sub Metrics
        Mapping” below. (This element appears only when the CVSS Scoring
        feature is turned on in the user’s subscription and the API
        request includes the parameter details=All.)
        exploitability    -- EXPLOITABILITY child element.  A CVSS
        exploitability metric. This metric measures the current state of
        exploit techniques or code availability. The value is: Undefined,
        Unproven, Proof-of- concept, Functional, or Widespread. See “CVSS V2
        Sub Metrics Mapping” below. (This element appears only when the CVSS
        Scoring feature is turned on in the user’s subscription and the
        API request includes the parameter details=All.)
        remediation_level -- REMEDIATION_LEVEL child element.  A CVSS
        remediation level metric. The remediation level of a vulnerability is
        an important factor for prioritization. The value is: Undefined,
        Official-fix, Temporary-fix, Workaround, or Unavailable. See “CVSS V2
        Sub Metrics Mapping” below. (This element appears only when the CVSS
        Scoring feature is turned on in the user’s subscription and the
        API request includes the parameter details=All.)
        report_confidence -- REPORT_CONFIDENCE child element.  A CVSS report
        confidence metric. This metric measures the degree of confidence in the
        existence of the vulnerability and the credibility of the known
        technical details. The value is: Undefined, Not confirmed,
        Uncorroborated, or Confirmed. See “CVSS V2 Sub Metrics Mapping” below.
        (This element appears only when the CVSS Scoring feature is turned on
        in the user’s subscription and the API request includes the parameter
        details=All.)
        '''

        base = None
        temporal = None
        access = None
        impact = None
        authentication = None
        exploitability = None
        remediation_level = None
        report_confidence = None
        product   = None
        vendor_id = None

        def __init__(self, *args, **kwargs):

            elem = None
            if 'elem' in kwargs:
                elem = kwargs.pop('elem')
            elif len(args) or 'xml' in kwargs:
                # we assume xml binary string
                xml    = args[0] if len(args) else kwargs.pop('xml')
                elem = lxml.objectify.fromstring(xml)

            if elem:
                self.base              = getattr(elem, 'BASE', None)
                self.temporal          = getattr(elem, 'TEMPORAL', None)
                self.access            = \
                        CVSSAccess(getattr(elem, 'ACCESS', None))
                self.impact            = \
                        CVSSImpact(getattr(elem, 'IMPACT', None))
                self.authentication    = getattr(elem, 'AUTHENTICATION', None)
                self.exploitability    = getattr(elem, 'EXPLOITABILITY', None)
                self.remediation_level = getattr(elem, 'REMEDIATION_LEVEL', None)
                self.report_confidence = getattr(elem, 'REPORT_CONFIDENCE', None)
            else:
                self.base              = kwargs.pop('BASE', None)
                self.temporal          = kwargs.pop('TEMPORAL', None)
                self.access            = \
                        self.CVSSAccess(**(kwargs.pop('ACCESS', {})))
                self.impact            = \
                        self.CVSSImpact(**(kwargs.pop('IMPACT', {})))
                self.authentication    = kwargs.pop('AUTHENTICATION', None)
                self.exploitability    = kwargs.pop('EXPLOITABILITY', None)
                self.remediation_level = kwargs.pop('REMEDIATION_LEVEL', None)
                self.report_confidence = kwargs.pop('REPORT_CONFIDENCE', None)

        class CVSSImpact(CacheableQualysObject):
            '''
            CVSS impacted areas.

            Params:

            confidentiality -- CONFIDENTIALITY child element.  A CVSS
            confidentiality impact metric. This metric measures the impact on
            confidentiality of a successfully exploited vulnerability. The
            value is: Undefined, None, Partial, or Complete. See “CVSS V2 Sub
            Metrics Mapping” below. (This element appears only when the CVSS
            Scoring feature is turned on in the user’s subscription and the API
            request includes the parameter details=All.)
            integrity -- INTEGRITY child element.  A CVSS integrity impact
            metric. This metric measures the impact to integrity of a
            successfully exploited vulnerability. The value is: Undefined,
            None, Partial, or Complete. See “CVSS V2 Sub Metrics Mapping”
            below. (This element appears only when the CVSS Scoring feature is
            turned on in the user’s subscription and the API request includes
            the parameter details=All.)
            availability -- AVAILABILITY child element.  A CVSS availability
            impact metric. This metric measures the impact to availability of a
            successfully exploited vulnerability. The value is: Undefined,
            None, Partial, or Complete. See “CVSS V2 Sub Metrics Mapping”
            below. (This element appears only when the CVSS Scoring feature is
            turned on in the user’s subscription and the API request includes
            the parameter details=All.)
            '''
            confidentiality = None
            integrity       = None
            availability    = None

            def __init__(self, *args, **kwargs):

                elem = None
                if 'elem' in kwargs:
                    elem = kwargs.pop('elem')
                elif len(args) or 'xml' in kwargs:
                    # we assume xml binary string
                    xml    = args[0] if len(args) else kwargs.pop('xml')
                    elem = lxml.objectify.fromstring(xml)

                if elem:
                    confidentiality = getattr(elem, 'CONFIDENTIALITY', None)
                    integrity       = getattr(elem, 'INTEGRITY', None)
                    availability    = getattr(elem, 'AVAILABILITY', None)
                else:
                    confidentiality = kwargs.pop('CONFIDENTIALITY', None)
                    integrity       = kwargs.pop('INTEGRITY', None)
                    availability    = kwargs.pop('AVAILABILITY', None)


        class CVSSAccess(CacheableQualysObject):
            '''
            A tuple of data, but made an object because of feature and
            extension desireability.

            Params:

            vector -- A CVSS access vector metric. This metric reflects how the
            vulnerability is exploited. The more remote an attacker can be to
            attack a host, the greater the vulnerability score. The value is
            one of the following: Network, Adjacent Network, Local Access, or
            Undefined. See “CVSS V2 Sub Metrics Mapping” below. (This element
            appears only when the CVSS Scoring feature is turned on in the
            user’s subscription and the API request includes the parameter
            details=All.)
            complexity -- A CVSS access complexity metric. This metric measures
            the complexity of the attack required to exploit the vulnerability
            once an attacker has gained access to the target system. The value
            is one of the following: Undefined, Low, Medium, or High. See “CVSS
            V2 Sub Metrics Mapping” below. (This element appears only when the
            CVSS Scoring feature is turned on in the user’s subscription and
            the API request includes the parameter details=All.)

            '''
            vector = None
            complexity = None

            def __init__(self, *args, **kwargs):

                elem = None
                if 'elem' in kwargs:
                    elem = kwargs.pop('elem')
                elif len(args) or 'xml' in kwargs:
                    # we assume xml binary string
                    xml    = args[0] if len(args) else kwargs.pop('xml')
                    elem = lxml.objectify.fromstring(xml)

                if elem:
                    vector     = getattr(elem, 'VECTOR', None)
                    complexity = getattr(elem, 'COMPLEXITY', None)
                else:
                    vector     = kwargs.pop('VECTOR', None)
                    complexity = kwargs.pop('COMPLEXITY', None)


    class VulnSoftware(CacheableQualysObject):
        '''
        Information on known associated software.
        '''
        product   = None
        vendor_id = None

        def __init__(self, *args, **kwargs):

            elem = None
            if 'elem' in kwargs:
                elem = kwargs.pop('elem')
            elif len(args) or 'xml' in kwargs:
                # we assume xml binary string
                xml    = args[0] if len(args) else kwargs.pop('xml')
                elem = lxml.objectify.fromstring(xml)

            if elem:
                self.product   = getattr(elem, 'PRODUCT', None)
                self.vendor_id = getattr(elem, 'VENDOR', None)
            else:
                self.product   = kwargs.pop('PRODUCT', None)
                self.vendor_id = kwargs.pop('VENDOR', None)

    class VulnVendor(CacheableQualysObject):
        '''
        Information on vendors associated with software.
        '''
        vendor_id = None
        url       = None

        def __init__(self, *args, **kwargs):

            elem = None
            if 'elem' in kwargs:
                elem = kwargs.pop('elem')
            elif len(args) or 'xml' in kwargs:
                # we assume xml binary string
                xml    = args[0] if len(args) else kwargs.pop('xml')
                elem = lxml.objectify.fromstring(xml)

            if elem:
                self.vendor_id = getattr(elem, 'ID', None)
                self.url       = getattr(elem, 'URL', None)
            else:
                self.vendor_id = kwargs.pop('ID', None)
                self.url       = kwargs.pop('URL', None)

    class Compliance(CacheableQualysObject):
        '''
        Information about a specific associated compliance failure association
        with a vulnerability.
        '''
        # TYPE, SECTION, DESCRIPTION
        ctype       = None
        csection    = None
        description = None

        def __init__(self, *args, **kwargs):

            elem = None
            if 'elem' in kwargs:
                elem = kwargs.pop('elem')
            elif len(args) or 'xml' in kwargs:
                # we assume xml binary string
                xml = args[0] if len(args) else kwargs.pop('xml')
                elem =  lxml.objectify.fromstring(xml)

            if elem:
                self.ctype       = getattr(elem, 'TYPE', None)
                self.csection    = getattr(elem, 'SECTION', None)
                self.description = getattr(elem, 'DESCRIPTION', None)
            else:
                self.ctype       = kwargs.pop('TYPE', None)
                self.csection    = kwargs.pop('SECTION', None)
                self.description = kwargs.pop('DESCRIPTION', None)

    class Exploit(CacheableQualysObject):
        '''
        Information about a specific exploit associated with a vulnerability.
        '''
        src  = None
        ref  = None
        desc = None
        link = None

        def __init__(self, *args, **kwargs):

            elem = None
            if 'elem' in kwargs:
                elem = kwargs.pop('elem')
            elif len(args) or 'xml' in kwargs:
                # we assume xml binary string
                xml = args[0] if len(args) else kwargs.pop('xml')
                elem =  lxml.objectify.fromstring(xml)

            # source must come from kwargs
            self.src = kwargs.pop('SRC', None)
            if not self.src:
                raise exceptions.QualysFrameworkException('Source must be \
                    included as a keyword argument to this class.')

            if elem:
                self.ref  = getattr(elem, 'REF',  None )
                self.desc = getattr(elem, 'DESC', None )
                self.link = getattr(elem, 'LINK', None )

            else:
                self.ref  = kwargs.pop('REF',  None )
                self.desc = kwargs.pop('DESC', None )
                self.link = kwargs.pop('LINK', None )

    class Malware(CacheableQualysObject):
        '''
        Information about a specific piece of malware using a known exploit
        associated with this vulnerability.
        '''
        mwid     = None
        mwtype   = None
        platform = None
        alias    = None
        rating   = None

        def __init__(self, *args, **kwargs):

            elem = None
            if 'elem' in kwargs:
                elem = kwargs.pop('elem')
            elif len(args) or 'xml' in kwargs:
                # we assume xml binary string
                xml = args[0] if len(args) else kwargs.pop('xml')
                elem =  lxml.objectify.fromstring(xml)

            # source must come from kwargs
            self.src = kwargs.pop('SRC', None)
            if not self.src:
                raise exceptions.QualysFrameworkException('Source must be \
                    included as a keyword argument to this class.')

            if elem:
                self.mwid     = getattr(elem, 'MW_ID',       None )
                self.mwtype   = getattr(elem, 'MW_TYPE',     None )
                self.platform = getattr(elem, 'MW_PLATFORM', None )
                self.alias    = getattr(elem, 'MW_ALIAS',    None )
                self.rating   = getattr(elem, 'MW_RATING',   None )

            else:
                self.mwid     = kwargs.pop('MW_ID',       None )
                self.mwtype   = kwargs.pop('MW_TYPE',     None )
                self.platform = kwargs.pop('MW_PLATFORM', None )
                self.alias    = kwargs.pop('MW_ALIAS',    None )
                self.rating   = kwargs.pop('MW_RATING',   None )

    class Bugtraq(CacheableQualysObject):
        '''
        A single bugtraq metadata set
        '''
        bugid = None
        url = None

        def __init__(self, *args, **kwargs):

            elem = None
            if 'elem' in kwargs:
                elem = kwargs.pop('elem')
            elif len(args) or 'xml' in kwargs:
                # we assume xml binary string
                xml = args[0] if len(args) else kwargs.pop('xml')
                elem =  lxml.objectify.fromstring(xml)

            if elem:
                self.bugid = getattr(elem, 'ID', None)
                self.url   = getattr(elem, 'URL', None)
            else:
                self.bugid = kwargs.pop('ID', None)
                self.url   = kwargs.pop('URL', None)

    def __init__(self, *args, **kwargs):
        '''gracefully handle xml passed in as a blind ordered argument binary
        string.

        Otherwise operate with dictionaries/keyword arguments.
        '''
        elem = None
        if 'elem' in kwargs:
            elem = kwargs.pop('elem')
        elif len(args) or 'xml' in kwargs:
            # we assume xml binary string
            xml = args[0] if len(args) else kwargs.pop('xml')
            elem =  lxml.objectify.fromstring(xml)

        if elem:
            self.qid               = getattr(elem, 'QID', None)
            self.vtype             = getattr(elem, 'VULN_TYPE', None)
            self.severity          = getattr(elem, 'SEVERITY_LEVEL', None)
            self.title             = getattr(elem, 'TITLE', None)
            self.vcat              = getattr(elem, 'CATEGORY', None)
            self.usermod_date      = getattr(elem, 'LAST_CUSTOMIZATION', None)
            self.servicemod_date   = getattr(elem, 'LAST_SERVICE_MODIFICATION_DATETIME', None)
            self.publ_date         = getattr(elem, 'PUBLISHED_DATETIME', None)
            self.patch_avail       = \
                False if int(getattr(elem, 'PATCHABLE', 0)) else True
            self.diagnosis         = getattr(elem, 'DIAGNOSIS', None)
            self.diagnosis_notes   = getattr(elem, 'DIAGNOSIS_COMMENT', None)
            self.consequence       = getattr(elem, 'CONSEQUENCE', None)
            self.consequence_notes = getattr(elem, 'CONSEQUENCE_COMMENT', None)
            self.solution          = getattr(elem, 'SOLUTION', None)
            self.solution_notes    = getattr(elem, 'SOLUTION_COMMENT', None)
            self.pci_mustfix       = \
                False if int(getattr(elem, 'PCI_FLAG', 0)) else True
            self.cvss              = self.CVSS(elem = getattr(elem, 'CVSS', None))
            # lists / subparse objects
            self.bugtraq_listing   = \
                    [ self.Bugtraq(elem = item) for item in getattr(elem,
                        'BUGTRAQ_LIST', []) ]
            self.cve_list          = \
                    [ self.CVE(elem = item) for item in getattr(elem,
                        'CVE_LIST', [])]
            self.pci_reasons = \
                    [ self.PCIReason(elem = item) for item in getattr(elem,
                        'PCI_REASONS', [])]
            self.affected_software = \
                    [ self.VulnSoftware(elem = item) for item in getattr(elem,
                        'SOFTWARE_LIST', [])]
            self.vendor_list       = \
                    [ self.VulnVendor(elem = item) for item in getattr(elem,
                        'VENDOR_REFERENCE_LIST', [])]
            self.compliance_notice_list = \
                    [ self.Compliance(elem = item) for item in getattr(elem,
                        'COMPLIANCE_LIST', [])]

            # correlation is a bit more tricky
            correlation             = getattr(elem, 'CORRELATION', None)
            if correlation:
                # reverse the source/mw|ex nesting to mw.source and ex.source
                for exsource in getattr( correlation, 'EXPLOITS', []):
                    self.known_exploits.extend( (
                        Exploit(
                            src = exsource.EXPLT_SRC,
                            ref = explt.REF,
                            desc = explt.DESC,
                            link = explt.LINK)
                        for explt in expltsource.EXPLT_LIST ) )
                # the DTD and XPATH conflict in the docs.  Needs to be verified
                for mwsource in getattr( correlation, 'MALWARE', []):
                    self.known_malware.extend( (
                        Malware(
                            src = mwsource.MW_SRC,
                            mwid = mwinfo.MW_ID,
                            mwtype = mwinfo.MW_TYPE,
                            platform = mwinfo.MW_PLATFORM,
                            alias = mwinfo.MW_PLATFORM,
                            rating = mwinfo.MW_PLATFORM,
                            link = mwinfo.MW_PLATFORM )
                        for mwinfo in mwsource.MW_LIST ) )

            #remote boolean ? +authtype list if false.
            if hasattr(elem, 'DISCOVERY'):
                self.remote_detectable = \
                        False if elem.DISCOVERY.REMOTE else True
                self.auth_type_list      = \
                        [ auth_type for auth_type in
                            getattr(elem.DISCOVERY, 'AUTH_TYPE_LIST', [])]
        else:
            # we assume standard kwarg arguments
            self.qid               = kwargs.pop('QID', None)
            self.vtype             = kwargs.pop('VULN_TYPE', None)
            self.severity          = kwargs.pop('SEVERITY_LEVEL', None)
            self.title             = kwargs.pop('TITLE', None)
            self.vcat              = kwargs.pop('CATEGORY', None)
            self.usermod_date      = kwargs.pop('LAST_CUSTOMIZATION', None)
            self.servicemod_date   = kwargs.pop('LAST_SERVICE_MODIFICATION_DATETIME', None)
            self.publ_date         = kwargs.pop('PUBLISHED_DATETIME', None)
            self.patch_avail       = \
                False if int(kwargs.pop('PATCHABLE', 0)) else True
            self.diagnosis         = kwargs.pop('DIAGNOSIS', None)
            self.diagnosis_notes   = kwargs.pop('DIAGNOSIS_COMMENT', None)
            self.consequence       = kwargs.pop('CONSEQUENCE', None)
            self.consequence_notes = kwargs.pop('CONSEQUENCE_COMMENT', None)
            self.solution          = kwargs.pop('SOLUTION', None)
            self.solution_notes    = kwargs.pop('SOLUTION_COMMENT', None)
            self.pci_mustfix       = \
                False if int(kwargs.pop('PCI_FLAG', 0)) else True
            self.cvss              = self.CVSS(elem = kwargs.pop('CVSS', None))
            # lists / subparse objects
            #TODO: make this graceful
            raise exceptions.QualysFrameworkException('Not yet implemented: \
                kwargs lists grace.')


class OptionProfile(CacheableQualysObject):
    title = None
    is_default = False
    def __init__(self, *args, **kwargs):
        el = None

        # args or kwargs...
        if len(args):
            el = args[0]
        elif kwargs.get('elem', None):
            el = kwargs.get('elem')

        if el is not None:
            self.title = el.text
            self.is_default = (el.get('option_profile_default', 1) == 0)


class Map(CacheableQualysObject):
    '''
    A simple object wrapper around the qualys api concept of a map.

    Params:
    name = None
    ref = None
    date = None
    domain = None
    status = None
    report_id = None
    '''
    name = None
    ref = None
    date = None
    domain = None
    status = None
    report_id = None

    def __init__(self, *args, **kwargs):
        '''Instantiate a new Map.'''

        #superclass handles json serialized properties
        super(Map, self).__init__(**kwargs)

        if 'json' in kwargs:
            # our option profiles will be dicts... resolve
            self.option_profiles = [OptionProfile(json=json.dumps(op)) for op in
                self.option_profiles]
        #instantiate from an etree element
        elem = kwargs.pop('elem', None)
        if elem is not None: #we are being initialized with an lxml element, assume it's in CVE export format
            logging.debug('Map with elem\n\t\t%s' % pprint.pformat(elem))
            self.ref = elem.get('ref', None)
            self.date = elem.get('date', None)
            self.domain = elem.get('domain', None)
            self.status = elem.get('status', None)

            for child in elem:
                if lxml.etree.QName(child.tag).localname.upper() == 'TITLE':
                    if child.text:
                        self.name = child.text
                    else:
                        self.name="".join(child.itertext())
                if lxml.etree.QName(child.tag).localname.upper() == \
                    'OPTION_PROFILE':
                    self.option_profiles = [OptionProfile(op) for op in child]

        # instance from kwargs
        for key in kwargs.keys():
            setattr(self, key, kwargs[key])

    def getKey(self):
        return self.ref if self.ref is not None else self.name

    def hasReport(self):
        return self.report_id is not None

    def setReport(self, **kwargs):
        report_id = kwargs.get('report_id', None)
        report = kwargs.get('report', None)
        if report_id is None and report is None:
            raise exceptions.QualysException('No report or report id.')
        self.report_id = report_id if report is None else report.id

    def __str__(self):
        '''Stringify this object.  NOT the same as repr().'''
        return '<Map name=\'%s\' date=\'%s\' ref=\'%s\' />' % (self.name, \
                self.date, self.ref)


class MapResult(Map):
    '''The actual results of a map.'''
    def __init__(self):
        '''A map result is a subclass of Map but it gets it's values of name,
        ref, date, domain, status from different fields in a result.'''
        raise QualysException('This class hasn\'t been implemented yet.')


class Scan(CacheableQualysObject):
    def __init__(self, assetgroups, duration, launch_datetime, option_profile, processed, ref, status, target, title, type, user_login):
        self.assetgroups = assetgroups
        self.duration = str(duration)
        launch_datetime = str(launch_datetime).replace('T', ' ').replace('Z', '').split(' ')
        date = launch_datetime[0].split('-')
        time = launch_datetime[1].split(':')
        self.launch_datetime = datetime.datetime(int(date[0]), int(date[1]), int(date[2]), int(time[0]), int(time[1]), int(time[2]))
        self.option_profile = str(option_profile)
        self.processed = int(processed)
        self.ref = str(ref)
        self.status = str(status.STATE)
        self.target = str(target).split(', ')
        self.title = str(title)
        self.type = str(type)
        self.user_login = str(user_login)

    def __repr__(self):
        ''' Represent this object in a human-readable string '''
        return '''
    Scan '%s':
        lanch datetime: %s
        option profile: %s
        scan ref: %s
        status: %s
        target: %s
        type: %s
        user: %s
        ''' % (self.title, self.launch_datetime, self.option_profile, self.ref,
                self.status, self.target, self.type, self.user_login)

    def cancel(self, conn):
        cancelled_statuses = ['Cancelled', 'Finished', 'Error']
        if any(self.status in s for s in cancelled_statuses):
            raise ValueError("Scan cannot be cancelled because its status is "+self.status)
        else:
            call = '/api/2.0/fo/scan/'
            parameters = {'action': 'cancel', 'scan_ref': self.ref}
            conn.request(call, parameters)

            parameters = {'action': 'list', 'scan_ref': self.ref, 'show_status': 1}
            self.status = lxml.objectify.fromstring(conn.request(call, parameters)).RESPONSE.SCAN_LIST.SCAN.STATUS.STATE

    def pause(self, conn):
        if self.status != "Running":
            raise ValueError("Scan cannot be paused because its status is "+self.status)
        else:
            call = '/api/2.0/fo/scan/'
            parameters = {'action': 'pause', 'scan_ref': self.ref}
            conn.request(call, parameters)

            parameters = {'action': 'list', 'scan_ref': self.ref, 'show_status': 1}
            self.status = lxml.objectify.fromstring(conn.request(call, parameters)).RESPONSE.SCAN_LIST.SCAN.STATUS.STATE

    def resume(self, conn):
        if self.status != "Paused":
            raise ValueError("Scan cannot be resumed because its status is "+self.status)
        else:
            call = '/api/2.0/fo/scan/'
            parameters = {'action': 'resume', 'scan_ref': self.ref}
            conn.request(call, parameters)

            parameters = {'action': 'list', 'scan_ref': self.ref, 'show_status': 1}
            self.status = lxml.objectify.fromstring(conn.request(call, parameters)).RESPONSE.SCAN_LIST.SCAN.STATUS.STATE


class MapReport(CacheableQualysObject):
    '''
    A class to wrap an actual map report given a report format.
    This will probably be a stub class.
    '''
    pass


class SimpleReturnResponse(CacheableQualysObject):
    '''A wrapper for qualys responses to api commands (as opposed to requests).

    Properties:
    response_time -- Response header timestamp.
    response_text -- Response header text.
    response_items -- A list of key/value pairs returned with the header.  This
    isn't private, but it should be considered protected.  Mostly.
    '''
    reponse_time   = None
    response_text  = None
    response_code  = None
    response_items = {}

    def __init__(self, *args, **kwargs):
        elem = None
        if 'elem' in kwargs:
            elem = kwargs.pop('elem')
        elif len(args) or 'xml' in kwargs:
            # we assume xml binary string
            xml = args[0] if len(args) else kwargs.pop('xml')
            elem =  lxml.objectify.fromstring(xml)

        if elem:
            self.reponse_time   = getattr(elem, 'DATETIME', None )
            self.response_code  = getattr(elem, 'CODE',     None )
            self.response_text  = getattr(elem, 'TEXT',     None )
            self.response_items = dict(((item.KEY, item.VALUE) for item in \
                getattr(elem, 'ITEM_LIST', [])))
        else:
            self.reponse_time   = kwargs.pop('DATETIME', None )
            self.response_code  = kwargs.pop('CODE',     None )
            self.response_text  = kwargs.pop('TEXT',     None )
            self.response_items = dict(((item.KEY, item.VALUE) for item in \
                kwargs.pop('ITEM_LIST', [])))

    def getStatus(self):
        '''A wrapper around the response status attribute that should handle
        all of the various api responses the same.'''
        # TODO: implement
        raise exceptions.QualysFrameworkException('Not yet implemented.')

    def hasItem(self, key):
        '''Check for a key/value pair'''
        return True if key in self.response_items else False

    def getItemValue(self, key, default=None):
        '''hook for dict.get to callers'''
        return self.response_items.get(key, default)

    def getItemKeys(self):
        '''hook for dict.keys to callers'''
        return self.response_items.keys()

    def wasSuccessful(self):
        '''A bit more complicated than a simple 200 response, this method
        attempts to unify multiple types of responses into a unified
        success/fail test.  Child classes can extend this for additional
        conditions that include response codes, different response texts and
        anything else useful for a unilateral true/false.
        '''
        return True if self.response_text != 'Failed' else False

class QualysUser(CacheableQualysObject):
    ''' Common shared wrapper class for a User representation of the User
    element.
    <!ELEMENT LOGIN     (# PCDATA)>
    <!ELEMENT FIRSTNAME (# PCDATA)>
    <!ELEMENT LASTNAME  (# PCDATA)>
    Params
    login     -- username
    firstname -- frist... name
    lastname  -- last... name
    '''
    login     = ''
    firstname = ''
    lastname  = ''
    def __init__(self, *args, **kwargs):
        elem = None
        if 'elem' in kwargs:
            elem = kwargs.pop('elem')
        elif len(args) or 'xml' in kwargs:
            # we assume xml binary string
            xml = args[0] if len(args) else kwargs.pop('xml')
            elem =  lxml.objectify.fromstring(xml)

        if elem:
            self.login     = getattr(elem, 'LOGIN',     None )
            self.firstname = getattr(elem, 'FIRSTNAME', None )
            self.lastname  = getattr(elem, 'LASTNAME',  None )
        else:
            self.login     = kwargs.pop('LOGIN',     None )
            self.firstname = kwargs.pop('FIRSTNAME', None )
            self.lastname  = kwargs.pop('LASTNAME',  None )



class ReportTemplate(CacheableQualysObject):
    ''' Wrapper class for a report template

    DTD:
    <!ELEMENT REPORT_TEMPLATE (ID,
        TYPE,
        TEMPLATE_TYPE,
        TITLE,
        USER,
        LAST_UPDATE,
        GLOBAL,
        DEFAULT?)>
    <!ELEMENT ID (#PCDATA)>
    <!ELEMENT TYPE (#PCDATA)>
    <!ELEMENT TEMPLATE_TYPE (#PCDATA)>
    <!ELEMENT TITLE (#PCDATA)>
    <!ELEMENT USER (LOGIN, FIRSTNAME, LASTNAME)>
    <!ELEMENT LAST_UPDATE (#PCDATA)>
    <!ELEMENT GLOBAL (#PCDATA)>
    <!ELEMENT DEFAULT (#PCDATA)>

    Params:


    '''
    template_id    = None
    report_type   = None
    template_type = None
    title         = None
    user          = None
    last_update   = None
    is_global     = False
    is_default    = False

    def __init__(self, *args, **kwargs):

        elem = None
        if 'elem' in kwargs:
            elem = kwargs.pop('elem')
        elif len(args) or 'xml' in kwargs:
            # we assume xml binary string
            xml = args[0] if len(args) else kwargs.pop('xml')
            elem =  lxml.objectify.fromstring(xml)

        if elem:
            self.template_id    = getattr(elem, 'ID', self.template_id)
            self.report_type   = getattr(elem, 'TYPE', self.report_type)
            self.template_type = getattr(elem, 'TEMPLATE_TYPE', self.template_type)
            self.title         = getattr(elem, 'TITLE', self.title)
            self.user          = getattr(elem, 'USER', self.user)
            self.last_update   = getattr(elem, 'LAST_UPDATE', self.last_update)
            self.is_global     = getattr(elem, 'GLOBAL', self.is_global)
            self.is_default    = getattr(elem, 'DEFAULT', self.is_default)
        else:
            self.template_id    = kwargs.pop('ID', self.template_id)
            self.report_type   = kwargs.pop('TYPE', self.report_type)
            self.template_type = kwargs.pop('TEMPLATE_TYPE', self.template_type)
            self.title         = kwargs.pop('TITLE', self.title)
            self.user = \
                    QualysUser(**(kwargs.pop('USER', {})))
            self.last_update   = kwargs.pop('LAST_UPDATE', self.last_update)
            self.is_global     = kwargs.pop('GLOBAL', self.is_global)
            self.is_default    = kwargs.pop('DEFAULT', self.is_default)


# element to api_object mapping
# this is temporary in lieu of an object which allows for user-override of
# parse object (subclass parse consumers)
obj_elem_map = {
    'MAP_REPORT' : Map,
    'MAP_RESULT' : MapResult,
    'VULN' : QKBVuln,
    'REPORT_TEMPLATE': ReportTemplate,
    'SESPONSE': SimpleReturnResponse,
}

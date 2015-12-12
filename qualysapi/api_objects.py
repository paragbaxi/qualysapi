import datetime
import lxml
import logging
import pprint

obj_elem_map = {
    'MAP_REPORT' : Map,
}


class Host(object):
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

class AssetGroup(object):
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

class ReportTemplate(object):
    def __init__(self, isGlobal, id, last_update, template_type, title, type, user):
        self.isGlobal = int(isGlobal)
        self.id = int(id)
        self.last_update = str(last_update).replace('T', ' ').replace('Z', '').split(' ')
        self.template_type = template_type
        self.title = title
        self.type = type
        self.user = user.LOGIN

class Report(object):
    def __init__(self, expiration_datetime, id, launch_datetime, output_format, size, status, type, user_login):
        self.expiration_datetime = str(expiration_datetime).replace('T', ' ').replace('Z', '').split(' ')
        self.id = int(id)
        self.launch_datetime = str(launch_datetime).replace('T', ' ').replace('Z', '').split(' ')
        self.output_format = output_format
        self.size = size
        self.status = status.STATE
        self.type = type
        self.user_login = user_login

    def download(self, conn):
        call = '/api/2.0/fo/report'
        parameters = {'action': 'fetch', 'id': self.id}
        if self.status == 'Finished':
            return conn.request(call, parameters)


class Map(object):
    def __init__(self, *args, **kwargs):
        '''Instantiate a new Map.'''
        elem = kwargs.pop('elem', None)
        if elem is not None: #we are being initialized with an lxml element, assume it's in CVE export format
            for child in elem:
                logging.debug(lxml.etree.QName(child.tag).localname.upper())


class Scan(object):
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

from multiprocessing import process, queue, pool
class BuffFlusher(Process):
    '''A multiprocessing class that is capable of doing side-process buffer
    flushing to a database or object cash or anything else while the parse
    continues to parse a large data set.'''

    def __init__(self, **kwargs):
        '''Initializes a buffer flusher'''
        pass

    def start(self):
        pass

class BuffQueue(object):
    '''A thread/process safe queue for append/pop operations with the import
    buffer.  Initially this is just a wrapper around a collections deque but in
    the future it will be based off of multiprocess queue for access across
    processes (which isn't really possible right now)'''
    queue = Queue()

    def consume(self, lim):
        '''Consume up to but no more than lim elements and return them in a new
        list, cleaning up the buffer.

        @params
        lim -- the maximum (limit) to consume from the list.  If less items
        exist in the list then that's fine too.
        '''
        lim = len(queue) if len(queue) < lim else lim
        return [self.queue.popleft() for i in range(lim)]

    def add(self, element):
        '''Adds a new object to the end of the queue.'''
        self.queue.append(element)

    def getsize(self):
        ''' return the number of items currently in the queue at the exact
        moment this was called.  This is only really useful for metrics since
        the number can change at any time based on consumer(s).
        '''
        return len(queue)


class BufferStats(object):
    '''A simple wrapper for statistics about speeds and times.'''
    processed = 0

    #data processing stats
    updates = 0
    adds = 0
    deletes = 0

    #time stats
    start_time = None
    end_time = None


    def calculate_processing_average(self):
        '''Function to give the average time per operation between start_time,
        end_time and number processed.  Useful for metrics.'''
        pass


class BufferConsumer(process):
    '''This will eventually be a subclass of Process, but for now it is simply
    a consumer which will consume buffer objects and do somethign with them.
    '''

    def __init__(self, **kwargs):
        '''
        initialize this consumer with a bite_size to consume from the buffer.
        '''
        self.bite_size = kwargs.get('bite_size', 1000)
        self.queue = kwargs.get('queue', None)

    def run(self):
        '''a processes that consumes a queue in bite-sized chunks'''
        for item in self.queue.consume(self.bite_size):
            #the base class just logs this stuff
            logging.debug(str(item, 'utf-8'))


class ImportBuffer(object):
    '''
        This is a queue manager for a multiprocesses queue consumer for
        incoming data from qualys.  Rather than making huge lists of objects
        from xml, this buffer is used to place new objects as they are parsed
        out of the xml.  A trigger_limit and bite_size are set and used to
        trigger consumption of the queue.

        The general idea is that the buffer creates a single consumer on
        instantiation and tells it to start consuming queue items.  If the
        trigger_limit is reached then a second consumer is created which also
        begins consuming items from the que with each process consuming
        bite_size queue items at a time.  In this way concurrent processing of
        thread queues is retained.

        Consumers are responsible for making sure that transactionalized
        insertion of data doesn't clobber each other.  This module is not
        capable of ensuring that items inserted in one processes but not yet
        comitted to the database will be detected by another process.
        Obviously.
    '''
    queue = BuffQueue()
    stats = bufferStats()

    trigger_limit = 5000
    bite_size = 1000
    max_consumers = 5
    process_pool = 

    def __init__(self, *args, **kwargs):
        '''
        Creates a new import buffer.

        @Params
        trigger_limit -- set the consumer triggering limit.  The default is
        5000.
        bite_size -- set the consumer consumption size (bites NOT BYTES).  The
        default is 1000.
        max_consumers -- set the maximum number of queue consumers to spawn.
        The default is five.
        '''
        tlimit = kwargs.pop('trigger_limit', None)
        if tlimit is not None:
            self.trigger_limit = tlimit
        bsize = kwargs.pop('bite_size', None)
        if bsize is not None:
            self.bite_size = bsize
        mxcons = kwargs.pop('max_consumers', None)
        if mxcons is not None:
            self.max_consumers = mxcons

    def add(self, item):
        '''Place a new object into the buffer'''
        queue.add(item)
        if 

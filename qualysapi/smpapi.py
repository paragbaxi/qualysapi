#!/usr/bin/env python -w

# smp classes and wrappers for synchronous multiprocessing of the
# qualysapi framework

# bring in just the objects we will be working with a lot
import datetime
import lxml
import logging
import pprint
import json

#smp libs
import multiprocessing
import threading

from qualysapi import exceptions
from qualysapi.api_objects import *
from qualysapi.api_actions import QGActions


class BufferQueue(Queue):
    '''A thread/process safe queue for append/pop operations with the import
    buffer.  Initially this is just a wrapper around a collections deque but in
    the future it will be based off of multiprocess queue for access across
    processes (which isn't really possible right now)
    '''

    def __init__(self, **kwargs):
        super(BufferQueue,self).__init__(**kwargs)

    def consume(self, lim):
        '''Consume up to but no more than lim elements and return them in a new
        list, cleaning up the buffer.

        @params
        lim -- the maximum (limit) to consume from the list.  If less items
        exist in the list then that's fine too.
        '''
        lim = len(self) if len(self) < lim else lim
        return [self.popleft() for i in range(lim)]


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

    def increment_updates(self):
        '''
        Increase updates..
        '''
        self.updates+=1

    def increment_insertions(self):
        '''
        Increase additions.
        '''
        self.adds+=1

    def decrement(self):
        '''
        Increase deleted items
        '''
        self.deletes+=1


class BufferConsumer(multiprocessing.Process):
    '''This will eventually be a subclass of Process, but for now it is simply
    a consumer which will consume buffer objects and do something with them.
    '''
    bite_size = 1
    queue = None
    results_list = None
    def __init__(self, **kwargs):
        '''
        initialize this consumer with a bite_size to consume from the buffer.
        @Parms
        queue -- a BufferQueue object
        results_list -- Optional.  A list in which to store processing results.
        None by default.
        '''
        super(BufferConsumer, self).__init__() #pass to parent
        self.bite_size = kwargs.get('bite_size', 1000)
        self.queue = kwargs.get('queue', None)
        if self.queue is None:
            raise exceptions.ParsingBufferException('Consumer initialized without an input \
                queue.')

        self.results_list = kwargs.get('results_list', None)

    def run(self):
        '''a processes that consumes a queue in bite-sized chunks
        This class and method should be overridden by child implementations in
        order to actually do something useful with results.
        '''
        done = False
        while not done:
            try:
                item = self.queue.get(timeout=0.5)
                #the base class just logs this stuff
                if self.results_list is not None:
                    self.results_list.append(item)
            except queue.Empty:
                logging.debug('Queue timed out, assuming closed.')
                done = True


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
    queue = BufferQueue(ctx=multiprocessing.get_context())
    stats = BufferStats()
    consumer = None

    trigger_limit = 5000
    bite_size = 1000
    max_consumers = 5

    results_list = None
    running = []

    callback = None


    def __init__(self, *args, **kwargs):
        '''
        Creates a new import buffer.

        @Params
        completion_callback -- Required.  A function that gets called when the buffer has
        been flushed and all consumers have finished.  Must allow keyword
        arguments list.
        consumer_callback -- Optional.  a function that gets called each time a consumer
        completes but the buffer hasn't been clearned or finished.
        trigger_limit -- set the consumer triggering limit.  The default is
        5000.
        bite_size -- set the consumer consumption size (bites NOT BYTES).  The
        default is 1000.
        max_consumers -- set the maximum number of queue consumers to spawn.
        The default is five.
        consumer -- the buffer consumer.  A type of multiprocessing.Process and
        responsible to do something with the results buffer.  This is optional,
        but not really useful in its optional form since it really just fills
        up a threadsafe list taken from the buffer.  By default this is set to
        a BufferConsumer(results_list=self.results_list).
        callback -- a method intended to receive results.  Allows using the
        finish method as a bind-only hook for pools with callbacks for result
        processing.
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

        self.manager = multiprocessing.Manager()
        self.results_list = self.manager.list()

        self.consumer = kwargs.pop('consumer', None)
        if self.consumer is None:
            self.consumer = BufferConsumer

        self.callback = kwargs.pop('callback', None)


    def add(self, item):
        '''Place a new object into the buffer'''
        self.queue.put(item)
        #see if we should start a consumer...
        if not len(self.running):
            new_consumer = self.consumer(queue=self.queue, results_list=self.results_list)
            new_consumer.start()
            self.running.append(new_consumer)

        #check for finished consumers and clean them up...
        for csmr in self.running:
            if not csmr.is_alive():
                self.running.remove(csmr)

    def setCallback(self, callback):
        '''set or replace a callback in an existing buffer instance.'''
        self.callback = callback

    def finish(self):
        '''
        Notifies the buffer that we are done filling it.
        This command binds to any processes still running and lets them
        finish and then copies and flushes the managed results list.
        '''
        for csmr in self.running:
            csmr.join()
        # turn this into a list instead of a managed list
        result = list(self.results_list)
        del self.results_list[:]
        if self.callback:
            return self.callback(result)
        else:
            return result


class QualysStatusMonitor(threading.Thread):
    '''A threading class designed specifically to use semaphore pools to
    connect to the request sockets and chec for finished reports and map
    reqports as well as scans and maps.'''
    pool_sema = None
    qualys_config = None
    callbacks = None
    api_actions = None
    nice_time = 30

    __suicide = threading.Event
    actions = None

    def __init__(self, qconfig, **kwargs):
        ''' Explicit parent constructor.  No ambiguity or flexability here, all
        child classes must pass in the config.

        Parametrs:
        qconfig -- the configuration for the request to the qualysapi
        nice_time -- (Optional) override the niceness time before checking the
        qualysapi again for this particular request.
        '''
        self.qualys_config = qconfig
        self.nice_time = kwargs.pop('nice_time', self.nice_time)
        # instantiate a connection and action object for child classes to work
        # with.
        self.actions = api_actions.QGActions(
                qcache.APICacheInstance(qualys_config))

    def setPool(self, pool):
        '''Pre-run configuration of the semaphore for the conneciton pool.'''
        self.pool_sema = pool

    def singleRequestResponse(self):
        '''This is the method ot override in your implementation.'''
        raise exceptions.QualysFrameworkException('Abstract thread subclass. \
            You need to implement your own subclass.')

    def commitSuicide(self):
        self.__suicide.set()

    def run(self):
        '''Begin running and monitoring.'''
        while not self.__suicide.wait(timeout=self.nice_time):
            self.singleRequestResponse()

    def getMetrics(self):
        '''An abstract stub method for children to override if they wish.
        Please use good sense and make this read-only on any internal
        metrics so that it is thread safe regardless of the state of the
        thread.  I can\'t think of any reason for not doing that here, but this
        is an API...'''
        pass


class MapReportRunner(QualysStatusMonitor):
    '''
    Take a map_report ID and kick off a report.  Monitor the progress of the
    report until finished and then pull in the report and process it.
    '''
    __mapr = None # minimal map result required for a report
    # personal thread instance of a QGActions object
    def __init__(self, qconfig, **kwargs):
        '''
        initialize this report runner.
        @Parms
        Parent Params:
        qconfig -- the current api configuration from the parent threadpool.

        Keyword Params (passed to the action object):

        '''
        if 'mapr' not in kwargs:
            raise exceptions.QualysFrameworkException('A map result is \
            required for the report runner to monitor and update.')
        self.__mapr = kwargs.pop('mapr')
        super(QualysStatusMonitor, self).__init__(qconfig, **kwargs) #pass to parent

    def singleRequestResponse(self):
        '''Begin consuming map references and generating reports on them (also
        capable of resuming monitoring of running reports).
        '''
        if not self.__mapr.report_id:
            # we haven't started or don't know a report id for this map.  Let's
            # take care of that.
            (mapr, report_id) = self.actions

        while not done:
            try:
                map_instance = self.queue.get(timeout=1)
                # see if the map we are working on has a report associated.
                while map_instance.report_id is None:
                    # check the cash to see if we are out of date...
                    rconn = self.redis_cache.getConnection()
                    rconn.load_api_object(obj=map_instance)
                    # recheck, and if still none then attempt to generate a
                    # report for the map_instance.
                    if map_instance.report_id is None:
                        pass


            except queue.Empty:
                logging.debug('Queue timed out, assuming closed.')
                done = True


class RequestDispatchMonitorServer(object):
    '''This class is intended to kick off a number of requests to qualys which
    may return results immediately but require additional requests and result
    checking before the tasks can complete.  As such it will create a thread
    pool and a very nice low-priority thread to check until the report is
    ready.

    It makes no sense to use async request here since we aren't waiting for the
    request response but rather polling the API in a nice way for a specific
    response.'''

    monitors=[]
    pool_sema=None
    kill_timeout=5 # wait 5 seconds for threads to suicide

    def __init__(self, *args, **kwargs):
        ''' Simple interface to threading out multiple QualysStatusMonitor
        classes.  We build out a thread pool of them and then keep an eye on
        them and clean them up when they finish.  This class is not designed to
        be subclassed or to do anything with results.  If you want that,
        your're going to have to write your own threadpool manager.

        Params:
        request_proxies -- A list of QualysStatusMonitor or subclasses.
        max_sockets -- (Optional)  The maximum number of concurrent requests to
        allow to qualys API servers.  This is default at 10.
        callback -- (Optional) A callback that recieves a result set of
        objects when the monitored qualys process finishes and returns actual
        results.  This is discouraged in favor of subclassing a consumer
        process, but for small result sets or tasks requiring more than one
        result set it can be useful or even necessary.
        '''
        max_sockets = 20
        request_proxies = None
        if len(args):
            request_proxies = args[0]
        else:
            request_proxies = kwargs.pop('request_proxies', [])

        if not request_proxies: # should catch none or []
            raise exceptions.QualysFrameworkException('You have to pass in \
                    QualysStatusMonitor objects or subclasses...')

        # maximum request sockets...
        self.max_sockets = kwargs.pop('max_sockets', self.max_sockets)
        self.pool_sema = threading.BoundedSemaphore(value=max_sockets)
        for proxy in request_proxies:
            if not issubclass(proxy, QualysStatusMonitor):
                raise exceptions.QualysFrameworkException('\'%s\' is not a \
                subclass of QualysStatusMonitor.' % type(proxy).__name__)
            else:
                self.monitors.append(proxy)
                proxy.setPool(self.pool_sema)
                proxy.start()

    def getServerMetrics(self, *args, **kwargs):
        '''Get some metrics from the running request proxies.  It is assumed
        that child classes will handle any required locking for metrics or at
        least make their metrics read-only for this method so that a threadlock
        isn't required.'''

        metrics_results = []
        for proxy in self.monitors:
            metrics_results.append(proxy.getMetrics())
        return metrics_results

    def addRequest(self, proxy):
        '''push another request proxy thread onto the running stack.'''
        if not issubclass(proxy, QualysStatusMonitor):
            raise exceptions.QualysFrameworkException('\'%s\' is not a \
            subclass of QualysStatusMonitor.' % type(proxy).__name__)
        else:
            self.monitors.append(proxy)
            proxy.setPool(self.pool_sema)
            proxy.start()

    def forceThreadCheck(self, *args, **kwargs):
        ''' Check the status of managed threads.  This overrides the server
        default monitoring and forces and immediate check. '''
        self.monitors[:] = [x for x in self.monitors if x.is_running()]

    def killServices(self, *args, **kwargs):
        ''' attempt a nice shutdown of the thread request pool. '''
        for threadx in self.monitors:
            threadx.commitSuicide()

        for threadx in self.monitors:
            threadx.join(self.kill_timeout)

        self.forceThreadCheck()
        if len(self.monitors):
            raise threading.ThreadError('Our children are misbehaving!')


class QGSMPActions(QGActions):
    '''An extension to QGActions specifically to allow efficient SMP across
    thread/process pools.

    For the most part, parent class methods must be handled differently.

    Additional Properties:
    import_buffer
    '''
    import_buffer = None
    def __init__(self, *args, **kwargs):
        '''
        Extended Params:
            import_buffer -- an optional parse buffer which handles parsing using
            both an object instance factory and a multiprocess/thread parse
            handler.  This is efficient for enterprise applications which have
            large numbers of maps and scans with very large result sets and custom
            handling attached to the qualys objects.
        '''
        super(QGSMPActions, self).__init__(*args, **kwargs)
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
        if not source:
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
        context = lxml.etree.iterparse(response, events=('end',))
        for event, elem in context:
            # Use QName to avoid specifying or stripping the namespace, which we don't need
            if lxml.etree.QName(elem.tag).localname.upper() in obj_elem_map:
                self.import_buffer.add(obj_elem_map[lxml.etree.QName(elem.tag).localname.upper()](elem=elem))
                clear_ok = True
            if clear_ok:
                elem.clear() #don't fill up a dom we don't need.
                clear_ok = False
        return self.import_buffer.finish() if block else self.import_buffer


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



#!/usr/bin/env python -w

# smp classes and wrappers for synchronous multiprocessing of the
# qualysapi framework

# bring in just the objects we will be working with a lot
import datetime
from lxml import etree
import logging
logger = logging.getLogger(__name__)
import pprint
import json

#smp libs
import multiprocessing
import threading

from qualysapi import exceptions
from qualysapi.api_objects import *
from qualysapi.api_actions import QGActions

# for exceptions
import queue

#debug

class BufferQueue(multiprocessing.queues.JoinableQueue):
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

    If a consumer error occurs then a regular exception will suffice unless
    it's a response error or some other error that means the entire processing
    chain is doomed.  In that case the consumer_err bound semaphore will notify
    the process controller to end all processing and then pass of the error to
    the response error handler.
    '''
    bite_size    = 1
    queue        = None
    results_list = None
    response_err = None #: event to communicate with queue.  Optional.
    #logger       = None
    results_queue = None
    def __init__(self, **kwargs):
        '''
        initialize this consumer with a bite_size to consume from the buffer.
        @Parms
        queue -- a BufferQueue object
        results_queue -- Optional.  An output queue for nonblocking results.
        consumer_error -- A semaphore to the process manager.  Used by buffer
        consuemrs to alert that there is a critical consumer failure so that it
        can stop processing and raise a fatal exception.
        '''
        #self.logger = getLogger(__class__.__name__)
        self.bite_size = kwargs.pop('bite_size', 1000)
        self.queue = kwargs.pop('queue', None)
        if self.queue is None:
            raise exceptions.ParsingBufferException('Consumer initialized'
            'without an input queue.')

        self.results_queue = kwargs.pop('results_queue', None)
        self.response_error = kwargs.pop('response_error', None)
        self.setUp()
        super(BufferConsumer, self).__init__(**kwargs) #pass to parent


    def singleItemHandler(self, item):
        '''Override method for child classes to handle individual items.

        This method does nothing but return the item without processing.
        '''
        return item

    def setUp(self):
        """setUp
        A function run once by the init method.  This funciton is useful for
        things like configuration loading which are only needed once per
        processor instance but are instance-only properties.
        """
        pass

    def cleanUp(self):
        '''Final processing command to flush any cached data, persist to the
        database, etc...'''
        pass

    def run(self):
        '''Consumes the queue in the framework, passing off each item to the
        ItemHandler method.

        NOTE: by default this class will consume any/all RESPONSE
        (SimpleReturnResponse) objects by default if not implemented in a child
        class.
        '''
        while True:
            try:
                item = self.queue.get(timeout=3)
                #the base class just logs this stuff
                rval = self.singleItemHandler(item)
                self.queue.task_done()
                if rval and self.results_queue:
                    self.results_queue.put(rval)
            except queue.Empty:
                logger.debug('Queue timed out after 3 seconds.')
                break
            except EOFError:
                info(
                    '%s has finished consuming queue.' % (__class__.__name__))
                break
            except Exception as e:
                #general thread exception.
                logger.error('Consumer exception %s' % e)
                #TODO: continue trying/trap exceptions?
                raise
        self.cleanUp()


class QueueImportBuffer(ImportBuffer):
    queue = None
    def __init__(self, *args, **kwargs):
        self.queue = queue.Queue()
        #self.logger = getLogger(__class__.__name__)
        super(QueueImportBuffer, self).__init__(*args, **kwargs)

    #TODO: break up ImportBuffer for ST/MT/MP
    #NOTE: make sure to add a queue finished dump


class MTQueueImportBuffer(QueueImportBuffer):
    """MTQueueImportBuffer
    Adds thread-library support for Queue processing with consumer framework.
    """
    def __init__(self, *args, **kwargs):
        super(MTQueueImportBuffer, self).__init__(*args, **kwargs)


class MPQueueImportBuffer(QueueImportBuffer):
    # TODO: add min/max buffer consumer controls
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
    #TODO: move stats into parent class.  Standard stat framework needed.
    stats = BufferStats()
    consumer = None
    response_error = None

    trigger_limit = 5000
    bite_size = 1000
    max_consumers = 5

    running = []

    callback = None
    results_queue = None


    def __init__(self, *args, **kwargs):
        '''
        Creates a new import buffer.

        @Params
        completion_callback -- Required.  A function that gets called when the
        buffer has
        been flushed and all consumers have finished.  Must allow keyword
        arguments list.
        consumer_callback -- Optional.  a function that gets called each time a
        consumer
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

        super(MPQueueImportBuffer, self).__init__(*args, **kwargs)

        self.manager = multiprocessing.Manager()
        #override default list
        #self.results_list = self.manager.list()

        self.consumer = kwargs.pop('consumer', None)
        if self.consumer is None:
            self.consumer = BufferConsumer

        self.callback = kwargs.pop('callback', None)

        # make parent queue an MP queue
        self.queue = BufferQueue(ctx=multiprocessing.get_context())
        self.results_queue = multiprocessing.JoinableQueue()
        self.response_error = multiprocessing.Event

    def queueAdd(self, item):
        try:
            self.queue.put(item)
        except AssertionError:
            #queue has been closed, remake it (let the other GC)
            logger.warn('Queue closed early.')
            self.queue = BufferQueue(ctx=multiprocessing.get_context())
            self.queue.put(item)
        except BrokenPipeError:
            #workaround for pipe issue
            logger.warn('Broken pipe, Forcing creation of new queue.')
            # all reading procesess should suicide and new ones spawned.
            self.queue = BufferQueue(ctx=multiprocessing.get_context())
#             address = 'localhost'
#             if address in multiprocessing.managers.BaseProxy._address_to_local:
#                 del BaseProxy._address_to_local[address][0].connection
            self.queue.put(item)
        except Exception as e:
            #general thread exception.
            logger.error('Buffer queue exception %s' % e)
            #TODO: continue trying/trap exceptions?
            raise
        # check for finished consumers and clean them up before we check to see
        # if we need to add additional consumers.
        for csmr in self.running:
            if not csmr.is_alive():
                debug('Child dead, releasing.')
                self.running.remove(csmr)

        #see if we should start a consumer...
        # TODO: add min/max processes (default and override)
        if not self.running:
            debug('Spawning consumer.')
            new_consumer = self.consumer(
                    queue=self.queue,
                    results_queue=self.results_queue,
                    response_error=self.response_error)
            new_consumer.start()
            self.running.append(new_consumer)

    def setCallback(self, callback):
        '''set or replace a callback in an existing buffer instance.'''
        self.callback = callback

    def finish(self, block=True, **kwargs):
        '''
        Notifies the buffer that we are done filling it.
        This command binds to any processes still running and lets them
        finish and then copies and flushes the managed results list.
        '''
        # close the queue and wait until it is consumed
        if block:
            self.queue.close()
            self.queue.join_thread()
            # make sure the consumers are done consuming the queue
            for csmr in self.running:
                csmr.join()
            #TODO: implement this
#             while not self.result_queue.empty():
#                 try:
#                     self.results_list.append(self.result_queue.get(timeout=0.1))
#                 except queue.Empty:
#                     break
            del self.running[:]
            if self.callback:
                return self.callback(self.results_list)
        else:
            return self.results_list


# class ReportMPQueueImportBuffer(MPQueueImportBuffer):
#     """ReportMPQueueImportBuffer
#         Specifically designed to handle report line items during report
#         processing since the nesting tree for other elements breaks for
#         reports.
#     """
#     report_ref
#     def __init__(self, report, *args, **kwargs):
#         """__init__
# 
#         :param report:
#         assigns the internal report reference for this particular buffer.
#         :param *args:
#         expansion/parent pass-through
#         :param **kwargs:
#         expansion/parent pass-through
#         """
#         self.report_ref = report
#         super(ReportMPQueueImportBuffer, *args, **kwargs)


class SMPActionPool(object):

    def __init__(self, *args, **kwargs):
        super(SMPActionPool, self).__init__(*args, **kwargs)

    def getAction(self):
        """getSMPAction
        returns a QGSMPAction class bound to a socket connection if one is
        available.  If the maximum number of concurrent SMP connections has been
        reached, this method will block.  (Semaphore lock)
        """
        with self.spawnlimit:
            return self._get_action(QGSMPAction)



class ActionPool(object):
    '''A semaphore-bound class to keep track of request-bound action objects in
    order to prevent stupid-level request spawning.'''
    running_actions       = None
    available_smp_actions = None
    available_actions     = None
    lock                  = None
    config                = None
    use_cache             = False
    import_buffer_proto   = None
    consumer_proto        = None
    def __init__(self, config, buffer_prototype = None, consumer_prototype =
            None, use_cache=False, max_spawn=5):
        """__init__

        :param config:
        A qualysapi configuration to use when spawning new action objects.
        :param max_spawn:
        The maximum number of concurrent qualys actions to perform at a time.
        This defaults to 10.
        :param buffer_prototype:
        Prototype to use for action buffers.
        :param consumer_prototype:
        Prototype to use for action consumers.
        :param use_cache:
        flag to enable/disable the cache specific to this pool.
        """
        super(ActionPool, self).__init__()
        self.config              = config
        self.use_cache           = use_cache
        self.lock                = threading.Lock()
        self.spawnlimit          = threading.Semaphore(max_spawn)
        self.running_actions     = {}
        self.available_actions   = queue.Queue()
        self.import_buffer_proto = buffer_prototype
        self.consumer_proto      = consumer_prototype

    def get_action(self):
        """get_action - synonymn for getAction"""
        return self.getAction()

    def getAction(self):
        """getAction
        returns a QGAction class bound to a socket connection if one is
        available.  If the maximum number of concurrent connections has been
        reached, this method will block. (Semaphore lock)
        """
        with self.spawnlimit:
            return self.__get_action(QGAction)

    def releaseAction(self, tname=None):
        """releaseAction

        :param tname:
        The name of the thread to release the action from.  if tname evaluates
        to False (empty string, None, etc...) then the name of the current
        thread is used.  This method is synchronized.
        """
        with self.lock:
            if not tname:
                tname = threading.current_thread().name
            actn = self.running_actions.pop(tname, None)
            if actn is not None:
                self.available_actions.put(actn)
            else:
                warn('''Can't release action from unknown thread with name\
 %s''' % (tname))

    def _get_action(self, proto):
        """
        prototyped implementation of getSMPAction and getAction.  This method
        is synchronized.
        :param proto:
        Prototype for the type of action to get.
        """
        with self.lock:
            try:
                actn = self.available_actions.get()
                self.running_actions.put(actn)
                return actn
            except queue.Empty:
                actn = None
                if self.use_cache:
                    actn = proto(cache_connection =
                            qcache.APICacheInstance(self.config))
                else:
                    import_buffer_proto = self.import_buffer_proto if \
                        self.import_buffer_proto is not None else MPQueueImportBuffer
                    actn = proto(connection = connector.QGConnector(
                        self.config.get_auth(),
                        hostname=self.config.get_hostname(),
                        proxies=self.config.proxies,
                        max_retries=self.config.max_retries,
                        config=self.config),
                        buffer_proto=import_buffer_proto(consumer=self.consumer_proto))
                self.running_actions.put(actn)
                return actn

    def __enter__(self):
        return self.getAction()

    def __exit__(self, *args):
        """__exit__
        :param *args:
        the Context Manager arguments.  This class does not suppress exceptions.
        """
        self.releaseAction(self, threading.current_thread.name)


class ThreadedAction(threading.Thread):
    '''Base class for threaded QGActions'''
    pool      = None
    source    = None
    data      = None
    nice_time = None
    def __init__(self, action_pool, source, data={}, name=None,
            use_cache=False, nice_time=120):
        """__init__

        :param action_pool:
        A pool of QGAction objects from which to get a request handler.
        :param source:
        The qualysapi source endpoint
        :param data:
        The qualysapi data parameters for the request.  An empty dict by
        default.
        :param name:
        The name of this thread.  If not set then it will be set to the source
        + data dictionary.'
        :param use_cache:
        Enable/Disable use of caching for this action thread.
        :param nice_time:
        Set the yield time between repeat action calls.
        """
        self.pool      = action_pool
        self.source    = source
        self.data      = data
        self.use_cache = use_cache
        self.nice_time = nice_time
        if name is None:
            name = source.join(('|%s=%s' % (n,v) for n,v in data.items()))
        self.nice_time = nice_time
        super(ThreadedAction, self).__init__(name=name)

    def singleRequestResponse(self, action):
        """singleRequestResponse

        :param action:
        An action class around a socket connection and possibly a cache
        connection which handles a single request/response cycle.
        """
        raise exceptions.QualysFrameworkException('Abstract thread subclass. \
You need to implement your own subclass.')

    def commitSuicide(self):
        """commitSuicide
        instructs the polling cycle to end
        """
        self.__suicide.set()

    def run(self):
        '''Begin running and monitoring.'''
        while not self.__suicide.wait(timeout=self.nice_time):
            with self.pool as action:
                self.singleRequestResponse(action)

    def getMetrics(self):
        '''An abstract stub method for children to override if they wish.
        Please use good sense and make this read-only on any internal
        metrics so that it is thread safe regardless of the state of the
        thread.  I can\'t think of any reason for not doing that here, but this
        is an API...'''
        pass


class QualysReportDownloader(ThreadedAction):
    '''
    A threading class designed to allow for size monitoring and multiple report
    downloads from qualys.

    If the source/data params don't point to a report download it is very
    unlikely to turn out well, but the results are probably going to die
    quietly... probably.
    '''


class MapReportRunner(ThreadedAction):
    '''
    Takes a map result and attempts to generate a report for it.  It will keep
    trying (using nice time) until the report can be generated.  It
    then monitors the status of the report until finished, after which it
    processes the report..
    '''
    __mapr = None # minimal map result required for a report
    __rpt = None
    # personal thread instance of a QGActions object
    def __init__(self, mapr, *args, **kwargs):
        """__init__

        :param mapr:
        The map result object to handle.
        :param *args:
        pass to parent
        :param **kwargs:
        pass to parent
        """
        self.__mapr = mapr
        super(MapReportRunner, self).__init__(*args, **kwargs) #pass to parent

    def singleRequestResponse(self, action):
        '''Begin consuming map references and generating reports on them (also
        capable of resuming monitoring of running reports).
        '''
        if not self.__mapr.report_id:
            response = action.startMapReportOnMap(self.__mapr)
            if response:
                #deal with this if we have to?
                (mapr, mapid) = response
        else:
            # check to see if the report is finished...
            rlist = action.listReports(id=self.__mapr.report_id)
            if rlist:
                self.__rpt = rlist[0]
                if self.__rpt.status == 'Finished':
                    result = action.fetchReport(report=self.__rpt)
                    if result:
                        self.__rpt = result

        # now if we have a report, let's deal with it...


class RequestDispatchMonitorServer(object):
    '''This class is intended to kick off a number of requests to qualys which
    may return results immediately but require additional requests and result
    checking before the tasks can complete.  As such it will create a thread
    pool and a very nice low-priority thread to check until the report is
    ready.

    It makes no sense to use async request here since we aren't waiting for the
    request response but rather polling the API in a nice way for a specific
    response.

    In addition, this object is aware of specific types of request relevant to
    the specifics of the Qualys API, such as requesting headers for report
    downloads and finding out the size of the report for metrics before
    starting the actual download (for time/size metrics and load management
    reasons later on).'''

    monitors     = []
    pool_sema    = None
    kill_timeout = 5 # wait 5 seconds for threads to suicide
    max_sockets  = 10 # be conservative at first...

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

        # working around this need.  I want to spawn request proxies as needed.
#        if not request_proxies: # should catch none or []
#            raise exceptions.QualysFrameworkException('You have to pass in \
#                    QualysStatusMonitor objects or subclasses...')

        # maximum request sockets...
        self.max_sockets = kwargs.pop('max_sockets', self.max_sockets)
        self.pool_sema = threading.BoundedSemaphore(value=max_sockets)
        for proxy in request_proxies:
            if not issubclass(type(proxy), QualysStatusMonitor):
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
        if not issubclass(type(proxy), QualysStatusMonitor):
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
    buffer_prototype = None
    consumer_prototype = None
    def __init__(self, *args, **kwargs):
        '''
        :param kwargs:
            buffer_prototype -- Optional.  A prototype to use instead of the
            base MPQueueImportBuffer
            consumer_prototype -- Optional.  A prototype to pass to any new
            instance of MPQueueImportBuffer and subclasses which consumes the buffer.
        '''
        super(QGSMPActions, self).__init__(*args, **kwargs)
        self.buffer_prototype = kwargs.get('buffer_prototype', None)
        self.consumer_prototype = kwargs.get('consumer_prototype', None)

    def parseResponse(self, **kwargs):
        '''
        An internal utility method that implements an lxml parser capable of
        handling streams and mapping objects to elements.

        Please note that this utiliy is only capable of parsing known Qualys
        API DTDs properly.

        :param kwargs:
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
        buffer_prototype -- a prototype to use for the buffer.
        consumer_prototype -- a prototype to use for the buffer consumer.
        '''

        source = kwargs.pop('source', None)
        if not source:
            raise QualysException('No source file or URL or raw stream found.')

        block = kwargs.get('block', True)
        callback = kwargs.pop('completion_callback', None)
        #TODO: consider passing in an import_buffer for thread management reuse
        #of this object
        #TODO: consider replacing this requirement
        if not block and not callback:
            logger.info('No callback on nonblocking call.  No smp results ' +\
                'will be returned by this function.  Consumer only.')
        #select the response file-like object
        response = None
        if isinstance(source, str):
            response = self.stream_request(source, **kwargs)
        else:
            response = source

        consumer = None
        if 'consumer_prototype' in kwargs:
            consumer = kwargs.pop('consumer_prototype')
        else:
            consumer = self.consumer_prototype

        if self.import_buffer is None:
            if self.buffer_prototype is None:
                self.import_buffer = MPQueueImportBuffer(callback=callback, consumer=consumer)
            else:
                self.import_buffer = self.buffer_prototype(callback=callback,
                        consumer=consumer)
        rstub = None
        if 'report' in kwargs:
            rstub = kwargs.get('report')
            if not isinstance(rstub, Report):
                raise exceptions.QualysFrameworkException('Only Report objects'
                ' and subclasses can be passed to this function as reports.')

        context = etree.iterparse(response, events=('end',))
        #optional default elem/obj mapping override
        local_elem_map = kwargs.get('obj_elem_map', queue_elem_map)
        for event, elem in context:
            # Use QName to avoid specifying or stripping the namespace, which we don't need
            stag = etree.QName(elem.tag).localname.upper()
            if stag in local_elem_map:
                self.import_buffer.queueAdd(local_elem_map[stag](elem=elem,
                    report_stub=rstub))
            elif stag in obj_elem_map:
                self.import_buffer.add(obj_elem_map[stag](elem=elem,
                    report_stub=rstub))
                # elem.clear() #don't fill up a dom we don't need.
        results = self.import_buffer.finish(block=block)
        self.checkResults(results)

        # special case: report encapsulization...
        return results


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

    def replaceBuffer(self, parse_buffer):
        '''
        Add an MPQueueImportBuffer to this action object.
        '''
        self.import_buffer = parse_buffer

    def finish(self):
        if self.import_buffer:
            return self.import_buffer.finish(block=True)
        else:
            return []


queue_elem_map = {
    'MAP_RESULT'        : MapResult,
    'VULN'              : QKBVuln,
    'ASSET_GROUP_LIST'  : AssetGroupList,
    # this is disabled (for now)
    'HOST'              : Host,
}

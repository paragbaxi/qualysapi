# internal exceptions
class QualysException(Exception):
    '''
    Top level qualysapi exception event
    '''


class QualysAuthenticationException(QualysException):
    '''
    Raised for authentication exceptions in Qualys
    '''


class NoConnectionError(QualysException):
    '''
    Raised for calls that require a valid connection to Qualys but didn't get
    one.
    '''


class ParsingBufferException(QualysException):
    '''
    Raised for API calls using a parsing buffer in which the buffer had an
    exception of some kind.
    '''

class QCacheException(Exception):
    '''
    Simple cache exception wrapper
    '''
    pass

class QualysFrameworkException(QualysException):
    '''
    Raised when you attempt to call a framework api method with a standard
    rather than enhanced qualysapi connection.
    '''
    pass

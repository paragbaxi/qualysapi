# internal exceptions
class QualysException(Exception):
    '''
    Top level qualysapi exception event
    '''
    pass


class QualysAuthenticationException(QualysException):
    '''
    Raised for authentication exceptions in Qualys
    '''
    pass


class NoConnectionError(QualysException):
    '''
    Raised for calls that require a valid connection to Qualys but didn't get
    one.
    '''
    pass

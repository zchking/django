from __future__ import unicode_literals

import cgi
import codecs
import logging
import sys
from io import BytesIO
from threading import Lock
import warnings

from django import http
from django.conf import settings
from django.core import signals
from django.core.handlers import base
from django.core.urlresolvers import set_script_prefix
from django.utils import datastructures
from django.utils.deprecation import RemovedInDjango19Warning
from django.utils.encoding import force_str, force_text
from django.utils.functional import cached_property
from django.utils import six

# For backwards compatibility -- lots of code uses this in the wild!
from django.http.response import REASON_PHRASES as STATUS_CODE_TEXT  # NOQA

logger = logging.getLogger('django.request')

# encode() and decode() expect the charset to be a native string.
ISO_8859_1, UTF_8 = str('iso-8859-1'), str('utf-8')


class LimitedStream(object):
    '''
    LimitedStream wraps another stream in order to not allow reading from it
    past specified amount of bytes.
    '''
    def __init__(self, stream, limit, buf_size=64 * 1024 * 1024):
        self.stream = stream
        self.remaining = limit
        self.buffer = b''
        self.buf_size = buf_size

    def _read_limited(self, size=None):
        if size is None or size > self.remaining:
            size = self.remaining
        if size == 0:
            return b''
        result = self.stream.read(size)
        self.remaining -= len(result)
        return result

    def read(self, size=None):
        if size is None:
            result = self.buffer + self._read_limited()
            self.buffer = b''
        elif size < len(self.buffer):
            result = self.buffer[:size]
            self.buffer = self.buffer[size:]
        else:  # size >= len(self.buffer)
            result = self.buffer + self._read_limited(size - len(self.buffer))
            self.buffer = b''
        return result

    def readline(self, size=None):
        while b'\n' not in self.buffer and \
              (size is None or len(self.buffer) < size):
            if size:
                # since size is not None here, len(self.buffer) < size
                chunk = self._read_limited(size - len(self.buffer))
            else:
                chunk = self._read_limited()
            if not chunk:
                break
            self.buffer += chunk
        sio = BytesIO(self.buffer)
        if size:
            line = sio.readline(size)
        else:
            line = sio.readline()
        self.buffer = sio.read()
        return line


class WSGIRequest(http.HttpRequest):
    def __init__(self, environ):
        script_name = get_script_name(environ)
        path_info = get_path_info(environ)
        if not path_info:
            # Sometimes PATH_INFO exists, but is empty (e.g. accessing
            # the SCRIPT_NAME URL without a trailing slash). We really need to
            # operate as if they'd requested '/'. Not amazingly nice to force
            # the path like this, but should be harmless.
            path_info = '/'
        self.environ = environ
        self.path_info = path_info
        # be careful to only replace the first slash in the path because of
        # http://test/something and http://test//something being different as
        # stated in http://www.ietf.org/rfc/rfc2396.txt
        self.path = '%s/%s' % (script_name.rstrip('/'),
                               path_info.replace('/', '', 1))
        self.META = environ
        self.META['PATH_INFO'] = path_info
        self.META['SCRIPT_NAME'] = script_name
        self.method = environ['REQUEST_METHOD'].upper()
        _, content_params = cgi.parse_header(environ.get('CONTENT_TYPE', ''))
        if 'charset' in content_params:
            try:
                codecs.lookup(content_params['charset'])
            except LookupError:
                pass
            else:
                self.encoding = content_params['charset']
        self._post_parse_error = False
        try:
            content_length = int(environ.get('CONTENT_LENGTH'))
        except (ValueError, TypeError):
            content_length = 0
        self._stream = LimitedStream(self.environ['wsgi.input'], content_length)
        self._read_started = False
        self.resolver_match = None

    def _get_scheme(self):
        return self.environ.get('wsgi.url_scheme')

    def _get_request(self):
        warnings.warn('`request.REQUEST` is deprecated, use `request.GET` or '
                      '`request.POST` instead.', RemovedInDjango19Warning, 2)
        if not hasattr(self, '_request'):
            self._request = datastructures.MergeDict(self.POST, self.GET)
        return self._request

    @cached_property
    def GET(self):
        # The WSGI spec says 'QUERY_STRING' may be absent.
        raw_query_string = get_bytes_from_wsgi(self.environ, 'QUERY_STRING', '')
        return http.QueryDict(raw_query_string, encoding=self._encoding)

    def _get_post(self):
        if not hasattr(self, '_post'):
            self._load_post_and_files()
        return self._post

    def _set_post(self, post):
        self._post = post

    @cached_property
    def COOKIES(self):
        raw_cookie = get_str_from_wsgi(self.environ, 'HTTP_COOKIE', '')
        return http.parse_cookie(raw_cookie)

    def _get_files(self):
        if not hasattr(self, '_files'):
            self._load_post_and_files()
        return self._files

    POST = property(_get_post, _set_post)
    FILES = property(_get_files)
    REQUEST = property(_get_request)


class WSGIHandler(base.BaseHandler):
    """
      1.What is WSGI?
        An interface specification(规范) by which server and application communicate.

        Both server and application interface sides are specified. It does not exist anywhere else other than as words in the PEP 3333. If an application (or framework or toolkit) is written to the WSGI spec then it will run on any server written to that spec.

        A WSGI server (meaning WSGI compliant) only receives the request from the client, pass it to the application and then send the response provided by the application to the client. It does nothing else. All the gory details must be supplied by the application or middleware.


      2.The Application spec:
        The WSGI application interface is implemented as a callable object: a function, a method, a class or an instance with a __call__ method. That callable must accept two positional parameters:

        A dictionary containing CGI like variables; and
        a callback function that will be used by the application to send HTTP status code/message and HTTP headers to the server.
        and must return the response body to the server as strings wrapped in an iterable.
      
      3.Notice the response:
        If the last script worked change the return line from:

          return [response_body]
        to:

          return response_body

        Run again.Noticed it slower? What happened is that the server iterated over the string sending a single byte at a time to the client. 
        ***So don't forget to *wrap the response* in a better performance iterable like a list***.



      4.WSGI environ Variables

        ->REQUEST_METHOD
          The HTTP request method, such as "GET" or "POST" . This cannot ever be an empty string, and so is always required.

        ->SCRIPT_NAME
          The initial portion of the request URL's "path" that corresponds to the application object, so that the application knows its virtual "location". 
          This may be an empty string, if the application corresponds to the "root" of the server.

        ->PATH_INFO
          The remainder of the request URL's "path", designating the virtual "location" of the request's target within the application.
          This may be an empty string, if the request URL targets the application root and does not have a trailing slash.

        ->QUERY_STRING
          The portion of the request URL that follows the "?" , if any. May be empty or absent.

        ->CONTENT_TYPE
          The contents of any Content-Type fields in the HTTP request. May be empty or absent.

        ->CONTENT_LENGTH
          The contents of any Content-Length fields in the HTTP request. May be empty or absent.

        ->SERVER_NAME , SERVER_PORT
          When combined with SCRIPT_NAME and PATH_INFO , these two strings can be used to complete the URL. 
          Note, however, that HTTP_HOST , if present, should be used in preference to SERVER_NAME for reconstructing the request URL. 
          See the URL Reconstruction section below for more detail. SERVER_NAME and SERVER_PORT can never be empty strings, and so are always required.

        ->SERVER_PROTOCOL
          The version of the protocol the client used to send the request. 
          Typically this will be something like "HTTP/1.0" or "HTTP/1.1" and may be used by the application to determine how to treat any HTTP request headers. 
          (This variable should probably be called REQUEST_PROTOCOL , since it denotes the protocol used in the request, 
          and is not necessarily the protocol that will be used in the server's response. 
          However, for compatibility with CGI we have to keep the existing name.)

        ->HTTP_ Variables
          Variables corresponding to the client-supplied HTTP request headers (i.e., variables whose names begin with "HTTP_" ). 
          The presence or absence of these variables should correspond with the presence or absence of the appropriate HTTP header in the request.
    """
    initLock = Lock()
    request_class = WSGIRequest

    def __call__(self, environ, start_response):
        # Set up middleware if needed. We couldn't do this earlier, because
        # settings weren't available.
        if self._request_middleware is None:
            with self.initLock:
                try:
                    # Check that middleware is still uninitialized.
                    if self._request_middleware is None:
                        self.load_middleware()
                except:
                    # Unload whatever middleware we got
                    self._request_middleware = None
                    raise

        set_script_prefix(get_script_name(environ))
        signals.request_started.send(sender=self.__class__, environ=environ)
        try:
            request = self.request_class(environ)
        except UnicodeDecodeError:
            logger.warning('Bad Request (UnicodeDecodeError)',
                exc_info=sys.exc_info(),
                extra={
                    'status_code': 400,
                }
            )
            response = http.HttpResponseBadRequest()
        else:
            response = self.get_response(request)

        response._handler_class = self.__class__

        status = '%s %s' % (response.status_code, response.reason_phrase)
        response_headers = [(str(k), str(v)) for k, v in response.items()]
        for c in response.cookies.values():
            response_headers.append((str('Set-Cookie'), str(c.output(header=''))))
        start_response(force_str(status), response_headers)
        return response


def get_path_info(environ):
    """
    Returns the HTTP request's PATH_INFO as a unicode string.
    """
    path_info = get_bytes_from_wsgi(environ, 'PATH_INFO', '/')

    return path_info.decode(UTF_8)


def get_script_name(environ):
    """
    Returns the equivalent of the HTTP request's SCRIPT_NAME environment
    variable. If Apache mod_rewrite has been used, returns what would have been
    the script name prior to any rewriting (so it's the script name as seen
    from the client's perspective), unless the FORCE_SCRIPT_NAME setting is
    set (to anything).


    @Somethings about charset codecs:
       1.python2 -> str(As the bytes of some charset codes(utf-8,gbk))
                    unicode(unicode's str(characters))
         python3 -> str(unicode's str(characters))
                    bytes(As the bytes of some charset codes(utf-8,gbk))

       2.about encode & decode
         decode to unicode and encode from unicode to utf-8 ...
         
         python2 -> encode 
                    unicode ->str(such as utf-8)
                 -> decode
                    str(such as utf-8) -> unicode
         python3 -> encode
                    str(unicode) -> bytes(such as utf-8)
                 -> decode 
                    bytes(such as utf-8) -> str(unicode)
                    
    """
    if settings.FORCE_SCRIPT_NAME is not None:
        return force_text(settings.FORCE_SCRIPT_NAME)

    # If Apache's mod_rewrite had a whack at the URL, Apache set either
    # SCRIPT_URL or REDIRECT_URL to the full resource URL before applying any
    # rewrites. Unfortunately not every Web server (lighttpd!) passes this
    # information through all the time, so FORCE_SCRIPT_NAME, above, is still
    # needed.
    script_url = get_bytes_from_wsgi(environ, 'SCRIPT_URL', '')
    if not script_url:
        script_url = get_bytes_from_wsgi(environ, 'REDIRECT_URL', '')

    if script_url:
        path_info = get_bytes_from_wsgi(environ, 'PATH_INFO', '')
        script_name = script_url[:-len(path_info)]
    else:
        script_name = get_bytes_from_wsgi(environ, 'SCRIPT_NAME', '')

    return script_name.decode(UTF_8)


def get_bytes_from_wsgi(environ, key, default):
    """
    Get a value from the WSGI environ dictionary as bytes.

    key and default should be str objects. Under Python 2 they may also be
    unicode objects provided they only contain ASCII characters.
    """
    value = environ.get(str(key), str(default))
    # Under Python 3, non-ASCII values in the WSGI environ are arbitrarily
    # decoded with ISO-8859-1. This is wrong for Django websites where UTF-8
    # is the default. Re-encode to recover the original bytestring.
    return value.encode(ISO_8859_1) if six.PY3 else value


def get_str_from_wsgi(environ, key, default):
    """
    Get a value from the WSGI environ dictionary as str.

    key and default should be str objects. Under Python 2 they may also be
    unicode objects provided they only contain ASCII characters.
    """
    value = get_bytes_from_wsgi(environ, key, default)
    return value.decode(UTF_8, errors='replace') if six.PY3 else value

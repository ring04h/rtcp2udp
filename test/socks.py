"""
SocksiPy 2.0 - Python SOCKS module
Based on socksipy 1.0
https://sourceforge.net/projects/socksipy
"""

from socket import *
from socket import _fileobject
from socket import create_connection
from socket import ssl
import socket as _socket
import struct
import time
# _socket.setdefaulttimeout(20)
try:
    _GLOBAL_DEFAULT_TIMEOUT = _socket._GLOBAL_DEFAULT_TIMEOUT
except AttributeError:
    pass

from errno import EALREADY, EINPROGRESS, EWOULDBLOCK

import logging
log = logging.getLogger('socks')

PROXY_TYPE_SOCKS4 = 1
PROXY_TYPE_SOCKS5 = 2
PROXY_TYPE_HTTP = 3
PROXY_TYPE_HTTPS = 4

_defaultproxy = None
_orgsocket = _socket.socket


class ProxyError(_socket.error):
    def __init__(self, *args):
        self.value = args
        _socket.error.__init__(self, *args)

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return '%s(%r)' % (type(self).__name__, repr(self.value))


class GeneralProxyError(ProxyError):
    pass


class Socks5AuthError(ProxyError):
    pass


class Socks5Error(ProxyError):
    pass


class Socks4Error(ProxyError):
    pass


class HTTPError(ProxyError):
    pass

_generalerrors = ("success",
           "invalid data",
           "not connected",
           "not available",
           "bad proxy type",
           "bad input")

_socks5errors = ("succeeded",
          "general SOCKS server failure",
          "connection not allowed by ruleset",
          "Network unreachable",
          "Host unreachable",
          "Connection refused",
          "TTL expired",
          "Command not supported",
          "Address type not supported",
          "Unknown error")

_socks5autherrors = ("succeeded",
              "authentication is required",
              "all offered authentication methods were rejected",
              "unknown username or invalid password",
              "unknown error")

_socks4errors = ("request granted",
          "request rejected or failed",
          "request rejected because SOCKS server cannot connect to identd on the client",
          "request rejected because the client program and identd report different user-ids",
          "unknown error")


def setdefaultproxy(proxytype = None, addr = None, port = None, rdns = True, username = None, password = None):
    """setdefaultproxy(proxytype, addr[, port[, rdns[, username[, password]]]])
    Sets a default proxy which all further socksocket objects will use,
    unless explicitly changed.
    """
    global _defaultproxy
    _defaultproxy = (proxytype, addr, port, rdns, username, password)


def wrapmodule(module):
    """wrapmodule(module)

    Attempts to replace a module's socket library with a SOCKS socket. Must set
    a default proxy using setdefaultproxy(...) first.
    This will only work on modules that import socket directly into the namespace;
    most of the Python Standard Library falls into this category.
    """
    if _defaultproxy is not None:
        module.socket.socket = socksocket
    else:
        raise GeneralProxyError((4, "no proxy specified"))


class socksocket(_orgsocket):
    """socksocket([family[, type[, proto]]]) -> socket object

    Open a SOCKS enabled socket. The parameters are the same as
    those of the standard socket init. In order for SOCKS to work,
    you must specify family=AF_INET, type=SOCK_STREAM and proto=0.
    """

    def __init__(self, family = _socket.AF_INET, type = _socket.SOCK_STREAM, proto = 0, _sock = None):
        _orgsocket.__init__(self, family, type, proto, _sock)

        if _defaultproxy is not None:
            self.__proxy = _defaultproxy
        else:
            self.__proxy = (None, None, None, None, None, None)
        self.__proxysockname = None
        self.__proxypeername = None

    def __recvall(self, bytes):
        """__recvall(bytes) -> data
        Receive EXACTLY the number of bytes requested from the socket.
        Blocks until the required number of bytes have been received.
        """
        data = ""
        while len(data) < bytes:
            data += self.recv(bytes - len(data))
            time.sleep(.001)
        return data

    def setproxy(self, proxytype = None, addr = None, port = None, rdns = True, username = None, password = None):
        """setproxy(proxytype, addr[, port[, rdns[, username[, password]]]])
        Sets the proxy to be used.
        proxytype - The type of the proxy to be used. Three types
                are supported: PROXY_TYPE_SOCKS4 (including socks4a),
                PROXY_TYPE_SOCKS5 and PROXY_TYPE_HTTP
        addr -      The address of the server (IP or DNS).
        port -      The port of the server. Defaults to 1080 for SOCKS
                servers and 8080 for HTTP proxy servers.
        rdns -      Should DNS queries be preformed on the remote side
                (rather than the local side). The default is True.
                Note: This has no effect with SOCKS4 servers.
        username -  Username to authenticate with to the server.
                The default is no authentication.
        password -  Password to authenticate with to the server.
                Only relevant when username is also provided.
        """
        self.__proxy = (proxytype, addr, port, rdns, username, password)

    def __negotiatesocks5(self, destaddr, destport):
        """__negotiatesocks5(self,destaddr,destport)
        Negotiates a connection through a SOCKS5 server.
        """
        # First we'll send the authentication packages we support.
        if (self.__proxy[4] is not None) and (self.__proxy[5] is not None):
            # The username/password details were supplied to the
            # setproxy method so we support the USERNAME/PASSWORD
            # authentication (in addition to the standard none).
            self.sendall("\x05\x02\x00\x02")
        else:
            # No username/password were entered, therefore we
            # only support connections with no authentication.
            self.sendall("\x05\x01\x00")
        # We'll receive the server's response to determine which
        # method was selected
        chosenauth = self.__recvall(2)
        if chosenauth[0] != "\x05":
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        # Check the chosen authentication method
        if chosenauth[1] == "\x00":
            # No authentication is required
            pass
        elif chosenauth[1] == "\x02":
            # Okay, we need to perform a basic username/password
            # authentication.
            self.sendall("\x01" + chr(len(self.__proxy[4])) + self.__proxy[4] + chr(len(self.__proxy[5])) + self.__proxy[5])
            authstat = self.__recvall(2)
            if authstat[0] != "\x01":
                # Bad response
                self.close()
                raise GeneralProxyError((1, _generalerrors[1]))
            if authstat[1] != "\x00":
                # Authentication failed
                self.close()
                raise Socks5AuthError((3, _socks5autherrors[3]))
            # Authentication succeeded
        else:
            # Reaching here is always bad
            self.close()
            if chosenauth[1] == "\xFF":
                raise Socks5AuthError((2, _socks5autherrors[2]))
            else:
                raise GeneralProxyError((1, _generalerrors[1]))
        # Now we can request the actual connection
        req = "\x05\x01\x00"
        # If the given destination address is an IP address, we'll
        # use the IPv4 address request even if remote resolving was specified.
        try:
            ipaddr = _socket.inet_aton(destaddr)
            req = req + "\x01" + ipaddr
        except _socket.error:
            # Well it's not an IP number,  so it's probably a DNS name.
            if self.__proxy[3] == True:
                # Resolve remotely
                ipaddr = None
                req = req + "\x03" + chr(len(destaddr)) + destaddr
            else:
                # Resolve locally
                try:
                    ipaddr = _socket.inet_aton(_socket.gethostbyname(destaddr))
                    req = req + "\x01" + ipaddr
                except _socket.gaierror:
                    # Fallback to remote resolution on local resolver issues
                    ipaddr = None
                    req = req + "\x03" + chr(len(destaddr)) + destaddr

        req = req + struct.pack(">H", destport)
        self.sendall(req)
        # Get the response
        resp = self.__recvall(4)
        if resp[0] != "\x05":
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        elif resp[1] != "\x00":
            # Connection failed
            self.close()
            if ord(resp[1]) <= 8:
                raise Socks5Error((ord(resp[1]), _socks5errors[ord(resp[1])]))
            else:
                raise Socks5Error((9, _socks5errors[9]))
        # Get the bound address/port
        elif resp[3] == "\x01":
            boundaddr = self.__recvall(4)
        elif resp[3] == "\x03":
            resp = resp + self.recv(1)
            boundaddr = self.__recvall(resp[4])
        else:
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        boundport = struct.unpack(">H", self.__recvall(2))[0]
        self.__proxysockname = (boundaddr, boundport)
        if ipaddr is not None:
            self.__proxypeername = (_socket.inet_ntoa(ipaddr), destport)
        else:
            self.__proxypeername = (destaddr, destport)

    def getproxysockname(self):
        """getsockname() -> address info
        Returns the bound IP address and port number at the proxy.
        """
        return self.__proxysockname

    def getproxypeername(self):
        """getproxypeername() -> address info
        Returns the IP and port number of the proxy.
        """
        return _orgsocket.getpeername(self)

    def getpeername(self):
        """getpeername() -> address info
        Returns the IP address and port number of the destination
        machine (note: getproxypeername returns the proxy)
        """
        return self.__proxypeername

    def __negotiatesocks4(self, destaddr, destport):
        """__negotiatesocks4(self,destaddr,destport)
        Negotiates a connection through a SOCKS4 server.
        """
        # Check if the destination address provided is an IP address
        rmtrslv = False
        try:
            ipaddr = _socket.inet_aton(destaddr)
        except _socket.error:
            # It's a DNS name. Check where it should be resolved.
            if self.__proxy[3] == True:
                ipaddr = "\x00\x00\x00\x01"
                rmtrslv = True
            else:
                try:
                    ipaddr = _socket.inet_aton(_socket.gethostbyname(destaddr))
                except _socket.gaierror:
                    # Fallback to remote resolution on local resolver issues
                    ipaddr = "\x00\x00\x00\x01"
                    rmtrslv = True
        # Construct the request packet
        req = "\x04\x01" + struct.pack(">H", destport) + ipaddr
        # The username parameter is considered userid for SOCKS4
        if self.__proxy[4] is not None:
            req = req + self.__proxy[4]
        req = req + "\x00"
        # DNS name if remote resolving is required
        # NOTE: This is actually an extension to the SOCKS4 protocol
        # called SOCKS4A and may not be supported in all cases.
        if rmtrslv == True:
            req = req + destaddr + "\x00"
        self.sendall(req)
        # Get the response from the server
        resp = self.__recvall(8)
        if resp[0] != "\x00":
            # Bad data
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        if resp[1] != "\x5A":
            # Server returned an error
            self.close()
            if ord(resp[1]) in (91, 92, 93):
                self.close()
                raise Socks4Error((ord(resp[1]), _socks4errors[ord(resp[1]) - 90]))
            else:
                raise Socks4Error((94, _socks4errors[4]))
        # Get the bound address/port
        self.__proxysockname = (_socket.inet_ntoa(resp[4:]), struct.unpack(">H", resp[2:4])[0])
        if rmtrslv is not None:
            self.__proxypeername = (_socket.inet_ntoa(ipaddr), destport)
        else:
            self.__proxypeername = (destaddr, destport)

    def __negotiatehttps(self, destaddr, destport):
        #now connect, very simple recv and error checking
        try:
            self._sock = _socket.ssl(self._sock)
            self.__negotiatehttp(destaddr, destport)
        except Exception, e:
            raise _socket.error(e)

    def __negotiatehttp(self, destaddr, destport):
        """__negotiatehttp(self,destaddr,destport)
        Negotiates a connection through an HTTP server.
        """
        # If we need to resolve locally, we do this now

        addr = destaddr
        if self.__proxy[3] == False:
            try:
                addr = _socket.gethostbyname(destaddr)
            except _socket.gaierror:
                pass

        self.sendall("CONNECT " + addr + ":" + str(destport) + " HTTP/1.1\r\n" +
                     "Host: " + destaddr + "\r\n" +
                     self.__httpauthstring() + "\r\n")
        # We read the response until we get the string "\r\n\r\n"
        last = resp = self.recv(1)
        while len(resp) < (32 * 1024) and last and resp.find("\r\n\r\n") == -1:
            last = self.recv(1)
            resp = resp + last

        if not last or len(resp) >= (32 * 1024):
            raise GeneralProxyError((1, _generalerrors[1], 'no response or response too large: %r' % resp))

        # We just need the first line to check if the connection
        # was successful
        statusline = resp.splitlines()[0].split(" ", 2)
        if statusline[0] not in ("HTTP/1.0", "HTTP/1.1"):
            self.close()
            raise GeneralProxyError((1, _generalerrors[1], 'unknown statusline %r (resp = %r)' % (statusline, resp)))
        try:
            statuscode = int(statusline[1])
        except ValueError:
            self.close()
            raise GeneralProxyError((1, _generalerrors[1], 'unknown status code in: %r (resp = %r)' % (statuscode, resp)))
        if statuscode != 200:
            self.close()
            raise HTTPError((statuscode, statusline[2], 'non-200 status code: %r (resp = %r)' % (statuscode, resp)))

        self.__proxysockname = ("0.0.0.0", 0)
        self.__proxypeername = (addr, destport)

    def __httpauthstring(self):
        (proxytype, addr, port, rdns, username, password) = self.__proxy
        if all((username, password)):
            raw = "%s:%s" % (username, password)
            auth = 'Basic %s' % ''.join(raw.encode('base-64').strip().split())
            return 'Proxy-Authorization: %s\r\n' % auth
        else:
            return ''

    def connect(self, destpair):
        if self.family == _socket.AF_INET and self.type == _socket.SOCK_STREAM:
            return self._connect(destpair, _orgsocket.connect)
        else:
            return _orgsocket.connect(self, destpair)

    def _connect(self, destpair, connector):
        """connect(self,despair)
        Connects to the specified destination through a proxy.
        destpar - A tuple of the IP/DNS address and the port number.
        (identical to socket's connect).
        To select the proxy server use setproxy().
        """
        E = None
        return_val = None
        try:
            # Do a minimal input check first
            destpair = self.check_destpair(destpair)

            stuff = {
                     PROXY_TYPE_SOCKS5: (1080, self.__negotiatesocks5),
                     PROXY_TYPE_SOCKS4: (1080, self.__negotiatesocks4),
                     PROXY_TYPE_HTTP  : (8080, self.__negotiatehttp),
                     PROXY_TYPE_HTTPS : (8080, self.__negotiatehttps),
                     }

            if self.__proxy[0] in stuff:
                def_port, negotiate = stuff[self.__proxy[0]]

                if self.__proxy[2] is not None:
                    portnum = self.__proxy[2]
                else:
                    portnum = def_port
                try:
                    return_val = connector(self, (self.__proxy[1], portnum))
                except _socket.error, e:
                    if e.args and e.args[0] not in (EINPROGRESS, EALREADY, EWOULDBLOCK):
                        raise ProxyError(*e.args)

                log.debug('negotiating proxy for destpair %r: %r, password=%s', destpair, self.__proxy[:-1], bool(self.__proxy[-1]))
                negotiate(destpair[0], destpair[1])
            elif self.__proxy[0] is None:
                log.debug('No proxy settings. connecting destpair %r', destpair)
                return_val = connector(self, (destpair[0], destpair[1]))
            else:
                raise GeneralProxyError((4, _generalerrors[4]))
        except _socket.error, e:
            E = e
            raise e
        except Exception, e:
            E = e
            raise _socket.error(e)
        finally:
            if E is not None:
                if E.args and E.args[0] not in (EINPROGRESS, EALREADY, EWOULDBLOCK):
                    log.debug('Error connecting to %r. self.__proxy is %r. Exception was %r', destpair, self.__proxy[:4], E)

        return return_val

    def check_destpair(self, destpair):
        if isinstance(destpair[0], basestring):
            try:
                destpair = str(destpair[0]), destpair[1]
            except ValueError:
                raise _socket.gaierror("Couldn't coerce %r to str. Invalid hostname." % destpair[0])

        if (type(destpair) in (list, tuple) == False) or (len(destpair) < 2) or (type(destpair[0]) != str) or (type(destpair[1]) != int):
            raise GeneralProxyError((5, _generalerrors[5]))

        return destpair

SocketType = socksocket

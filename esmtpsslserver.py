#!/usr/bin/env python
"""ESMTP server base class.  Nick Besant 2014-2016 hwf@fesk.net

Originally based on bcoe's https://github.com/bcoe/secure-smtpd and posts to http://bugs.python.org/issue1057417 from Mark D Roth

Creates a threaded ESMTP server that supports SSL/TLS, STARTTLS and LOGIN authentication.

Requires OpenSSL.

Override methods;
    validate_credentials(self,username,password)
    process_message(self, sender, recipients, msg)
    deny_sender(self,sender)
    deny_recipient(self,recipient)
    deny_host(self,hosttuple)
    
as per their docstrings to provide authentication etc.

Useful stuff;

._email_addr_looks_valid(self,emailaddr)- very basic check for a valid email address
._is_valid_HELO(self,args) - very basic checks for valid HELO/EHLO hostname
.fdqn = set to fully qualified domain name of listening server
.version = set to display string for server name (after 'hostname ESMTP')
.username = set by AUTH, read in process_message to determine login name
.loggerfunc = set with a valid logging.getLogger() function to see debug output, or set with a function that has a .debug(str) method
.client_address = read for tuple(remote_ip,port) 

If you don't have a certificate and key file pair, the module will generate one on the fly for use.

EXAMPLE USAGE FOR SSL/TLS CONNECTION;
from esmtpsslserver import SSLSMTPServer, ESMTPRequestHandler
import socket

# certfile and keyfile are optional - if not included a cert/key pair will be generated
server = SSLSMTPServer(('0.0.0.0',4650),
                                YourESMTPRequestHandler,
                                certfile='/etc/somewhere/certfile.cert',
                                keyfile='/etc/somewhere/certfile.key',
                                )

server.RequestHandlerClass.fqdn=socket.getfqdn()
server.RequestHandlerClass.version='My funky ESMTP server'
server.serve_forever()

EXAMPLE USAGE FOR SUPPORTING STARTTLS;
from esmtpsslserver import SSLSMTPServer, ESMTPRequestHandler
import socket

server = SSLSMTPServer(('0.0.0.0',2500),
                                YourESMTPRequestHandler,
                                use_ssl=False,
                                certfile='/etc/somewhere/certfile.cert',
                                keyfile='/etc/somewhere/certfile.key',
                                )

server.RequestHandlerClass.support_starttls=True
# following are optional - if not included one will be generated
server.RequestHandlerClass.tls_keyfile = 'path/to/certfile'
server.RequestHandlerClass.tls_certfile = 'path/to/keyfile'
server.RequestHandlerClass.fqdn=socket.getfqdn()
server.RequestHandlerClass.version='My funky ESMTP server'
server.serve_forever()

"""

from SocketServer import TCPServer, ThreadingMixIn, StreamRequestHandler
import ssl
import socket
import base64
import re
import sys
import os

VERBOSE = False # VERY chatty on debug


def generate_ephemeral_certificate(return_as_strings=False):
    """ Create ephemeral self-signed certificate and return it with key.

    Based on http://www.web2pyslices.com/slice/show/1507/generate-ssl-self-signed-certificate-and-key-enable-https-encryption-in-web2py

    Args:
        return_as_strings - Boolean.  If True, will return strings containing file content. If False, will
                                        return path to each file

    Returns:
        tuple of str - either path_to_certfile, path_to_keyfile or certfile_content, keyfile_content

    """
    from OpenSSL import crypto, rand
    from socket import gethostname
    from tempfile import mkstemp
    from os import write as os_write, unlink

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)

    # poor effort at providing a random serial number for the cert
    randbytes = rand.bytes(4)
    cert_serial = ord(randbytes[0])
    for c in randbytes[1:]:
        cert_serial = cert_serial * ord(c)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "GB"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Company"
    cert.get_subject().OU = "Organization"
    cert.get_subject().CN = gethostname()
    cert.set_serial_number(cert_serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    # we have to write a file to disk as Python's ssl implementation calls C code that expects an actual file
    cfile, cfile_path = mkstemp()
    kfile, kfile_path = mkstemp()
    os_write(cfile, crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    os_write(kfile, crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

    if return_as_strings:
        cert_data = ''.join(open(cfile_path, 'r').readlines())
        key_data = ''.join(open(kfile_path, 'r').readlines())
        try:
            unlink(cfile_path)
            unlink(kfile_path)
        except:
            pass
        return cert_data, key_data

    else:
        return cfile_path, kfile_path


class BaseSSLServer(TCPServer):
    """Base class for providing SSL-wrapped TCPServer.

    Args:
        [server_address]: tuple (str(ip), int(portno))
        [RequestHandlerClass]: class for handling requests (see ESMTPRequestHandler)
        use_ssl: True|False  - enable SSL/TLS
        certfile: string containing certificate or None to generate one
        keyfile: string containing private key or None to generate one
        ssl_version: what version of SSL/TLS to support (None for defaults)
        cipherlist: string containing list of ciphers in openssl format to support

    """
    allow_reuse_address = 1
    use_ssl = True

    def __init__(self, server_address, RequestHandlerClass, use_ssl=True, certfile=None, keyfile=None,
                 ssl_version=ssl.PROTOCOL_TLSv1, cipherlist=None):
        bind_and_activate = True
        TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        if certfile is None or keyfile is None:
            self.certfile, self.keyfile = generate_ephemeral_certificate()
        self.ssl_version = ssl_version
        self.cipherlist = cipherlist
        self.use_ssl = use_ssl

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        if self.use_ssl:
            connstream = ssl.wrap_socket(newsocket,
                                         server_side=True,
                                         certfile=self.certfile,
                                         keyfile=self.keyfile,
                                         ssl_version=self.ssl_version,
                                         ciphers=self.cipherlist)
            return connstream, fromaddr
        else:
            return newsocket, fromaddr


class SSLSMTPServer(ThreadingMixIn, BaseSSLServer):
    """SMTP Server class.
    
    Args:
        [server_address]: tuple (str(ip), int(portno))
        [RequestHandlerClass]: class for handling requests (see ESMTPRequestHandler)
        use_ssl: True|False  - enable SSL/TLS
        certfile: string containing certificate or None to generate one
        keyfile: string containing private key or None to generate one
        ssl_version: what version of SSL/TLS to support (None for defaults)
        cipherlist: string containing list of ciphers in openssl format to support

    """
    pass


class ESMTPRequestHandler(StreamRequestHandler):
    """SMTP request handler base class.  Called when a new connection comes in.
        
        Override these methods to make a useful server;
            validate_credentials(self,username,password)
            process_message(self, sender, recipients, msg)
            deny_sender(self,sender)
            deny_recipient(self,recipient)
            deny_host(self,hosttuple)
            
        as per their docstrings.
        
        Useful things in an instance;

        support_starttls = set to True to support STARTTLS
        require_starttls = if set to False, emails can be sent without STARTTLS being used (i.e. in the clear)
        tls_keyfile = Set to path of key file to use for TLS
        tls_certfile = Set to path of certificate file to use for TLS
        fdqn = set to fully qualified domain name of listening server
        version = set to display string for server name (after 'hostname ESMTP')
        username = set by AUTH, read in process_message to determine login name
        loggerfunc = set with a valid logging.getLogger() function to see debug output, or set with a function that
                        has at least a debug(str) method
        client_address = read for tuple(remote_ip,port)
        strict_helo = if set to True, won't treat HELO the same as EHLO and will not offer AUTH or STARTTLS
        exit_on_file_modified = If set to a tuple of (modulefilename.py, lastmtime) where modulefilename.py is the
                    file name of any file (doesn't have to be a python module) and lastmtime is the value from
                    os.path.getmtime() for that file, check whether that file's last-modified time has changed, and
                    quit if so.  This is useful for a managed/supervised process.
    
    """

    # SMTP state values
    STATE_INIT = 0  # no transaction currently in progress
    STATE_MAIL = 1  # after MAIL command
    STATE_RCPT = 2  # after first RCPT command, before DATA command

    # Things that can/should be set outside the class
    fqdn = 'localhost'
    version = 'Server'
    username = ''
    support_starttls = False
    require_starttls = True
    tls_keyfile = None
    tls_certfile = None
    loggerfunc = None
    openrelay = False
    strict_helo = False
    exit_on_file_modified = None
    tls_version = None
    tls_cipher_suites = None

    # Things that shouldn't be set outside the class
    _starttls_started = False
    _currently_authenticating = False
    _authenticated = False
    _logger = None
    _close_flag = False
    _helo = None
    _state = STATE_INIT
    _mail_from = None
    _rcpt_to = []

    class EmptyLogger:
        """Empty logger stub"""

        def __init__(self):
            pass

        def debug(self, msg):
            pass

        def info(self, msg):
            pass

        def warn(self, msg):
            pass

    def handle(self):
        """Main loop for the SMTP connection."""
        if self.loggerfunc:
            self._logger = self.loggerfunc
        else:
            self._logger = self.EmptyLogger

        if self.exit_on_file_modified is not None and len(self.exit_on_file_modified) == 2:
            try:
                if os.path.getmtime(self.exit_on_file_modified[0]) != self.exit_on_file_modified[1]:
                    self._logger.info(u'File {0} last-modified time changed, exiting'.format(self.exit_on_file_modified[0]))
                    sys.exit()
            except Exception as e:
                self._logger.info(u'Exception on filetime check for {0}: {1}'.format(self.exit_on_file_modified, e))

        if self.openrelay:
            self._authenticated = True
            self.username = ''

        if self.tls_certfile is None or self.tls_keyfile is None:
            self.tls_certfile, self.tls_keyfile = generate_ephemeral_certificate()

        self._close_flag = False
        self._helo = None
        self.reset_state()

        if self.deny_host(self.client_address) is not None:
            self._logger.debug('Rejecting connection from {0}'.format(self.client_address))
            return

        if VERBOSE:
            self._logger.debug('Connection from {0}'.format(self.client_address))

        try:
            self.send_response('220 {0} ESMTP {1}'.format(self.fqdn, self.version))
            while not self._close_flag:
                args = self.read_command()

                if VERBOSE:
                    self._logger.debug('Got message: {0}'.format(args))

                if args is None:
                    # EOF
                    break

                if self._currently_authenticating:
                    cmd = 'AUTH'
                else:
                    cmd = args.pop(0).upper()

                msg = u'501 Temporary failure'
                valid_method = False

                # White list of operations that are allowed prior to AUTH.

                if self.support_starttls:
                    # if STARTTLS is supported and we've not done it yet...
                    if not self._starttls_started:
                        if self.require_starttls:
                            if cmd not in ['EHLO', 'HELO', 'STARTTLS']:
                                msg = u'530 Must issue a STARTTLS command first'
                            else:
                                valid_method = True
                        else:
                            if cmd not in ['AUTH', 'EHLO', 'HELO', 'NOOP', 'RSET', 'QUIT',
                                           'VRFY']:
                                msg = u'530 Authentication required'
                            else:
                                valid_method = True

                    # if STARTTLS is supported and we've STARTedTLS but not authed
                    elif self._starttls_started:
                        if cmd not in ['AUTH', 'EHLO', 'HELO', 'NOOP', 'RSET', 'QUIT',
                                       'VRFY'] and not self._authenticated:
                            msg = u'530 Authentication required'
                        else:
                            valid_method = True

                else:
                    # if STARTTLS is not supported and we've not authed
                    if cmd not in ['AUTH', 'EHLO', 'HELO', 'NOOP', 'RSET', 'QUIT',
                                   'VRFY', 'STARTTLS'] and not self._authenticated:
                        msg = u'530 Authentication required'
                    else:
                        valid_method = True

                if valid_method:
                    method_name = '_smtp_' + cmd.upper()
                    if hasattr(self, method_name):
                        method = getattr(self, method_name)
                        msg = method(args)

                    else:
                        msg = u'501 unknown or unsupported command "{0}"'.format(cmd)

                if VERBOSE:
                    self._logger.debug(u'Returning message {0}'.format(msg))

                self.send_response(msg)

                if cmd.upper() == u'STARTTLS':
                    # server and client must make no assumptions about previous
                    # conversation after STARTTLS (see RFC3207)
                    self.reset_state()
                    # close off existing (possibly not required)
                    self.wfile.close()
                    self.rfile.close()
                    # wrap the existing socket and re-assign so that this class instance is using the
                    # correct socket
                    self.connection = ssl.wrap_socket(self.connection,
                                                      server_side=True,
                                                      certfile=self.tls_certfile,
                                                      keyfile=self.tls_keyfile,
                                                      ssl_version=self.tls_version,
                                                      ciphers=self.tls_cipher_suites)

                    self._starttls_started = True
                    if VERBOSE:
                        self._logger.debug('STARTTLS now started')
                    # re-assign input and output 'files'
                    self.rfile = self.connection.makefile('rb', self.rbufsize)
                    self.wfile = self.connection.makefile('wb', self.wbufsize)

        except socket.error, e:
            self._logger.debug(u'Unhandled exception in handle(): {0}'.format(e))

    def reset_state(self):
        """Utility function to reset the state of the SMTP session.
        Should be called before a new SMTP transaction is started.
        """
        self._state = self.STATE_INIT
        self._mail_from = None
        self._helo = None
        self._rcpt_to = []

    def read_command(self):
        """Read a command from the client, parse it into arguments,
        and return the argument list.
        """
        line = self.rfile.readline()
        if not line:
            # return None on EOF
            return None
        line = line.strip()
        return line.split(' ')

    def send_response(self, msg):
        """Sends an SMTP response to the client."""
        # self.logger.debug('Sending: {0}'.format(msg))
        self.wfile.write(msg + '\r\n')

    @staticmethod
    def _email_addr_looks_valid(emailaddr):
        """Perform basic regex to check if an email looks valid.
        
        Very basic - just checks for vaguely correct address format.
        
        """

        pattern = '[\.\w]{1,}[@]\w+[.][a-zA-Z]+'
        if emailaddr[0] == '<' and emailaddr[-1] == '>':
            emailaddr = emailaddr[1:-1]

        if re.match(pattern, emailaddr):
            return True
        else:
            return False

    @staticmethod
    def _is_valid_HELO(args):
        """
        Check if hostname in HELO/EHLO string looks valid.
        
        Very basic checks for;
            IP literal - [1.2.3.4]
            NOT just IP - 1.2.3.4
            3-part host - host.name.tld
        
        """

        arg = ''.join(args)
        if re.match('\d+.\d+.\d+.\d+$', arg):
            # plain IP address - reject
            return False
        elif re.match('\[\d+.\d+.\d+.\d+\]$', arg):
            # IP literal
            return True
        else:
            return True
            # uncomment below / replace this function to implement your own checks
            # if re.match('[a-zA-Z0-9]+.[a-zA-Z0-9]+.[a-zA-Z]+$', arg):
            #     # looks hostname-y
            #     return True
            # for dpart in arg.split('.'):
            #     if not re.match('[a-zA-Z0-9]+$', dpart):
            #         return False
            # if re.match('[a-zA-Z]+$', arg.split('.')[-1]):
            #     return True
            # return False

    def _smtp_EHLO(self, args):
        if not args or not self._is_valid_HELO(args):
            return u'501 Syntax: EHLO hostname'
        if self._helo:
            return u'503 we\'ve already met, hello again! Use RSET to reset message envelope'
        else:
            self._helo = args[0]
            if self.support_starttls and not self._starttls_started:
                return u'250-{0} Hello {1}\r\n250 STARTTLS'.format(self.fqdn, ''.join(args))
            else:
                return u'250-{0} Hello {1}\r\n250 AUTH LOGIN'.format(self.fqdn, ''.join(args))

    def _smtp_HELO(self, args):
        if self.strict_helo:
            if not args or not self._is_valid_HELO(args):
                return u'501 usage: HELO hostname'
            if self._helo:
                return u'503 we\'ve already met, hello again!'
            self._helo = args[0]
            return u'250 ok'
        else:
            return self._smtp_EHLO(args)

    def _smtp_QUIT(self, args):
        # Setting this flag tells the main loop in the handler() method
        # that the connection should be closed after sending this
        # response.
        self._close_flag = True
        return u'221 closing connection'

    def _smtp_VRFY(self, arg):
        return u'252 recipient unverified, try anyway'

    def _smtp_STARTTLS(self, arg):
        if self.support_starttls:
            return u'220 Ready to start TLS'
        else:
            return u'501 unknown or unsupported command "STARTTLS"'

    def _smtp_AUTH(self, args):

        try:
            if 'LOGIN' in [x.upper() for x in args]:
                self._currently_authenticating = True
                if VERBOSE:
                    self._logger.debug('In authenticating mode')
                # Some implementations of 'LOGIN' seem to provide the username
                # along with the 'LOGIN' stanza, hence both situations are
                # handled.
                if len(args) == 2:
                    self.username = base64.b64decode(args[1])
                    return u'334 {0}'.format(base64.b64encode(u'Username:'))
                else:
                    return u'334 {0}'.format(base64.b64encode(u'Username:'))

            elif not self.username:
                self.username = base64.b64decode(args[0])
                return u'334 {0}'.format(base64.b64encode(u'Password:'))
            else:
                self._currently_authenticating = False
                if VERBOSE:
                    self._logger.debug('Leaving authenticating mode to validate credentials')

                self.password = base64.b64decode(args[0])
                if self.validate_credentials(self.username, self.password):
                    self._authenticated = True
                    return u'235 Authentication successful.'
                else:
                    self._close_flag = True
                    self._logger.debug(u'Password incorrect')
                    return u'454 Temporary authentication failure, closing connection.'

        except TypeError:
            self._logger.debug(u'Got type error for args {0}'.format(args))
            self._close_flag = True
            # The extra . here is to help debug where auth failure happened
            return u'454 Temporary authentication failure, closing connection..'

        except Exception as e:
            self._logger.debug(u'Got unhandled exception in smtp_AUTH with args {0}: {1}'.format(args, e))
            self._close_flag = True
            # The extra .. here is to help debug where auth failure happened
            return u'454 Temporary authentication failure, closing connection...'

    def _smtp_RSET(self, args):
        self.reset_state()
        return u'250 Reset ok'

    def _smtp_NOOP(self, args):
        return u'250 ok'

    def _smtp_MAIL(self, sentargs):
        # handle "MAIL FROM:<address>", "MAIL FROM <address>", "MAIL FROM: <address>"
        # will also support MAIL FROM:<address> AUTH=<> etc. for rfc2554
        # https://tools.ietf.org/rfc/rfc2554.txt
        # http://www.fehcom.de/qmail/smtpauth.html
        # https://tools.ietf.org/rfc/rfc1891.txt
        args = []

        if len(sentargs) == 1:
            # this must only be ['FROM:<mailaddr>']
            if sentargs[0].upper().startswith('FROM:') and len(sentargs[0]) > 5:
                args = ['FROM', sentargs[0][5:]]
        else:
            # this must be one of ['FROM', '<addr>'], ['FROM[:]', '<addr>'], ['FROM:<addr>', 'morestuff'],
            #   or ['FROM[:]', '<addr>', 'morestuff', '....']
            if 'FROM:' in sentargs[0].upper() and '@' in sentargs[0]:
                # ['FROM:<addr>', 'morestuff']
                args = ['FROM', sentargs[0][5:]]
            elif 'FROM' in sentargs[0].upper() and '@' in sentargs[1]:
                # ['FROM', '<addr>' [, 'morestuff']] or ['FROM:', '<addr>' [, 'morestuff']]
                args = ['FROM', sentargs[1]]

        if len(args) == 0:
            return u'501 usage: MAIL FROM address'

        if self._state != self.STATE_INIT:
            return u'503 transaction already in progress - use RSET to abort'

        deny_sender = self.deny_sender(args[1])
        if deny_sender:
            return deny_sender

        self._state = self.STATE_MAIL
        self._mail_from = args[1]
        return u'250 sender ok'

    def _smtp_RCPT(self, args):
        # handle "RCPT TO:<address>" or "RCPT TO <address>"
        if len(args) == 1 and args[0].upper().startswith('TO:') and \
                        len(args[0]) > 3:
            args = ['TO', args[0][3:]]
        elif args[0].endswith(':'):
            args[0] = args[0][:len(args[0]) - 1]
        if len(args) != 2 or args[0].upper() != 'TO':
            return u'501 usage: RCPT TO address'

        if self._state not in (self.STATE_MAIL, self.STATE_RCPT):
            return u'503 send MAIL command first'

        deny_recip = self.deny_recipient(args[1])
        if deny_recip:
            return deny_recip

        self._state = self.STATE_RCPT
        self._rcpt_to.append(args[1])
        return u'250 Ok'

    def _smtp_DATA(self, args):
        if self._state != self.STATE_RCPT:
            return u'503 send RCPT command first'
        self.send_response(u'354 end DATA with <CR><LF>.<CR><LF>')

        data = []
        while True:
            line = self.rfile.readline().rstrip('\n\r')
            if line.startswith('.'):
                if len(line) == 1:
                    break
                data.append(line[1:])
                continue
            data.append(line)

        result = self.process_message(self._mail_from, self._rcpt_to,
                                      '\n'.join(data))
        self.reset_state()
        if result:
            return result
        return u'250 message accepted'

    def _smtp_ETRN(self, args):
        return u'500 No delivery options are available'

    def validate_credentials(self, username, password):
        """Override this method to authenticate users - 
        must return None for failure or non-None for success.
        
        Args:
            username - string with actual username (after decoding)
            password - string with actual password (after decoding)
        
        Returns:
            None on failure or non-None on success
        
        """
        return True

    def process_message(self, sender, recipients, msg):
        """Override this method to handle messages from the client.

        Args:
            sender- string containing address of originator
            recipients - list of addresses the client wants message delivery to
            msg - string containing the entire full text of the message (everything
                    including headers + encoded attachments etc.),

        Returns:
            None if the message was processed successfully.  Return string if failure.
        """

        self._logger.debug(u'Dumping email from peer {0}'.format(self.client_address[0]))

        print 'Sender: {0}'.format(sender)
        for rcpt in recipients:
            print 'Recipient: {0}'.format(rcpt)
        print 'Raw message:\n\n{0}\n\n\n'.format(msg)
        return None

    def deny_sender(self, sender):
        """Determine if sender is permitted.  Override with functional code
        to perform check (address format, allowed list etc.).

        Args:
            sender: string containing address (may be wrapped in <>)

        Returns:
            None/False if allowed or string with error
        """
        return not self._email_addr_looks_valid(sender)

    def deny_recipient(self, recipient):
        """Determine if recipient is permitted.  Override with functional code
        to perform check (address format, allowed list etc.).

        Args:
            sender: string containing address (may be wrapped in <>)

        Returns:
            None/False if allowed or string with error
        """
        return not self._email_addr_looks_valid(recipient)

    def deny_host(self, host):
        """Determine if remote host is allowed to connect.  Override with functional code
        to perform check (blacklist, SNI etc.).

        Args:
            sender: tuple of ('ip address',port number)

        Returns:
            None/False if allowed or string with error
        """
        return None


if __name__ == '__main__':
    # Start an example print-to-console ESMTP server
    # Run on port 2025
    # 
    server = SSLSMTPServer(('', 2025), ESMTPRequestHandler, use_ssl=False, )
    server.RequestHandlerClass.fqdn = socket.getfqdn()

    server.serve_forever()

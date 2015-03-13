#!/usr/bin/env python
<<<<<<< HEAD
"""ESMTP server base class.  Nick Besant 2014-2015 hwf@fesk.net
=======
"""ESMTP server base class.  Nick Besant 2014 hwf@fesk.net
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d

Mainly based on bcoe's https://github.com/bcoe/secure-smtpd and posts to http://bugs.python.org/issue1057417 from Mark D Roth

Creates a threaded ESMTP server that supports SSL/TLS and LOGIN authentication.

Override methods;
    validate_credentials(self,username,password)
    process_message(self, sender, recipients, msg)
    deny_sender(self,sender)
    deny_recipient(self,recipient)
    deny_host(self,hosttuple)
    
as per their docstrings to provide authentication etc.


Useful things in an instance;

._email_addr_looks_valid(self,emailaddr)- very basic check for a valid email address
._is_valid_HELO(self,args) - very basic checks for valid HELO/EHLO hostname
.fdqn = set to fully qualified domain name of listening server
.version = set to display string for server name (after 'hostname ESMTP')
.username = set by AUTH, read in process_message to determine login name
.loggerfunc = set with a valid logging.getLogger() function to see debug output, or set with a function that has a .debug(str) method
.client_address = read for tuple(remote_ip,port) 

EXAMPLE USAGE;
from esmtpsslserver import SSLSMTPServer, ESMTPRequestHandler
import socket

server = SSLSMTPServer(('0.0.0.0',4650),
                                DQESMTPRequestHandler,
                                use_ssl=True,
                                certfile='/etc/somewhere/certfile.cert',
                                keyfile='/etc/somewhere/certfile.key',
                                )

server.RequestHandlerClass.fqdn=socket.getfqdn()
server.RequestHandlerClass.version='My funky ESMTP server'
server.serve_forever()

"""

from SocketServer import TCPServer, ThreadingMixIn,StreamRequestHandler
import ssl
import socket
import base64
import re

<<<<<<< HEAD

=======
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d
class BaseSSLServer(TCPServer):
    """Base class for providing SSL-wrapped TCPServer.  See SSLSMTPServer for info"""
    allow_reuse_address = 1
    use_ssl=True
    
    def __init__(self,server_address,RequestHandlerClass,use_ssl=True,certfile=None,keyfile=None,ssl_version=ssl.PROTOCOL_TLSv1):
        bind_and_activate=True
        TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version
        self.use_ssl=use_ssl

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        if self.use_ssl:
            connstream = ssl.wrap_socket(newsocket,
                                         server_side=True,
                                         certfile = self.certfile,
                                         keyfile = self.keyfile,
                                         ssl_version = self.ssl_version)
            return connstream, fromaddr
        else:
            return newsocket, fromaddr        
<<<<<<< HEAD

=======
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d
        
class SSLSMTPServer(ThreadingMixIn, BaseSSLServer): 
    """SMTP Server class.
    
    Args:
        server_address - tuple (str(ip), int(portno))
        RequestHandlerClass - class name for handling requests (intended to be based on ESMTPRequestHandler)
        use_ssl - whether to enable SSL or not
        certfile - path to .cert file
        keyfile - path to .key file
        ssl_version - version from ssl lib to use
    
    """
    pass

<<<<<<< HEAD

=======
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d
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
        
        .fdqn = set to fully qualified domain name of listening server
        .version = set to display string for server name (after 'hostname ESMTP')
        .username = set by AUTH, read in process_message to determine login name
        .loggerfunc = set with a valid logging.getLogger() function to see debug output, or set with a function that has a .debug(str) method
        .client_address = read for tuple(remote_ip,port) 
    
    """

    # SMTP state values
    STATE_INIT = 0       # no transaction currently in progress
    STATE_MAIL = 1       # after MAIL command
    STATE_RCPT = 2       # after first RCPT command, before DATA command

    # Stuff
    fqdn='localhost'
    version='Server'
    authenticating=False
    authenticated=False
    username=''
    loggerfunc=None
<<<<<<< HEAD
    openrelay=False
=======
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d

    class __emptylogger():
        """Empty logger stub"""
    
        def debug(self,msg):
            pass

        def info(self,msg):
            pass

        def warn(self,msg):
            pass


    def handle(self):
        """Main loop for the SMTP connection."""
        if self.loggerfunc:
            self.logger=self.loggerfunc
        else:
            self.logger=self.__emptylogger
            
<<<<<<< HEAD
        if self.openrelay:
            self.authenticated=True
            self.username=''
            
=======
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d
        self.close_flag = False
        self.helo = None
        self.reset_state()

        if self.deny_host(self.client_address) is not None:
            self.logger.debug('Rejecting connection from {0}'.format(self.client_address))
            return
        
        try:
            self.send_response('220 {0} ESMTP {1}'.format(self.fqdn,self.version))
            while not self.close_flag:
                args = self.read_command()
                if args is None:
                    # EOF
                    break
                
                if self.authenticating:
                    cmd='AUTH'
                else:
                    cmd = args.pop(0).upper()
                    
<<<<<<< HEAD
                #self.logger.debug('Got command: {0}'.format(cmd))
=======
                self.logger.debug('Got command: {0}'.format(cmd))
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d

                # White list of operations that are allowed prior to AUTH.
                if cmd not in ['AUTH', 'EHLO', 'HELO', 'NOOP', 'RSET', 'QUIT', 'VRFY'] and not self.authenticated:
                    msg='530 Authentication required'
                else:
<<<<<<< HEAD
                    method_name = 'smtp_' + cmd.upper()
=======
                    method_name = 'smtp_' + cmd
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d
                    if hasattr(self, method_name):
                        method = getattr(self, method_name)
                        msg = method(args)
                    else:
                        msg = '501 unknown or unsupported command "{0}"'.format(cmd)
                
                self.send_response(msg)
                    
        except socket.error, e:
            self.logger.debug(u'Unhandled exception in handle(): {0}'.format(e))

    def reset_state(self):
        """Utility function to reset the state of the SMTP session.
        Should be called before a new SMTP transaction is started.
        """
        self.state = self.STATE_INIT
        self.mail_from = None
        self.helo=None
        self.rcpt_to = [ ]

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
<<<<<<< HEAD
        #self.logger.debug('Sending: {0}'.format(msg))
=======
        self.logger.debug('Sending: {0}'.format(msg))
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d
        self.wfile.write(msg + '\r\n')
    
    
    def _email_addr_looks_valid(self,emailaddr):
        """Perform basic regex to check if an email looks valid.
        
        Very basic - just checks for vaguely correct address format.
        
        """

        pattern='[\.\w]{1,}[@]\w+[.][a-zA-Z]+'        
        if emailaddr[0]=='<' and emailaddr[-1]=='>':
            emailaddr=emailaddr[1:-1]
    
        if re.match(pattern, emailaddr):
            return True
        else:
            return False    
    
    def _is_valid_HELO(self,args):
        """
        Check if hostname in HELO/EHLO string looks valid.
        
        Very basic checks for;
            IP literal - [1.2.3.4]
            NOT just IP - 1.2.3.4
            3-part host - host.name.tld
        
        """
        
        arg=''.join(args)
        if re.match('\d+.\d+.\d+.\d+$',arg):
            # plain IP address - reject
            return False
        elif re.match('\[\d+.\d+.\d+.\d+\]$',arg):
            # IP literal
            return True
<<<<<<< HEAD
        else:
            return True
            if re.match('[a-zA-Z0-9]+.[a-zA-Z0-9]+.[a-zA-Z]+$',arg):
                # looks hostname-y
                return True
            for dpart in arg.split('.'):
                if not re.match('[a-zA-Z0-9]+$',dpart):
                    return False
            if re.match('[a-zA-Z]+$',arg.split('.')[-1]):
                return True
            
=======
        elif re.match('[a-zA-Z0-9]+.[a-zA-Z0-9]+.[a-zA-Z]+$',arg):
            # looks hostname-y
            return True
        else:
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d
            return False
    
    def smtp_EHLO(self, args):
        if not args or not self._is_valid_HELO(args):
            return '501 Syntax: EHLO hostname'
        if self.helo:
            return '503 we\'ve already met, hello again! Use RSET to reset message envelope'
        else:
            self.helo = args[0]
            return '250-%s Hello %s\r\n250 AUTH LOGIN' %  (self.fqdn, ''.join(args))
        
    def smtp_HELO(self, args):
        if not args or not self._is_valid_HELO(args):
            return '501 usage: HELO hostname'
        if self.helo:
            return '503 we\'ve already met, hello again!'
        self.helo = args[0]
        return '250 ok'

    def smtp_QUIT(self, args):
        # Setting this flag tells the main loop in the handler() method
        # that the connection should be closed after sending this
        # response.
        self.close_flag = True
        return '221 closing connection'

    def smtp_VRFY(self,arg):
        return '252 recipient unverified, try anyway'
    
    def smtp_AUTH(self, args):
        try:
            if 'LOGIN' in [x.upper() for x in args]:
                self.authenticating = True
                
                # Some implementations of 'LOGIN' seem to provide the username
                # along with the 'LOGIN' stanza, hence both situations are
                # handled.
                if len(args) == 2:
<<<<<<< HEAD
                    self.username = base64.b64decode( args[1] )
=======
                    self.username = base64.b64decode( args.split[1] )
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d
                    return '334 %s' % base64.b64encode('Username')
                else:
                    return '334 %s' % base64.b64encode('Username')
                    
            elif not self.username:
                self.username = base64.b64decode( args[0] )
                return '334 %s' % base64.b64encode('Password')
            else:
                self.authenticating = False
                self.password = base64.b64decode(args[0])
                if self.validate_credentials(self.username, self.password):
                    self.authenticated = True
                    return '235 Authentication successful.'
                else:
                    self.close_flag = True
                    self.logger.debug(u'Password incorrect')
                    return '454 Temporary authentication failure, closing connection.'
                
        except TypeError:
            self.logger.debug(u'Got type error for args {0}'.format(args))
            self.close_flag = True
            return '454 Temporary authentication failure, closing connection..'
        
        except Exception as e:
            self.logger.debug(u'Got unhandled exception in smtp_AUTH with args {0}: {1}'.format(args,e))
            self.close_flag = True
            return '454 Temporary authentication failure, closing connection...'
            
    
    def smtp_RSET(self, args):
        self.reset_state()
        return '250 Reset ok'

    def smtp_NOOP(self, args):
        return '250 ok'

    def smtp_MAIL(self, args):
        # handle "MAIL FROM:<address>" or "MAIL FROM <address>"
        if len(args) == 1 and args[0].upper().startswith('FROM:') and \
           len(args[0]) > 5:
            args = [ 'FROM', args[0][5:] ]
        elif args[0].endswith(':'):
            args[0] = args[0][:len(args[0]) - 1]
        if len(args) != 2 or args[0].upper() != 'FROM':
            return '501 usage: MAIL FROM address'

        if self.state != self.STATE_INIT:
            return '503 transaction already in progress - use RSET to abort'
        
        deny_sender= self.deny_sender(args[1])
        if deny_sender:
            return deny_sender

        self.state = self.STATE_MAIL
        self.mail_from = args[1]
        return '250 sender ok'

    def smtp_RCPT(self, args):
        # handle "RCPT TO:<address>" or "RCPT TO <address>"
        if len(args) == 1 and args[0].upper().startswith('TO:') and \
           len(args[0]) > 3:
            args = [ 'TO', args[0][3:] ]
        elif args[0].endswith(':'):
            args[0] = args[0][:len(args[0]) - 1]
        if len(args) != 2 or args[0].upper() != 'TO':
            return '501 usage: RCPT TO address'

        if self.state not in (self.STATE_MAIL, self.STATE_RCPT):
            return '503 send MAIL command first'
        
        deny_recip = self.deny_recipient(args[1])
        if deny_recip:
            return deny_recip
        
        self.state = self.STATE_RCPT
        self.rcpt_to.append(args[1])
        return '250 Ok'

    def smtp_DATA(self, args):
        if self.state != self.STATE_RCPT:
            return '503 send RCPT command first'
        self.send_response('354 end DATA with <CR><LF>.<CR><LF>')

        data = [ ]
        while True:
            line = self.rfile.readline().rstrip('\n\r')
            if line.startswith('.'):
                if len(line) == 1:
                    break
                data.append(line[1:])
                continue
            data.append(line)

        result = self.process_message(self.mail_from, self.rcpt_to,
                                      '\n'.join(data))
        self.reset_state()
        if result:
            return result
        return '250 message accepted'

    def smtp_ETRN(self,args):
        return '500 No delivery options are available'

    def validate_credentials(self,username,password):
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
        
        self.logger.debug(u'Dumping email from peer {0}'.format(self.client_address[0]))
        
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
    server = SSLSMTPServer(('', 2025), ESMTPRequestHandler,use_ssl=False,)
    server.RequestHandlerClass.fqdn=socket.getfqdn()
    
    server.serve_forever()



<<<<<<< HEAD
            
=======
            
>>>>>>> 4c36a5eb339c51c0a00909d5eda811cb1b58361d

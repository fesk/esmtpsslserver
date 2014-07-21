esmtpsslserver
==============

Python - threaded ESMTP server that supports SSL/TLS and LOGIN authentication


Mainly based on bcoe's https://github.com/bcoe/secure-smtpd and posts to http://bugs.python.org/issue1057417 from Mark D Roth

Creates a threaded ESMTP server that supports SSL/TLS and LOGIN authentication.

Methods to sub
----------------

*    `validate_credentials(self,username,password)`
    
*    `process_message(self, sender, recipients, msg)`

*    `deny_sender(self,sender)`

*   `deny_recipient(self,recipient)`

*    `deny_host(self,hosttuple)`

### Useful things in an instance;


`._email_addr_looks_valid(self,emailaddr)` - very basic check for a valid email address

`._is_valid_HELO(self,args)` - very basic checks for valid HELO/EHLO hostname

`.fdqn` = set to fully qualified domain name of listening server

`.version` = set to display string for server name (after 'hostname ESMTP')

`.username` = set by AUTH, read in process_message to determine login name

`.loggerfunc` = set with a valid logging.getLogger() function to see debug output, or set with a function that has a .debug(str) method

`.client_address` = read for tuple(remote_ip,port) 


EXAMPLE USAGE;

    from esmtpsslserver import SSLSMTPServer, ESMTPRequestHandler
    import socket

    server = SSLSMTPServer(('0.0.0.0',4650),
                                ESMTPRequestHandler,
                                use_ssl=True,
                                certfile='/etc/somewhere/certfile.cert',
                                keyfile='/etc/somewhere/certfile.key',
                                )

    server.RequestHandlerClass.fqdn=socket.getfqdn()
    server.RequestHandlerClass.version='My funky ESMTP server'
    server.serve_forever()

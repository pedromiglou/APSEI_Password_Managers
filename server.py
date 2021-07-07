#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor
import logging
import binascii
import json
import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import cryptography.hazmat.backends as backends

logger = logging.getLogger('root')
FORMAT = "[%(asctime)s %(filename)s:%(lineno)s] %(message)s"
logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
logger.setLevel(logging.INFO)

class PasswordManagerServer(resource.Resource):
    isLeaf = True
    userPasswords = dict()
    userVaults = dict()

    # Handle a GET request
    def render_GET(self, request):
        try:
            if request.path == b'/api/vault':
                data = json.loads(request.content.read())
                username = data['username']
                auth = binascii.a2b_base64(data['auth'].encode('latin'))

                logger.info("Received request for a vault: u - " + username + ", p - " + str(auth))

                if username not in self.userPasswords.keys():
                    logger.info("Not existant user")
                    request.setResponseCode(400)
                    request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
                    return b''
                
                # derive another 100100 times to get Authentication Key
                logger.info("deriving authentication key...")
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=username.encode('latin'),
                    iterations=100100, backend=backends.default_backend())
                authentication_key = kdf.derive(auth)
                logger.info("authentication_key: "+str(authentication_key))
                
                if authentication_key != self.userPasswords[username]:
                    logger.info("Wrong password")
                    request.setResponseCode(400)
                    request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
                    return b''

                logger.info("Sending vault: "+str(self.userVaults[username]))
                
                return self.userVaults[username]
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b''

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
    
    # Handle a POST request
    def render_POST(self, request):
        try:
            if request.path == b'/api/register':
                data = json.loads(request.content.read())
                username = data['username']
                auth = binascii.a2b_base64(data['auth'].encode('latin'))
                vault = binascii.a2b_base64(data['vault'].encode('latin'))

                logger.info("Received register request: u - " + username + ", p - " + str(auth) + ", vault - " + str(vault))

                # derive another 100100 times to get Authentication Key
                logger.info("deriving authentication key...")
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=username.encode('latin'), iterations=100100, backend=backends.default_backend())
                authentication_key = kdf.derive(auth)
                logger.info("authentication_key: "+str(authentication_key))

                self.userPasswords[username] = authentication_key
                self.userVaults[username] = vault
                logger.info("register sucessful")
                request.setResponseCode(200)
                return b''
            
            if request.path == b'/api/vault':
                data = json.loads(request.content.read())
                username = data['username']
                auth = binascii.a2b_base64(data['auth'].encode('latin'))
                vault = binascii.a2b_base64(data['vault'].encode('latin'))

                logger.info("Received update vault request: u - " + username + ", p - " + str(auth) + ", vault - " + str(vault))

                if username not in self.userPasswords.keys():
                    logger.info("Not existant user")
                    request.setResponseCode(400)
                    request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
                    return b''

                # derive another 100100 times to get Authentication Key
                logger.info("deriving authentication key...")
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=username.encode('latin'), iterations=100100, backend=backends.default_backend())
                authentication_key = kdf.derive(auth)
                logger.info("authentication_key: "+str(authentication_key))

                if authentication_key != self.userPasswords[username]:
                    logger.info("Wrong password")
                    request.setResponseCode(400)
                    request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
                    return b''

                self.userVaults[username] = vault
                logger.info("update sucessful")
                request.setResponseCode(200)
                return b''

            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b''

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

print("Server started")
print("URL is: http://IP:8080")

s = server.Site(PasswordManagerServer())
reactor.listenTCP(8080, s)
reactor.run()
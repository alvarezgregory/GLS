#! /usr/bin/env python
# -*- coding: utf-8 -*-

#  GLS.py
#
#  Goswell Layer Security Project
#
#  GLS Interface for python
#
#  Created by Grégory ALVAREZ (greg@goswell.net) on 05/02/12.
# 
#  Copyright (c) 2012, Goswell SAS
#  All rights reserved.
# 
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#	* Redistributions of source code must retain the above copyright
#	notice, this list of conditions and the following disclaimer.
#	* Redistributions in binary form must reproduce the above copyright
#	notice, this list of conditions and the following disclaimer in the
#	documentation and/or other materials provided with the distribution.
#	* Neither the name of Goswell SAS nor the
#	names of its contributors may be used to endorse or promote products
#	derived from this software without specific prior written permission.
# 
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL GOSWELL SAS BE LIABLE FOR ANY
#  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os, sys
from ctypes import *
import exceptions

# Locale Variables
libgls = 0
libc = 0
libGlsInit = False

def initGLSLibrary():
    global libGlsInit
    global libgls
    global libc
    if libGlsInit == False:
	# Replace the libgsl's name with the one on your system
	libgls = CDLL("/usr/local/lib/libgls.so")
	# The name of your Libc library 
	libc = CDLL("libc.so.6")
	libGlsInit = True
	
class GLSServer:
    
    def __init__(self, secureMem = False, sizeMem = 0):
	global libgls
	global libc
	initGLSLibrary()
	self.library = libgls
	self.libraryc = libc
	if secureMem:
		lGLSServer = self.library.GLSServerSecure
		lGLSServer.argtypes = [c_int, c_int]
		lGLSServer.restype = c_void_p
		co_mem = c_int(1)
		co_size = c_int(sizeMem)
		self.myServerSocket = lGLSServer(co_mem, co_size)
	else:
		lGLSServer = self.library.GLSServer
		lGLSServer.restype = c_void_p
		self.myServerSocket = lGLSServer()
		
    def initServer(self, port="3600", waitQueue=5, isReuse=False):
	lInitServer = self.library.initServer
	lInitServer.argtypes = [c_void_p, c_char_p, c_int, c_int]
	init_re = c_int(0)
	if isReuse:
	    init_re = c_int(1)
	init_port = c_char_p(port)
	init_queue = c_int(waitQueue)
	vre = lInitServer(self.myServerSocket, init_port, init_queue, init_re)
	if int(vre) != 0:
	    raise GlsError(int(vre), "Error initServer")
	
    def __del__(self):
	# Freeing the GLSServer Socket
	lCloseGLSServer = self.library.freeGLSServer
	lCloseGLSServer.argtypes = [c_void_p]
	vre = lCloseGLSServer(self.myServerSocket)
	
	# Freeing the pointer for GLSServer
	#free = self.libraryc.free
	#free.argtypes = [c_void_p]
	#free(self.myServerSocket)
	
	if int(vre) < 0:
	    raise GlsError(int(vre), "Error del GLSServer")
	
    def waitForClient(self):
	lwaitForClient = self.library.waitForClient
	lwaitForClient.argtypes = [c_void_p, c_void_p]
	myClient = c_void_p(0)
	vre = int(lwaitForClient(self.myServerSocket, byref(myClient)))
	if vre != 0:
	    if myClient != 0:
		free = self.libraryc.free
		free.argtypes = [c_void_p]
		free(cast(myClient, c_void_p))
	    raise GlsError(int(vre), "Error waitForClient")
	client = GLSSocket(myClient)
	return client
   
# int addServerCertificate(GLSServerSock* myGLSServerSock, const char* publicCert, const char* privateKey);

    def addServerCertificate(self, public, private):
	laddServerCert = self.library.addServerCertificate
	laddServerCert.argtypes = [c_void_p, c_char_p, c_char_p]
	co_public = c_char_p(public)
	co_private = c_char_p(private)
	vre = laddServerCert(self.myServerSocket, co_public, co_private)
	if int(vre) != 0:
	    raise GlsError(int(vre), "Error addServerCertificate")

# int addServerCertificateFromFile(GLSServerSock* myGLSServerSock, const char* publicCertFile, const char* privateKeyFile);

    def addServerCertificateFromFile(self, public, private):
	laddServerCertFile = self.library.addServerCertificateFromFile
	laddServerCertFile.argtypes = [c_void_p, c_char_p, c_char_p]
	co_public = c_char_p(public)
	co_private = c_char_p(private)
	vre = laddServerCertFile(self.myServerSocket, co_public, co_private)
	if int(vre) != 0:
	    raise GlsError(int(vre), "Error addServerCertificateFromFile")


class GLSSocket:
    
    def __init__(self, sock = 0, secureMem = False, sizeMem = 0):
	global libgls
	global libc
	initGLSLibrary()
	self.library = libgls
	self.libraryc = libc
	if sock == 0:
		if secureMem:
			lGLSSocket = self.library.GLSSocketSecure
			lGLSSocket.argtypes = [c_int, c_int]
			lGLSSocket.restype = c_void_p
			co_mem = c_int(1)
			co_size = c_int(sizeMem)
			self.mySocket = lGLSSocket(co_mem, co_size)
		else:
			lGLSSocket = self.library.GLSSocket
			lGLSSocket.restype = c_void_p
			self.mySocket = lGLSSocket()
	else:
	    self.mySocket = cast(sock, c_void_p)
    
    def __del__(self):
	# Freeing the GLS Socket
	lCloseGLSSocket = self.library.freeGLSSocket
	# Bug doesn't take c_void_p "Exception TypeError: 'item 1 in _argtypes_ has no from_param method'"
	lCloseGLSSocket.argtypes = [c_char_p]
	vre = lCloseGLSSocket(cast(self.mySocket, c_char_p))
	
	# Freeing the pointer for GLSSocket (create error -> not allocated)
	#free = self.libraryc.free
	#free.argtypes = [c_char_p]
	#free(cast(self.mySocket, c_char_p))
	
	if int(vre) < 0:
	    raise GlsError(int(vre), "Error del GLSSocket")

#int connexion(GLSSock* myGLSSocket, const char* address, const char* port);
    
    def connexion(self, address, port):
	lconnexion = self.library.connexion
	lconnexion.argtypes = [c_void_p, c_char_p, c_char_p]
	co_address = c_char_p(address)
	co_port = c_char_p(port)
	vre = lconnexion(self.mySocket, co_address, co_port)
	if int(vre) != 0:
	    raise GlsError(int(vre), "Error connexion")

#int sendRegister(GLSSock* myGLSSocket, const char* address, const char* port, const byte* buffer, const int sizeBuffer);

    def sendRegister(self, address, port, buffer):
	lsendRegister = self.library.sendRegister
	lsendRegister.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_int]
	co_address = c_char_p(address)
	co_port = c_char_p(port)
	co_buffer = c_char_p(buffer)
	co_size = c_int(len(buffer))
	vre = lsendRegister(self.mySocket, co_address, co_port, co_buffer, co_size)
	if int(vre) != 0:
	    raise GlsError(int(vre), "Error sendRegister")

# int getRegisterMessage(GLSSock* myGLSSocket, byte** message);

    def getRegisterMessage(self):
	lgetRegister = self.library.getRegisterMessage
	lgetRegister.argtypes = [c_void_p, c_void_p]
	co_buffer = c_void_p(0)
	vre = lgetRegister(self.mySocket, byref(co_buffer))
	if vre < 0:
	    if co_buffer != 0:
		free = self.libraryc.free
		free.argtypes = [c_void_p]
		free(cast(co_buffer, c_void_p))
	    raise GlsError(int(vre), "Error getRegisterMessage")	     

	# Creation en string python de co_buffer
	myString = cast(co_buffer, c_char_p).value
	
	# Freeing the pointer for co_buffer
	free = self.libraryc.free
	free.argtypes = [c_void_p]
	free(co_buffer)
	
	return myString
	

#int glsSend(GLSSock* myGLSSocket, const byte* buffer, const int sizeBuffer);

    def glsSend(self, buffer):
	lglsSend = self.library.glsSend
	lglsSend.argtypes = [c_void_p, c_char_p, c_int]
	co_buffer = c_char_p(buffer)
	co_size = c_int(len(buffer) + 1)
	vre = lglsSend(self.mySocket, co_buffer, co_size)
	if int(vre) < 0:
	    raise GlsError(int(vre), "Error glsSend")

#int glsRecv(GLSSock* myGLSSocket, byte** buffer);

    def glsRecv(self):
	lglsRecv = self.library.glsRecv
	lglsRecv.argtypes = [c_void_p, c_void_p]
	co_buffer = c_void_p(0)
	vre = lglsRecv(self.mySocket, byref(co_buffer))
	if vre < 0:
	    if co_buffer != 0:
		free = self.libraryc.free
		free.argtypes = [c_void_p]
		free(cast(co_buffer, c_void_p))
	    raise GlsError(int(vre), "Error glsRecv")	     

	# Creation en string python de co_buffer
	myString = cast(co_buffer, c_char_p).value
	
	# Freeing the pointer for co_buffer
	free = self.libraryc.free
	free.argtypes = [c_void_p]
	free(co_buffer)
	
	return myString
	
#int addKey(GLSSock* myGLSSocket, const char* key, int isSha);

    def addKey(self, key, isSha = False):
	laddKey = self.library.addKey
	laddKey.argtypes = [c_void_p, c_char_p, c_int]
	add_key = c_char_p(key)
	add_sha = c_int(0)
	if isSha:
	    add_sha = c_int(1)
	vre = laddKey(self.mySocket, add_key, add_sha)
	if int(vre) != 0:
	    raise GlsError(int(vre), "Error addKey")
	
#int clearKey(GLSSock* myGLSSocket);
    
    def clearKey(self):
	lclearKey = self.library.clearKey
	lclearKey.argtypes = [c_void_p]
	vre = lclearKey(self.mySocket)
	if int(vre) != 0:
	    raise GlsError(int(vre), "Error clearKey")
	
#int getTypeConnexion(GLSSock* myGLSSocket);

    def getTypeConnexion(self):
	lgetTypeConnexion = self.library.getTypeConnexion
	lgetTypeConnexion.argtypes = [c_void_p]
	vre = lgetTypeConnexion(self.mySocket)
	return int(vre)
    
#int getUserId(GLSSock* myGLSSocket, char** userId);

    def getUserId(self):
	lgetUserId = self.library.getUserId
	lgetUserId.argtypes = [c_void_p, c_void_p]
	co_buffer = c_void_p(0)
	vre = lgetUserId(self.mySocket, byref(co_buffer))
	if vre < 0:
	    if co_buffer != 0:
		free = self.libraryc.free
		free.argtypes = [c_void_p]
		free(cast(co_buffer, c_void_p))
	    raise GlsError(int(vre), "Error getUserId")
	
	# Creation in python string of co_buffer
	myString = cast(co_buffer, c_char_p).value

	# Freeing the pointer for co_buffer
	free = self.libraryc.free
	free.argtypes = [c_void_p]
	free(co_buffer)
	
	return myString
	
#int setUserId(GLSSock* myGLSSocket, const char* userId);

    def setUserId(self, userId):
	lsetUserId = self.library.setUserId
	lsetUserId.argtypes = [c_void_p, c_char_p]
	set_id = c_char_p(userId)
	vre = lsetUserId(self.mySocket, set_id)
	if vre != 0:
	    raise GlsError(int(vre), "Error setUserId")
 
#int finishHandShake(GLSSock* myGLSSocket);

    def finishHandShake(self):
	lfinishHandShake = self.library.finishHandShake
	lfinishHandShake.argtypes = [c_void_p]
	vre = lfinishHandShake(self.mySocket)
	if vre != 0:
	    raise GlsError(int(vre), "Error finishHandShake")
	    
#int addRootCertificate(GLSSock* myGLSSocket, const char* cert);

    def addRootCertificate(self, cert):
	laddRoot = self.library.addRootCertificate
	laddRoot.argtypes = [c_void_p, c_char_p]
	co_cert = c_char_p(cert)
	vre = laddRoot(self.mySocket, co_cert)
	if vre != 0:
	    raise GlsError(int(vre), "Error addRootCertificate")

# int addRootCertificateFromFile(GLSSock* myGLSSocket, const char* certFile);

    def addRootCertificateFromFile(self, certFile):
	laddRootFile = self.library.addRootCertificateFromFile
	laddRootFile.argtypes = [c_void_p, c_char_p]
	co_certFile = c_char_p(certFile)
	vre = laddRootFile(self.mySocket, co_certFile)
	if vre != 0:
	    raise GlsError(int(vre), "Error addRootCertificateFromFile")

# int addToCrl(GLSSock* myGLSSocket, const char* serial);

    def addToCrl(self, serial):
	laddToCrl = self.library.addToCrl
	laddToCrl.argtypes = [c_void_p, c_char_p]
	co_serial = c_char_p(serial)
	vre = laddToCrl(self.mySocket, co_serial)
	if vre != 0:
	    raise GlsError(int(vre), "Error addToCrl")


class GlsError(Exception):
    
    def __init__(self, number, value):
	self.parameter = value
	self.numError = number
	
    def __str__(self):
	return repr(self.parameter)

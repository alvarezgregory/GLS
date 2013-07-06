/*
 *  GLS.h
 *
 *  Goswell Layer Security Project
 *
 *  Created by Grégory ALVAREZ (greg@goswell.net) on 03/11/11.
 *  Copyright (c) 2012 Goswell.
 *
 *  This library is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or (at
 *  your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307,
 *  USA.
 *
 */

#ifndef GLS_h
#define GLS_h

/*
 *
 *  CONFIGURATION
 *
 */

/*
 * Choose the OS for the compilation
 * it will be implemented in the make file on a next release
 * works fine on Linux and OSX, I didn't try it on windows.
 */

#define linux
/* #define win32 */
/* #define osx */
/* #define ios */

/* Already implemented on the make file - leave commented */
/* Debug mode - Make debug */
/*#define GLS_DEBUG_MODE_ENABLE*/
/* Benchmark - Make bench */
/*#define GLS_DEBUG_TIME_MODE_ENABLE*/

/*
 *
 *  END CONFIGURATION
 *
 */

#include <netinet/in.h>

/* Compilation on iOS */
#if defined (ios)
#include "gcrypt.h"
#else
#include "gcrypt.h"
#endif

#include <pthread.h>
#include <netdb.h>
typedef struct sockaddr_in SOCKADDR_IN;
typedef unsigned char byte;

/* Type of connexion */
#define GLS_CONNEXION_STANDARD 1
#define GLS_CONNEXION_REGISTER 2

/*
 * Error abstraction make easier background
 * API modification without interfering with
 * the user (he will not have to modify is
 * application).
 */

/* Standard socket errors */
#define GLS_ERROR_ACCES -1
#define GLS_ERROR_PERM -2
#define GLS_ERROR_ADDRINUSE -3
#define GLS_ERROR_AFNOSUPPORT -4
#define GLS_ERROR_AGAIN -5
#define GLS_ERROR_ALREADY -6
#define GLS_ERROR_BADF -7
#define GLS_ERROR_CONNREFUSED -8
#define GLS_ERROR_FAULT -9
#define GLS_ERROR_INPROGRESS -10
#define GLS_ERROR_INTR -11
#define GLS_ERROR_ISCONN -12
#define GLS_ERROR_NETUNREACH -13
#define GLS_ERROR_NOTSOCK -14
#define GLS_ERROR_TIMEDOUT -15

#define GLS_ERROR_AI_ADDRFAMILY -16
#define GLS_ERROR_AI_AGAIN -17
#define GLS_ERROR_AI_BADFLAGS -18
#define GLS_ERROR_AI_FAIL -19
#define GLS_ERROR_AI_FAMILY -20
#define GLS_ERROR_AI_MEMORY -21
#define GLS_ERROR_AI_NODATA -22
#define GLS_ERROR_AI_NONAME -23
#define GLS_ERROR_AI_SERVICE -24
#define GLS_ERROR_AI_SOCKTYPE -25
#define GLS_ERROR_AI_SYSTEM -26

#define GLS_ERROR_WOULDBLOCK -27
#define GLS_ERROR_CONNRESET -28
#define GLS_ERROR_DESTADDRREQ -29
#define GLS_ERROR_INVAL -30
#define GLS_ERROR_MSGSIZE -31
#define GLS_ERROR_NOBUFS -32
#define GLS_ERROR_NOMEM -33
#define GLS_ERROR_NOTCONN -34
#define GLS_ERROR_OPNOTSUPP -35
#define GLS_ERROR_PIPE -36

#define GLS_ERROR_CONNABORTED -37
#define GLS_ERROR_MFILE -38
#define GLS_ERROR_NFILE -39
#define GLS_ERROR_PROTO -40
#define GLS_ERROR_NOSR -41
#define GLS_ERROR_SOCKTNOSUPPORT -42
#define GLS_ERROR_PROTONOSUPPORT -43

#define GLS_ERROR_ADDRNOTAVAIL -44
#define GLS_ERROR_ISDIR -45
#define GLS_ERROR_IO -46
#define GLS_ERROR_LOOP -47
#define GLS_ERROR_NAMETOOLONG -48
#define GLS_ERROR_NOENT -49
#define GLS_ERROR_NOTDIR -50
#define GLS_ERROR_ROFS -51
#define GLS_ERROR_HOSTDOWN - 52

/* GLS errors */
#define GLS_ERROR_USERNOTCONF -146
#define GLS_ERROR_NOPASSWD -147
#define GLS_ERROR_UNKNOWN -148
#define GLS_ERROR_NOMESSAGE -149
#define GLS_ERROR_CRYPTO -150
#define GLS_ERROR_MAC -151
#define GLS_ERROR_IVDESYNC -152
#define GLS_ERROR_BADPASSWD -153
#define GLS_ERROR_BADSERVERCERT -154
#define GLS_ERROR_VERSION -155
#define GLS_ERROR_TOMANYKEY -156
#define GLS_ERROR_BADSIZEKEY -157
#define GLS_ERROR_BASE64 -158
#define GLS_ERROR_ASN1 -159
#define GLS_ERROR_NOCERT -160
#define GLS_ERROR_BADROOTCERT -161
#define GLS_ERROR_NOFILE -162
#define GLS_ERROR_REGISTERREFUSED -163
#define GLS_ERROR_BADSIZE -164



/*
 * Structure of the GLS socket
 */
struct glsSockStr {

    /* network variables */
    int m_sock;
    struct addrinfo *m_infoConnexion;
    struct sockaddr *m_infoClient;

    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    int m_isServeur;
    #endif

    /* state configuration variables */
    int m_isSocketConfig;
    int m_isHandShakeFinish;
    int m_isCryptoKey;
    int m_isHandlerInit;
    int m_isUserConfig;

    /* encryption keys */
    byte *m_key1;
    byte *m_key2;
    byte* (*m_keys);
    int m_sizeKeys;

    /* Initialisation vectors */
    byte m_iv1[16];
    byte m_iv2[16];
    byte m_iv3[16];
    byte m_iv4[16];

    /* Encryption handlers from libgcrypt */
    gcry_cipher_hd_t m_serpentHandlerCTS;
    gcry_cipher_hd_t m_twofishHandlerCTS;
    gcry_cipher_hd_t m_serpentHandlerECB;
    gcry_cipher_hd_t m_twofishHandlerECB;

    /* State connexion variables */
    byte *m_idUser;
    int m_sizeIdUser;
    byte *m_messageHelloEncrypt;
    int m_sizeMessageHelloEncrypt;
    int m_connexionType;

    /* Mutex */
    pthread_mutex_t m_mutexRecvPacket;
    pthread_mutex_t m_mutexSendPacket;
    pthread_mutex_t m_mutexGlsSend;
    pthread_mutex_t m_mutexGlsRecv;

    /* Certificat */
    byte* m_certRoot;
    int m_certRootSize;
    byte* m_publicCert;
    int m_publicCertSize;
    byte* m_privateKey;
    int m_privateKeySize;

    /* CRL */
    byte* (*m_crl);
    int m_sizeCrl;

    /* Message Register */
    byte* m_messageRegister;
    int m_sizeMessageRegister;

};

/*
 * GLSServer socket definition
 */
struct glsServerStr {

    int m_sock;
    int sock_err;
    int isServer;
    int secureMem;
    int sizeMem;
    struct addrinfo *res;

    /* Certificate */
    char *m_publicKey;
    char *m_privateKey;
    char *m_publicKeyFile;
    char *m_privateKeyFile;

};

/* Struct GLS */
typedef struct glsSockStr GLSSock;
typedef struct glsServerStr GLSServerSock;




/*
 * GLSSocket use libgcrypt, if your application use it too
 * and you want secure memory don't forget to initialise the
 * library from your application and add 16k of memory for GLS.
 *
 * By default GLSSocket() use secure memory, if you want more
 * memory or want to disable it use GLSSocketSecure().
 *
 * You are responsible for deallocating the socket with freeGLSSocket().
 *
 * Return a pointer to the Socket
 */
GLSSock* GLSSocket();
GLSSock* GLSSocketSecure(const int secureMem, const int sizeMem);

/*
 * Close the connexion and free the GLS socket
 */
void freeGLSSocket(GLSSock* myGLSSocket);

/*
 * Connect the socket to a GLS Server, you need to add
 * an encryption key first with addKey() and an id with
 * setUserId().
 *
 * Return 0 for success, a negative number for an error.
 */
int connexion(GLSSock* myGLSSocket, const char* address, const char* port);

/*
 * Send an register message to a GLS Server. You need to
 * add a root certificate first with addRootCertificate().
 *
 * Return 0 for success, a negative number for an error.
 */
int sendRegister(GLSSock* myGLSSocket, const char* address, const char* port, const byte* buffer, const int sizeBuffer);

/*
 * For Server - Get the register message send by sendRegister().
 *
 * You are responsible for deallocating message with free().
 *
 * Return the message's size or a negative number for an error.
 */
int getRegisterMessage(GLSSock* myGLSSocket, byte** message);

/*
 * Send a message using the secure connexion. You can use this function
 * on a thread.
 *
 * Return the message's size send or a negative number for an error.
 */
int glsSend(GLSSock* myGLSSocket, const byte* buffer, const int sizeBuffer);

/*
 * Wait for a message, you can use this function on a thread.
 *
 * You are responsible for deallocating the buffer with free().
 *
 * Return the size of the received message or a negative number for an error.
 */
int glsRecv(GLSSock* myGLSSocket, byte** buffer);

/*
 * Add user's password, you can have 10 different password.
 * If the password is already in SHA-512, use the function
 * with isSha = 1. Maximum password's length => 60 bytes.
 *
 * Return 0 for success, a negative number for an error.
 */
int addKey(GLSSock* myGLSSocket, const char* key, int isSha);

/*
 * Remove all the key add by addKey().
 *
 * Return 0 for success, a negative number for an error.
 */
int clearKey(GLSSock* myGLSSocket);

/*
 * Return the connexion's type or a negative number for an error :
 * GLS_CONNEXION_STANDARD
 * GLS_CONNEXION_REGISTER
 */
int getTypeConnexion(GLSSock* myGLSSocket);

/*
 * Return the user's id.
 *
 * You are responsible for deallocating userId.
 *
 * Return the char's size or a negative number for an error.
 */
int getUserId(GLSSock* myGLSSocket, char** userId);

/*
 * Set the user's id.
 *
 * Return 0 for success, a negative number for an error.
 */
int setUserId(GLSSock* myGLSSocket, const char* userId);

/*
 * For Server - Finish the handshake for the connexion, you can
 * after use glsRecv() and glsSend().
 *
 * Return 0 for success, a negative number for an error.
 */
int finishHandShake(GLSSock* myGLSSocket);

/*
 * Add a root certificate for the Register connexion. PEM format.
 * Return 0 for success, a negative number for an error.
 */
int addRootCertificate(GLSSock* myGLSSocket, const char* cert);

/*
 * Add a root certificate from a file for the Register connexion. PEM format.
 * Return 0 for success, a negative number for an error.
 */
int addRootCertificateFromFile(GLSSock* myGLSSocket, const char* certFile);

/*
 * Add a serial number to the CRL.
 * Return 0 for success, a negative number for an error.
 */
int addToCrl(GLSSock* myGLSSocket, const char* serial);



/*
 * GLSServer use libgcrypt, if your application use it too
 * and you want secure memory don't forget to initialize the
 * library from your application and add 16k of memory for GLS.
 *
 * By default GLSServer() use secure memory, if you want more
 * memory or want to disable it use GLSServerSecure().
 *
 * You are responsible for deallocating the socket with freeGLSServer().
 *
 * Return a pointer to the Socket Server.
 */
GLSServerSock* GLSServer();
GLSServerSock* GLSServerSecure(const int secureMem, const int sizeMem);

/*
 * Close the connexion and free the GLS server socket
 */
void freeGLSServer(GLSServerSock* myGLSServerSock);

/*
 * Initialize the server for listening on a port. waitQueue is the number of waiting list. isReuse force
 * the socket to listen on an address already used (for UNIX network problem).
 *
 * Return 0 for success, a negative number for an error.
 */
int initServer(GLSServerSock* myGLSServerSock, const char *port, const int waitQueue, const int isReuse);

/*
 * Wait for a connexion and allocate a GLSSock on myClient.
 * You are responsible for deallocating the socket with freeGLSSocket().
 *
 * Return 0 for success, a negative number for an error.
 */
int waitForClient(GLSServerSock* myGLSServerSock, GLSSock** myClient);

/*
 * Add the server certificate from a file for the Register connexion. PEM format.
 * Return 0 for success, a negative number for an error.
 */
int addServerCertificate(GLSServerSock* myGLSServerSock, const char* publicCert, const char* privateKey);
int addServerCertificateFromFile(GLSServerSock* myGLSServerSock, const char* publicCertFile, const char* privateKeyFile);


#endif

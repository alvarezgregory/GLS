/*
 *  GLSHeaders.h
 *
 *  Goswell Layer Security Project
 *
 *  Created by Grégory ALVAREZ (greg@goswell.net) on 01/05/12.
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


#ifndef GLSHeader_h
#define GLSHeader_h

#include "libgls.h"

/* Compilation on Windows */
#if defined (win32)

#include <winsock2.h>
#include <windows.h> 
typedef int socklen_t;

/* Compilation on Linux */
#elif defined (linux)

#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
typedef struct sockaddr SOCKADDR;
#define closesocket(s) close(s)

/* Compilation on OS X */
#elif defined (osx)

#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
typedef struct sockaddr SOCKADDR;
#define closesocket(s) close(s)

/* Compilation on OS X */
#elif defined (ios)

#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
typedef struct sockaddr SOCKADDR;
#define closesocket(s) close(s)

#endif

/* Standard C files */
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>

/* Library ASN.1 */
#if defined (ios)
#include "libtasn1.h"
#else
#include "libtasn1.h"
#endif

/* Type of message for getTypeGLS() */
#define GLS_TYPE_HELLO 1
#define GLS_TYPE_HELLO_SERVER 2
#define GLS_TYPE_REGISTER 3
#define GLS_TYPE_REGISTER_WITH_INFO 4
#define GLS_TYPE_REGISTER_SERVER 5
#define GLS_TYPE_REGISTER_SERVER_OK 6
#define GLS_TYPE_ERROR 7

/* 
 * Use of headers for sending and receiving messages. 
 * The size of the message is added at the begining of
 * the packet to have a control under the network flux.
 */
#define GLS_HEADER_PACKET

/* Size maximum of a network packet, encoded in 2 bytes (GLS_SIZE_PACKET < 65535) */
#define GLS_SIZE_PACKET 60000

/* Timeout between send & recv packet */
#define GLS_TIMEOUT_PACKET 3

/* Gcrypt library */
#define GCRYPT_NO_DEPRECATED
GCRY_THREAD_OPTION_PTHREAD_IMPL;

/* Base 64 */
#define B64(_)          \
((_) == 'A' ? 0       \
: (_) == 'B' ? 1       \
: (_) == 'C' ? 2       \
: (_) == 'D' ? 3       \
: (_) == 'E' ? 4       \
: (_) == 'F' ? 5       \
: (_) == 'G' ? 6       \
: (_) == 'H' ? 7       \
: (_) == 'I' ? 8       \
: (_) == 'J' ? 9       \
: (_) == 'K' ? 10        \
: (_) == 'L' ? 11        \
: (_) == 'M' ? 12        \
: (_) == 'N' ? 13        \
: (_) == 'O' ? 14        \
: (_) == 'P' ? 15        \
: (_) == 'Q' ? 16        \
: (_) == 'R' ? 17        \
: (_) == 'S' ? 18        \
: (_) == 'T' ? 19        \
: (_) == 'U' ? 20        \
: (_) == 'V' ? 21        \
: (_) == 'W' ? 22        \
: (_) == 'X' ? 23        \
: (_) == 'Y' ? 24        \
: (_) == 'Z' ? 25        \
: (_) == 'a' ? 26        \
: (_) == 'b' ? 27        \
: (_) == 'c' ? 28        \
: (_) == 'd' ? 29        \
: (_) == 'e' ? 30        \
: (_) == 'f' ? 31        \
: (_) == 'g' ? 32        \
: (_) == 'h' ? 33        \
: (_) == 'i' ? 34        \
: (_) == 'j' ? 35        \
: (_) == 'k' ? 36        \
: (_) == 'l' ? 37        \
: (_) == 'm' ? 38        \
: (_) == 'n' ? 39        \
: (_) == 'o' ? 40        \
: (_) == 'p' ? 41        \
: (_) == 'q' ? 42        \
: (_) == 'r' ? 43        \
: (_) == 's' ? 44        \
: (_) == 't' ? 45        \
: (_) == 'u' ? 46        \
: (_) == 'v' ? 47        \
: (_) == 'w' ? 48        \
: (_) == 'x' ? 49        \
: (_) == 'y' ? 50        \
: (_) == 'z' ? 51        \
: (_) == '0' ? 52        \
: (_) == '1' ? 53        \
: (_) == '2' ? 54        \
: (_) == '3' ? 55        \
: (_) == '4' ? 56        \
: (_) == '5' ? 57        \
: (_) == '6' ? 58        \
: (_) == '7' ? 59        \
: (_) == '8' ? 60        \
: (_) == '9' ? 61        \
: (_) == '+' ? 62        \
: (_) == '/' ? 63        \
: -1)


int _acceptConnexion(GLSSock* myGLSSocket, const int socketServer);

/* Encryption / Decryption function for standard connexion */
int firstEncrypt(GLSSock* myGLSSocket, const byte* plaintext, const int size, byte** cypherText);
int firstDecrypt(GLSSock* myGLSSocket, const byte* cipherText, const int size, byte** plainText);
int allEncrypt(GLSSock* myGLSSocket, const byte* plaintext, const int size, byte** cypherText);
int allDecrypt(GLSSock* myGLSSocket, const byte* cipherText, const int size, byte** plainText);

/* Send and receive packet from network */
int sendPacket(GLSSock* myGLSSocket, const byte* buffer, const int size);
int recvPacket(GLSSock* myGLSSocket, byte** buffer, const int withTimeout);

/* GLS message parsing function */
int getTypeGLS(const byte* message, const int size);
int getVersionGLS(const byte* message, const int size);
int setIdGLS(GLSSock* myGLSSocket, const byte* message, const int size);
int getNumError(const byte* message, const int size);

/* Key management function */
int addKeyToArray(const byte* key, byte** (*array), int* size);

/* Encryption initialisation function */
int getIV(byte* iv);
int initHandler(GLSSock* myGLSSocket);

/* Fonction recv() and send() with timeout and header */
ssize_t recvWithTimeout(const int socket, byte *buffer, const ssize_t size, const int flag, const int timeout);
ssize_t	sendWithHeader(const int socket, const byte *buffer, const ssize_t size, const int flag);
ssize_t	recvWithHeader(const int socket, byte *buffer, const size_t size, const int flag);

/* Certificate management function */
int base64Decode(byte* buffer, int bufferSize, const byte* src, int srcSize);
int pemToAsn(const byte *pem, const int pemLen, byte** asn);
int getPublicRsaFromDer(const byte *der, const int sizeDerInBits, gcry_sexp_t *publicKey);
int byteToHex(const byte *buffer, const int sizeBuffer, char **hex);
int charFromFile(const char* fileName, char **content);
int _encryptWithPK(const byte *cert, const int certLen, const byte* plainText, const int sizePlainText, byte** cypherText);
int _decryptWithPK(GLSSock* myGLSSocket, const byte* cipherText, const int sizeCipherText, byte** plainText);
int getModulusSize(const byte *cert, const int certLen);
int checkCertificate(GLSSock* myGLSSocket, const byte *cert, const int certLen);
int encryptWithPK(const byte *cert, const int certLen, const byte* plainText, const int sizePlainText, byte** cypherText);
int decryptWithPK(GLSSock* myGLSSocket, const byte* cipherText, const int sizeCipherText, byte** plainText);
int getPrivateRsaFromDer(const byte *der, const int sizeDer, gcry_sexp_t *privateKey);
int _addServerCertificate(GLSSock* myGLSSocket, const char* publicCert, const char* privateKey);
int _addServerCertificateFromFile(GLSSock* myGLSSocket, const char* publicCertFileName, const char* privateKeyFileName);
                   
#endif

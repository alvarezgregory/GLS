/*
 *  GLSServer.c
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

#include "GLSHeaders.h"




/*-------------------------------------------------------
 
            GLS Server Socket constructor
 
 ---------------------------------------------------------*/

GLSServerSock* GLSServer() {
    
    return GLSServerSecure(0, 0);
    
}

GLSServerSock* GLSServerSecure(const int secureMem, const int sizeMem){
    
    GLSServerSock* myGLSServerSock = malloc(sizeof(GLSServerSock));
    
    if (myGLSServerSock != NULL) {
        
        /* variable initialisation */
        myGLSServerSock->sock_err = 0;
        myGLSServerSock->m_sock = 0;
        myGLSServerSock->isServer = 0;
        myGLSServerSock->res = 0;
        myGLSServerSock->secureMem = secureMem;
        myGLSServerSock->sizeMem = sizeMem;
        myGLSServerSock->m_privateKey = 0;
        myGLSServerSock->m_privateKeyFile = 0;
        myGLSServerSock->m_publicKey = 0;
        myGLSServerSock->m_publicKeyFile = 0;
        
    }
    
    return myGLSServerSock;
    
}




/*-------------------------------------------------------
 
            GLS Server Socket destructor
 
 ---------------------------------------------------------*/

void freeGLSServer(GLSServerSock* myGLSServerSock){
    
    /* We close the server */
    shutdown(myGLSServerSock->m_sock, 2);
    closesocket(myGLSServerSock->m_sock);
    
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Closing socket serveur.\n");
    #endif
    
    /* Freeing addrinfo */
    if (myGLSServerSock->res != NULL) {
        
        freeaddrinfo(myGLSServerSock->res);
        myGLSServerSock->res = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete infoConnexion (res) OK\n");
        #endif
        
    }
    
    /* Freeing the public key  */
    if (myGLSServerSock->m_publicKey != NULL) {
        
        free(myGLSServerSock->m_publicKey);
        myGLSServerSock->m_publicKey = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete m_publicKey OK\n");
        #endif
        
    }
    
    /* Freeing the public key file path */
    if (myGLSServerSock->m_publicKeyFile != NULL) {
        
        free(myGLSServerSock->m_publicKeyFile);
        myGLSServerSock->m_publicKeyFile = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete m_publicKeyFile OK\n");
        #endif
        
    }
    
    /* Freeing the private key */
    if (myGLSServerSock->m_privateKey != NULL) {
        
        free(myGLSServerSock->m_privateKey);
        myGLSServerSock->m_privateKey = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete m_privateKey OK\n");
        #endif
        
    }
    
    /* Freeing the private key file path */
    if (myGLSServerSock->m_privateKeyFile != NULL) {
        
        free(myGLSServerSock->m_privateKeyFile);
        myGLSServerSock->m_privateKeyFile = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete m_publicKey OK\n");
        #endif
        
    }
    
    /* Compilation on Windows */
    #if defined (WIN32)
    
    WSACleanup();
    
    #endif
    
    /* Freeing GLSServerSock */
    free(myGLSServerSock);
     
        
}




/*-------------------------------------------------------
 
            GLS Server init
 
 ---------------------------------------------------------*/

int initServer(GLSServerSock* myGLSServerSock, const char *port, const int waitQueue, const int isReuse){
    
    /* Arguments check */
    if (port == NULL || waitQueue < 0) {
        
        return GLS_ERROR_INVAL;
        
    }
    else {
        
        myGLSServerSock->isServer = 1;
    
    }
    
    /* Compilation on Windows */
    #if defined (WIN32)
    WSADATA WSAData;
    int erreur = WSAStartup(MAKEWORD(2,2), &WSAData);
    #else
    int erreur = 0;
    #endif
    
    /* If windows socket works fine */
    if(erreur == 0) {
        
        /* Server context creation */
        struct addrinfo hints;
        
        /* first, load up address structs with getaddrinfo(): */
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;  /* use IPv4 or IPv6, whichever */
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;     /* fill in my IP for me */
        
        /* fill in addrinfo */
        erreur = getaddrinfo(NULL, port, &hints, &myGLSServerSock->res);
        if (erreur != 0){
            
            /* if any error occurs during the addrinfo configuration */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Impossible to bind the socket.\n");
            #endif
            
            /* return getaddrinfo error */
            switch (erreur) {
                    
                case EAI_ADDRFAMILY :
                    return GLS_ERROR_AI_ADDRFAMILY;
                    break;
                    
                case EAI_AGAIN :
                    return GLS_ERROR_AI_AGAIN;
                    break;
                    
                case EAI_BADFLAGS :
                    return GLS_ERROR_AI_BADFLAGS;
                    break;
                    
                case EAI_FAIL :
                    return GLS_ERROR_AI_FAIL;
                    break;
                    
                case EAI_FAMILY :
                    return GLS_ERROR_AI_FAMILY;
                    break;
                    
                case EAI_MEMORY :
                    return GLS_ERROR_AI_MEMORY;
                    break;
                    
                case EAI_NODATA :
                    return GLS_ERROR_AI_NODATA;
                    break;
                    
                case EAI_NONAME :
                    return GLS_ERROR_AI_NONAME;
                    break;
                    
                case EAI_SERVICE :
                    return GLS_ERROR_AI_SERVICE;
                    break;
                    
                case EAI_SOCKTYPE :
                    return GLS_ERROR_AI_SOCKTYPE;
                    break;
                    
                default:
                    return GLS_ERROR_AI_SYSTEM;
                    break;
                    
            }
            
        }
        
        /* socket creation */
        myGLSServerSock->m_sock = socket(myGLSServerSock->res->ai_family, myGLSServerSock->res->ai_socktype, myGLSServerSock->res->ai_protocol);
        
        /* Forcing the listening on the port (TIME_WAIT state) with SO_REUSEADDR */
        if(isReuse == 1) {
        
            int optval = 1;
            setsockopt(myGLSServerSock->m_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        
        }
        
        /* If valid socket, we configure it with addrinfo */
        if(myGLSServerSock->m_sock != INVALID_SOCKET)
        {
            
            /* Bind socket with addrinfo  */
            myGLSServerSock->sock_err = bind(myGLSServerSock->m_sock, myGLSServerSock->res->ai_addr, myGLSServerSock->res->ai_addrlen);
                        
            /* if sock is bind */
            if(myGLSServerSock->sock_err != SOCKET_ERROR)
            {
                
                /* connexion listening (mode server) */
                myGLSServerSock->sock_err = listen(myGLSServerSock->m_sock, waitQueue);
                
                /* if we have an error with listen */
                if (myGLSServerSock->sock_err == SOCKET_ERROR) {
                    
                    /* getting error */
                    int errorListen = errno;
                    
                    /* debug only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("Impossible to listen on the socket.\n");
                    printf("Error Listen : %d\n", errorListen);
                    #endif
                    
                    /* Return bind error */
                    switch (errorListen) {
                            
                        case EADDRINUSE :
                            return GLS_ERROR_ADDRINUSE;
                            break;
                            
                        case ENOTSOCK :
                            return GLS_ERROR_NOTSOCK;
                            break;
                            
                        case EOPNOTSUPP :
                            return GLS_ERROR_OPNOTSUPP;
                            break;
                            
                        case EBADF :
                            return GLS_ERROR_BADF;
                            break;
                            
                        default:
                            return GLS_ERROR_UNKNOWN;
                            break;
                            
                    }
                    
                }
                
            }
            else {
                
                /* getting error */
                int errorBind = errno;
                
                /* debug only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Impossible to bind the socket.\n");
                printf("Error Bind : %d\n", errorBind);
                #endif
                
                /* Return bind error */
                switch (errorBind) {
                        
                    case EADDRINUSE :
                        return GLS_ERROR_ADDRINUSE;
                        break;
                        
                    case EADDRNOTAVAIL :
                        return GLS_ERROR_ADDRNOTAVAIL;
                        break;
                        
                    case EAFNOSUPPORT :
                        return GLS_ERROR_AFNOSUPPORT;
                        break;
                        
                    case EBADF :
                        return GLS_ERROR_BADF;
                        break;
                        
                    case EINVAL :
                        return GLS_ERROR_INVAL;
                        break;
                        
                    case ENOTSOCK :
                        return GLS_ERROR_NOTSOCK;
                        break;
                        
                    case EOPNOTSUPP :
                        return GLS_ERROR_OPNOTSUPP;
                        break;
                        
                    case EACCES :
                        return GLS_ERROR_ACCES;
                        break;
                        
                    case EDESTADDRREQ :
                        return GLS_ERROR_DESTADDRREQ;
                        break;
                        
                    case EISDIR :
                        return GLS_ERROR_ISDIR;
                        break;
                        
                    case EIO :
                        return GLS_ERROR_IO;
                        break;
                        
                    case ELOOP :
                        return GLS_ERROR_LOOP;
                        break;
                        
                    case ENAMETOOLONG :
                        return GLS_ERROR_NAMETOOLONG;
                        break;
                        
                    case ENOENT :
                        return GLS_ERROR_NOENT;
                        break;
                        
                    case ENOTDIR :
                        return GLS_ERROR_NOTDIR;
                        break;
                        
                    case EROFS :
                        return GLS_ERROR_ROFS;
                        break;
                        
                    case EISCONN :
                        return GLS_ERROR_ISCONN;
                        break;
                        
                    case ENOBUFS :
                        return GLS_ERROR_NOBUFS;
                        break;
                        
                    default:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                }
                
            }
            
        }
        else {

            /* debug only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Impossible to create the socket\n");
            #endif
            
            return GLS_ERROR_SOCKTNOSUPPORT;
        
        }
    
    }
    else {
        
        /*
         *  Windows Error handlling
         *  Actually not implemented -> next release
         */
        
        return GLS_ERROR_UNKNOWN;
        
    }
    
    return 0;
    
}




/*-------------------------------------------------------
 
              Listening Function (Server)
 
 ---------------------------------------------------------*/

int waitForClient(GLSServerSock* myGLSServerSock, GLSSock** myClient) {
    
    if (myGLSServerSock->isServer == 1) {
        
        if(myGLSServerSock->m_sock != INVALID_SOCKET && myGLSServerSock->sock_err != SOCKET_ERROR) {
            
            int error = -1;
            *myClient = 0;
            
            while(error != 0) {
                
                if (*myClient != NULL) {
                    
                    freeGLSSocket(*myClient);
                
                }
                
                *myClient = 0;
                *myClient = GLSSocketSecure(myGLSServerSock->secureMem, myGLSServerSock->sizeMem);
                
                if (*myClient == NULL) {
                    
                    return GLS_ERROR_NOMEM;
                
                }
                
                /* adding server certificate */
                if (myGLSServerSock->m_publicKey != NULL && myGLSServerSock->m_privateKey != NULL) {
                    
                    _addServerCertificate(*myClient, myGLSServerSock->m_publicKey, myGLSServerSock->m_privateKey);
                    
                }
                else if(myGLSServerSock->m_publicKeyFile != NULL && myGLSServerSock->m_privateKeyFile != NULL) {
                    
                    _addServerCertificateFromFile(*myClient, myGLSServerSock->m_publicKeyFile, myGLSServerSock->m_privateKeyFile);
                    
                }
                
                error = _acceptConnexion(*myClient, myGLSServerSock->m_sock);
                
            }
            
        }
        else {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No socket for listening.\n");
            #endif
            
            return GLS_ERROR_NOTSOCK;
            
        }
        
    }
    else {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Server not init.\n");
        #endif
        
        return GLS_ERROR_NOTSOCK;
        
    }
    
    return 0;

}



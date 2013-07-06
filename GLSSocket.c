/*
 *  GLSSocket.c
 *
 *  Goswell Layer Security Project
 *
 *  Created by Grégory ALVAREZ (greg@goswell.net) on 18/02/12.
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
 
 Create a GLS socket
 
 ---------------------------------------------------------*/

/* Global variable for gcrypt */
int m_isCryptoInit = 0;

GLSSock* GLSSocket() {
    
    return GLSSocketSecure(1, 160000);
    
}

GLSSock* GLSSocketSecure(const int secureMem, const int sizeMem){
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### GLSSocket() Start ###\n");
    #endif
    
    GLSSock* myGLSSocket = malloc(sizeof(GLSSock));
    
    /* If no memory return NULL */
    if (myGLSSocket == NULL) return myGLSSocket;
    
    /* Variable init */
    myGLSSocket->m_sock = 0;
    myGLSSocket->m_isSocketConfig = 0;
    myGLSSocket->m_isCryptoKey = 0;
    myGLSSocket->m_isHandlerInit = 0;
    myGLSSocket->m_isUserConfig = 0;
    myGLSSocket->m_connexionType = 0;
    myGLSSocket->m_messageHelloEncrypt = 0;
    myGLSSocket->m_idUser = 0;
    myGLSSocket->m_sizeIdUser = 0;
    myGLSSocket->m_sizeMessageHelloEncrypt = 0;
    myGLSSocket->m_isHandShakeFinish = 0;
    myGLSSocket->m_sizeKeys = 0;
    myGLSSocket->m_keys = 0;
    myGLSSocket->m_infoClient = 0;
    myGLSSocket->m_infoConnexion = 0;
    myGLSSocket->m_certRoot = 0;
    myGLSSocket->m_certRootSize = 0;
    myGLSSocket->m_publicCert = 0;
    myGLSSocket->m_publicCertSize = 0;
    myGLSSocket->m_privateKey = 0;
    myGLSSocket->m_privateKeySize = 0;
    myGLSSocket->m_crl = 0;
    myGLSSocket->m_sizeCrl = 0;
    myGLSSocket->m_sizeMessageRegister = 0;
    myGLSSocket->m_messageRegister = 0;
    
    /* Mutexs init */
    pthread_mutex_init(&myGLSSocket->m_mutexSendPacket, NULL);
    pthread_mutex_init(&myGLSSocket->m_mutexRecvPacket, NULL);
    pthread_mutex_init(&myGLSSocket->m_mutexGlsSend, NULL);
    pthread_mutex_init(&myGLSSocket->m_mutexGlsRecv, NULL);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    myGLSSocket->m_isServeur = 0;
    #endif
    
    /* library gcrypt initialisation */
    
    if(m_isCryptoInit == 0) {
        
        /* We block other thread to prevent multiple initialisation */
        m_isCryptoInit = 1;
        
        /* 
         * In case of the library is loaded in a application who also uses libgcrypt,
         * we check if the library is already initialised 
         */
        if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {

            /* Threads management init */
            gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
            
            /* Version check should be the very first call because it
             makes sure that important subsystems are intialized. */
            if (!gcry_check_version (GCRYPT_VERSION)) {
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("libgcrypt version mismatch\n");
                #endif
                
                free(myGLSSocket);
                return 0; 
            
            }
            
            /*
             * You can activate the libgcrypt debug but very verbose 
             */
            /*
            #if defined (GLS_DEBUG_MODE_ENABLE)
            gcry_control (GCRYCTL_SET_DEBUG_FLAGS);
            #endif
            */
            
            if (secureMem == 1) {
            
                /* We don’t want to see any warnings, e.g. because we have not yet
                 parsed program options which might be used to suppress such
                 warnings. */
                gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
                
                /* ... If required, other initialization goes here.  Note that the
                 process might still be running with increased privileges and that
                 the secure memory has not been intialized.  */
                /* Allocate a pool of 16k secure memory.  This make the secure memory
                 available and also drops privileges where needed.  */
                gcry_control (GCRYCTL_INIT_SECMEM, sizeMem, 0);
                
                /* It is now okay to let Libgcrypt complain when there was/is
                 a problem with the secure memory. */
                gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Secure Memory initialized\n");
                #endif
            
            }
                
            /* ... If required, other initialization goes here.  */
            /* Tell Libgcrypt that initialization has completed. */
            gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
            
            if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("libgcrypt has not been initialized\n");
                #endif
                abort(); 
                m_isCryptoInit = 0;
                
            }
            
            /* Test libgcrypt algorithme */
            int err = gcry_control(GCRYCTL_SELFTEST);
            if (err != 0) {
                
                /* Debug only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Error %d : %s\n", err, gcry_strerror(err));
                printf("libgcrypt algo test failed\n");
                #endif
                abort(); 
                m_isCryptoInit = 0;
                
            }
            
            
        }
        
    }
    else {
        
        /* We wait for the first thread to init the libgcrypt library */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("libgcrypt has been initialized\n");
        #endif
        sleep(1);
        
    }
    
    /* Init key1 and key2 into secure memory */
    myGLSSocket->m_key1 = (byte*) gcry_malloc_secure(32);
    myGLSSocket->m_key2 = (byte*) gcry_malloc_secure(32);
    if (myGLSSocket->m_key1 == NULL || myGLSSocket->m_key2 == NULL) {
        
        /* Debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No memory - Constructor.\n");
        #endif
        
        free(myGLSSocket);
        
        return 0;
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### GLSSocket() End ###\n");
    #endif
    
    return myGLSSocket;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Add keys into an array
 
 ---------------------------------------------------------*/

int addKeyToArray(const byte* key, byte** (*array), int* size) {
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### addKeyToArray() Start ###\n");
    printf("Size = %d\n", *size);
    printf("array = %p\n\n", *array);
    printf("Key = %p\n\n", key);
    #endif
    
    /* Creating a temp array */
    byte* (*tempArray) = malloc((*size + 1) * sizeof(byte*));
    if (tempArray == NULL) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No memory - addKeyToArray.\n");
        #endif
        return GLS_ERROR_NOMEM;
        
    }
    
    /* We fill tempArray with myArray */
    int i = 0;
    for (i = 0; i < *size; i++) {
        
        tempArray[i] = (*array)[i];
        
    }
    
    /* adding key, *size +1 -1 = *size */
    tempArray[*size] = (byte*) key;
    
    /* array size + 1 */
    *size += 1;
    
    /* array swap and deleting old one */
    if(*array != NULL) free(*array);
    *array = tempArray;
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Size = %d\n", *size);
    printf("tempArray = %p\n", tempArray);
    printf("Key = %p\n", tempArray[*size - 1]);
    printf("### addKeyToArray() End ###\n\n");
    #endif
    
    return 0;
    
}




/*-------------------------------------------------------
 
 GLSSocket destructor
 
 ---------------------------------------------------------*/

void freeGLSSocket(GLSSock* myGLSSocket){
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### CloseGLSSocket() Start ###\n");
    printf("Deleting socket...\n");
    #endif
    
    /* Closing socket */
    shutdown(myGLSSocket->m_sock, SHUT_RDWR);
    closesocket(myGLSSocket->m_sock);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Socket closed OK...\n");
    #endif
    
    /* Compilation on Windows */
    #if defined (win32)
    
    WSACleanup();
    
    #endif
    
    /* Wipe keys vectors */
    if (myGLSSocket->m_isCryptoKey) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Wipe keys vectors\n");
        #endif
        
        /* Key iteration and wipe */
        int i = 0;
        for(i = 0; i < myGLSSocket->m_sizeKeys; i++)
        {
            byte* myKey = (byte*) myGLSSocket->m_keys[i];
            
            int y = 0;
            for (y = 0; y < 64; y++) {
                
                myKey[y] = 0; 
                myKey[y] = 1; 
                myKey[y] = 2; 
                
            }
            
            gcry_free(myKey);
            
        }
        
        if (myGLSSocket->m_keys != NULL) {
            
            free(myGLSSocket->m_keys);
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Free m_keys\n");
            #endif
            
        }
        
        myGLSSocket->m_isCryptoKey = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Wipe keys vectors OK\n");
        #endif
    
    }
    
    /* Wipe de key1 */
    int i = 0;
    for (i = 0; i < 32; i++) {
        myGLSSocket->m_key1[i] = 0;
        myGLSSocket->m_key1[i] = 1;
        myGLSSocket->m_key1[i] = 2;
    }
    gcry_free(myGLSSocket->m_key1);
    myGLSSocket->m_key1 = 0;
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Wiping key1\n");
    #endif
    
    /* Wipe de key2 */
    for (i = 0; i < 32; i++) {
        myGLSSocket->m_key2[i] = 0;
        myGLSSocket->m_key2[i] = 1;
        myGLSSocket->m_key2[i] = 2;
    }
    gcry_free(myGLSSocket->m_key2);
    myGLSSocket->m_key2 = 0;
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Wiping key2\n");
    #endif
    
    if (myGLSSocket->m_isHandlerInit) {
        
        /* Closing handlers */
        gcry_cipher_close(myGLSSocket->m_serpentHandlerCTS);
        gcry_cipher_close(myGLSSocket->m_twofishHandlerCTS);
        gcry_cipher_close(myGLSSocket->m_serpentHandlerECB);
        gcry_cipher_close(myGLSSocket->m_twofishHandlerECB);
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete handler OK\n");
        #endif
        
    }
    
    /* If user set */
    if (myGLSSocket->m_isUserConfig) {
        
        /* Delete userId */
        if (myGLSSocket->m_idUser != NULL) {
            
            free(myGLSSocket->m_idUser);
            myGLSSocket->m_idUser = 0;
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Delete UserId OK\n");
            #endif
            
        }
        
    }
    
    /* if encrypted hello message still in memory */
    if (myGLSSocket->m_messageHelloEncrypt != NULL) {
        
        free(myGLSSocket->m_messageHelloEncrypt);
        myGLSSocket->m_messageHelloEncrypt = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete Message Hello Encrypted OK\n");
        #endif
        
    }
    
    /* if encrypted register message still in memory */
    if (myGLSSocket->m_messageRegister != NULL) {
        
        free(myGLSSocket->m_messageRegister);
        myGLSSocket->m_messageRegister = 0;
        myGLSSocket->m_sizeMessageRegister = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete Message Register OK\n");
        #endif
        
    }
    
    /* deleting addrInfo (client mode) */
    if (myGLSSocket->m_infoConnexion != NULL) {
        
        freeaddrinfo(myGLSSocket->m_infoConnexion);
        myGLSSocket->m_infoConnexion = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete infoConnexion OK\n");
        #endif
        
    }
        
    /* Delete CRL (client mode) */
    if (myGLSSocket->m_sizeCrl > 0) {
        
        /* ID iteration and wipe wipe */
        int i = 0;
        for(i = 0; i < myGLSSocket->m_sizeCrl; i++)
        {
            byte* myKey = (byte*) myGLSSocket->m_crl[i];
            
            free(myKey);
            
        }
        
        if (myGLSSocket->m_crl != NULL) {
            
            free(myGLSSocket->m_crl);
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Free m_crl\n");
            #endif
            
        }
        
        myGLSSocket->m_sizeCrl = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete CRL OK\n");
        #endif
        
    }
    
    /* Freeing root certificate */
    if (myGLSSocket->m_certRoot != NULL) {
        
        free(myGLSSocket->m_certRoot);
        myGLSSocket->m_certRoot = 0;
        myGLSSocket->m_certRootSize = 0;
    
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete Root Certificate OK\n");
        #endif
        
    }

    /* Freeing public certificate */
    if (myGLSSocket->m_publicCert != NULL) {
        
        free(myGLSSocket->m_publicCert);
        myGLSSocket->m_publicCert = 0;
        myGLSSocket->m_publicCertSize = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete Public Certificate OK\n");
        #endif
        
    }
    
    /* Freeing private key */
    if (myGLSSocket->m_privateKey != NULL) {
        
        gcry_free(myGLSSocket->m_privateKey);
        myGLSSocket->m_privateKey = 0;
        myGLSSocket->m_privateKeySize = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Delete Private Key OK\n");
        #endif
        
    }
    
    /* Freeing GLSSock */
    free(myGLSSocket);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### ~GLSSocket() End ###\n\n");
    #endif
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Return the GLS message type :
 
 GLS_TYPE_HELLO
 GLS_TYPE_HELLO_WITH_CERT
 GLS_TYPE_HELLO_SERVER
 GLS_TYPE_REGISTER
 GLS_TYPE_REGISTER_WITH_INFO
 GLS_TYPE_REGISTER_SERVER
 GLS_TYPE_REGISTER_SERVER_OK
 GLS_TYPE_ERROR (=> not negatif)
 
 erreur -> negative number
 
 ---------------------------------------------------------*/

int getTypeGLS(const byte* message, const int size) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getTypeGLS() Start ###\n");
    #endif
    
    /* check argument */
    if (message == NULL) return GLS_ERROR_UNKNOWN;
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Message : ");
    int di = 0;
    for (di = 0; di < size; di++) {
        printf("%c", message[di]);
    }
    printf("\n");
    #endif
    
    /* Test hello message */
    /* Test minimum hello message size */
    if (size >= 17) {
    
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Test Hello Message\n");
        #endif
        
        /* Getting Hello message part */
        byte messageHello[5];
        char hello[6] = "HELLO";
        int i = 0;
        for (i = 0; i < 5; i++) {
            
            /* putting message in uppercase */
            messageHello[i] = toupper(message[i + 8]); 
            
        }        
        /* bytes comparing */
        i = 0;
        int z = 0;
        for (z = 0; z < 5; z++) {
            
            if (messageHello[z] == hello[z]) i++;
            else break;
            
        }
        
        /* If message is hello type, checking for hello server Type */
        if (i == 5) {
            
            /* If message size is the same as Hello Server type */
            if (size == 22) {
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Test Hello Server Message\n");
                #endif
                
                /* Getting Server message part */
                byte messageServer[6];
                char server[7] = "SERVER";
                int i = 0;
                for (i = 0; i < 6; i++) {
                    
                    /* in uppercase */
                    messageServer[i] = toupper(message[i + 14]); 
                    
                }     
                
                /* bytes check */
                int y = 0;
                z = 0;
                for(y = 0; y < 6; y++) {
                    
                    if(messageServer[y] == server[y]) z++;
                    
                }
                /* If message is HelloServer, testing
                 * CR (13) + LF (10) at the end  
                 */
                if (z == 6 && message[20] == 13 && message[21] == 10) {
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### getTypeGLS() End ###\n\n");
                    #endif
                    
                    /* Return type Hello Server */
                    return GLS_TYPE_HELLO_SERVER;
                    
                }
                /* If not, message is Hello type */
                else {
                        
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### getTypeGLS() End ###\n\n");
                    #endif
                    
                    return GLS_TYPE_HELLO;
                    
                }
                
            }
            /* If not, message is Hello type */
            else {
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### getTypeGLS() End ###\n\n");
                #endif
                
                return GLS_TYPE_HELLO;
            
            }
        
        }
        
        
    }
    
    /* Register type test */
    if (size == 18) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Test Register Message\n");
        #endif
        
        /* Getting REGISTER message part */
        byte messageRegister[8];
        char reg[9] = "REGISTER";
        int i = 0;
        for (i = 0; i < 8; i++) {
            
            /* in uppercase */
            messageRegister[i] = toupper(message[i + 8]); 
            
        }        
        /* bytes check */
        i = 0;
        int y = 0;
        for(i = 0; i < 8; i++) {
            
            if(messageRegister[i] == reg[i]) y++;
            
        }
        /* return GLS_TYPE_REGISTER if message match */
        if (y == 8 && message[16] == 13 && message[17] == 10) {
        
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### getTypeGLS() End ###\n\n");
            #endif
            
            return GLS_TYPE_REGISTER;
            
        }
        
    }
    
    /* If message size is the same as Register Server type */
    if (size == 28) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Test Register Server OK\n");
        #endif
        
        /* Getting REGISTER SERVER OK part of message */
        byte messageRegisterServerOk[18];
        char regServerOk[19] = "REGISTER SERVER OK";
        int i = 0;
        for (i = 0; i < 18; i++) {
            
            /* In uppercase */
            messageRegisterServerOk[i] = toupper(message[i + 8]); 
            
        }        
        /* bytes comparaison */
        i = 0;
        int y = 0;
        for(i = 0; i < 18; i++) {
            
            if(messageRegisterServerOk[i] == regServerOk[i]) y++;
            
        }
        /* if message match return GLS_TYPE_REGISTER_SERVER_OK */
        if (y == 18 && message[26] == 13 && message[27] == 10) {
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### getTypeGLS() End ###\n\n");
            #endif
            
            return GLS_TYPE_REGISTER_SERVER_OK;
            
        }
        
    }
    
    /* If the message is at least the size of REGISTER SERVER type */
    if (size >= 25) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Test Register Server\n");
        #endif
        
        /* Getting part of the message to compare */
        byte messageRegisterServer[15];
        char regServer[16] = "REGISTER SERVER";
        int i = 0;
        for (i = 0; i < 15; i++) {
            
            /* in uppercase */
            messageRegisterServer[i] = toupper(message[i + 8]); 
            
        }        
        /* bytes check */
        i = 0;
        int y = 0;
        for(i = 0; i < 15; i++) {
            
            if(messageRegisterServer[i] == regServer[i]) y++;
            
        }
        /* If message match return GLS_TYPE_REGISTER_SERVER */
        if (y == 15 && message[23] == 13 && message[24] == 10) {
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### getTypeGLS() End ###\n\n");
            #endif
            
            return GLS_TYPE_REGISTER_SERVER;
            
        }
        
    }
    
    /* Test Register with info type */
    if (size > 18) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Test Register with info\n");
        #endif
        
        /* Getting the message part to compare */
        byte messageRegister[8];
        char reg[9] = "REGISTER";
        int i = 0;
        for (i = 0; i < 8; i++) {
            
            /* in uppercase */
            messageRegister[i] = toupper(message[i + 8]); 
            
        }        
        /* bytes check*/
        i = 0;
        int y = 0;
        for(i = 0; i < 8; i++) {
            
            if(messageRegister[i] == reg[i]) y++;
            
        }
        /* if message match return GLS_TYPE_REGISTER_WITH_INFO */
        if (y == 8 && message[16] == 13 && message[17] == 10) {
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### getTypeGLS() End ###\n\n");
            #endif
            
            return GLS_TYPE_REGISTER_WITH_INFO;
            
        }
        
    }
    
    /* Test error message type */
    if (size >= 19) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Test error message\n");
        #endif
        
        /* Getting message part to compare */
        byte messageError[6];
        char error[7] = "ERROR ";
        int i = 0;
        for (i = 0; i < 6; i++) {
            
            /* in uppercase */
            messageError[i] = toupper(message[i + 8]); 
            
        }        
        /* bytes checks */
        i = 0;
        int y = 0;
        for(i = 0; i < 6; i++) {
            
            if(messageError[i] == error[i]) y++;
            
        }
        /* If message match return GLS_TYPE_ERROR */
        if (y == 6) {
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### getTypeGLS() End ###\n\n");
            #endif
            
            return GLS_TYPE_ERROR;
            
        }
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getTypeGLS() End ###\n\n");
    #endif
    
    return GLS_ERROR_UNKNOWN;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Return the GLS message version, ex: 1.1 -> 11 (int)
 Return a negative number for an error.
 
 ---------------------------------------------------------*/

int getVersionGLS(const byte* message, const int size) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getVersionGLS() Start ###\n");
    #endif
    
    /* Minimal GLS header size check */
    if (size >= 7) {
        
        /* Getting the message part to compare */
        byte messageGLS[3];
        char gls[4] = "GLS";
        int i = 0;
        for (i = 0; i < 3; i++) {
            
            /* in uppercase */
            messageGLS[i] = toupper(message[i]); 
            
        }        
        /* bytes check */
        i = 0;
        int z = 0;
        for (z = 0; z < 3; z++) {
            
            if (messageGLS[i] == gls[i]) i++;
            else break;
            
        }

        /* If it's a GLS header */
        if (i == 3) {
            
            /* Convertion of the version in int, major * 10 + minor */
            char majeurC[2];
            majeurC[0] = message[4];
            majeurC[1] = '\0';
            char mineurC[2];
            mineurC[0] = message[6];
            mineurC[1] = '\0';
            
            int majeur = atoi(majeurC);
            int mineur = atoi(mineurC);
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### getVersionGLS() End ###\n\n");
            #endif
            
            return majeur * 10 + mineur;
            
        }
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getVersionGLS() End ###\n\n");
    #endif
    
    return GLS_ERROR_UNKNOWN;
    
}


/*-------------------------------------------------------
 
 PRIVATE
 
 Return the error number from the GLS error message
 or a negative number for an error (of the function).
 
 ---------------------------------------------------------*/

int getNumError(const byte* message, const int size) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getNumError() Start ###\n");
    #endif
    
    /* check minimal size of the ERROR GLS message */
    if (size >= 19) {
                    
        /* Convertion of the error in numeric value */
        char centaineC[2];
        centaineC[0] = message[14];
        centaineC[1] = '\0';
        char dizaineC[2];
        dizaineC[0] = message[15];
        dizaineC[1] = '\0';
        char uniteC[2];
        uniteC[0] = message[16];
        uniteC[1] = '\0';
        
        int centaine = atoi(centaineC);
        int dizaine = atoi(dizaineC);
        int unite = atoi(uniteC);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getNumError() End ###\n\n");
        #endif
        
        return centaine * 100 + dizaine * 10 + unite;
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getNumError() End ###\n\n");
    #endif
    
    return GLS_ERROR_MSGSIZE;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Set the user's id for a standard GLS connexion extracting 
 information from a GLS message. Return 0 for success, 
 a negative number for an error. 
 
 Used by _acceptConnexion(). Do not confuse with setUserId()
 and getUserId().
 
 ---------------------------------------------------------*/

int setIdGLS(GLSSock* myGLSSocket, const byte* message, const int size) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### setIdGLS() Start ###\n");
    #endif
    
    /* Check minimum size of a Hello message */
    if (size >= 17) {
        
        /* Getting the id size from th message (CRLF = 2 bytes and Header = 14 bytes) */
        int sizeId = size - 2 - 14;
        if (sizeId > 254) return GLS_ERROR_MSGSIZE;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Allocating memory for setIdGLS.\n");
        printf("Size m_idUser : %d\n", sizeId);
        printf("m_idUser : %p.\n", myGLSSocket->m_idUser);
        #endif
        
        /* Memory allocation for the ID */
        if (myGLSSocket->m_idUser != NULL) free(myGLSSocket->m_idUser);
        myGLSSocket->m_idUser = 0;
        myGLSSocket->m_idUser = malloc(sizeId);
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("m_idUser : %p.\n",  myGLSSocket->m_idUser);
        #endif
        myGLSSocket->m_sizeIdUser = sizeId;
        if (myGLSSocket->m_idUser == NULL) {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No memory - setIdGLS.\n");
            #endif
            return GLS_ERROR_NOMEM;
            
        }
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("setIdGLS : ");
        #endif
        int i = 0;
        for (i = 0; i < sizeId; i++) {
            
            /* On copie l'id dans idUser */
            myGLSSocket->m_idUser[i] = message[i + 14];
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("%c",  myGLSSocket->m_idUser[i]);
            #endif
            
        }
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("\n");
        #endif
        
        /* Telling the socket that the id is set */
        myGLSSocket->m_isUserConfig = 1;
        
    }
    else {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### setIdGLS() End ###\n\n");
        #endif
        
        return GLS_ERROR_MSGSIZE;
    
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### setIdGLS() End ###\n\n");
    #endif
    
    return 0;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Accept connexion from the socket server and configure the
 GLSSocket according to the GLS negociation.
 Return 0 for success, a negative number for an error.
 
 ---------------------------------------------------------*/

int _acceptConnexion(GLSSock* myGLSSocket, const int socketServer){
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### acceptConnexion() Start ###\n");
    #endif
    
    if (myGLSSocket->m_isSocketConfig == 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        myGLSSocket->m_isServeur = 1;
        #endif
        
        /* Accept the client connexion */
        socklen_t addr_size = sizeof(myGLSSocket->m_infoClient);
        myGLSSocket->m_sock = accept(socketServer, (struct sockaddr*) &myGLSSocket->m_infoClient, &addr_size);
        if (myGLSSocket->m_sock < 0) {
            
            /* Getting socket error */
            int numError = errno;
            
            /* Debug only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Error accept()\n");
            printf("### acceptConnexion() End ###\n\n");
            #endif
            
            /* Return accept() error */
            switch (numError) {
                    
                case EAGAIN :
                    return GLS_ERROR_AGAIN;
                    break;
                    
                case EBADF :
                    return GLS_ERROR_BADF;
                    break;
                    
                case ECONNABORTED :
                    return GLS_ERROR_CONNABORTED;
                    break;
                    
                case EINTR :
                    return GLS_ERROR_INTR;
                    break;
                    
                case EINVAL :
                    return GLS_ERROR_INVAL;
                    break;
                    
                case EMFILE :
                    return GLS_ERROR_MFILE;
                    break;
                    
                case ENFILE :
                    return GLS_ERROR_NFILE;
                    break;
                    
                case ENOBUFS :
                    return GLS_ERROR_NOBUFS;
                    break;
                    
                case ENOMEM :
                    return GLS_ERROR_NOMEM;
                    break;
                    
                case ENOTSOCK :
                    return GLS_ERROR_NOTSOCK;
                    break;
                    
                case EOPNOTSUPP :
                    return GLS_ERROR_OPNOTSUPP;
                    break;
                    
                case EPROTO :
                    return GLS_ERROR_PROTO;
                    break;
                    
                case EPERM :
                    return GLS_ERROR_PERM;
                    break;
                    
                case ENOSR :
                    return GLS_ERROR_NOSR;
                    break;
                    
                case ESOCKTNOSUPPORT :
                    return GLS_ERROR_SOCKTNOSUPPORT;
                    break;
                    
                case EPROTONOSUPPORT :
                    return GLS_ERROR_PROTONOSUPPORT;
                    break;
                    
                case ETIMEDOUT :
                    return GLS_ERROR_TIMEDOUT;
                    break;
                    
                default:
                    return GLS_ERROR_UNKNOWN;
                    break;
                    
            }
            
        }
        
        /* Receiving the first message from client in plaintext */
        byte (*firstMessage) = 0;
        int sizeFirstMessage = recvPacket(myGLSSocket, &firstMessage, 0);
        /* if error return it */
        if (sizeFirstMessage < 0) {
            
            if (firstMessage != NULL) {
                
                free(firstMessage);
                firstMessage = 0;
            
            }
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### acceptConnexion() End ###\n\n");
            #endif
            
            return sizeFirstMessage;
            
        }
        
        /* Getting GLS Client version */
        int version = getVersionGLS(firstMessage, sizeFirstMessage);
        if (version < 11) {
            
            /* If the version is less than 1.1 => send an error message */
            byte error[24] = "GLS/1.1 ERROR 200 1.1  ";
            error[21] = 13;
            error[22] = 10;
            /* Sending 23 bytes to remove the '\0' from the string */
            sendPacket(myGLSSocket, error, 23);
            
            /* Freeing memory */
            if (firstMessage != NULL) {
                
                free(firstMessage);
                firstMessage = 0;
                
            }
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### acceptConnexion() End ###\n\n");
            #endif
            
            return GLS_ERROR_VERSION;
            
        }
        
        /* Message type check to know how to handle it */
        int typeMessage = getTypeGLS(firstMessage, sizeFirstMessage);
        
        if (typeMessage == GLS_TYPE_HELLO) {
            
            /* Cleaning memory */
            if (myGLSSocket->m_messageHelloEncrypt != NULL) free(myGLSSocket->m_messageHelloEncrypt);
            
            /* Receiving second message from client in ciphertext */
            int sizeSecondMessage = recvPacket(myGLSSocket, &myGLSSocket->m_messageHelloEncrypt, 1);
            /* Return the error if exist */
            if (sizeSecondMessage < 0) {
                
                if (myGLSSocket->m_messageHelloEncrypt != NULL) {
                    
                    free(myGLSSocket->m_messageHelloEncrypt);
                    myGLSSocket->m_messageHelloEncrypt = 0;
                
                }
                
                if (firstMessage != NULL) {
                    
                    free(firstMessage);
                    firstMessage = 0;
                    
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### acceptConnexion() End ###\n\n");
                #endif
                
                /* return error */
                return sizeSecondMessage;
                
            }
            else myGLSSocket->m_sizeMessageHelloEncrypt = sizeSecondMessage;
            
            /* Configure user's id with the first message in plaintext */
            int numError = setIdGLS(myGLSSocket, firstMessage, sizeFirstMessage);
            if (numError != 0) {
                
                /* If no ID in the message send an error */
                byte error[20] = "GLS/1.1 ERROR 401  ";
                error[17] = 13;
                error[18] = 10;
                /* sending 19 bytes to remove the '\0' from the string */
                sendPacket(myGLSSocket, error, 19);
                
                if (firstMessage != NULL) {
                    
                    free(firstMessage);
                    firstMessage = 0;
                
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### acceptConnexion() End ###\n\n");
                #endif
                
                /* return error */
                return numError;
                
            }
            
            /* Configure the socket with the connexion type */
            myGLSSocket->m_connexionType = GLS_CONNEXION_STANDARD;
            myGLSSocket->m_isSocketConfig = 1;
            
        }
        else if (typeMessage == GLS_TYPE_REGISTER) {
            
            /* Creating [Regiser Server + certificat] message */
            byte registerServer[26] = "GLS/1.1 REGISTER SERVER  ";
            registerServer[23] = 13;
            registerServer[24] = 10;
            int sizeRegisterServerCertificate = 25 + myGLSSocket->m_publicCertSize;
            byte *registerServerCertificate = 0;
            registerServerCertificate = malloc(sizeRegisterServerCertificate);
            if (registerServerCertificate == NULL) {
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### acceptConnexion() End ###\n\n");
                #endif
                
                /* Freeing memory */
                if (firstMessage != NULL) {
                    
                    free(firstMessage);
                    firstMessage = 0;
                    
                }
                
                /* return error */
                return GLS_ERROR_NOMEM;
                
            }
            int i = 0;
            for (i = 0; i < 25; i++) {
                registerServerCertificate[i] = registerServer[i];
            }
            for (i = 0; i < myGLSSocket->m_publicCertSize; i++) {
                registerServerCertificate[i + 25] = myGLSSocket->m_publicCert[i];
            }
            
            /* sending Register Server with certificat */
            int error = sendPacket(myGLSSocket, registerServerCertificate, sizeRegisterServerCertificate);
            if (error < 0) {
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### acceptConnexion() End ###\n\n");
                #endif
                
                /* Freeing memory */
                if (firstMessage != NULL) {
                    
                    free(firstMessage);
                    firstMessage = 0;
                    
                }
                if (registerServerCertificate != NULL) {
                    
                    free(registerServerCertificate);
                    registerServerCertificate = 0;
                    
                }
                
                /* Return error */
                return GLS_ERROR_NOMEM;
                
            }
            
            /* Getting encrypted register message from client */
            byte (*secondMessage) = 0;
            int sizeSecondMessage = recvPacket(myGLSSocket, &secondMessage, 1);
            /* If error using the recvPacket() */
            if (sizeSecondMessage < 0) {
                
                /* freeing memory */
                if (firstMessage != NULL) {
                    
                    free(firstMessage);
                    firstMessage = 0;
                    
                }
                if (registerServerCertificate != NULL) {
                    
                    free(registerServerCertificate);
                    registerServerCertificate = 0;
                    
                }
                if (secondMessage != NULL) {
                    
                    free(secondMessage);
                    secondMessage = 0;
                    
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### acceptConnexion() End ###\n\n");
                #endif
                
                /* return error */
                return sizeSecondMessage;
                
            }
            
            /* Sending Register Server OK */
            byte registerServerOk[29] = "GLS/1.1 REGISTER SERVER OK  ";
            registerServerOk[26] = 13;
            registerServerOk[27] = 10;
            /* sending 28 bytes to remove the '\0' from the string */
            error = sendPacket(myGLSSocket, registerServerOk, 28);
            if (error < 0) {
                
                /* Freeing memory */
                if (firstMessage != NULL) {
                    
                    free(firstMessage);
                    firstMessage = 0;
                    
                }
                if (registerServerCertificate != NULL) {
                    
                    free(registerServerCertificate);
                    registerServerCertificate = 0;
                    
                }
                if (secondMessage != NULL) {
                    
                    free(secondMessage);
                    secondMessage = 0;
                    
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### acceptConnexion() End ###\n\n");
                #endif
                
                /* return error */
                return error;
                
            }
            
            /* Closing socket */
            shutdown(myGLSSocket->m_sock, SHUT_RDWR);
            closesocket(myGLSSocket->m_sock);
            
            /*
             * The next part cause a DOS when too many message are 
             * decrypted in _acceptConnexion() because you can't 
             * thread it, the decryption part will be moved on the 
             * getRegisterMessage() function to prevent it. I initialy
             * put this part here to prevent false positive and only
             * give a working socket to the user with waitForClient().
             */
            
            /* We decrypt the message after closing the connexion to prevent timings attacks */
            byte *decryptMessage = 0;
            int sizeDecryptMessage = decryptWithPK(myGLSSocket, secondMessage, sizeSecondMessage, &decryptMessage);
            if (sizeDecryptMessage < 0) {
                
                /* On vide la mémoire */
                if (firstMessage != NULL) {
                    
                    free(firstMessage);
                    firstMessage = 0;
                    
                }
                if (registerServerCertificate != NULL) {
                    
                    free(registerServerCertificate);
                    registerServerCertificate = 0;
                    
                }
                if (secondMessage != NULL) {
                    
                    free(secondMessage);
                    secondMessage = 0;
                    
                }
                if (decryptMessage != NULL) {
                    
                    free(decryptMessage);
                    decryptMessage = 0;
                    
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### acceptConnexion() End ###\n\n");
                #endif
                
                /* return error */
                return sizeDecryptMessage;
            }
            
            /* add plaintext register message to the GLS socket */
            myGLSSocket->m_messageRegister = decryptMessage;
            myGLSSocket->m_sizeMessageRegister = sizeDecryptMessage;
            
            /* Configure the socket with the connexion type */
            myGLSSocket->m_connexionType = GLS_CONNEXION_REGISTER;
            myGLSSocket->m_isHandShakeFinish = 1;
            
            /* freeing memory */
            if (registerServerCertificate != NULL) {
                
                free(registerServerCertificate);
                registerServerCertificate = 0;
                
            }
            if (secondMessage != NULL) {
                
                free(secondMessage);
                secondMessage = 0;
                
            }
            /* decryptMessage is used in the socket, FreeGLSSocket() free it */
            decryptMessage = 0;
            
        }
        else {
            
            /* If message doesn't corespond to any type => send error */
            byte error[20] = "GLS/1.1 ERROR 400  ";
            error[17] = 13;
            error[18] = 10;
            /* Sending 19 bytes to remove the '\0' from the string */
            sendPacket(myGLSSocket, error, 19);
            
            /* Freeing memory and returning error */
            if (firstMessage != NULL) {
                
                free(firstMessage);
                firstMessage = 0;
                
            }
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### acceptConnexion() End ###\n\n");
            #endif
            
            return GLS_ERROR_UNKNOWN;
            
        }
        
        /* Freeing memory */
        if (firstMessage != NULL) {
            
            free(firstMessage);
            firstMessage = 0;
            
        }
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### acceptConnexion() End ###\n\n");
        #endif
        
        /* Everything worked fine, return 0 */
        return 0;
        
    }
    else {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### acceptConnexion() End ###\n\n");
        #endif
        
        /* The socket is already connected, return error */
        return GLS_ERROR_ISCONN;

    }
    
}




/*-------------------------------------------------------
 
 Return the connexion type, or a negative number for an error.
 
 ---------------------------------------------------------*/

int getTypeConnexion(GLSSock* myGLSSocket) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getTypeConnexion() Start ###\n");
    printf("### getTypeConnexion() End ###\n\n");
    #endif
    
    if (myGLSSocket->m_connexionType != 0) return myGLSSocket->m_connexionType;
    else return GLS_ERROR_NOTCONN;
    
}




/*-------------------------------------------------------
 
 Finish the handshake for a standard GLS connexion.
 
 ---------------------------------------------------------*/

int finishHandShake(GLSSock* myGLSSocket) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### finishHandShake() Start ###\n");
    #endif
    
    /* check if the handshake needs to be done and the encryption keys are present */
    if (myGLSSocket->m_isHandShakeFinish == 0 && myGLSSocket->m_isSocketConfig == 1 && myGLSSocket->m_isCryptoKey == 1) {
    
        if (myGLSSocket->m_connexionType == GLS_CONNEXION_STANDARD) {
            
            /* We decrypt the hello message */
            byte (*plainTextHelloMessage) = 0;
            int sizePlainTextMessage = firstDecrypt(myGLSSocket, myGLSSocket->m_messageHelloEncrypt, myGLSSocket->m_sizeMessageHelloEncrypt, &plainTextHelloMessage);
            if (sizePlainTextMessage < 0) {
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("GLS/1.1 ERROR 100\n");
                #endif
                
                /* if the message can't be decrypted = bad password => send an error message */
                byte error[20] = "GLS/1.1 ERROR 100  ";
                error[17] = 13;
                error[18] = 10;
                /* Sending 19 bytes to remove the '\0' from the string */
                sendPacket(myGLSSocket, error, 19);
                
                /* On supprime la mémoire en cas d'erreur */
                if (plainTextHelloMessage != NULL) {
                    
                    free(plainTextHelloMessage);
                    plainTextHelloMessage = 0;
                
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### finishHandShake() End ###\n\n");
                #endif
                
                /* return error */
                return GLS_ERROR_BADPASSWD;
            
            }
            
            /* We check if the message can be read and handle it */
            int typeMessage = getTypeGLS(plainTextHelloMessage, sizePlainTextMessage);
            if (typeMessage == GLS_TYPE_HELLO) {
                
                /* Getting the user id to compare it with the one on the encrypted message */
                char* oldId = 0;
                int sizeOldId = getUserId(myGLSSocket, &oldId);
                if (sizeOldId < 0) {
                    
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("GLS/1.1 ERROR 500\n");
                    #endif
                    
                    /* if error with getUserId() */
                    byte error[20] = "GLS/1.1 ERROR 500  ";
                    error[17] = 13;
                    error[18] = 10;
                    /* Sending 19 bytes to remove the '\0' from the string */
                    sendPacket(myGLSSocket, error, 19);
                    
                    /* On supprime la mémoire en cas d'erreur */
                    if (plainTextHelloMessage != NULL) {
                        
                        free(plainTextHelloMessage);
                        plainTextHelloMessage = 0;
                        
                    }
                    
                    /* Free memory */
                    if (oldId != NULL) {
                        
                        free(oldId);
                        oldId = 0;
                        
                    }
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### finishHandShake() End ###\n\n");
                    #endif
                    
                    /* return error */
                    return GLS_ERROR_UNKNOWN;

                }
                
                /* We configure the socket with the id on the encrypted message */
                if (setIdGLS(myGLSSocket, plainTextHelloMessage, sizePlainTextMessage) != 0) {
                    
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("GLS/1.1 ERROR 401\n");
                    #endif
                    
                    /* If ID can't be read send error */
                    byte error[20] = "GLS/1.1 ERROR 401  ";
                    error[17] = 13;
                    error[18] = 10;
                    /* Sending 19 bytes to remove the '\0' from the string */
                    sendPacket(myGLSSocket, error, 19);
                    
                    /* free memory */
                    if (plainTextHelloMessage != NULL) {
                        
                        free(plainTextHelloMessage);
                        plainTextHelloMessage = 0;
                        
                    }
                    if (oldId != NULL) {
                        
                        free(oldId);
                        oldId = 0;
                        
                    }
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### finishHandShake() End ###\n\n");
                    #endif
                    
                    /* return error */
                    return GLS_ERROR_UNKNOWN;
                    
                }
                
                /* Getting ID from encrypted message */
                char* newId = 0;
                int sizeNewdId = getUserId(myGLSSocket, &newId);
                if (sizeNewdId < 0) {
                    
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("GLS/1.1 ERROR 500\n");
                    #endif
                    
                    /* If ID can't be read send error */
                    byte error[20] = "GLS/1.1 ERROR 500  ";
                    error[17] = 13;
                    error[18] = 10;
                    /* Sending 19 bytes to remove the '\0' from the string */
                    sendPacket(myGLSSocket, error, 19);
                    
                    /* Free memory */
                    if (plainTextHelloMessage != NULL) {
                        
                        free(plainTextHelloMessage);
                        plainTextHelloMessage = 0;
                        
                    }
                    if (oldId != NULL) {
                        
                        free(oldId);
                        oldId = 0;
                        
                    }
                    if (newId != NULL) {
                        
                        free(newId);
                        newId = 0;
                        
                    }
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### finishHandShake() End ###\n\n");
                    #endif
                    
                    /* return error */
                    return sizeNewdId;
                    
                }
                
                /* Check if the two IDs are the same */
                int i = 0;
                int y = 0;
                for (y = 0; y < sizeOldId; y++) {
                    
                    if (i < sizeOldId && i < sizeNewdId) {
                        
                        if (newId[i] == oldId[i]) i++;
                        else break;
                        
                    }
                    else break;
                    
                }
                if (!(i == sizeOldId) || !(i == sizeNewdId) || !(sizeOldId == sizeNewdId)) {
                 
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("GLS/1.1 ERROR 401 - ID Invalide entre oldId et newId\n");
                    printf("Old ID : %s\n", oldId);
                    printf("New ID : %s\n", newId);
                    printf("i : %d\n", i);
                    #endif
                    
                    /* if the IDs aren't the same => send error */
                    byte error[20] = "GLS/1.1 ERROR 401  ";
                    error[17] = 13;
                    error[18] = 10;
                    /* Sending 19 bytes to remove the '\0' from the string */
                    sendPacket(myGLSSocket, error, 19);
                    
                    /* Free memory */
                    if (plainTextHelloMessage != NULL) {
                        
                        free(plainTextHelloMessage);
                        plainTextHelloMessage = 0;
                        
                    }
                    if (oldId != NULL) {
                        
                        free(oldId);
                        oldId = 0;
                        
                    }
                    if (newId != NULL) {
                        
                        free(newId);
                        newId = 0;
                        
                    }
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### finishHandShake() End ###\n\n");
                    #endif
                    
                    /* return error */
                    return GLS_ERROR_UNKNOWN;
                    
                }
                
                /* 
                 * At this point the user's identification has been done
                 * and we need to send back a Hello Server message 
                 */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Authentication OK\n");
                #endif
                
                byte helloServer[23] = "GLS/1.1 HELLO SERVER  ";
                helloServer[20] = 13;
                helloServer[21] = 10;
                /* Sending 75 bytes to remove the '\0' from the string */
                byte (*cihperMessage) = 0;
                int sizeCipherMessage = allEncrypt(myGLSSocket, helloServer, 22, &cihperMessage);
                if (sizeCipherMessage < 0) {
                    
                    /* If the encryption doesn't work we send a internal error */
                    byte error[20] = "GLS/1.1 ERROR 500  ";
                    error[17] = 13;
                    error[18] = 10;
                    /* Sending 19 bytes to remove the '\0' from the string */
                    sendPacket(myGLSSocket, error, 19);
                    
                    /* Free memory */
                    if (plainTextHelloMessage != NULL) {
                        
                        free(plainTextHelloMessage);
                        plainTextHelloMessage = 0;
                        
                    }
                    if (cihperMessage != NULL) {
                        
                        free(cihperMessage);
                        cihperMessage = 0;
                        
                    }
                    if (oldId != NULL) {
                        
                        free(oldId);
                        oldId = 0;
                        
                    }
                    if (newId != NULL) {
                        
                        free(newId);
                        newId = 0;
                        
                    }
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### finishHandShake() End ###\n\n");
                    #endif
                    
                    /* return error */
                    return sizeCipherMessage;
                    
                }
                
                /* Sending encrypted Hello Server */
                int error = sendPacket(myGLSSocket, cihperMessage, sizeCipherMessage);
                
                /* Free memory */
                if (plainTextHelloMessage != NULL) {
                    
                    free(plainTextHelloMessage);
                    plainTextHelloMessage = 0;
                    
                }
                if (cihperMessage != NULL) {
                    
                    free(cihperMessage);
                    cihperMessage = 0;
                    
                }
                if (oldId != NULL) {
                    
                    free(oldId);
                    oldId = 0;
                    
                }
                if (newId != NULL) {
                    
                    free(newId);
                    newId = 0;
                    
                }
                
                /* If an error occured, return it */
                if (error != 0) return error;
                else { 
                    
                    /* Socket configuration to say everything is OK */
                    myGLSSocket->m_isHandShakeFinish = 1;
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### finishHandShake() End ###\n\n");
                    #endif
                    
                    return 0;
                    
                }
                
            }
            else {
                
                /* If the message doesn't have a type send an error */
                byte error[20] = "GLS/1.1 ERROR 401  ";
                error[17] = 13;
                error[18] = 10;
                /* Sending 19 bytes to remove the '\0' from the string */
                sendPacket(myGLSSocket, error, 19);
                
                /* Free memory */
                if (plainTextHelloMessage != NULL) {
                    
                    free(plainTextHelloMessage);
                    plainTextHelloMessage = 0;
                
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### finishHandShake() End ###\n\n");
                #endif
                
                /* return error */
                return GLS_ERROR_UNKNOWN;
                
            }
            
        }
        else if (myGLSSocket->m_connexionType == GLS_CONNEXION_REGISTER) {
            
            
            
        }
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### finishHandShake() End ###\n\n");
        #endif
        
        return GLS_ERROR_UNKNOWN;
    
    }
    else {
        
        /* Debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        if (myGLSSocket->m_isSocketConfig == 0) printf("Socket not configured.\n");
        if (myGLSSocket->m_isHandShakeFinish == 1) printf("HandShake done.\n");
        if (myGLSSocket->m_isCryptoKey == 0) printf("No encryption key.\n");
        printf("### finishHandShake() End ###\n\n");
        #endif
        
        if (myGLSSocket->m_isSocketConfig == 0) return GLS_ERROR_NOTCONN;
        else if (myGLSSocket->m_isCryptoKey == 0) return GLS_ERROR_NOPASSWD;
        else if (myGLSSocket->m_isHandShakeFinish == 1) return GLS_ERROR_ISCONN;
        else return GLS_ERROR_UNKNOWN;
        
    }
    
}




/*-------------------------------------------------------
 
 Set a pointer to the memory where the user's id is copied
 in userId. You have to free the memory yourself.
 
 Return the size of userId or a negative number for an error.
 
 ---------------------------------------------------------*/

int getUserId(GLSSock* myGLSSocket, char** userId) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getUserId() Start ###\n");
    #endif
    
    /* If the socket have an user ID */
    if (myGLSSocket->m_isUserConfig == 1) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("GetUserId.\n");
        printf("SizeIdUser : %d\n",  myGLSSocket->m_sizeIdUser);
        printf("m_idUser : %p.\n",  myGLSSocket->m_idUser);
        printf("UserId : ");
        #endif

        /* allocating memory for userId + 1 byte for '\0' */
        *userId = malloc(myGLSSocket->m_sizeIdUser + 1);
        if (*userId == NULL) {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No memory - getUserId.\n");
            #endif
            return GLS_ERROR_NOMEM;
            
        }
        
        /* ID copy */
        int i = 0;
        for (i = 0; i < myGLSSocket->m_sizeIdUser; i++) {
            
            (*userId)[i] = (char) myGLSSocket->m_idUser[i];
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("%c",  myGLSSocket->m_idUser[i]);
            #endif
        
        }
        /* add the '\0' at the end of the char */
        (*userId)[myGLSSocket->m_sizeIdUser] = '\0';
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("\n");
        printf("GetUserId End.\n");
        #endif
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getUserId() End ###\n\n");
        #endif
        
        /* Return the size of the userId char + 1 for the '\0' */
        return myGLSSocket->m_sizeIdUser + 1;
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getUserId() End ###\n\n");
    #endif
    
    return GLS_ERROR_USERNOTCONF;
    
}




/*-------------------------------------------------------
 
 Set the user's id.
 Return 0 for success, a negative number for an error.
 
 ---------------------------------------------------------*/

int setUserId(GLSSock* myGLSSocket, const char* userId) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### setUserId() Start ###\n");
    #endif
    
    /* Get userId's size */
    int size = (int) strlen(userId);
    
    /* Test user's id size */
    if (size > 254 || size < 1) return GLS_ERROR_BADSIZE;
    
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("size : %d.\n",  size);
    printf("m_idUser : %p.\n",  myGLSSocket->m_idUser);
    #endif
    
    /* memory allocation for id */
    if (myGLSSocket->m_idUser != NULL) free(myGLSSocket->m_idUser);
    myGLSSocket->m_idUser = malloc(size * sizeof(byte));
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("m_idUser : %p.\n",  myGLSSocket->m_idUser);
    #endif
    myGLSSocket->m_sizeIdUser = size;
    if (myGLSSocket->m_idUser == NULL) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No memory - setUserId.\n");
        #endif
        return GLS_ERROR_NOMEM;
        
    }
    int i = 0;
    for (i = 0; i < size; i++) {
        
        /* Copy ID into socket */
        myGLSSocket->m_idUser[i] = userId[i];
        
    }
    
    /* Config socket */
    myGLSSocket->m_isUserConfig = 1;
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### setUserId() End ###\n\n");
    #endif
    
    return 0;
    
}




/*-------------------------------------------------------
 
 Send a register message to a GLS Server
 
 Return 0 for success, a negative number for an error.
 
 ---------------------------------------------------------*/

int sendRegister(GLSSock* myGLSSocket, const char* address, const char* port, const byte* buffer, const int sizeBuffer) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### sendRegister() Start ###\n");
    #endif
    
    if (myGLSSocket->m_certRoot != NULL && myGLSSocket->m_isSocketConfig == 0 && myGLSSocket->m_isHandShakeFinish == 0) {
        
        /* Debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        myGLSSocket->m_isServeur = 0;
        #endif
        
        #if defined (win32)
        WSADATA WSAData;
        int errorWindows = WSAStartup(MAKEWORD(2,2), &WSAData);
        #else
        int errorWindows = 0;
        #endif
        
        /* If windows's socket works */
        if(errorWindows == 0) {
            
            /* Creating register message */
            char messageRegister[18] = "GLS/1.1 REGISTER  ";
            /* Insertion CR at size -2 */
            messageRegister[16] = 13;
            /* Insertion LF at size -1 */
            messageRegister[17] = 10;
            
            /* addrinfo configuration for getaddrinfo() */
            struct addrinfo hints;
            memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            
            /* Server address configuration */
            int error = getaddrinfo(address, port, &hints, &myGLSSocket->m_infoConnexion);
            if (error != 0){
                
                /* No memory to clean */
                
                /* debug only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Impossible to config infoConnexion.\n");
                printf("### sendRegister() End ###\n\n");
                #endif
                
                /* return getaddrinfo error */
                switch (error) {
                        
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
            
            /* Socket creation */
            myGLSSocket->m_sock = socket(myGLSSocket->m_infoConnexion->ai_family, myGLSSocket->m_infoConnexion->ai_socktype, myGLSSocket->m_infoConnexion->ai_protocol);
            
            /* If connection impossible */
            if(connect(myGLSSocket->m_sock, myGLSSocket->m_infoConnexion->ai_addr, myGLSSocket->m_infoConnexion->ai_addrlen) == SOCKET_ERROR) {
                
                /* get error number */
                int numError = errno;
                
                /* No memory to clean */
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Impossible to connect.\n");
                printf("Num error : %d\n", numError);
                printf("### sendRegister() End ###\n\n");
                #endif
                
                /* Closing socket */
                shutdown(myGLSSocket->m_sock, SHUT_RDWR);
                closesocket(myGLSSocket->m_sock);
                
                /* return getaddrinfo error */
                switch (numError) {
                        
                    case EACCES :
                        return GLS_ERROR_ACCES;
                        break;
                        
                    case EPERM :
                        return GLS_ERROR_PERM;
                        break;
                        
                    case EADDRINUSE :
                        return GLS_ERROR_ADDRINUSE;
                        break;
                        
                    case EAFNOSUPPORT :
                        return GLS_ERROR_AFNOSUPPORT;
                        break;
                        
                    case EAGAIN :
                        return GLS_ERROR_AGAIN;
                        break;
                        
                    case EALREADY :
                        return GLS_ERROR_ALREADY;
                        break;
                        
                    case EBADF :
                        return GLS_ERROR_BADF;
                        break;
                        
                    case ECONNREFUSED :
                        return GLS_ERROR_CONNREFUSED;
                        break;
                        
                    case EHOSTDOWN :
                        return GLS_ERROR_HOSTDOWN;
                        break;
                        
                    case EFAULT :
                        return GLS_ERROR_FAULT;
                        break;
                        
                    case EINPROGRESS :
                        return GLS_ERROR_INPROGRESS;
                        break;
                        
                    case EINTR :
                        return GLS_ERROR_INTR;
                        break;
                        
                    case EISCONN :
                        return GLS_ERROR_ISCONN;
                        break;
                        
                    case ENETUNREACH :
                        return GLS_ERROR_NETUNREACH;
                        break;
                        
                    case ENOTSOCK :
                        return GLS_ERROR_NOTSOCK;
                        break;
                        
                    case ETIMEDOUT :
                        return GLS_ERROR_TIMEDOUT;
                        break;
                        
                    default:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                }
                
            }
            
            /* Send register message */
            error = sendPacket(myGLSSocket, (byte*) messageRegister, 18);
            
            /* If sending message is impossible */
            if (error < 0) {
                
                /* No memory to clean */
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Impossible to send the packet.\n");
                printf("### connexion() End ###\n\n");
                #endif
                
                /* Closing socket */
                shutdown(myGLSSocket->m_sock, SHUT_RDWR);
                closesocket(myGLSSocket->m_sock);
                
                /* return error */
                return error;
                
            }
            
            /* get Register Server message with certificate */
            byte (*registerServer) = 0;
            int sizeRegisterServer = recvPacket(myGLSSocket, &registerServer, 1);
            if (sizeRegisterServer < 0) {
                
                /* Free memory */
                if (registerServer != NULL) {
                    
                    free(registerServer);
                    registerServer = 0;
                    
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Error size registerServer Connexion\n");
                printf("### sendPacket() End ###\n\n");
                #endif
                
                /* Closing socket */
                shutdown(myGLSSocket->m_sock, SHUT_RDWR);
                closesocket(myGLSSocket->m_sock);
                
                /* return error */
                return sizeRegisterServer;
                
            }
            
            /* Test if the message is a Register Server type */
            int messageType = getTypeGLS(registerServer, sizeRegisterServer);
            
            if (messageType == GLS_TYPE_REGISTER_SERVER) {
                
                /* We extract the certificate from the message Register Server */
                byte* serverCertificate = malloc((sizeRegisterServer - 25));
                int sizeServerCertificate = (sizeRegisterServer - 25);
                if (serverCertificate == NULL) {
                    
                    /* Free memory */
                    if (registerServer != NULL) {
                        
                        free(registerServer);
                        registerServer = 0;
                        
                    }
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("Error no memory\n");
                    printf("### sendPacket() End ###\n\n");
                    #endif
                    
                    /* Closing socket */
                    shutdown(myGLSSocket->m_sock, SHUT_RDWR);
                    closesocket(myGLSSocket->m_sock);
                    
                    /* Return error */
                    return GLS_ERROR_NOMEM;
                    
                }
                
                /* Copying certificate */
                int i = 0;
                for (i = 0; i < sizeServerCertificate; i++) {
                    
                    serverCertificate[i] = registerServer[25 + i];
                
                }
                
                /* Checking certificate validity */
                error = checkCertificate(myGLSSocket, serverCertificate, sizeServerCertificate);
                if (error != 0) {
                    
                    /* free memory */
                    if (registerServer != NULL) {
                        
                        free(registerServer);
                        registerServer = 0;
                        
                    }
                    if (serverCertificate != NULL) {
                        
                        free(serverCertificate);
                        serverCertificate = 0;
                        
                    }
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### sendPacket() End ###\n\n");
                    #endif
                    
                    /* Closing socket */
                    shutdown(myGLSSocket->m_sock, SHUT_RDWR);
                    closesocket(myGLSSocket->m_sock);
                    
                    /* return error */
                    return error;
                    
                }
                
                /* buffer encryption */
                byte *cipherText = 0;
                int sizeCipherText = encryptWithPK(serverCertificate, sizeServerCertificate, buffer, sizeBuffer, &cipherText);
                if (sizeCipherText <= 0) {
                    
                    /* Free memory */
                    if (registerServer != NULL) {
                        
                        free(registerServer);
                        registerServer = 0;
                        
                    }
                    if (serverCertificate != NULL) {
                        
                        free(serverCertificate);
                        serverCertificate = 0;
                        
                    }
                    if (cipherText != NULL) {
                        
                        free(cipherText);
                        cipherText = 0;
                        
                    }
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### sendPacket() End ###\n\n");
                    #endif
                    
                    /* Closing socket */
                    shutdown(myGLSSocket->m_sock, SHUT_RDWR);
                    closesocket(myGLSSocket->m_sock);
                    
                    /* Return error */
                    return sizeCipherText;
                    
                }
                
                /* Sending cipherText */
                error = sendPacket(myGLSSocket, cipherText, sizeCipherText);
                if (error < 0) {
                    
                    /* Free memory */
                    if (registerServer != NULL) {
                        
                        free(registerServer);
                        registerServer = 0;
                        
                    }
                    if (serverCertificate != NULL) {
                        
                        free(serverCertificate);
                        serverCertificate = 0;
                        
                    }
                    if (cipherText != NULL) {
                        
                        free(cipherText);
                        cipherText = 0;
                        
                    }
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### sendPacket() End ###\n\n");
                    #endif
                    
                    /* Closing socket */
                    shutdown(myGLSSocket->m_sock, SHUT_RDWR);
                    closesocket(myGLSSocket->m_sock);
                    
                    /* return error */
                    return error;
                    
                }
                
                /* Get message Register Server OK */
                byte (*registerServerOk) = 0;
                int sizeRegisterServerOk = recvPacket(myGLSSocket, &registerServerOk, 1);
                if (sizeRegisterServerOk < 0) {
                    
                    /* Free memory */
                    if (registerServer != NULL) {
                        
                        free(registerServer);
                        registerServer = 0;
                        
                    }
                    if (serverCertificate != NULL) {
                        
                        free(serverCertificate);
                        serverCertificate = 0;
                        
                    }
                    if (cipherText != NULL) {
                        
                        free(cipherText);
                        cipherText = 0;
                        
                    }
                    if (registerServerOk != NULL) {
                        
                        free(registerServerOk);
                        registerServerOk = 0;
                        
                    }
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### sendPacket() End ###\n\n");
                    #endif
                    
                    /* Closing socket */
                    shutdown(myGLSSocket->m_sock, SHUT_RDWR);
                    closesocket(myGLSSocket->m_sock);
                    
                    /* return error */
                    return sizeRegisterServerOk;
                    
                }
                
                /* Check message serveur is OK */
                if(getTypeGLS(registerServerOk, sizeRegisterServerOk) != GLS_TYPE_REGISTER_SERVER_OK) {
                    
                    /* Free memory */
                    if (registerServer != NULL) {
                        
                        free(registerServer);
                        registerServer = 0;
                        
                    }
                    if (serverCertificate != NULL) {
                        
                        free(serverCertificate);
                        serverCertificate = 0;
                        
                    }
                    if (cipherText != NULL) {
                        
                        free(cipherText);
                        cipherText = 0;
                        
                    }
                    if (registerServerOk != NULL) {
                        
                        free(registerServerOk);
                        registerServerOk = 0;
                        
                    }
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### sendPacket() End ###\n\n");
                    #endif
                    
                    /* Closing socket */
                    shutdown(myGLSSocket->m_sock, SHUT_RDWR);
                    closesocket(myGLSSocket->m_sock);
                    
                    /* return error */
                    return GLS_ERROR_REGISTERREFUSED;
                    
                }
                
                /* Free memory */
                if (serverCertificate != NULL) {
                    
                    free(serverCertificate);
                    serverCertificate = 0;
                    
                }
                if (cipherText != NULL) {
                    
                    free(cipherText);
                    cipherText = 0;
                    
                }
                if (registerServerOk != NULL) {
                    
                    free(registerServerOk);
                    registerServerOk = 0;
                    
                }

                
            }
            else if (messageType == GLS_TYPE_ERROR) {
                
                /* Get the error number */
                int messageError = getNumError(registerServer, sizeRegisterServer);
                
                /* Free memory */
                if (registerServer != NULL) {
                    
                    free(registerServer);
                    registerServer = 0;
                    
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### sendRegister() End ###\n\n");
                #endif
                
                /* Close socket */
                shutdown(myGLSSocket->m_sock, SHUT_RDWR);
                closesocket(myGLSSocket->m_sock);
                
                /* return the GLS error */
                switch (messageError) {
                        
                    case 100:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 101:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 102:
                        return GLS_ERROR_NOCERT;
                        break;
                        
                    case 200:
                        return GLS_ERROR_VERSION;
                        break;
                        
                    case 300:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 301:
                        return GLS_ERROR_BADSERVERCERT;
                        break;
                        
                    case 302:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 400:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 401:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 402:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 403:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 404:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 500:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    default:
                        return GLS_ERROR_UNKNOWN;
                        break;
                }
                
            }
            else error = GLS_ERROR_UNKNOWN;
            
            /* Free memory */
            if (registerServer != NULL) {
                
                free(registerServer);
                registerServer = 0;
                
            }
            
            /* Closing socket */
            shutdown(myGLSSocket->m_sock, SHUT_RDWR);
            closesocket(myGLSSocket->m_sock);
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### sendRegister() End ###\n\n");
            #endif
            
            if (error != 0) return GLS_ERROR_UNKNOWN;
            else return 0;
            
        }
        else {
            
            /* Debug only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Impossible to connect (WSADATA).\n");
            printf("### sendRegister() End ###\n\n");
            #endif
            
            /*
             * RETURN WINDOWS ERROR
             * Not yet implemented
             */
            
            return GLS_ERROR_UNKNOWN;
            
        }
        
    }
    else {
        
        /* Debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        if (myGLSSocket->m_certRoot == NULL) printf("No root certificate.\n");
        if (myGLSSocket->m_isSocketConfig == 1) printf("Socket already configured.\n");
        if (myGLSSocket->m_isHandShakeFinish == 1) printf("HandShake done.\n");
        #endif
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### sendRegister() End ###\n\n");
        #endif
        
        if (myGLSSocket->m_certRoot == NULL) return GLS_ERROR_NOCERT;
        else if (myGLSSocket->m_isSocketConfig == 1 || myGLSSocket->m_isHandShakeFinish == 1) return GLS_ERROR_ISCONN;
        else return GLS_ERROR_UNKNOWN;
        
    }
    
}




/*-------------------------------------------------------
 
 Set a pointer to a copy of the register message
 
 Return the size of the message or a negative number for 
 an error
 
 ---------------------------------------------------------*/

int getRegisterMessage(GLSSock* myGLSSocket, byte** message) {
    
    if (myGLSSocket->m_messageRegister != NULL && myGLSSocket->m_sizeMessageRegister > 0) {
        
        byte *temp = malloc(myGLSSocket->m_sizeMessageRegister);
        if (temp == NULL) return GLS_ERROR_NOMEM;
        
        int i = 0;
        for (i = 0; i < myGLSSocket->m_sizeMessageRegister; i++) {
            
            temp[i] = myGLSSocket->m_messageRegister[i];
            
        }
                
        (*message) = temp;
        
        return myGLSSocket->m_sizeMessageRegister;
        
    }
    else return GLS_ERROR_NOMESSAGE;
    
}




/*-------------------------------------------------------
 
 Connexion to a socket server
 
 Return 0 for success, a negative number for an error.
 
 ---------------------------------------------------------*/

int connexion(GLSSock* myGLSSocket, const char* address, const char* port) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### connexion() Start ###\n");
    #endif
    
     if (myGLSSocket->m_isSocketConfig == 0 && myGLSSocket->m_isHandShakeFinish == 0 && myGLSSocket->m_isUserConfig == 1 && myGLSSocket->m_isCryptoKey == 1) {
         
        /* Debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        myGLSSocket->m_isServeur = 0;
        #endif
         
        #if defined (win32)
        WSADATA WSAData;
        int erreur = WSAStartup(MAKEWORD(2,2), &WSAData);
        #else
        int erreur = 0;
        #endif
    
        /* If windows's socket works */
        if(erreur == 0) {
            
            /* Get user's ID */
            char (*userId) = 0;
            int sizeUserId = getUserId(myGLSSocket, &userId);
            if (sizeUserId < 1) {
                
                /* free memory if error */
                if (userId != NULL) {
                    
                    free(userId);
                    userId = 0;
                    
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### connexion() End ###\n\n");
                #endif
                
                /* return error */
                return GLS_ERROR_USERNOTCONF;
                
            }
            
            /* Memory allocation for Hello message (-1 for '\0') */
            byte (*messageHello) = malloc((16 + sizeUserId - 1) * sizeof(byte));
            
            /* Fill Hello message */
            char header[15] = "GLS/1.1 HELLO ";
            int i = 0;
            for (i = 0; i < 14; i++) {
                
                messageHello[i] = header[i];
                
            }
            i = 0;
            for (i = 0; i < (sizeUserId - 1); i++) {
                
                messageHello[i + 14] = userId[i];
                
            }
            /* Insertion CR at size -2 */
            messageHello[16 + (sizeUserId - 1) - 2] = 13;
            /* Insertion LF at size -1 */
            messageHello[16 + (sizeUserId - 1) - 1] = 10;
            
            /* Encryption message hello */
            byte (*cipherText) = 0;
            int sizeCipherText = firstEncrypt(myGLSSocket, messageHello, (16 + sizeUserId - 1), &cipherText);
            if (sizeCipherText < 0) {
                
                /* Free memory */
                if (userId != NULL) {
                    
                    free(userId);
                    userId = 0;
                    
                }
                if (messageHello != NULL) {
                    
                    free(messageHello);
                    messageHello = 0;
                    
                }
                if (cipherText != NULL) {
                    
                    free(cipherText);
                    cipherText = 0;
                    
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### connexion() End ###\n\n");
                #endif
                
                return sizeCipherText;
                
            }
            
            /* addrinfo configuration for getaddrinfo() */
            struct addrinfo hints;
            memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            
            /* Server address config */
            int erreur = getaddrinfo(address, port, &hints, &myGLSSocket->m_infoConnexion);
            if (erreur != 0){
                
                /* Free memory */
                if (userId != NULL) {
                    
                    free(userId);
                    userId = 0;
                    
                }
                if (messageHello != NULL) {
                    
                    free(messageHello);
                    messageHello = 0;
                    
                }
                if (cipherText != NULL) {
                    
                    free(cipherText);
                    cipherText = 0;
                    
                }
                
                /* Debug only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Impossible to config infoConnexion.\n");
                printf("### connexion() End ###\n\n");
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
            
            /* Socket creation */
            myGLSSocket->m_sock = socket(myGLSSocket->m_infoConnexion->ai_family, myGLSSocket->m_infoConnexion->ai_socktype, myGLSSocket->m_infoConnexion->ai_protocol);
            
            /* If connexion impossible */
            if(connect(myGLSSocket->m_sock, myGLSSocket->m_infoConnexion->ai_addr, myGLSSocket->m_infoConnexion->ai_addrlen) == SOCKET_ERROR) {
                
                /* get error */
                int numError = errno;
                
                /* free memory */
                if (userId != NULL) {
                    
                    free(userId);
                    userId = 0;
                    
                }
                if (messageHello != NULL) {
                    
                    free(messageHello);
                    messageHello = 0;
                    
                }
                if (cipherText != NULL) {
                    
                    free(cipherText);
                    cipherText = 0;
                    
                }
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Impossible de se connecter.\n");
                printf("Num error : %d\n", numError);
                printf("### connexion() End ###\n\n");
                #endif
                
                /* return connect error */
                switch (numError) {
                        
                    case EACCES :
                        return GLS_ERROR_ACCES;
                        break;
                        
                    case EPERM :
                        return GLS_ERROR_PERM;
                        break;
                        
                    case EADDRINUSE :
                        return GLS_ERROR_ADDRINUSE;
                        break;
                        
                    case EAFNOSUPPORT :
                        return GLS_ERROR_AFNOSUPPORT;
                        break;
                        
                    case EAGAIN :
                        return GLS_ERROR_AGAIN;
                        break;
                        
                    case EALREADY :
                        return GLS_ERROR_ALREADY;
                        break;
                        
                    case EBADF :
                        return GLS_ERROR_BADF;
                        break;
                        
                    case ECONNREFUSED :
                        return GLS_ERROR_CONNREFUSED;
                        break;
                        
                    case EHOSTDOWN :
                        return GLS_ERROR_HOSTDOWN;
                        break;
                        
                    case EFAULT :
                        return GLS_ERROR_FAULT;
                        break;
                        
                    case EINPROGRESS :
                        return GLS_ERROR_INPROGRESS;
                        break;
                    
                    case EINTR :
                        return GLS_ERROR_INTR;
                        break;
                        
                    case EISCONN :
                        return GLS_ERROR_ISCONN;
                        break;
                        
                    case ENETUNREACH :
                        return GLS_ERROR_NETUNREACH;
                        break;
                        
                    case ENOTSOCK :
                        return GLS_ERROR_NOTSOCK;
                        break;
                        
                    case ETIMEDOUT :
                        return GLS_ERROR_TIMEDOUT;
                        break;
                        
                    default:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                }
                                
            }
            
            /* Sending hello message */
            int error = sendPacket(myGLSSocket, messageHello, (16 + sizeUserId - 1));
            
            /* If impossible to send the message, return error */
            if (error < 0) {
                
                /* free memory */
                if (userId != NULL) {
                    
                    free(userId);
                    userId = 0;
                    
                }
                if (messageHello != NULL) {
                    
                    free(messageHello);
                    messageHello = 0;
                    
                }
                if (cipherText != NULL) {
                    
                    free(cipherText);
                    cipherText = 0;
                    
                }
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Impossible to send the packet.\n");
                printf("### connexion() End ###\n\n");
                #endif

                /* return error */
                return error;
                
            }
            
            
            /* Leave time for the server to process the request (getting password) */
            sleep(1);
            
            /* Send second message (encrypted) */
            error = sendPacket(myGLSSocket, cipherText, sizeCipherText);
            
            /* If impossible to send the message, return error */
            if (error < 0) {
                
                /* free memory */
                if (userId != NULL) {
                    
                    free(userId);
                    userId = 0;
                    
                }
                if (messageHello != NULL) {
                    
                    free(messageHello);
                    messageHello = 0;
                    
                }
                if (cipherText != NULL) {
                    
                    free(cipherText);
                    cipherText = 0;
                    
                }
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Impossible to send the packet.\n");
                printf("### connexion() End ###\n\n");
                #endif
                
                /* return error */
                return error;
                
            }
            
            /* First message reception */
            byte (*firstMessage) = 0;
            int sizeFirstMessage = recvPacket(myGLSSocket, &firstMessage, 1);
            if (sizeFirstMessage < 0) {
                
                /* free memory */
                if (userId != NULL) {
                    
                    free(userId);
                    userId = 0;
                    
                }
                if (messageHello != NULL) {
                    
                    free(messageHello);
                    messageHello = 0;
                    
                }
                if (cipherText != NULL) {
                    
                    free(cipherText);
                    cipherText = 0;
                    
                }
                if (firstMessage != NULL) {
                    
                    free(firstMessage);
                    firstMessage = 0;
                    
                }
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Error size firstMessage Connexion\n");
                printf("### connexion() End ###\n\n");
                #endif
                
                /* return error */
                return sizeFirstMessage;
                
            }
            
            /* Message decryption */
            byte (*helloServer) = 0;
            int sizeHelloServer = allDecrypt(myGLSSocket, firstMessage, sizeFirstMessage, &helloServer);
            if (sizeHelloServer < 0) {
                
                error = -1;
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Error Decrypt Connexion\n");
                #endif
                
            }
            /*
             * Check message type, if impossible to decrypt, it's used like
             * a plaintext message (error message).
             */
            int messageType = 0;
            if (error == 0) messageType = getTypeGLS(helloServer, sizeHelloServer);
            else messageType = getTypeGLS(firstMessage, sizeFirstMessage);
            
            if (messageType == GLS_TYPE_HELLO_SERVER) {
                
                /*
                 * Do something if it's ok.
                 * Normaly nothing needs to be done, it's just 
                 * in case (for a futur need).
                 */
            }
            else if (messageType == GLS_TYPE_ERROR) {
                
                /* Get the error (considering encryption) */
                int messageError = 1;
                if (error == 0) messageError = getNumError(helloServer, sizeHelloServer);
                else messageError = getNumError(firstMessage, sizeFirstMessage);
                
                /* Free memory */
                if (userId != NULL) {
                    
                    free(userId);
                    userId = 0;
                    
                }
                if (messageHello != NULL) {
                    
                    free(messageHello);
                    messageHello = 0;
                    
                }
                if (cipherText != NULL) {
                    
                    free(cipherText);
                    cipherText = 0;
                    
                }
                if (firstMessage != NULL) {
                    
                    free(firstMessage);
                    firstMessage = 0;
                    
                }
                if (helloServer != NULL) {
                    
                    free(helloServer);
                    helloServer = 0;
                    
                }
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### connexion() End ###\n\n");
                #endif
                
                /* Return GLS error */
                switch (messageError) {
                        
                    case 100:
                        return GLS_ERROR_BADPASSWD;
                        break;
                        
                    case 101:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 102:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 200:
                        return GLS_ERROR_VERSION;
                        break;
                        
                    case 300:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 301:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 302:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 400:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 401:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 402:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 403:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 404:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    case 500:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                    default:
                        return GLS_ERROR_UNKNOWN;
                        break;
                }
                
            }
            else error = -1;
            
            /* If no error, configuring the socket to say everything is ok */
            if (error == 0) {
                
                myGLSSocket->m_isHandShakeFinish = 1;
                myGLSSocket->m_isSocketConfig = 1;
                
            }
            
            /* free memory */
            if (userId != NULL) {
                
                free(userId);
                userId = 0;
                
            }
            if (messageHello != NULL) {
                
                free(messageHello);
                messageHello = 0;
                
            }
            if (cipherText != NULL) {
                
                free(cipherText);
                cipherText = 0;
                
            }
            if (firstMessage != NULL) {
                
                free(firstMessage);
                firstMessage = 0;
                
            }
            if (helloServer != NULL) {
                
                free(helloServer);
                helloServer = 0;
                
            }
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### connexion() End ###\n\n");
            #endif
            
            /* return error if one or 0 if success */
            if (error != 0) return GLS_ERROR_UNKNOWN;
            else return 0;
            
        }
        else {
            
            /* Debug only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Impossible to connect (WSADATA).\n");
            printf("### connexion() End ###\n\n");
            #endif
            
            /*
             * RETURN WINDOWS ERROR
             * not yet implemented
             */
            return GLS_ERROR_UNKNOWN;
            
        }
                  
     }
     else {
         
         /* Debug only */
         #if defined (GLS_DEBUG_MODE_ENABLE)
         if (myGLSSocket->m_isSocketConfig == 1) printf("Socket already config.\n");
         if (myGLSSocket->m_isHandShakeFinish == 1) printf("HandShake done.\n");
         if (myGLSSocket->m_isCryptoKey == 0) printf("No encryption key.\n");
         if (myGLSSocket->m_isUserConfig == 0) printf("No user id\n");
         #endif
         
         /* Debug Only */
         #if defined (GLS_DEBUG_MODE_ENABLE)
         printf("### connexion() End ###\n\n");
         #endif
         
         if (myGLSSocket->m_isSocketConfig == 1 || myGLSSocket->m_isHandShakeFinish == 1) return GLS_ERROR_ISCONN;
         else if (myGLSSocket->m_isCryptoKey == 0) return GLS_ERROR_NOPASSWD;
         else if (myGLSSocket->m_isUserConfig == 0) return GLS_ERROR_USERNOTCONF;
         else return GLS_ERROR_UNKNOWN;
     
     }
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Send packet over the network with size = GLS_SIZE_PACKET
 (configurable in GLSHeaders.h).
 
 Return 0 for success, a negative number for an error.
 
 ---------------------------------------------------------*/

int sendPacket(GLSSock* myGLSSocket, const byte* buffer, const int size) {
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### sendPacket() Start ###\n");
    if (myGLSSocket->m_isServeur) printf("Serveur - sendPacket() %d bytes\n", size);
    else printf("Client - sendPacket() %d bytes\n", size);
    #endif
    
    /* Block other send in other threads */
    pthread_mutex_lock(&myGLSSocket->m_mutexSendPacket);
    
    /* Check if we need to send one or more packets */
    if (size >= GLS_SIZE_PACKET) {
        
        /* Variables init */
        long sock_size = 0;
        byte temp[GLS_SIZE_PACKET];
        int y = 0;
        int sizeLeft = size;
        
        /* While it still content to send */
        while (sizeLeft > 0) {
            
            /* 
             * Check if it still more than one packet to send
             * or we create an array of the size left.
             */
            if (sizeLeft > GLS_SIZE_PACKET) {
                
                /* fill temp variable with buffer */
                int i = 0;
                for (i = 0; i < GLS_SIZE_PACKET; i++) {
                    
                    temp[i] = buffer[i + y * GLS_SIZE_PACKET]; 
                    
                }
                
                /* Debug only (a lot of printf, takes times) */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                usleep(10000);
                #endif
                
                /* if headers in packet are used */
                #if defined (GLS_HEADER_PACKET)
                sock_size = sendWithHeader(myGLSSocket->m_sock, temp, GLS_SIZE_PACKET, 0);
                #else
                /* Sending packet of GLS_SIZE_PACKET bytes */
                sock_size = send(myGLSSocket->m_sock, temp, GLS_SIZE_PACKET, 0);
                #endif

                if(sock_size == SOCKET_ERROR || sock_size == 0) {
                    
                    /* get error */
                    int numError = errno;
                    
                    /* Debug only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("Erreur de transmission sendPacket 1\n");
                    #endif
                    
                    /* deblock mutex to let other thread to use the funciton */
                    pthread_mutex_unlock(&myGLSSocket->m_mutexSendPacket);
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### sendPacket() End ###\n\n");
                    #endif
                    
                    /* return send error */
                    switch (numError) {
                            
                        case EACCES :
                            return GLS_ERROR_ACCES;
                            break;
                            
                        case EAGAIN :
                            return GLS_ERROR_AGAIN;
                            break;
                            
                        case EBADF :
                            return GLS_ERROR_BADF;
                            break;
                            
                        case ECONNRESET :
                            return GLS_ERROR_CONNRESET;
                            break;
                            
                        case EDESTADDRREQ :
                            return GLS_ERROR_DESTADDRREQ;
                            break;
                            
                        case EFAULT :
                            return GLS_ERROR_FAULT;
                            break;
                            
                        case EINTR :
                            return GLS_ERROR_INTR;
                            break;
                            
                        case EINVAL :
                            return GLS_ERROR_INVAL;
                            break;
                            
                        case EISCONN :
                            return GLS_ERROR_ISCONN;
                            break;
                            
                        case EMSGSIZE :
                            return GLS_ERROR_MSGSIZE;
                            break;
                            
                        case ENOBUFS :
                            return GLS_ERROR_NOBUFS;
                            break;
                            
                        case ENOMEM :
                            return GLS_ERROR_NOMEM;
                            break;
                            
                        case ENOTCONN :
                            return GLS_ERROR_NOTCONN;
                            break;
                            
                        case ENOTSOCK :
                            return GLS_ERROR_NOTSOCK;
                            break;
                        
                        case EOPNOTSUPP :
                            return GLS_ERROR_OPNOTSUPP;
                            break;
                            
                        case EPIPE :
                            return GLS_ERROR_PIPE;
                            break;
                            
                        default:
                            return GLS_ERROR_UNKNOWN;
                            break;
                            
                    }

                    
                } 
                
                /* remove send bytes from size left */
                y++;
                sizeLeft -= GLS_SIZE_PACKET;

            }
            else if (sizeLeft == GLS_SIZE_PACKET){
                
                /* fill temp var from buffer */
                int i = 0;
                for (i = 0; i < GLS_SIZE_PACKET; i++) {
                    
                    temp[i] = buffer[i + y * GLS_SIZE_PACKET]; 
                    
                }
                
                /* Debug only (a lot of printf) */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                usleep(10000);
                #endif
                
                /* if headers used */
                #if defined (GLS_HEADER_PACKET)
                sock_size = sendWithHeader(myGLSSocket->m_sock, temp, GLS_SIZE_PACKET, 0);
                #else
                /* Send packet of GLS_SIZE_PACKET bytes */
                sock_size = send(myGLSSocket->m_sock, temp, GLS_SIZE_PACKET, 0);
                #endif

                if(sock_size == SOCKET_ERROR || sock_size == 0) {
                    
                    /* get error */
                    int numError = errno;
                    
                    /* Debug only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("Erreur de transmission sendPacket 2\n");
                    #endif
                    
                    /* deblock mutex to let other thread to use the funciton */
                    pthread_mutex_unlock(&myGLSSocket->m_mutexSendPacket);
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### sendPacket() End ###\n\n");
                    #endif

                    /* return send error */
                    switch (numError) {
                            
                        case EACCES :
                            return GLS_ERROR_ACCES;
                            break;
                            
                        case EAGAIN :
                            return GLS_ERROR_AGAIN;
                            break;
                            
                        case EBADF :
                            return GLS_ERROR_BADF;
                            break;
                            
                        case ECONNRESET :
                            return GLS_ERROR_CONNRESET;
                            break;
                            
                        case EDESTADDRREQ :
                            return GLS_ERROR_DESTADDRREQ;
                            break;
                            
                        case EFAULT :
                            return GLS_ERROR_FAULT;
                            break;
                            
                        case EINTR :
                            return GLS_ERROR_INTR;
                            break;
                            
                        case EINVAL :
                            return GLS_ERROR_INVAL;
                            break;
                            
                        case EISCONN :
                            return GLS_ERROR_ISCONN;
                            break;
                            
                        case EMSGSIZE :
                            return GLS_ERROR_MSGSIZE;
                            break;
                            
                        case ENOBUFS :
                            return GLS_ERROR_NOBUFS;
                            break;
                            
                        case ENOMEM :
                            return GLS_ERROR_NOMEM;
                            break;
                            
                        case ENOTCONN :
                            return GLS_ERROR_NOTCONN;
                            break;
                            
                        case ENOTSOCK :
                            return GLS_ERROR_NOTSOCK;
                            break;
                            
                        case EOPNOTSUPP :
                            return GLS_ERROR_OPNOTSUPP;
                            break;
                            
                        case EPIPE :
                            return GLS_ERROR_PIPE;
                            break;
                            
                        default:
                            return GLS_ERROR_UNKNOWN;
                            break;
                            
                    }
                    
                }
                
                /* Debug only (a lot of printf) */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                usleep(10000);
                #endif
                
                /* Last packet, send EOF (only when packet = GLS_SIZE_PACKET) */
                /* If headers used */
                #if defined (GLS_HEADER_PACKET)
                sock_size = sendWithHeader(myGLSSocket->m_sock, (byte*) "EOF", 4, 0);
                #else
                sock_size = send(myGLSSocket->m_sock, "EOF", 4, 0);
                #endif

                if(sock_size == SOCKET_ERROR || sock_size == 0) {
                    
                    /* get error */
                    int numError = errno;
                    
                    /* Debug only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("Erreur de transmission sendPacket 3\n");
                    #endif
                    
                    /* deblock mutex to let other thread to use the funciton */
                    pthread_mutex_unlock(&myGLSSocket->m_mutexSendPacket);
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### sendPacket() End ###\n\n");
                    #endif

                    /* Return send error */
                    switch (numError) {
                            
                        case EACCES :
                            return GLS_ERROR_ACCES;
                            break;
                            
                        case EAGAIN :
                            return GLS_ERROR_AGAIN;
                            break;
                            
                        case EBADF :
                            return GLS_ERROR_BADF;
                            break;
                            
                        case ECONNRESET :
                            return GLS_ERROR_CONNRESET;
                            break;
                            
                        case EDESTADDRREQ :
                            return GLS_ERROR_DESTADDRREQ;
                            break;
                            
                        case EFAULT :
                            return GLS_ERROR_FAULT;
                            break;
                            
                        case EINTR :
                            return GLS_ERROR_INTR;
                            break;
                            
                        case EINVAL :
                            return GLS_ERROR_INVAL;
                            break;
                            
                        case EISCONN :
                            return GLS_ERROR_ISCONN;
                            break;
                            
                        case EMSGSIZE :
                            return GLS_ERROR_MSGSIZE;
                            break;
                            
                        case ENOBUFS :
                            return GLS_ERROR_NOBUFS;
                            break;
                            
                        case ENOMEM :
                            return GLS_ERROR_NOMEM;
                            break;
                            
                        case ENOTCONN :
                            return GLS_ERROR_NOTCONN;
                            break;
                            
                        case ENOTSOCK :
                            return GLS_ERROR_NOTSOCK;
                            break;
                            
                        case EOPNOTSUPP :
                            return GLS_ERROR_OPNOTSUPP;
                            break;
                            
                        case EPIPE :
                            return GLS_ERROR_PIPE;
                            break;
                            
                        default:
                            return GLS_ERROR_UNKNOWN;
                            break;
                            
                    }
                    
                }
                
                /* remove send bytes from size left */
                y++;
                sizeLeft -= GLS_SIZE_PACKET;
                
                /* Debug only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                if (myGLSSocket->m_isServeur) printf("Serveur - sendPacket(myGLSSocket, ) EOF\n");
                else printf("Client - sendPacket() EOF\n");
                #endif
                
            }
            else {
                
                /* Alloc memory of the buffer size */
                byte (*tempFinal) = malloc(sizeLeft * sizeof(byte));                
                if (tempFinal == NULL) {
                    
                    /* Debug only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("No memory sendPacket.\n");
                    #endif
                    
                    return GLS_ERROR_NOMEM;
                    
                }

                /* fill temp var from buffer */
                int i = 0;
                for (i = 0; i < sizeLeft; i++) {
                    
                    tempFinal[i] = buffer[i + y * GLS_SIZE_PACKET]; 
                    
                }
                
                /* Debug only (a lot of printf) */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                usleep(10000);
                #endif
                
                /* Send packet of sizeLeft bytes */
                /* If headers used */
                #if defined (GLS_HEADER_PACKET)
                sock_size = sendWithHeader(myGLSSocket->m_sock, tempFinal, sizeLeft, 0);
                #else
                /* Send packet of sizeLeft bytes */
                sock_size = send(myGLSSocket->m_sock, tempFinal, sizeLeft, 0);
                #endif

                if(sock_size == SOCKET_ERROR || sock_size == 0) {
                    
                    /* get error */
                    int numError = errno;
                    
                    /* free memory */
                    free(tempFinal);
                    tempFinal = 0;
                    
                    /* Debug only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("Erreur de transmission sendPacket 4\n");
                    #endif
                    
                    /* deblock mutex to let other thread to use the funciton */
                    pthread_mutex_unlock(&myGLSSocket->m_mutexSendPacket);
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### sendPacket() End ###\n\n");
                    #endif

                    /* Return send error */
                    switch (numError) {
                            
                        case EACCES :
                            return GLS_ERROR_ACCES;
                            break;
                            
                        case EAGAIN :
                            return GLS_ERROR_AGAIN;
                            break;
                            
                        case EBADF :
                            return GLS_ERROR_BADF;
                            break;
                            
                        case ECONNRESET :
                            return GLS_ERROR_CONNRESET;
                            break;
                            
                        case EDESTADDRREQ :
                            return GLS_ERROR_DESTADDRREQ;
                            break;
                            
                        case EFAULT :
                            return GLS_ERROR_FAULT;
                            break;
                            
                        case EINTR :
                            return GLS_ERROR_INTR;
                            break;
                            
                        case EINVAL :
                            return GLS_ERROR_INVAL;
                            break;
                            
                        case EISCONN :
                            return GLS_ERROR_ISCONN;
                            break;
                            
                        case EMSGSIZE :
                            return GLS_ERROR_MSGSIZE;
                            break;
                            
                        case ENOBUFS :
                            return GLS_ERROR_NOBUFS;
                            break;
                            
                        case ENOMEM :
                            return GLS_ERROR_NOMEM;
                            break;
                            
                        case ENOTCONN :
                            return GLS_ERROR_NOTCONN;
                            break;
                            
                        case ENOTSOCK :
                            return GLS_ERROR_NOTSOCK;
                            break;
                            
                        case EOPNOTSUPP :
                            return GLS_ERROR_OPNOTSUPP;
                            break;
                            
                        case EPIPE :
                            return GLS_ERROR_PIPE;
                            break;
                            
                        default:
                            return GLS_ERROR_UNKNOWN;
                            break;
                            
                    }
                    
                }
                
                /* free buffer */
                free(tempFinal);
                tempFinal = 0;
                
                /* Set sizeLeft = 0 */
                sizeLeft = 0;
                
            }
            
        }
        
    }
    else if(size > 0 && size < GLS_SIZE_PACKET) {
        
        /* Variables init */
        long sock_size = 0;
        
        /* allocate temp buffer of the element size to send */
        byte (*tempFinal) = malloc(size * sizeof(byte));
        if (tempFinal == NULL) {
            
            /* Debug only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No memory sendPacket.\n");
            #endif
            
            return GLS_ERROR_NOMEM;
            
        }
        
        /* Fill the temp array with the buffer */
        int i = 0;
        for (i = 0; i < size; i++) {
            
            tempFinal[i] = buffer[i]; 
            
        }
        
        /* Debug only (a lot of printf) */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        usleep(10000);
        #endif
        
        /* Sending packet of sizeLeft bytes */
        /* If headers configured */
        #if defined (GLS_HEADER_PACKET)
        sock_size = sendWithHeader(myGLSSocket->m_sock, tempFinal, size, 0);
        #else
        /* Sending packet of sizeLeft bytes */
        sock_size = send(myGLSSocket->m_sock, tempFinal, size, 0);
        #endif

        if(sock_size == SOCKET_ERROR || sock_size == 0) {
            
            /* Get error */
            int numError = errno;
            
            /* Free memory */
            free(tempFinal);
            tempFinal = 0;
            
            /* Debug only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Erreur de transmission sendPacket 5\n");
            #endif
            
            /* Unlock the mutex to permit to use the socket */
            pthread_mutex_unlock(&myGLSSocket->m_mutexSendPacket);
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### sendPacket() End ###\n\n");
            #endif

            /* Return send error */
            switch (numError) {
                    
                case EACCES :
                    return GLS_ERROR_ACCES;
                    break;
                    
                case EAGAIN :
                    return GLS_ERROR_AGAIN;
                    break;
                    
                case EBADF :
                    return GLS_ERROR_BADF;
                    break;
                    
                case ECONNRESET :
                    return GLS_ERROR_CONNRESET;
                    break;
                    
                case EDESTADDRREQ :
                    return GLS_ERROR_DESTADDRREQ;
                    break;
                    
                case EFAULT :
                    return GLS_ERROR_FAULT;
                    break;
                    
                case EINTR :
                    return GLS_ERROR_INTR;
                    break;
                    
                case EINVAL :
                    return GLS_ERROR_INVAL;
                    break;
                    
                case EISCONN :
                    return GLS_ERROR_ISCONN;
                    break;
                    
                case EMSGSIZE :
                    return GLS_ERROR_MSGSIZE;
                    break;
                    
                case ENOBUFS :
                    return GLS_ERROR_NOBUFS;
                    break;
                    
                case ENOMEM :
                    return GLS_ERROR_NOMEM;
                    break;
                    
                case ENOTCONN :
                    return GLS_ERROR_NOTCONN;
                    break;
                    
                case ENOTSOCK :
                    return GLS_ERROR_NOTSOCK;
                    break;
                    
                case EOPNOTSUPP :
                    return GLS_ERROR_OPNOTSUPP;
                    break;
                    
                case EPIPE :
                    return GLS_ERROR_PIPE;
                    break;
                    
                default:
                    return GLS_ERROR_UNKNOWN;
                    break;
                    
            }
            
        }
        
        /* Free buffer */
        free(tempFinal);
        tempFinal = 0;
        
    }
    else {
        
        /* Debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Erreur d'argument sendPacket\n");
        #endif
        
        /* Unlock the mutex allowing the socket use */
        pthread_mutex_unlock(&myGLSSocket->m_mutexSendPacket);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### sendPacket() End ###\n\n");
        #endif
        
        return GLS_ERROR_UNKNOWN;
        
    }
    
    /* Unlock the mutex allowing the socket use */
    pthread_mutex_unlock(&myGLSSocket->m_mutexSendPacket);

    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    if (myGLSSocket->m_isServeur) printf("Serveur - sendPacket() END\n");
    else printf("Client - sendPacket() END\n");
    printf("### sendPacket() End ###\n\n");
    #endif
    
    return 0;

}




/*-------------------------------------------------------
 
 PRIVATE
 
 Receive packet from the network by GLS_SIZE_PACKET bytes
 (configurable in GLSHeaders.h).

 Return 0 for success, a negative number for an error.
 
 ---------------------------------------------------------*/

int recvPacket(GLSSock* myGLSSocket, byte** buffer, const int withTimeout) {
        
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### recvPacket() Start ###\n");
    if (myGLSSocket->m_isServeur) printf("Server - recvPacket()\n");
    else printf("Client - recvPacket()\n");
    #endif
    
    /* Lock the mutex */
    pthread_mutex_lock(&myGLSSocket->m_mutexRecvPacket);
    
    /* Variables init */
    long sock_size = 0;
    byte temp[GLS_SIZE_PACKET];
    int size = 0;
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    if (myGLSSocket->m_isServeur) printf("Server - recvPacket() - Waiting...\n");
    else printf("Client - recvPacket() - Waiting...\n");
    #endif
    
    /* If we use a timeout for the waiting period */
    if (withTimeout == 1) {
        
        sock_size = recvWithTimeout(myGLSSocket->m_sock, temp, GLS_SIZE_PACKET, 0, GLS_TIMEOUT_PACKET);
        
    }
    else {
        
        /* If headers set */
        #if defined (GLS_HEADER_PACKET)
        sock_size = recvWithHeader(myGLSSocket->m_sock, temp, GLS_SIZE_PACKET, 0);
        #else
        /* Reception of the first packet (No MSG_WAITALL) */
        sock_size = recv(myGLSSocket->m_sock, temp, GLS_SIZE_PACKET, 0);
        #endif
    
    }
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Size recv recvPacket : %ld\n", sock_size);
    #endif
    
    if(sock_size == SOCKET_ERROR || sock_size == 0) {
        
        /* get error */
        int numError = errno;
        
        /* Debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error transmission recvPacket 1\n");
        #endif
        
        /* Unlock the mutex */
        pthread_mutex_unlock(&myGLSSocket->m_mutexRecvPacket);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### recvPacket() End ###\n\n");
        #endif
        
        /* Return recv error */
        switch (numError) {
                
            case EAGAIN :
                return GLS_ERROR_AGAIN;
                break;
                
            case EBADF :
                return GLS_ERROR_BADF;
                break;
                
            case ECONNREFUSED :
                return GLS_ERROR_CONNREFUSED;
                break;
                
            case EFAULT :
                return GLS_ERROR_FAULT;
                break;
                
            case EINTR :
                return GLS_ERROR_INTR;
                break;
                
            case EINVAL :
                return GLS_ERROR_INVAL;
                break;
                
            case ENOMEM :
                return GLS_ERROR_NOMEM;
                break;
                
            case ENOTCONN :
                return GLS_ERROR_NOTCONN;
                break;
                
            case ENOTSOCK :
                return GLS_ERROR_NOTSOCK;
                break;
                
            default:
                return GLS_ERROR_UNKNOWN;
                break;
                
        }
        
    }
    else if(sock_size == GLS_ERROR_TIMEDOUT) {
        
        /* Debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error TimeOut recvPacket 1\n");
        #endif
        
        /* Unlock the mutex */
        pthread_mutex_unlock(&myGLSSocket->m_mutexRecvPacket);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### recvPacket() End ###\n\n");
        #endif
        
        return GLS_ERROR_TIMEDOUT;
        
    }
    
    /* Total size of buffer */
    size += (int)sock_size;
    
    /* If the packet isn't smaller than GLS_SIZE_PACKET there will be
       others to receive */
    if (!(size < GLS_SIZE_PACKET)) {
        
        /* Creating and filling the buffer with the first packet */
        *buffer = malloc(size * sizeof(byte));
        if (*buffer == NULL) {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No memory recvPacket\n");
            #endif
            
            return GLS_ERROR_NOMEM;
            
        }
        int i = 0;
        for (i = 0; i < size; i++) {
            
            (*buffer)[i] = temp[i];
            
        }
        
        /* While we are receiving packets */
        while (sock_size == GLS_SIZE_PACKET) {
            
            sock_size = recvWithTimeout(myGLSSocket->m_sock, temp, GLS_SIZE_PACKET, 0, GLS_TIMEOUT_PACKET);
            
            if(sock_size == SOCKET_ERROR || sock_size == 0) {
                
                /* Getting error */
                int numError = errno;
                
                /* Debug only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Error transmission recvPacket 2\n");
                #endif
                
                /* Unlock the mutex */
                pthread_mutex_unlock(&myGLSSocket->m_mutexRecvPacket);
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### recvPacket() End ###\n\n");
                #endif
                
                /* Return recv error */
                switch (numError) {
                        
                    case EAGAIN :
                        return GLS_ERROR_AGAIN;
                        break;
                        
                    case EBADF :
                        return GLS_ERROR_BADF;
                        break;
                        
                    case ECONNREFUSED :
                        return GLS_ERROR_CONNREFUSED;
                        break;
                        
                    case EFAULT :
                        return GLS_ERROR_FAULT;
                        break;
                        
                    case EINTR :
                        return GLS_ERROR_INTR;
                        break;
                        
                    case EINVAL :
                        return GLS_ERROR_INVAL;
                        break;
                        
                    case ENOMEM :
                        return GLS_ERROR_NOMEM;
                        break;
                        
                    case ENOTCONN :
                        return GLS_ERROR_NOTCONN;
                        break;
                        
                    case ENOTSOCK :
                        return GLS_ERROR_NOTSOCK;
                        break;
                        
                    default:
                        return GLS_ERROR_UNKNOWN;
                        break;
                        
                }
                
            }
            else if(sock_size == GLS_ERROR_TIMEDOUT) {
                
                /* Debug only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("Erreur TimeOut recvPacket 2\n");
                #endif
                
                /* Unlock the mutex */
                pthread_mutex_unlock(&myGLSSocket->m_mutexRecvPacket);
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### recvPacket() End ###\n\n");
                #endif
                
                return GLS_ERROR_TIMEDOUT;
                
            }
            
            /* If the packet's size is 4 bytes we check for a 
             EOF signal */
            if (sock_size == 4) {
                /* Creation of the EOF signal */
                char eof[4] = "EOF";
                
                /* bytes check */
                int i = 0;
                while (temp[i] == eof[i] && i < 4) {
                    
                    i++;
                    
                }
                /* If the signal is EOF we return the size and 
                 exit the funtion */
                if (i == 4) {
                    
                    /* Unlock the mutex */
                    pthread_mutex_unlock(&myGLSSocket->m_mutexRecvPacket);
                    
                    /* Debug only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    if (myGLSSocket->m_isServeur) printf("Server - recvPacket() EOF\n");
                    else printf("Client - recvPacket() EOF\n");
                    #endif

                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### recvPacket() End ###\n\n");
                    #endif
                    
                    return size;
                    
                }
            }
            
            /* Total actual buffer size */
            size += (int)sock_size;
            
            /* Creating a temp buffer to store all the packets */
            byte (*bufferTemp) = malloc(size * sizeof(byte));
            if (bufferTemp == NULL) {
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("No memory. recvPacket\n");
                #endif
                
                return GLS_ERROR_NOMEM;
                
            }
            /* Copying old packets in the temp buffer */
            int i = 0;
            for (i = 0; i < (size - (int)sock_size); i++) {
                
                bufferTemp[i] = (*buffer)[i];
                
            }
            /* Copying the new packet in the temp buffer */
            i = 0;
            for (i = 0; i < (int)sock_size; i++) {
                
                bufferTemp[i + (size - (int)sock_size)] = temp[i];
                
            }
            
            /* Free the old buffer and alloc a new one with the actual size */
            free(*buffer);
            *buffer = malloc(size * sizeof(byte));
            if (*buffer == NULL) {
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("No memory. recvPacket\n");
                #endif
                
                return GLS_ERROR_NOMEM;
                
            }
            
            /* Copying the temp buffer into the buffer and freeing bufferTemp */
            /* Remove for optimization and directly set buffer with bufferTemp pointer value */
            i = 0;
            for (i = 0; i < size; i++) {
                
                (*buffer)[i] = bufferTemp[i];
                
            }
            
            /* Free memory */
            free(bufferTemp);
            bufferTemp = 0;

        }
        
    }
    else {
        
        /* If there is only one packet we allocate the buffer */
        *buffer = malloc(size * sizeof(byte));
        if (*buffer == NULL) {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No memory recvPacket\n");
            #endif
            
            return GLS_ERROR_NOMEM;
            
        }
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("recvPacket() - Buffer < %d bytes\n", GLS_SIZE_PACKET);
        printf("Buffer : ");
        sleep(1);
        #endif                
        int i = 0;
        for (i = 0; i < size; i++) {
                
            (*buffer)[i] = temp[i];
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("%c", temp[i]);
            #endif
                
        }
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("\n");
        #endif
        
    }
    
    /* Unlock mutex */
    pthread_mutex_unlock(&myGLSSocket->m_mutexRecvPacket);
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    if (myGLSSocket->m_isServeur == 1) printf("Server - recvPacket() END\n");
    else printf("Client - recvPacket() END\n");
    printf("### recvPacket() End ###\n\n");
    #endif
    
    return size;
    
}
   



/*-------------------------------------------------------
 
 Send a message using the secure connexion. You can use this function
 on a thread.
 
 Return the message's size send or a negative number for an error.
 
 ---------------------------------------------------------*/

int glsSend(GLSSock* myGLSSocket, const byte* buffer, const int sizeBuffer){
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### glsSend() Start ###\n");
    #endif
    
    /* Check if connexion is ok */
    if (myGLSSocket->m_isSocketConfig == 1 && myGLSSocket->m_isHandShakeFinish == 1) {

        /* Lock mutex for threading */
        pthread_mutex_lock(&myGLSSocket->m_mutexGlsSend);
        
        #if defined (GLS_DEBUG_TIME_MODE_ENABLE)
        struct timeval sTime;
        gettimeofday(&sTime, NULL);
        /* ProcessTime example */
        struct timeval startTime;
        struct timeval endTime;
        /*structure for rusage */
        struct rusage ru;
        /* get the current time
         - RUSAGE_SELF for current process
         - RUSAGE_CHILDREN for *terminated* subprocesses */
        getrusage(RUSAGE_SELF, &ru);
        startTime = ru.ru_utime;
        #endif
        
       
        /* Buffer encryption */
        byte (*cipherText) = 0;
        int sizeCipherText = allEncrypt(myGLSSocket, buffer, sizeBuffer, &cipherText);
        
        #if defined (GLS_DEBUG_TIME_MODE_ENABLE)
        struct timeval eTime;
        gettimeofday(&eTime, NULL);
        double tS = sTime.tv_sec*1000000 + (sTime.tv_usec);
        double tE = eTime.tv_sec*1000000  + (eTime.tv_usec);
        printf("Time for total encryption (Clock) : %f microSeconds\n", tE - tS);
        printf("Speed Encryption (Clock) : %f Mo/s\n", (sizeBuffer / 1000) / ((tE - tS) / 1000));
        /* get the end time */
        getrusage(RUSAGE_SELF, &ru);
        endTime = ru.ru_utime;
        /* calculate time in microseconds */
        tS = startTime.tv_sec*1000000 + (startTime.tv_usec);
        tE = endTime.tv_sec*1000000  + (endTime.tv_usec);
        printf("Time for total encryption (CPU) : %f microSeconds\n", tE - tS);
        printf("Speed Encryption (CPU) : %f Mo/s\n", (sizeBuffer / 1000) / ((tE - tS) / 1000));
        #endif
        
        if (sizeCipherText < 0) {
            
            /* Free memory */
            if (cipherText != NULL) {
                free(cipherText);
                cipherText = 0;
            }
            
            /* Unlock mutex for threading */
            pthread_mutex_unlock(&myGLSSocket->m_mutexGlsSend);
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### glsSend() End ###\n\n");
            #endif
            
            return sizeCipherText;
        
        }
        
        /* Send message */
        int nbEssai = 0;
        int error = -1;
        while (error != 0 && nbEssai < 3) {
            
            /* Debug only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            if (myGLSSocket->m_isServeur) printf("Server - glsSend() sendPacket\n");
            else printf("Client - glsSend() sendPacket\n");
            #endif
            
            /* Send message */
            error = sendPacket(myGLSSocket, cipherText, sizeCipherText);
            if (error < 0) {
                
                /* Free memory */
                if (cipherText != NULL) {
                    free(cipherText);
                    cipherText = 0;
                }
                
                /* Unlock mutex for threading */
                pthread_mutex_unlock(&myGLSSocket->m_mutexGlsSend);
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### glsSend() End ###\n\n");
                #endif
                
                return error;
            
            }
            
            /* Debug only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            if (myGLSSocket->m_isServeur) printf("Server - glsSend() receive confirm\n");
            else printf("Client - glsSend() receive confirm\n");
            #endif
            
            /* Waiting for the acknowledgement of receipt with timeout */
            byte (*okMessage) = 0;
            int sizeOkMessage = recvPacket(myGLSSocket, &okMessage, 1);
            if (sizeOkMessage < 0) {
                
                /* On vide la mémoire */
                if (cipherText != NULL) {
                    free(cipherText);
                    cipherText = 0;
                }
                if (okMessage != NULL) {
                    free(okMessage);
                    okMessage = 0;
                }
                
                /* Unlock the mutex for threading */
                pthread_mutex_unlock(&myGLSSocket->m_mutexGlsSend);
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### glsSend() End ###\n\n");
                #endif
                
                return sizeOkMessage;
                
            }
            
            /* If any problem occured during the transmission we send
               the message again */
            if (sizeOkMessage > 0 && okMessage[0] == 1) error = 0;
            else error = -1;
            
            nbEssai++;
            
            /* Free memory */
            if (okMessage != NULL) {
                free(okMessage);
                okMessage = 0;
            }
            
        }
        
        /* Free memory */
        if (cipherText != NULL) {
            free(cipherText);
            cipherText = 0;
        }
        
        /* If there is always an error after 3 attempt we return
           an error. IVs will be desynchronized */
        if (error != 0) {
            
            /* Unlock the mutex */
            pthread_mutex_unlock(&myGLSSocket->m_mutexGlsSend);
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### glsSend() End ###\n\n");
            #endif
            
            return GLS_ERROR_IVDESYNC;
        
        }
        else {
            
            /* Unlock the mutex */
            pthread_mutex_unlock(&myGLSSocket->m_mutexGlsSend);
            
            /* Debug only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            if (myGLSSocket->m_isServeur) printf("Server - glsSend() finish OK\n");
            else printf("Client - glsSend() finish OK\n");
            printf("### glsSend() End ###\n\n");
            #endif
            
            /* Return packet's size */
            return error;
            
        }
        
    }
    else {
        
        /* We don't unlock the mutex because it's only lock
         if the condition is true */
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### glsSend() End ###\n\n");
        #endif
                
        if (myGLSSocket->m_isSocketConfig == 0 || myGLSSocket->m_isHandShakeFinish == 0) return GLS_ERROR_NOTCONN;
        else return GLS_ERROR_UNKNOWN;
    
    }

}




/*-------------------------------------------------------
 
 Wait for a message, you can use this function on a thread.
 You are responsible for deallocating the buffer with free().
 
 Return the size of the received message or a negative 
 number for an error.
 
 ---------------------------------------------------------*/

int glsRecv(GLSSock* myGLSSocket, byte** buffer){
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### glsRecv() Start ###\n");
    #endif
    
    /* Check if the connexion is ok */
    if (myGLSSocket->m_isSocketConfig == 1 && myGLSSocket->m_isHandShakeFinish == 1) {
        
        /* Lock mutex */
        pthread_mutex_lock(&myGLSSocket->m_mutexGlsRecv);
        
        /* Receive message */
        int nbEssai = 0;
        int error = -1;
        while (error != 0 && nbEssai < 3) {
            
            /* Debug only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            if (myGLSSocket->m_isServeur) printf("Server - glsRecV() recvPacket\n");
            else printf("Client - glsRecv() recvPacket\n");
            #endif
            
            /* Receive the encrypted message without timeout (Blocking mode) */
            byte (*cipherMessage) = 0;
            int sizeCipherMessage = recvPacket(myGLSSocket, &cipherMessage, 0);
            if (sizeCipherMessage < 0) {
                
                /* Free memory */
                if (cipherMessage != NULL) {
                    free(cipherMessage);
                    cipherMessage = 0;
                }
                
                /* Unlock mutex */
                pthread_mutex_unlock(&myGLSSocket->m_mutexGlsRecv);
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### glsRecv() End ###\n\n");
                #endif
                
                return sizeCipherMessage;
                
            }
            
            #if defined (GLS_DEBUG_TIME_MODE_ENABLE)
            struct timeval sTime;
            gettimeofday(&sTime, NULL);
            #endif

            /* Message decryption */
            byte (*plainTextMessage) = 0;
            int sizePlainTextMessage = allDecrypt(myGLSSocket, cipherMessage, sizeCipherMessage, &plainTextMessage);
            
            #if defined (GLS_DEBUG_TIME_MODE_ENABLE)
            struct timeval eTime;
            gettimeofday(&eTime, NULL);
            double tS = sTime.tv_sec*1000000 + (sTime.tv_usec);
            double tE = eTime.tv_sec*1000000  + (eTime.tv_usec);
            printf("Time for total decryption : %f microSeconds\n", tE - tS);
            printf("Speed Decryption : %f Mo/s\n", (sizeCipherMessage / 1000) / ((tE - tS) / 1000));
            #endif
            
            if (sizePlainTextMessage == GLS_ERROR_MAC) {
                
                /* Debug only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                if (myGLSSocket->m_isServeur) printf("Serveur - glsRecV() sendPacket error MAC\n");
                else printf("Client - glsRecv() sendPacket error MAC\n");
                #endif
                
                /* If MAC error we ask for another message */
                byte returnMessage[1];
                returnMessage[0] = 2;
                error = sendPacket(myGLSSocket, returnMessage, 1);
                if (error < 0) {
                    
                    /* Free memory */
                    if (cipherMessage != NULL) {
                        free(cipherMessage);
                        cipherMessage = 0;
                    }
                    if (plainTextMessage != NULL) {
                        free(plainTextMessage);
                        plainTextMessage = 0;
                    }
                    
                    /* Unlock mutex */
                    pthread_mutex_unlock(&myGLSSocket->m_mutexGlsRecv);
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### glsRecv() End ###\n\n");
                    #endif
                    
                    return error;
                    
                }
                
                /* Configuring error to do another time the while */
                error = -1;
            
            }
            else if (sizePlainTextMessage < 0) {
                
                /* Free memory */
                if (cipherMessage != NULL) {
                    free(cipherMessage);
                    cipherMessage = 0;
                }
                if (plainTextMessage != NULL) {
                    free(plainTextMessage);
                    plainTextMessage = 0;
                }
                
                /* Unlock mutex */
                pthread_mutex_unlock(&myGLSSocket->m_mutexGlsRecv);
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("### glsRecv() End ###\n\n");
                #endif
                
                return sizePlainTextMessage;
                
            }
            else {
                
                /* Debug only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                if (myGLSSocket->m_isServeur) printf("Server - glsRecV() sendPacket OK\n");
                else printf("Client - glsRecv() sendPacket OK\n");
                #endif
                
                /* If the message is goog we send back an ok message */
                byte okMessage[1];
                okMessage[0] = 1;
                error = sendPacket(myGLSSocket, okMessage, 1);
                if (error < 0) {
                    
                    /* Free memory */
                    if (cipherMessage != NULL) {
                        free(cipherMessage);
                        cipherMessage = 0;
                    }
                    if (plainTextMessage != NULL) {
                        free(plainTextMessage);
                        plainTextMessage = 0;
                    }
                    
                    /* Unlock mutex */
                    pthread_mutex_unlock(&myGLSSocket->m_mutexGlsRecv);
                    
                    /* Debug Only */
                    #if defined (GLS_DEBUG_MODE_ENABLE)
                    printf("### glsRecv() End ###\n\n");
                    #endif
                    
                    return error;
                    
                }
                
                /* Copy plaintext into the buffer */
                *buffer = plainTextMessage;
                plainTextMessage = 0;
                
                /* Free memory except plainTextMessage used by the buffer pointer */
                if (cipherMessage != NULL) {
                    free(cipherMessage);
                    cipherMessage = 0;
                }
                
                /* Unlock mutex */
                pthread_mutex_unlock(&myGLSSocket->m_mutexGlsRecv);
                
                /* Debug only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                if (myGLSSocket->m_isServeur) printf("Server - glsRecV() finish OK\n");
                else printf("Client - glsRecv() finish OK\n");
                printf("### glsRecv() End ###\n\n");
                #endif
                
                return sizePlainTextMessage;
                
            }
            
            nbEssai++;
            
            /* Free memory */
            if (cipherMessage != NULL) {
                free(cipherMessage);
                cipherMessage = 0;
            }
            if (plainTextMessage != NULL) {
                free(plainTextMessage);
                plainTextMessage = 0;
            }
            
        }
        
        /* Unlock mutex */
        pthread_mutex_unlock(&myGLSSocket->m_mutexGlsRecv);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### glsRecv() End ###\n\n");
        #endif
        
        return GLS_ERROR_IVDESYNC;
        
    }
    else {
        
        /* We don't unlock the mutex because it's only lock
         if the condition is true */
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### glsRecv() End ###\n\n");
        #endif
        
        if (myGLSSocket->m_isSocketConfig == 0 || myGLSSocket->m_isHandShakeFinish == 0) return GLS_ERROR_NOTCONN;
        else return GLS_ERROR_UNKNOWN;
    
    }
    
}




/*-------------------------------------------------------
 
 Add user's password, you can have 10 different password.
 If the password is already in SHA-512, use the function 
 with isSha = 1. Maximum password's length => 60 bytes.
 
 Return 0 for success, a negative number for an error.
 
 ---------------------------------------------------------*/

int addKey(GLSSock* myGLSSocket, const char* key, int isSha){
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### addKey() Start ###\n");
    #endif
    
    /* Check that the number of passwords isn't the maximum allowed (10) */
    int sizeKeys = myGLSSocket->m_sizeKeys;
    if(sizeKeys > 10) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Too many keys (max 10).\n");
        printf("### addKey() End ###\n\n");
        #endif
        
        return GLS_ERROR_TOMANYKEY;
        
    }

    /* If the char array is already a hash we convert it and insert it on 
       the array. Otherwise we hash it and insert it. */
    if(isSha == 1) {
        
        /* Read only the 512 first bits (or 127 bytes) */
        if (strlen(key) >= 127) {
            
            /* Secure memory allocation for the encryption key */
            byte (*keyToAdd) = (byte*) gcry_malloc_secure(64);
            if (keyToAdd == NULL) {
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("No memory. addKey()\n");
                #endif
                
                return GLS_ERROR_NOMEM;
                
            }
            
            /* Secure allocation for the temp memory */
            char *temp = (char*) gcry_malloc_secure(3);
            if (temp == NULL) {
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("No memory. addKey()\n");
                #endif
                
                return GLS_ERROR_NOMEM;                
            }
            
            /* Hash conversion (hexadecimal) in bytes */
            int i = 0;
            for (i = 0; i < 128; i += 2) {
                
                temp[0] = key[i];
                temp[1] = key[i + 1];
                temp[2] = '\0';
                keyToAdd[i / 2] = strtoul(temp, 0, 16);
                
            }
                              
            /* Add the encryption key to the socket's array */
            addKeyToArray(keyToAdd, &myGLSSocket->m_keys, &myGLSSocket->m_sizeKeys);
            
            /* Wipe the temp variable (not keyToAdd because used in the socket's array) */
            i = 0;
            for (i = 0; i < 3; i++) {
                temp[i] = 0;
                temp[i] = 1;
                temp[i] = 2;
            }
            gcry_free(temp);
            temp = 0;

        }
        else {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Bad size key.\n");
            printf("### addKey() End ###\n\n");
            #endif
            
            return GLS_ERROR_BADSIZEKEY;
            
        }
            
    }
    else {
        
        /* If the SHA-512 algorithm isn't available return an error */
        if(!gcry_md_test_algo(GCRY_MD_SHA512)) {
            
            /* Secure memory allocation of the encryption key */
            byte (*keyToAdd) = (byte*) gcry_malloc_secure(64);
            if (keyToAdd == NULL) {
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("No memory. addKey()\n");
                #endif
                
                return GLS_ERROR_NOMEM;
                
            }
            
            /* Get the password's size, we limit it at 60 bytes */
            int sizeKey = (int) strlen(key);
            if (sizeKey > 60) sizeKey = 60;
            
            /* Hash the password */
            gcry_md_hash_buffer(GCRY_MD_SHA512, keyToAdd, key, sizeKey);
           
            /* Add the key into the socket's array */
            int errorNum = addKeyToArray(keyToAdd, &myGLSSocket->m_keys, &myGLSSocket->m_sizeKeys);
            if (errorNum < 0) return errorNum;
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("m_keys : %p\n", myGLSSocket->m_keys);
            #endif
        
        }
        else {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Algorithme SHA-512 not available.\n");
            printf("### addKey() End ###\n\n");
            #endif
            
            return GLS_ERROR_CRYPTO;
            
        }
        
    }
    
    /* Get the array's size */
    sizeKeys = myGLSSocket->m_sizeKeys;
    
    /* Check if multiple hashes to generate the final hash otherwise copy
       the first element to be the final encryption key */
    if (sizeKeys > 1) {
        
        /* Generate the encryption key1 and key2 from the socket's array hashes */
        /* Total temp variable size */
        sizeKeys*= 64;
        
        /* Secure memory allocation */
        byte (*tempKey) = (byte*) gcry_malloc_secure(sizeKeys);
        if (tempKey == NULL) {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No memory. addKey()\n");
            #endif
            
            return GLS_ERROR_NOMEM;
            
        }

        int position = 0;
        
        /* add all the hashes into the temp variable */
        int i = 0;
        for(i = 0; i < myGLSSocket->m_sizeKeys; i++)
        {
            byte* myKey = (byte*) myGLSSocket->m_keys[i];
            
            int y = 0;
            for (y = 0; y < 64; y++) {
                
                tempKey[y + position * 64] = myKey[y]; 
                
            }
            
            position++;
            
        }
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Recuperation des clés OK\n");
        #endif
        
        /* Key hash */
        /* If the SHA-512 algorithm isn't available return an error */
        if(!gcry_md_test_algo(GCRY_MD_SHA512)) {
            
            /* Secure memory allocation for the final encryption key */
            byte (*finalKey) = (byte*) gcry_malloc_secure(64);
            if (finalKey == NULL) {
                
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("No memory. addKey()\n");
                #endif
                
                return GLS_ERROR_NOMEM;
                
            }
            
            /* Hash the temp variable */            
            gcry_md_hash_buffer(GCRY_MD_SHA512, finalKey, tempKey, sizeKeys);
            
            /* Fill key1 */
            int i = 0;
            for (i = 0; i < 32; i++) {
                
                myGLSSocket->m_key1[i] = finalKey[i]; 
                
            }
            
            /* Fill key2 */
            i = 0;
            for (i = 0; i < 32; i++) {
                
                myGLSSocket->m_key2[i] = finalKey[i + 32]; 
                
            }
            
            /* Wipe variable */
            i = 0;
            for (i = 0; i < 64; i++) {
                finalKey[i] = 0;
                finalKey[i] = 1;
                finalKey[i] = 2;
            }
            
            /* Free finalKey */
            gcry_free(finalKey);
            finalKey = 0;
            
        }
        else {
            
            /* Wipe variable */
            int i = 0;
            for (i = 0; i < sizeKeys; i++) {
                tempKey[i] = 0;
                tempKey[i] = 1;
                tempKey[i] = 2;
            }
            
            /* Free tempKey */
            gcry_free(tempKey);
            tempKey = 0;
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Algorithme SHA-512 not available.\n");
            printf("### addKey() End ###\n\n");
            #endif
            
            return GLS_ERROR_CRYPTO;
            
        }
        
        /* Wipe temp variable */
        i = 0;
        for (i = 0; i < sizeKeys; i++) {
            tempKey[i] = 0;
            tempKey[i] = 1;
            tempKey[i] = 2;
        }
        
        /* Free tempKey */
        gcry_free(tempKey);
        tempKey = 0;
        
    }
    else if(sizeKeys == 1) {
        
        /* Use the only hash available as encryption key */
        byte *finalKey;
        finalKey = (byte*) myGLSSocket->m_keys[0];

       /* Fill key1 */
        int i = 0;
        for (i = 0; i < 32; i++) {
            
            myGLSSocket->m_key1[i] = finalKey[i]; 
            
        }
        
        /* Fill key2 */
        i = 0;
        for (i = 0; i < 32; i++) {
            
            myGLSSocket->m_key2[i] = finalKey[i + 32]; 
            
        }
        
        /* No wipe and free because memory in use */
        
    }
    else {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No saved key.\n");
        printf("### addKey() End ###\n\n");
        #endif
        
        return GLS_ERROR_UNKNOWN;
        
    }
    
    /* Configure the socket to say that an encryption key is available */
    myGLSSocket->m_isCryptoKey = 1;
    
    /* Inititialize encryption handlers with the generated keys */
    int errorHandler = initHandler(myGLSSocket);
    if (errorHandler != 0) return errorHandler;
    
    /* Keys Printf for debug */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Key1 : ");
    int i = 0;
    for (i = 0; i < 32; i++) {
        
        printf("%2X",  myGLSSocket->m_key1[i]);
        
    }
    printf("\n");
    printf("Key2 : ");
    i = 0;
    for (i = 0; i < 32; i++) {
        
        printf("%2X",  myGLSSocket->m_key2[i]);
        
    }
    printf("\n");
    printf("### addKey() End ###\n\n");
    #endif
    
    return 0;
    
}




/*-------------------------------------------------------
 
 Remove all the key add by addKey().
 
 Return 0 for success, a negative number for an error.
 
 ---------------------------------------------------------*/

int clearKey(GLSSock* myGLSSocket){
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### clearKey() Start ###\n");
    #endif
    
    if (myGLSSocket->m_isCryptoKey == 1) {
        
        /* Keys wipe */
        /* Iteration of all the keys and wipe */
        int i = 0;
        for(i = 0; i < myGLSSocket->m_sizeKeys; i++)
        {
            
            byte* myKey = (byte*) myGLSSocket->m_keys[i];
            
            int y = 0;
            for (y = 0; y < 64; y++) {
                
                myKey[y] = 0; 
                myKey[y] = 1; 
                myKey[y] = 2; 
                
            }
            gcry_free(myKey);
            myKey = 0;

        }
        /* Free the key array */
        free(myGLSSocket->m_keys);
        myGLSSocket->m_keys = 0;
        myGLSSocket->m_sizeKeys = 0;
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Wipe key array\n");
        #endif
        
        /* Wipe key1 */
        i = 0;
        for (i = 0; i < 32; i++) {
            myGLSSocket->m_key1[i] = 0;
            myGLSSocket->m_key1[i] = 1;
            myGLSSocket->m_key1[i] = 2;
        }
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Wipe key1\n");
        #endif
        
        /* Wipe key2 */
        i = 0;
        for (i = 0; i < 32; i++) {
            myGLSSocket->m_key2[i] = 0;
            myGLSSocket->m_key2[i] = 1;
            myGLSSocket->m_key2[i] = 2;
        }
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Wipe key2\n");
        #endif
        
        /* Configure the socket to say that there isn't any encryption key */
        myGLSSocket->m_isCryptoKey = 0;
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### clearKey() End ###\n\n");
        #endif
        
        return 0;
        
    }
    else {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### clearKey() End ###\n\n");
        #endif
            
        return GLS_ERROR_NOPASSWD;
        
    }
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Reception Socket with Timeout
 
 ---------------------------------------------------------*/

ssize_t recvWithTimeout(const int socket, byte *buffer, const ssize_t size, const int flag, const int timeout) {
    
    /* Local variable */
    fd_set fds;
    int error;
    struct timeval tv;
    
    /* Selectors configuration */
    FD_ZERO(&fds);
    FD_SET(socket, &fds);
    
    /* Timeout configuration */
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    
    /* Waiting for data or a timeout */
    error = select(socket + 1, &fds, NULL, NULL, &tv);
    /* If we get a timeout we return it */
    if (error == 0) return GLS_ERROR_TIMEDOUT;
    /* If it's an error the same */
    else if (error < 0) return error;
    /* If everything is ok we return the data size */
    else {
        
        /* Si les headers sont configuré */
        #if defined (GLS_HEADER_PACKET)
        return recvWithHeader(socket, buffer, size, flag);
        #else
        return recv(socket, buffer, size, flag);
        #endif
    
    }
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Socket Send with Header
 
 ---------------------------------------------------------*/

ssize_t	sendWithHeader(const int socket, const byte *buffer, const ssize_t size, const int flag) {
    
    /* Packet size encoding (big-endian for network) in 2 bytes */
    unsigned short int sizePacket = htons((unsigned short int)size);
    byte *sizePacketByte = (byte*) &sizePacket;
    
    /* Temp memory allocation */
    byte (*temp) = malloc(sizeof(byte) * (size + 2));
    
    /* Insertion of the packet's size */
    temp[0] = sizePacketByte[0];
    temp[1] = sizePacketByte[1];
    
    /* Fill the temp var with buffer */
    int i = 0;
    for (i = 0; i < size; i++) {
        
        temp[i + 2] = buffer[i]; 
        
    }
    
    /* Configuration of the size left to send */
    ssize_t sizeLeftTemp = size + 2;
    ssize_t sizeTotal = 0;
    byte *tempPtr = temp;
    ssize_t sock_size = 0;
    
    /* Sending information until there is none */
    while (sizeLeftTemp > 0 && sock_size != SOCKET_ERROR) {
        
        /* Sending info */
        sock_size = send(socket, tempPtr, sizeLeftTemp, flag);
        /* Ajusting pointer with the size left */
        tempPtr += sock_size;
        /* Remove the information's size sent from the total size left */
        sizeLeftTemp -= sock_size;
        /* Add the size sent to the total size */
        sizeTotal += sock_size;
        
        /* In case of an error 0 */
        if (sock_size == 0) sock_size = SOCKET_ERROR;
            
    }
    
    /* Free memory */
    free(temp);
    temp = 0;
    tempPtr = 0;
    
    /* If no error happened return the size, otherwise SOCKET_ERROR */
    if (sock_size != SOCKET_ERROR) return sizeTotal - 2;
    else return SOCKET_ERROR;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Socket Recv with Header
 
 ---------------------------------------------------------*/

ssize_t	recvWithHeader(const int socket, byte *buffer, const size_t size, const int flag) {
    
    /* Variable init */
    ssize_t sock_size = 0;
    unsigned short int sizePacketTemp = 0;
    ssize_t sizePacket = 0;
    ssize_t total = 0;
    byte *sizePacketByte = (byte*) &sizePacketTemp;
    
    /* Memory temp allocation */
    byte (*temp) = malloc(sizeof(byte) * (size + 2));
    byte *tempPtr = temp;
    
    /* Info reception */
    sock_size = recv(socket, temp, size + 2, flag);
    
    /* Get the packet size */
    if (sock_size > 2) {
        
        /* Get size and convert it */
        sizePacketByte[0] = temp[0];
        sizePacketByte[1] = temp[1];
        sizePacket = (ssize_t) ntohs(sizePacketTemp);
        total += sock_size;
        
    }
    else {
    
        /* Free memory */
        free(temp);
        temp = 0;
        tempPtr = 0;
        
        return -1;
    
    }
    
    /* Get all the data */
    while (total < (sizePacket + 2) && sock_size != SOCKET_ERROR) {
        
        /* Pointer ajustement */
        tempPtr += sock_size;
        /* Get info */
        sock_size = recv(socket, tempPtr, (sizePacket + 2 - total), flag);
        /* Size ajustement */
        total += sock_size;
        
        /* In case of error 0 */
        if (sock_size == 0) sock_size = SOCKET_ERROR;
        
    }
    
    /* Copy temp buffer into final buffer */
    int i = 0;
    for (i = 0; i < sizePacket && i < size; i++) {
        
        buffer[i] = temp[i + 2];
        
    }
    
    /* Free memory */
    free(temp);
    temp = 0;
    tempPtr = 0;
    
    /* Return size if no error, otherwise SOCKET_ERROR */
    if (sock_size != SOCKET_ERROR) return total - 2;
    else return SOCKET_ERROR;
    
}
     



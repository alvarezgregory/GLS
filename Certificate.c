/*
 *  Certificate.c
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

#include "GLSHeaders.h"




/*-------------------------------------------------------
 
 Add serial to CRL
 
 ---------------------------------------------------------*/

int addToCrl(GLSSock* myGLSSocket, const char* serial) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### addToCrl() Start ###\n");
    printf("Serial Size : %ld\n", strlen(serial));
    #endif
    
    int size = (int) strlen(serial) / 2;
    char temp[3];
    byte *keyToAdd = malloc(size + 1);
    keyToAdd[0] = size;
    
    /* Hash conversion (Hexa -> byte) */
    int i = 0;
    for (i = 0; i < (size * 2); i += 2) {
        
        temp[0] = serial[i];
        temp[1] = serial[i + 1];
        temp[2] = '\0';
        keyToAdd[1 + i / 2] = strtoul(temp, 0, 16);
        
    }
    
    /* Add serial to the socket's CRL array */
    addKeyToArray(keyToAdd, &myGLSSocket->m_crl, &myGLSSocket->m_sizeCrl);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### addToCrl() End ###\n\n");
    #endif
    
    return 0;
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Read content of a file. return 0 for success or 
 a negative number for an error.
 
 ---------------------------------------------------------*/

int charFromFile(const char* fileName, char **content) {

    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### charFromFile() Start ###\n");
    #endif
    
    /* Getting file Size */
    struct stat fileStat;
    int status;
    int i = 0;
    status = stat(fileName, &fileStat);
    if (status != 0) {
        
        return GLS_ERROR_NOFILE;
    
    }
    
    /* Opening the file */
    FILE *file = fopen(fileName, "r");
    if (file == NULL) {
        
        return GLS_ERROR_NOFILE;
    
    }
    
    /* Temp variable */
    char *buffer;
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("file size : %jd\n", (intmax_t)fileStat.st_size);
    #endif
    
    /* Allocating buffer for file */
    buffer = malloc(fileStat.st_size + 1);
    if (buffer == NULL) {
        
        fclose(file);
        return GLS_ERROR_NOMEM;
    
    }
    
    /* Getting file content */
    i = 0;
    char t = 0;
    while (i < fileStat.st_size)
	{
        t = fgetc(file);
  	    if(t != EOF) buffer[i] = t;
        else break;
        i++;
	}
    
    /* EOL for buffer */
    buffer[fileStat.st_size] = '\0';
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("File content : ");
    for (i = 0; i < (int)fileStat.st_size; i++) {
        printf("%c", buffer[i]);
    }
    printf("\n");
    #endif
    
    /* removing CRLF from pemCert */
    /* counting nb of EOL */
    int nb = 0;
    for (i = 0; i < strlen(buffer); i++) {
        
        
        /* CR LF for Windows */
        #if defined (win32)
        if (buffer[i] == 13 && buffer[i + 1] == 10) nb++;

        /* LF for Linux */
        #elif defined (linux)
        if (buffer[i] == 10) nb++;
        
        /* LF OS X */
        #elif defined (osx)
        if (buffer[i] == 10) nb++;
		
		 /* LF iOS */
        #elif defined (ios)
        if (buffer[i] == 10) nb++;
        
        #endif
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("nb of EOL : %d\n", nb);
    printf("buffer len : %ld\n", strlen(buffer));
    #endif
    
    /* Allocating memory */
    byte *pem = 0;
    int pemLen = 0;
    /* CR LF for Windows */
    #if defined (win32)
    pem = malloc(strlen(buffer) - (nb * 2) + 1);
    pemLen = (int)strlen(buffer) - (nb * 2) + 1;
    
    /* LF for Linux */
    #elif defined (linux)
    pem = malloc(strlen(buffer) - (nb * 1) + 1);
    pemLen = (int)strlen(buffer) - (nb * 1) + 1;

    /* LF OS X */
    #elif defined (osx)
    pem = malloc(strlen(buffer) - (nb * 1) + 1);
    pemLen = (int)strlen(buffer) - (nb * 1) + 1;
    
    /* LF iOS */
    #elif defined (ios)
    pem = malloc(strlen(buffer) - (nb * 1) + 1);
    pemLen = (int)strlen(buffer) - (nb * 1) + 1;

    #endif
    if (pem == NULL)  {
        
        if (buffer != NULL) {
            free(buffer);
            buffer = 0;
        }
        
        fclose(file);
        return GLS_ERROR_NOMEM;
        
    }
    
    /* Copy of the cert */
    int y = 0;
    for (i = 0; i < strlen(buffer); i++) {
        
        /* CR LF for Windows */
        #if defined (win32)
        if (buffer[i] == 13 && buffer[i + 1] == 10) i++;
        
        /* LF for Linux */
        #elif defined (linux)
        if (buffer[i] == 10) continue;
        
        /* LF OS X */
        #elif defined (osx)
        if (buffer[i] == 10) continue;
        
        /* LF iOS */
        #elif defined (ios)
        if (buffer[i] == 10) continue;
        
        #endif
        else {
            
            pem[y] = buffer[i];
            y++;
            
        }
    }
    
    /* adding the null delimiter */
    pem[pemLen - 1] = '\0';
    
    /* Return pointer to buffer */
    (*content) = (char*) pem;
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Pem content : ");
    for (i = 0; i < (pemLen - 1); i++) {
        printf("%c", pem[i]);
    }
    printf("\n");
    #endif
    
    /* freeing memory */
    if (buffer != NULL) {
        free(buffer);
        buffer = 0;
    }
    fclose(file);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### charFromFile() End ###\n\n");
    #endif
    
    return 0;

}




/*-------------------------------------------------------
 
 Add a root certificate for the Register connexion. PEM format.
 Return 0 for success, a negative number for an error.
 
 ---------------------------------------------------------*/

int addRootCertificate(GLSSock* myGLSSocket, const char* cert) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### addRootCertificate() Start ###\n");
    #endif
    
    if (strlen(cert) < 52) return GLS_ERROR_BADROOTCERT;
    
    /* Free memory if cert already set */
    if (myGLSSocket->m_certRoot != NULL) {
        free(myGLSSocket->m_certRoot);
        myGLSSocket->m_certRoot = 0;
        myGLSSocket->m_certRootSize = 0;
    }
    
    /* memory allocation */
    myGLSSocket->m_certRoot = malloc(sizeof(byte) * strlen(cert));
    if (myGLSSocket->m_certRoot == NULL) return GLS_ERROR_NOMEM;
    
    /* Set the certificate's size */
    myGLSSocket->m_certRootSize = (int) strlen(cert);
    
    /* copy certificate */
    int i = 0;
    for (i = 0; i < myGLSSocket->m_certRootSize; i++) {
        
        myGLSSocket->m_certRoot[i] = cert[i];
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Size cert : %d\n", myGLSSocket->m_certRootSize);
    printf("### addRootCertificate() End ###\n\n");
    #endif
    
    return 0;
}




/*-------------------------------------------------------
 
 Add a root certificate from a file for the Register connexion. PEM format.
 Return 0 for success, a negative number for an error.
 
 ---------------------------------------------------------*/


int addRootCertificateFromFile(GLSSock* myGLSSocket, const char* certFile) {
    
    /* Getting the file */
    char *myFile = 0;
    int error = charFromFile(certFile, &myFile);
    if (error != 0) {
        
        if (myFile != NULL) {
            free(myFile);
            myFile = 0;
        }
        
        return error;
    }
    
    /* adding the file */
    error = addRootCertificate(myGLSSocket, myFile);
    if (error != 0) {
        
        if (myFile != NULL) {
            free(myFile);
            myFile = 0;
        }
        
        return error;
    }

    /* Freeing memory */
    if (myFile != NULL) {
        free(myFile);
        myFile = 0;
    }

    
    return 0;
    
}




/*-------------------------------------------------------
 
 Add the server certificate from a char for the Register 
 connexion. PEM format. Return 0 for success, a negative 
 number for an error.
 
 ---------------------------------------------------------*/

int addServerCertificate(GLSServerSock* myGLSServerSock, const char* publicCert, const char* privateKey) {
    
    if (publicCert == NULL || privateKey == NULL) return GLS_ERROR_BADSERVERCERT;
    
    int sizePubCert = (int) strlen(publicCert);
    int sizePrivCert = (int) strlen(privateKey);
    
    if (sizePubCert > 52 && sizePrivCert > 60) {
        
        /* Free memory if cert already set */
        if (myGLSServerSock->m_publicKey != NULL) {
            free(myGLSServerSock->m_publicKey);
            myGLSServerSock->m_publicKey = 0;
        }
        if (myGLSServerSock->m_privateKey != NULL) {
            free(myGLSServerSock->m_privateKey);
            myGLSServerSock->m_privateKey = 0;
        }
        
        /* memory allocation +1 for '\0' */
        myGLSServerSock->m_publicKey = malloc(sizePubCert + 1);
        if (myGLSServerSock->m_publicKey == NULL) return GLS_ERROR_NOMEM;
        myGLSServerSock->m_privateKey = malloc(sizePrivCert + 1);
        if (myGLSServerSock->m_privateKey == NULL) return GLS_ERROR_NOMEM;
    
        /* copy certificate */
        int i = 0;
        for (i = 0; i < sizePubCert; i++) {
            
            myGLSServerSock->m_publicKey[i] = publicCert[i];
            
        }
        myGLSServerSock->m_publicKey[sizePubCert] = '\0';
        for (i = 0; i < sizePrivCert; i++) {
            
            myGLSServerSock->m_privateKey[i] = privateKey[i];
            
        }
        myGLSServerSock->m_privateKey[sizePrivCert] = '\0';

        return 0;
        
    }
    else return GLS_ERROR_BADSERVERCERT;
    
}




/*-------------------------------------------------------
 
 Add the server certificate from a file for the Register 
 connexion. PEM format. Return 0 for success, a negative 
 number for an error.
 
 ---------------------------------------------------------*/

int addServerCertificateFromFile(GLSServerSock* myGLSServerSock, const char* publicCertFile, const char* privateKeyFile) {
    
    if (publicCertFile == NULL || privateKeyFile == NULL) return GLS_ERROR_BADSERVERCERT;
    
    int sizePubCertFile = (int) strlen(publicCertFile);
    int sizePrivCertFile = (int) strlen(privateKeyFile);
    
    if (sizePubCertFile > 0 && sizePrivCertFile > 0) {
        
        /* Free memory if cert already set */
        if (myGLSServerSock->m_publicKeyFile != NULL) {
            free(myGLSServerSock->m_publicKeyFile);
            myGLSServerSock->m_publicKeyFile = 0;
        }
        if (myGLSServerSock->m_privateKeyFile != NULL) {
            free(myGLSServerSock->m_privateKeyFile);
            myGLSServerSock->m_privateKeyFile = 0;
        }
        
        /* memory allocation +1 for '\0' */
        myGLSServerSock->m_publicKeyFile = malloc(sizePubCertFile + 1);
        if (myGLSServerSock->m_publicKeyFile == NULL) return GLS_ERROR_NOMEM;
        myGLSServerSock->m_privateKeyFile = malloc(sizePrivCertFile + 1);
        if (myGLSServerSock->m_privateKeyFile == NULL) return GLS_ERROR_NOMEM;
        
        /* copy certificate */
        int i = 0;
        for (i = 0; i < sizePubCertFile; i++) {
            
            myGLSServerSock->m_publicKeyFile[i] = publicCertFile[i];
            
        }
        myGLSServerSock->m_publicKeyFile[sizePubCertFile] = '\0';
        for (i = 0; i < sizePrivCertFile; i++) {
            
            myGLSServerSock->m_privateKeyFile[i] = privateKeyFile[i];
            
        }
        myGLSServerSock->m_privateKeyFile[sizePrivCertFile] = '\0';
        
        return 0;
        
    }
    else return GLS_ERROR_BADSERVERCERT;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Add the server certificate from a char for the GLSSocket. 
 PEM format. Return 0 for success, a negative 
 number for an error.
 
 ---------------------------------------------------------*/

int _addServerCertificate(GLSSock* myGLSSocket, const char* publicCert, const char* privateKey) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### addServerCertificate() Start ###\n");
    #endif
    
    /* Free memory if certificate already set */
    if (myGLSSocket->m_publicCert != NULL) {
        free(myGLSSocket->m_publicCert);
        myGLSSocket->m_publicCert = 0;
        myGLSSocket->m_publicCertSize = 0;
    }
    if (myGLSSocket->m_privateKey != NULL) {
        gcry_free(myGLSSocket->m_privateKey);
        myGLSSocket->m_privateKey = 0;
        myGLSSocket->m_privateKeySize = 0;
    }
    
    /* memory allocation */
    myGLSSocket->m_publicCert = malloc(sizeof(byte) * strlen(publicCert));
    if (myGLSSocket->m_publicCert == NULL) return GLS_ERROR_NOMEM;
    myGLSSocket->m_privateKey = gcry_malloc_secure(sizeof(byte) * strlen(privateKey));
    if (myGLSSocket->m_privateKey == NULL) {
        
        /* Free memory */
        if (myGLSSocket->m_publicCert != NULL) {
            free(myGLSSocket->m_publicCert);
            myGLSSocket->m_publicCert = 0;
            myGLSSocket->m_publicCertSize = 0;
        }
        
        return GLS_ERROR_NOMEM;
    }
    
    /* Get size */
    myGLSSocket->m_publicCertSize = (int) strlen(publicCert);
    myGLSSocket->m_privateKeySize = (int) strlen(privateKey);
    
    /* copy certificate */
    int i = 0;
    for (i = 0; i < myGLSSocket->m_publicCertSize; i++) {
        
        myGLSSocket->m_publicCert[i] = publicCert[i];
        
    }
    for (i = 0; i < myGLSSocket->m_privateKeySize; i++) {
        
        myGLSSocket->m_privateKey[i] = privateKey[i];
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Size cert : %d\n", myGLSSocket->m_certRootSize);
    printf("### addServerCertificate() End ###\n\n");
    #endif
    
    return 0;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Add the server certificate from a file for the GLSSocket. 
 PEM format. Return 0 for success, a negative 
 number for an error.
 
 ---------------------------------------------------------*/

int _addServerCertificateFromFile(GLSSock* myGLSSocket, const char* publicCertFileName, const char* privateKeyFileName) {
    
    /* Getting the file */
    char *myPublicFile = 0;
    char *myPrivateFile = 0;
    int error = charFromFile(publicCertFileName, &myPublicFile);
    int error2 = charFromFile(privateKeyFileName, &myPrivateFile);
    if (error != 0 || error2 !=0) {
        
        /* Freeing memory */
        if (myPublicFile != NULL) {
            free(myPublicFile);
            myPublicFile = 0;
        }
        if (myPrivateFile != NULL) {
            free(myPrivateFile);
            myPrivateFile = 0;
        }
        
        if (error != 0) return error;
        else return error2;
        
    }
    
    /* adding the file */
    error = _addServerCertificate(myGLSSocket, myPublicFile, myPrivateFile);
    if (error != 0) {
        
        /* Freeing memory */
        if (myPublicFile != NULL) {
            free(myPublicFile);
            myPublicFile = 0;
        }
        if (myPrivateFile != NULL) {
            free(myPrivateFile);
            myPrivateFile = 0;
        }

        return error;

    }
    
    /* Freeing memory */
    if (myPublicFile != NULL) {
        free(myPublicFile);
        myPublicFile = 0;
    }
    if (myPrivateFile != NULL) {
        free(myPrivateFile);
        myPrivateFile = 0;
    }
    
    return 0;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 decode base 64 to bytes
 
 ---------------------------------------------------------*/

int base64Decode(byte* buffer, int bufferSize, const byte* src, int srcSize) {
    
    signed char b64[0x100] = {
        B64 (0), B64 (1), B64 (2), B64 (3),
        B64 (4), B64 (5), B64 (6), B64 (7),
        B64 (8), B64 (9), B64 (10), B64 (11),
        B64 (12), B64 (13), B64 (14), B64 (15),
        B64 (16), B64 (17), B64 (18), B64 (19),
        B64 (20), B64 (21), B64 (22), B64 (23),
        B64 (24), B64 (25), B64 (26), B64 (27),
        B64 (28), B64 (29), B64 (30), B64 (31),
        B64 (32), B64 (33), B64 (34), B64 (35),
        B64 (36), B64 (37), B64 (38), B64 (39),
        B64 (40), B64 (41), B64 (42), B64 (43),
        B64 (44), B64 (45), B64 (46), B64 (47),
        B64 (48), B64 (49), B64 (50), B64 (51),
        B64 (52), B64 (53), B64 (54), B64 (55),
        B64 (56), B64 (57), B64 (58), B64 (59),
        B64 (60), B64 (61), B64 (62), B64 (63),
        B64 (64), B64 (65), B64 (66), B64 (67),
        B64 (68), B64 (69), B64 (70), B64 (71),
        B64 (72), B64 (73), B64 (74), B64 (75),
        B64 (76), B64 (77), B64 (78), B64 (79),
        B64 (80), B64 (81), B64 (82), B64 (83),
        B64 (84), B64 (85), B64 (86), B64 (87),
        B64 (88), B64 (89), B64 (90), B64 (91),
        B64 (92), B64 (93), B64 (94), B64 (95),
        B64 (96), B64 (97), B64 (98), B64 (99),
        B64 (100), B64 (101), B64 (102), B64 (103),
        B64 (104), B64 (105), B64 (106), B64 (107),
        B64 (108), B64 (109), B64 (110), B64 (111),
        B64 (112), B64 (113), B64 (114), B64 (115),
        B64 (116), B64 (117), B64 (118), B64 (119),
        B64 (120), B64 (121), B64 (122), B64 (123),
        B64 (124), B64 (125), B64 (126), B64 (127),
        B64 (128), B64 (129), B64 (130), B64 (131),
        B64 (132), B64 (133), B64 (134), B64 (135),
        B64 (136), B64 (137), B64 (138), B64 (139),
        B64 (140), B64 (141), B64 (142), B64 (143),
        B64 (144), B64 (145), B64 (146), B64 (147),
        B64 (148), B64 (149), B64 (150), B64 (151),
        B64 (152), B64 (153), B64 (154), B64 (155),
        B64 (156), B64 (157), B64 (158), B64 (159),
        B64 (160), B64 (161), B64 (162), B64 (163),
        B64 (164), B64 (165), B64 (166), B64 (167),
        B64 (168), B64 (169), B64 (170), B64 (171),
        B64 (172), B64 (173), B64 (174), B64 (175),
        B64 (176), B64 (177), B64 (178), B64 (179),
        B64 (180), B64 (181), B64 (182), B64 (183),
        B64 (184), B64 (185), B64 (186), B64 (187),
        B64 (188), B64 (189), B64 (190), B64 (191),
        B64 (192), B64 (193), B64 (194), B64 (195),
        B64 (196), B64 (197), B64 (198), B64 (199),
        B64 (200), B64 (201), B64 (202), B64 (203),
        B64 (204), B64 (205), B64 (206), B64 (207),
        B64 (208), B64 (209), B64 (210), B64 (211),
        B64 (212), B64 (213), B64 (214), B64 (215),
        B64 (216), B64 (217), B64 (218), B64 (219),
        B64 (220), B64 (221), B64 (222), B64 (223),
        B64 (224), B64 (225), B64 (226), B64 (227),
        B64 (228), B64 (229), B64 (230), B64 (231),
        B64 (232), B64 (233), B64 (234), B64 (235),
        B64 (236), B64 (237), B64 (238), B64 (239),
        B64 (240), B64 (241), B64 (242), B64 (243),
        B64 (244), B64 (245), B64 (246), B64 (247),
        B64 (248), B64 (249), B64 (250), B64 (251),
        B64 (252), B64 (253), B64 (254), B64 (255)
    };
    
    
    int dataLeft = bufferSize;
    
    while(srcSize >= 2) {
        
        if(!(0 <= b64[src[0]]) || !(0 <= b64[src[1]]))
            break;
        
        if(dataLeft) {
            
            *buffer++ = ((b64[src[0]] << 2) | (b64[src[1]] >> 4)); 
            dataLeft--;
        }
        
        if(srcSize == 2)
            break;
        
        if(src[2] == '=') {
            
            if(srcSize != 4)
                break;
            
            if(src[3] != '=')
                break;
        }
        else {
            
            if(!(0 <= b64[src[2]]))
                break;
            
            if(dataLeft) {
                
                *buffer++ = (((b64[src[1]] << 4) & 0xf0) | (b64[src[2]] >> 2));
                dataLeft--;
                
            }
            
            if(srcSize == 3)
                break;
            
            if(src[3] == '=') {
                
                if(srcSize != 4)
                    break;
            }
            else {
                
                if(!(0 <= b64[src[3]]))
                    break;
                
                if(dataLeft) {
                    
                    *buffer++ = (((b64[src[2]] << 6) & 0xc0) | b64[src[3]]);
                    dataLeft--;
                    
                }
                
            }
            
        }
        
        src += 4;
        srcSize -= 4;
        
    }
    
    if(srcSize != 0) return GLS_ERROR_BASE64;
    
    return (bufferSize - dataLeft);
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Convert PEM base64 certificate to an ASN1 in bytes. Return
 the buffer size in bytes or a negative number for an error.
 
 No line break allowed, remove them before.
 
 ---------------------------------------------------------*/

int pemToAsn(const byte *pem, const int pemLen, byte** asn) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### pemToAsn() Start ###\n");
    #endif
    
    /* Check size */
    if(pemLen < 29 || pem == NULL) return GLS_ERROR_NOCERT;
    
    /* Get type of certificate */
    char pubHeader[27] = "-----BEGIN CERTIFICATE-----";
    int sizeHeader = 0;
    int i = 0;
    for (i = 0; i < 27; i++) {
        if (pem[i] == pubHeader[i]) sizeHeader++;
    }
    
    /* Def header's size => counting a CR+LF at the end of the certificate !!!! */
    int headerStart = 0;
    int headerStop = 0;
    /* if public certificate */
    if (sizeHeader == 27) {
        headerStart = 27;
        headerStop = 25;
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Certificate detected\n");
        #endif
    }
    /* if private certificate */
    else {
        headerStart = 31;
        headerStop = 29;
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Private key detected\n");
        #endif
    }
    
    /* Memory allocation for the temp cert PEM */
    byte* pemTemp = malloc(sizeof(byte) * (pemLen - headerStart - headerStop));
    if (pemTemp == NULL) return GLS_ERROR_NOMEM;
    
    /* Fill pemTemp with only the base64 removing ASCII headers */
    for (i = 0; i < (pemLen - headerStart - headerStop); i++) {
        
        pemTemp[i] = pem[headerStart + i]; 
        
    }
    
    /* Buffer allocation for conversion */
    byte* bufferTemp = malloc(sizeof(byte) * (pemLen - headerStart - headerStop));
    if (bufferTemp == NULL) {
        
        /* Free memory */
        if (pemTemp != NULL) {
            free(pemTemp);
            pemTemp = 0;
        }
        
        return GLS_ERROR_NOMEM;
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("PemTemp content : ");
    for (i = 0; i < (pemLen - headerStart - headerStop); i++) {
        printf("%c", pemTemp[i]);
    }
    printf("\n");
    #endif
    
    /* pemTemp conversion */
    int sizeCert = base64Decode(bufferTemp, (sizeof(byte) * (pemLen - headerStart - headerStop)), pemTemp, (sizeof(byte) * (pemLen - headerStart - headerStop)));
    if (sizeCert < 0) {
        
        /* Free memory */
        if (pemTemp != NULL) {
            free(pemTemp);
            pemTemp = 0;
        }
        if (bufferTemp != NULL) {
            free(bufferTemp);
            bufferTemp = 0;
        }
        
        return sizeCert;
        
    }
    
    /* alloc final buffer */
    *asn = malloc(sizeCert);
    if (*asn == NULL) {
        
        /* Free memory */
        if (pemTemp != NULL) {
            free(pemTemp);
            pemTemp = 0;
        }
        if (bufferTemp != NULL) {
            free(bufferTemp);
            bufferTemp = 0;
        }
        
        return GLS_ERROR_NOMEM;
        
    }
    
    /* Fill final buffer */
    for (i = 0; i < sizeCert; i++) {
        
        (*asn)[i] = bufferTemp[i]; 
        
    }
    
    /* Free memory */
    if (pemTemp != NULL) {
        free(pemTemp);
        pemTemp = 0;
    }
    if (bufferTemp != NULL) {
        free(bufferTemp);
        bufferTemp = 0;
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("SizeCert : %d\n", sizeCert);
    printf("SizePem : %d\n", pemLen);
    printf("### pemToAsn() End ###\n\n");
    #endif
    
    return sizeCert;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Get the RSA public key from a DER and returns it in a gcry_sexp_t.
 Return 0 for success or a negative number for an error.
 
  ==> CHECK FOR BUFFER OVERFLOW <==
  ==> Optimization - one general array ASN1_ARRAY_TYPE <==
  ==> Optimization - allocate memory dynamically <==

 ---------------------------------------------------------*/

int getPublicRsaFromDer(const byte *der, const int sizeDerInBits, gcry_sexp_t *publicKey) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getPublicRsaFromDer() Start ###\n");
    #endif
    
    /* Convert size in bytes */
    if ((sizeDerInBits % 8) != 0) return GLS_ERROR_ASN1;
    int len = sizeDerInBits / 8;
    
    ASN1_ARRAY_TYPE def[] = {
        { "GLS", 536872976, NULL },
        { NULL, 1073741836, NULL },
        { "RSAPublicKey", 1610612741, NULL },
        { "modulus", 1073741827, NULL },
        { "publicExponent", 3, NULL },
        { "RSAPrivateKey", 1610612741, NULL },
        { "version", 1073741826, "Version"},
        { "modulus", 1073741827, NULL },
        { "publicExponent", 1073741827, NULL },
        { "privateExponent", 1073741827, NULL },
        { "prime1", 1073741827, NULL },
        { "prime2", 1073741827, NULL },
        { "exponent1", 1073741827, NULL },
        { "exponent2", 1073741827, NULL },
        { "coefficient", 1073741827, NULL },
        { "otherPrimeInfos", 16386, "OtherPrimeInfos"},
        { "Version", 1610874883, NULL },
        { "two-prime", 1073741825, "0"},
        { "multi", 1, "1"},
        { "OtherPrimeInfos", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "OtherPrimeInfo"},
        { "OtherPrimeInfo", 1610612741, NULL },
        { "prime", 1073741827, NULL },
        { "exponent", 1073741827, NULL },
        { "coefficient", 3, NULL },
        { "AlgorithmIdentifier", 1610612741, NULL },
        { "algorithm", 1073741836, NULL },
        { "parameters", 541081613, NULL },
        { "algorithm", 1, NULL },
        { "DigestInfo", 1610612741, NULL },
        { "digestAlgorithm", 1073741826, "DigestAlgorithmIdentifier"},
        { "digest", 2, "Digest"},
        { "DigestAlgorithmIdentifier", 1073741826, "AlgorithmIdentifier"},
        { "Digest", 1073741831, NULL },
        { "DSAPublicKey", 1073741827, NULL },
        { "DSAParameters", 1610612741, NULL },
        { "p", 1073741827, NULL },
        { "q", 1073741827, NULL },
        { "g", 3, NULL },
        { "DSASignatureValue", 1610612741, NULL },
        { "r", 1073741827, NULL },
        { "s", 3, NULL },
        { "DSAPrivateKey", 1610612741, NULL },
        { "version", 1073741827, NULL },
        { "p", 1073741827, NULL },
        { "q", 1073741827, NULL },
        { "g", 1073741827, NULL },
        { "Y", 1073741827, NULL },
        { "priv", 3, NULL },
        { "DHParameter", 536870917, NULL },
        { "prime", 1073741827, NULL },
        { "base", 1073741827, NULL },
        { "privateValueLength", 16387, NULL },
        { NULL, 0, NULL }
    };
    
    /* certificate's structure creation */
    ASN1_TYPE certDef = ASN1_TYPE_EMPTY;
    char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    int result = asn1_array2tree(def, &certDef, errorDescription);
    if (result != ASN1_SUCCESS) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems creating structure asn1_array2tree\n");
        int i = 0;
        for (i = 0; i < ASN1_MAX_ERROR_DESCRIPTION_SIZE; i++) {
            printf("%c", errorDescription[i]);
        }
        printf("\n");
        #endif
        
        /* Free memory */
        asn1_delete_structure(&certDef);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getPublicRsaFromDer() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /* ASN1 structure creation */
    ASN1_TYPE structDer = ASN1_TYPE_EMPTY;
    result = asn1_create_element(certDef, "GLS.RSAPublicKey", &structDer);
    int result2 = asn1_der_decoding(&structDer, der, len, errorDescription);
    if (result != ASN1_SUCCESS || result2 != ASN1_SUCCESS) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems with RSA der decoding\n");
        if (result != ASN1_SUCCESS) printf("Creation Error\n");
        else {
            int i = 0;
            for (i = 0; i < ASN1_MAX_ERROR_DESCRIPTION_SIZE; i++) {
                
                printf("%c", errorDescription[i]);
                
            }
            printf("\n");
        }
        #endif
        
        /* Free memory */
        asn1_delete_structure(&structDer);
        asn1_delete_structure(&certDef);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getPublicRsaFromDer() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /* Get public key */
    byte buffer[4096];
    int lenBuffer = 4096;
    byte bufferExpo[1024];
    int lenBufferExpo = 1024;
    result = asn1_read_value(structDer, "modulus", buffer, &lenBuffer);
    result2 = asn1_read_value(structDer, "publicExponent", bufferExpo, &lenBufferExpo);
    if (result != ASN1_SUCCESS || result2 != ASN1_SUCCESS) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems reading public key\n");
        #endif
        
        /* Free memory */
        asn1_delete_structure(&structDer);
        asn1_delete_structure(&certDef);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getPublicRsaFromDer() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /* We create the public key under gcrypt */
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Public key exponent : ");
    int i = 0;
    for (i = 0; i < lenBufferExpo; i++) {
        printf("%d", bufferExpo[i]);
    }
    printf("\n");
    #endif
    
    int error = gcry_sexp_build(publicKey, NULL, "(public-key(rsa(n%b)(e%b)))", lenBuffer, buffer, lenBufferExpo, bufferExpo);
    if (error != 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems creating S-Exp Gcrypt\n");
        #endif
        
        /* Free memory */
        asn1_delete_structure(&structDer);
        asn1_delete_structure(&certDef);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getPublicRsaFromDer() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
        
    /* Free memory */
    asn1_delete_structure(&structDer);
    asn1_delete_structure(&certDef);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getPublicRsaFromDer() End ###\n\n");
    #endif
    
    return 0;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Get the RSA private key from a DER and returns it in a gcry_sexp_t.
 Return 0 for success or a negative number for an error.
 
 ==> CHECK FOR BUFFER OVERFLOW <==
 ==> Optimization - one general array ASN1_ARRAY_TYPE <==
 ==> Optimization - allocate memory dynamically <==
 
 ---------------------------------------------------------*/

int getPrivateRsaFromDer(const byte *der, const int sizeDer, gcry_sexp_t *privateKey) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getPrivateRsaFromDer() Start ###\n");
    #endif
    
    int len = sizeDer;
    
    ASN1_ARRAY_TYPE def[] = {
        { "GLS", 536872976, NULL },
        { NULL, 1073741836, NULL },
        { "RSAPublicKey", 1610612741, NULL },
        { "modulus", 1073741827, NULL },
        { "publicExponent", 3, NULL },
        { "RSAPrivateKey", 1610612741, NULL },
        { "version", 1073741826, "Version"},
        { "modulus", 1073741827, NULL },
        { "publicExponent", 1073741827, NULL },
        { "privateExponent", 1073741827, NULL },
        { "prime1", 1073741827, NULL },
        { "prime2", 1073741827, NULL },
        { "exponent1", 1073741827, NULL },
        { "exponent2", 1073741827, NULL },
        { "coefficient", 1073741827, NULL },
        { "otherPrimeInfos", 16386, "OtherPrimeInfos"},
        { "Version", 1610874883, NULL },
        { "two-prime", 1073741825, "0"},
        { "multi", 1, "1"},
        { "OtherPrimeInfos", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "OtherPrimeInfo"},
        { "OtherPrimeInfo", 1610612741, NULL },
        { "prime", 1073741827, NULL },
        { "exponent", 1073741827, NULL },
        { "coefficient", 3, NULL },
        { "AlgorithmIdentifier", 1610612741, NULL },
        { "algorithm", 1073741836, NULL },
        { "parameters", 541081613, NULL },
        { "algorithm", 1, NULL },
        { "DigestInfo", 1610612741, NULL },
        { "digestAlgorithm", 1073741826, "DigestAlgorithmIdentifier"},
        { "digest", 2, "Digest"},
        { "DigestAlgorithmIdentifier", 1073741826, "AlgorithmIdentifier"},
        { "Digest", 1073741831, NULL },
        { "DSAPublicKey", 1073741827, NULL },
        { "DSAParameters", 1610612741, NULL },
        { "p", 1073741827, NULL },
        { "q", 1073741827, NULL },
        { "g", 3, NULL },
        { "DSASignatureValue", 1610612741, NULL },
        { "r", 1073741827, NULL },
        { "s", 3, NULL },
        { "DSAPrivateKey", 1610612741, NULL },
        { "version", 1073741827, NULL },
        { "p", 1073741827, NULL },
        { "q", 1073741827, NULL },
        { "g", 1073741827, NULL },
        { "Y", 1073741827, NULL },
        { "priv", 3, NULL },
        { "DHParameter", 536870917, NULL },
        { "prime", 1073741827, NULL },
        { "base", 1073741827, NULL },
        { "privateValueLength", 16387, NULL },
        { NULL, 0, NULL }
    };
    
    /* Certificate's structure creation */
    ASN1_TYPE certDef = ASN1_TYPE_EMPTY;
    char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    int result = asn1_array2tree(def, &certDef, errorDescription);
    if (result != ASN1_SUCCESS) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems creating structure asn1_array2tree\n");
        int i = 0;
        for (i = 0; i < ASN1_MAX_ERROR_DESCRIPTION_SIZE; i++) {
            printf("%c", errorDescription[i]);
        }
        printf("\n");
        #endif
        
        /* Free memory */
        asn1_delete_structure(&certDef);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getPrivateRsaFromDer() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /* ASN1 structure creation */
    ASN1_TYPE structDer = ASN1_TYPE_EMPTY;
    result = asn1_create_element(certDef, "GLS.RSAPrivateKey", &structDer);
    int result2 = asn1_der_decoding(&structDer, der, len, errorDescription);
    if (result != ASN1_SUCCESS || result2 != ASN1_SUCCESS) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems with RSA der decoding\n");
        if (result != ASN1_SUCCESS) printf("Creation Error\n");
        else {
            int i = 0;
            for (i = 0; i < ASN1_MAX_ERROR_DESCRIPTION_SIZE; i++) {
                
                printf("%c", errorDescription[i]);
                
            }
            printf("\n");
        }
        #endif
        
        /* Free memory */
        asn1_delete_structure(&structDer);
        asn1_delete_structure(&certDef);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getPrivateRsaFromDer() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /* Get information for the private key */
    byte modulus[4096];
    int lenModulus = 4096;
    byte publicExponent[4096];
    int lenPublicExponent = 4096;
    byte secretExponent[4096];
    int lenSecretExponent = 4096;
    byte secretPrimeP[4096];
    int lenSecretPrimeP = 4096;
    byte secretPrimeQ[4096];
    int lenSecretPrimeQ = 4096;
    byte multInverse[4096];
    int lenMultInverse = 4096;
    result = asn1_read_value(structDer, "modulus", modulus, &lenModulus);
    result2 = asn1_read_value(structDer, "publicExponent", publicExponent, &lenPublicExponent);
    int result3 = asn1_read_value(structDer, "privateExponent", secretExponent, &lenSecretExponent);
    int result4 = asn1_read_value(structDer, "prime1", secretPrimeP, &lenSecretPrimeP);
    int result5 = asn1_read_value(structDer, "prime2", secretPrimeQ, &lenSecretPrimeQ);
    int result6 = asn1_read_value(structDer, "coefficient", multInverse, &lenMultInverse);
    if (result != ASN1_SUCCESS || result2 != ASN1_SUCCESS || result3 != ASN1_SUCCESS || result4 != ASN1_SUCCESS || result5 != ASN1_SUCCESS || result6 != ASN1_SUCCESS) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems reading private key\n");
        #endif
        
        /* Free memory */
        asn1_delete_structure(&structDer);
        asn1_delete_structure(&certDef);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getPrivateRsaFromDer() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /* MPI Creation */
    gcry_mpi_t mpiModulus = 0;
    gcry_mpi_t mpiPublicExponent = 0;
    gcry_mpi_t mpiSecretExponent = 0;
    gcry_mpi_t mpiSecretPrimeP = 0;
    gcry_mpi_t mpiSecretPrimeQ = 0;
    gcry_mpi_t mpiMultInverse = 0;
    result = gcry_mpi_scan(&mpiModulus, GCRYMPI_FMT_USG, modulus, lenModulus, NULL);
    result += gcry_mpi_scan(&mpiPublicExponent, GCRYMPI_FMT_USG, publicExponent, lenPublicExponent, NULL);
    result += gcry_mpi_scan(&mpiSecretExponent, GCRYMPI_FMT_USG, secretExponent, lenSecretExponent, NULL);
    result += gcry_mpi_scan(&mpiSecretPrimeP, GCRYMPI_FMT_USG, secretPrimeP, lenSecretPrimeP, NULL);
    result += gcry_mpi_scan(&mpiSecretPrimeQ, GCRYMPI_FMT_USG, secretPrimeQ, lenSecretPrimeQ, NULL);
    result += gcry_mpi_scan(&mpiMultInverse, GCRYMPI_FMT_USG, multInverse, lenMultInverse, NULL);
    if (result != 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error creating MPI\n");
        #endif
        
        /* Free memory */
        asn1_delete_structure(&structDer);
        asn1_delete_structure(&certDef);
        gcry_mpi_release(mpiModulus);
        gcry_mpi_release(mpiPublicExponent);
        gcry_mpi_release(mpiSecretExponent);
        gcry_mpi_release(mpiSecretPrimeP);
        gcry_mpi_release(mpiSecretPrimeQ);
        gcry_mpi_release(mpiMultInverse);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getPrivateRsaFromDer() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
    
    /* We create the private key under gcrypt */
    
    /* For openSSL parameters, keys from this tool are a little different */
    if (gcry_mpi_cmp(mpiSecretPrimeP, mpiSecretPrimeQ) > 0) {
        
        gcry_mpi_swap(mpiSecretPrimeP, mpiSecretPrimeQ);
        gcry_mpi_invm(mpiMultInverse, mpiSecretPrimeP, mpiSecretPrimeQ);
        
    }
    
    int error = gcry_sexp_build(privateKey, NULL, "(private-key(rsa(n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))", mpiModulus, mpiPublicExponent, mpiSecretExponent, mpiSecretPrimeP, mpiSecretPrimeQ, mpiMultInverse);
    if (error != 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems creating S-Exp Gcrypt\n");
        #endif
        
        /* Free memory */
        asn1_delete_structure(&structDer);
        asn1_delete_structure(&certDef);
        gcry_mpi_release(mpiModulus);
        gcry_mpi_release(mpiPublicExponent);
        gcry_mpi_release(mpiSecretExponent);
        gcry_mpi_release(mpiSecretPrimeP);
        gcry_mpi_release(mpiSecretPrimeQ);
        gcry_mpi_release(mpiMultInverse);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getPublicRsaFromDer() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
    
    /* Free memory */
    asn1_delete_structure(&structDer);
    asn1_delete_structure(&certDef);
    gcry_mpi_release(mpiModulus);
    gcry_mpi_release(mpiPublicExponent);
    gcry_mpi_release(mpiSecretExponent);
    gcry_mpi_release(mpiSecretPrimeP);
    gcry_mpi_release(mpiSecretPrimeQ);
    gcry_mpi_release(mpiMultInverse);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getPrivateRsaFromDer() End ###\n\n");
    #endif
    
    return 0;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Check the certificate validity, return 0 for OK or a
 negative number for an error.
 
 ---------------------------------------------------------*/

int checkCertificate(GLSSock* myGLSSocket, const byte *cert, const int certLen) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### checkCertificate() Start ###\n");
    #endif
    
    /* Check for a root certificate */
    if (myGLSSocket->m_certRoot == NULL) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No root certificate");
        printf("### checkCertificate() End ###\n\n");
        #endif
        
        return GLS_ERROR_NOCERT;
        
    }
    
    /* Certificate's structure definition */
    ASN1_ARRAY_TYPE structCertificat[] = {
        { "PKIX1Implicit88", 536875024, NULL },
        { NULL, 1610612748, NULL },
        { "iso", 1073741825, "1"},
        { "identified-organization", 1073741825, "3"},
        { "dod", 1073741825, "6"},
        { "internet", 1073741825, "1"},
        { "security", 1073741825, "5"},
        { "mechanisms", 1073741825, "5"},
        { "pkix", 1073741825, "7"},
        { "id-mod", 1073741825, "0"},
        { "id-pkix1-implicit-88", 1, "2"},
        { "id-ce", 1879048204, NULL },
        { "joint-iso-ccitt", 1073741825, "2"},
        { "ds", 1073741825, "5"},
        { NULL, 1, "29"},
        { "id-ce-authorityKeyIdentifier", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "35"},
        { "AuthorityKeyIdentifier", 1610612741, NULL },
        { "keyIdentifier", 1610637314, "KeyIdentifier"},
        { NULL, 4104, "0"},
        { "authorityCertIssuer", 1610637314, "GeneralNames"},
        { NULL, 4104, "1"},
        { "authorityCertSerialNumber", 536895490, "CertificateSerialNumber"},
        { NULL, 4104, "2"},
        { "KeyIdentifier", 1073741831, NULL },
        { "id-ce-subjectKeyIdentifier", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "14"},
        { "SubjectKeyIdentifier", 1073741826, "KeyIdentifier"},
        { "id-ce-keyUsage", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "15"},
        { "KeyUsage", 1610874886, NULL },
        { "digitalSignature", 1073741825, "0"},
        { "nonRepudiation", 1073741825, "1"},
        { "keyEncipherment", 1073741825, "2"},
        { "dataEncipherment", 1073741825, "3"},
        { "keyAgreement", 1073741825, "4"},
        { "keyCertSign", 1073741825, "5"},
        { "cRLSign", 1073741825, "6"},
        { "encipherOnly", 1073741825, "7"},
        { "decipherOnly", 1, "8"},
        { "id-ce-privateKeyUsagePeriod", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "16"},
        { "PrivateKeyUsagePeriod", 1610612741, NULL },
        { "notBefore", 1619025937, NULL },
        { NULL, 4104, "0"},
        { "notAfter", 545284113, NULL },
        { NULL, 4104, "1"},
        { "id-ce-certificatePolicies", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "32"},
        { "CertificatePolicies", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "PolicyInformation"},
        { "PolicyInformation", 1610612741, NULL },
        { "policyIdentifier", 1073741826, "CertPolicyId"},
        { "policyQualifiers", 538984459, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "PolicyQualifierInfo"},
        { "CertPolicyId", 1073741836, NULL },
        { "PolicyQualifierInfo", 1610612741, NULL },
        { "policyQualifierId", 1073741826, "PolicyQualifierId"},
        { "qualifier", 541065229, NULL },
        { "policyQualifierId", 1, NULL },
        { "PolicyQualifierId", 1073741836, NULL },
        { "CPSuri", 1073741826, "IA5String"},
        { "UserNotice", 1610612741, NULL },
        { "noticeRef", 1073758210, "NoticeReference"},
        { "explicitText", 16386, "DisplayText"},
        { "NoticeReference", 1610612741, NULL },
        { "organization", 1073741826, "DisplayText"},
        { "noticeNumbers", 536870923, NULL },
        { NULL, 3, NULL },
        { "DisplayText", 1610612754, NULL },
        { "visibleString", 1612709890, "VisibleString"},
        { "200", 524298, "1"},
        { "bmpString", 1612709890, "BMPString"},
        { "200", 524298, "1"},
        { "utf8String", 538968066, "UTF8String"},
        { "200", 524298, "1"},
        { "id-ce-policyMappings", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "33"},
        { "PolicyMappings", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 536870917, NULL },
        { "issuerDomainPolicy", 1073741826, "CertPolicyId"},
        { "subjectDomainPolicy", 2, "CertPolicyId"},
        { "id-ce-subjectAltName", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "17"},
        { "SubjectAltName", 1073741826, "GeneralNames"},
        { "GeneralNames", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "GeneralName"},
        { "GeneralName", 1610612754, NULL },
        { "otherName", 1610620930, "AnotherName"},
        { NULL, 4104, "0"},
        { "rfc822Name", 1610620930, "IA5String"},
        { NULL, 4104, "1"},
        { "dNSName", 1610620930, "IA5String"},
        { NULL, 4104, "2"},
        { "x400Address", 1610620930, "ORAddress"},
        { NULL, 4104, "3"},
        { "directoryName", 1610620930, "Name"},
        { NULL, 4104, "4"},
        { "ediPartyName", 1610620930, "EDIPartyName"},
        { NULL, 4104, "5"},
        { "uniformResourceIdentifier", 1610620930, "IA5String"},
        { NULL, 4104, "6"},
        { "iPAddress", 1610620935, NULL },
        { NULL, 4104, "7"},
        { "registeredID", 536879116, NULL },
        { NULL, 4104, "8"},
        { "AnotherName", 1610612741, NULL },
        { "type-id", 1073741836, NULL },
        { "value", 541073421, NULL },
        { NULL, 1073743880, "0"},
        { "type-id", 1, NULL },
        { "EDIPartyName", 1610612741, NULL },
        { "nameAssigner", 1610637314, "DirectoryString"},
        { NULL, 4104, "0"},
        { "partyName", 536879106, "DirectoryString"},
        { NULL, 4104, "1"},
        { "id-ce-issuerAltName", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "18"},
        { "IssuerAltName", 1073741826, "GeneralNames"},
        { "id-ce-subjectDirectoryAttributes", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "9"},
        { "SubjectDirectoryAttributes", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "Attribute"},
        { "id-ce-basicConstraints", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "19"},
        { "BasicConstraints", 1610612741, NULL },
        { "cA", 1610645508, NULL },
        { NULL, 131081, NULL },
        { "pathLenConstraint", 537411587, NULL },
        { "0", 10, "MAX"},
        { "id-ce-nameConstraints", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "30"},
        { "NameConstraints", 1610612741, NULL },
        { "permittedSubtrees", 1610637314, "GeneralSubtrees"},
        { NULL, 4104, "0"},
        { "excludedSubtrees", 536895490, "GeneralSubtrees"},
        { NULL, 4104, "1"},
        { "GeneralSubtrees", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "GeneralSubtree"},
        { "GeneralSubtree", 1610612741, NULL },
        { "base", 1073741826, "GeneralName"},
        { "minimum", 1610653698, "BaseDistance"},
        { NULL, 1073741833, "0"},
        { NULL, 4104, "0"},
        { "maximum", 536895490, "BaseDistance"},
        { NULL, 4104, "1"},
        { "BaseDistance", 1611137027, NULL },
        { "0", 10, "MAX"},
        { "id-ce-policyConstraints", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "36"},
        { "PolicyConstraints", 1610612741, NULL },
        { "requireExplicitPolicy", 1610637314, "SkipCerts"},
        { NULL, 4104, "0"},
        { "inhibitPolicyMapping", 536895490, "SkipCerts"},
        { NULL, 4104, "1"},
        { "SkipCerts", 1611137027, NULL },
        { "0", 10, "MAX"},
        { "id-ce-cRLDistributionPoints", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "31"},
        { "CRLDistPointsSyntax", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "DistributionPoint"},
        { "DistributionPoint", 1610612741, NULL },
        { "distributionPoint", 1610637314, "DistributionPointName"},
        { NULL, 4104, "0"},
        { "reasons", 1610637314, "ReasonFlags"},
        { NULL, 4104, "1"},
        { "cRLIssuer", 536895490, "GeneralNames"},
        { NULL, 4104, "2"},
        { "DistributionPointName", 1610612754, NULL },
        { "fullName", 1610620930, "GeneralNames"},
        { NULL, 4104, "0"},
        { "nameRelativeToCRLIssuer", 536879106, "RelativeDistinguishedName"},
        { NULL, 4104, "1"},
        { "ReasonFlags", 1610874886, NULL },
        { "unused", 1073741825, "0"},
        { "keyCompromise", 1073741825, "1"},
        { "cACompromise", 1073741825, "2"},
        { "affiliationChanged", 1073741825, "3"},
        { "superseded", 1073741825, "4"},
        { "cessationOfOperation", 1073741825, "5"},
        { "certificateHold", 1, "6"},
        { "id-ce-extKeyUsage", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "37"},
        { "ExtKeyUsageSyntax", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "KeyPurposeId"},
        { "KeyPurposeId", 1073741836, NULL },
        { "id-kp-serverAuth", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "1"},
        { "id-kp-clientAuth", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "2"},
        { "id-kp-codeSigning", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "3"},
        { "id-kp-emailProtection", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "4"},
        { "id-kp-ipsecEndSystem", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "5"},
        { "id-kp-ipsecTunnel", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "6"},
        { "id-kp-ipsecUser", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "7"},
        { "id-kp-timeStamping", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "8"},
        { "id-pe-authorityInfoAccess", 1879048204, NULL },
        { NULL, 1073741825, "id-pe"},
        { NULL, 1, "1"},
        { "AuthorityInfoAccessSyntax", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "AccessDescription"},
        { "AccessDescription", 1610612741, NULL },
        { "accessMethod", 1073741836, NULL },
        { "accessLocation", 2, "GeneralName"},
        { "id-ce-cRLNumber", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "20"},
        { "CRLNumber", 1611137027, NULL },
        { "0", 10, "MAX"},
        { "id-ce-issuingDistributionPoint", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "28"},
        { "IssuingDistributionPoint", 1610612741, NULL },
        { "distributionPoint", 1610637314, "DistributionPointName"},
        { NULL, 4104, "0"},
        { "onlyContainsUserCerts", 1610653700, NULL },
        { NULL, 1073872905, NULL },
        { NULL, 4104, "1"},
        { "onlyContainsCACerts", 1610653700, NULL },
        { NULL, 1073872905, NULL },
        { NULL, 4104, "2"},
        { "onlySomeReasons", 1610637314, "ReasonFlags"},
        { NULL, 4104, "3"},
        { "indirectCRL", 536911876, NULL },
        { NULL, 1073872905, NULL },
        { NULL, 4104, "4"},
        { "id-ce-deltaCRLIndicator", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "27"},
        { "BaseCRLNumber", 1073741826, "CRLNumber"},
        { "id-ce-cRLReasons", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "21"},
        { "CRLReason", 1610874901, NULL },
        { "unspecified", 1073741825, "0"},
        { "keyCompromise", 1073741825, "1"},
        { "cACompromise", 1073741825, "2"},
        { "affiliationChanged", 1073741825, "3"},
        { "superseded", 1073741825, "4"},
        { "cessationOfOperation", 1073741825, "5"},
        { "certificateHold", 1073741825, "6"},
        { "removeFromCRL", 1, "8"},
        { "id-ce-certificateIssuer", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "29"},
        { "CertificateIssuer", 1073741826, "GeneralNames"},
        { "id-ce-holdInstructionCode", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "23"},
        { "HoldInstructionCode", 1073741836, NULL },
        { "holdInstruction", 1879048204, NULL },
        { "joint-iso-itu-t", 1073741825, "2"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "x9cm", 1073741825, "10040"},
        { NULL, 1, "2"},
        { "id-holdinstruction-none", 1879048204, NULL },
        { NULL, 1073741825, "holdInstruction"},
        { NULL, 1, "1"},
        { "id-holdinstruction-callissuer", 1879048204, NULL },
        { NULL, 1073741825, "holdInstruction"},
        { NULL, 1, "2"},
        { "id-holdinstruction-reject", 1879048204, NULL },
        { NULL, 1073741825, "holdInstruction"},
        { NULL, 1, "3"},
        { "id-ce-invalidityDate", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "24"},
        { "InvalidityDate", 1082130449, NULL },
        { "VisibleString", 1610620935, NULL },
        { NULL, 4360, "26"},
        { "NumericString", 1610620935, NULL },
        { NULL, 4360, "18"},
        { "IA5String", 1610620935, NULL },
        { NULL, 4360, "22"},
        { "TeletexString", 1610620935, NULL },
        { NULL, 4360, "20"},
        { "PrintableString", 1610620935, NULL },
        { NULL, 4360, "19"},
        { "UniversalString", 1610620935, NULL },
        { NULL, 4360, "28"},
        { "BMPString", 1610620935, NULL },
        { NULL, 4360, "30"},
        { "UTF8String", 1610620935, NULL },
        { NULL, 4360, "12"},
        { "id-pkix", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "identified-organization", 1073741825, "3"},
        { "dod", 1073741825, "6"},
        { "internet", 1073741825, "1"},
        { "security", 1073741825, "5"},
        { "mechanisms", 1073741825, "5"},
        { "pkix", 1, "7"},
        { "id-pe", 1879048204, NULL },
        { NULL, 1073741825, "id-pkix"},
        { NULL, 1, "1"},
        { "id-qt", 1879048204, NULL },
        { NULL, 1073741825, "id-pkix"},
        { NULL, 1, "2"},
        { "id-kp", 1879048204, NULL },
        { NULL, 1073741825, "id-pkix"},
        { NULL, 1, "3"},
        { "id-ad", 1879048204, NULL },
        { NULL, 1073741825, "id-pkix"},
        { NULL, 1, "48"},
        { "id-qt-cps", 1879048204, NULL },
        { NULL, 1073741825, "id-qt"},
        { NULL, 1, "1"},
        { "id-qt-unotice", 1879048204, NULL },
        { NULL, 1073741825, "id-qt"},
        { NULL, 1, "2"},
        { "id-ad-ocsp", 1879048204, NULL },
        { NULL, 1073741825, "id-ad"},
        { NULL, 1, "1"},
        { "id-ad-caIssuers", 1879048204, NULL },
        { NULL, 1073741825, "id-ad"},
        { NULL, 1, "2"},
        { "Attribute", 1610612741, NULL },
        { "type", 1073741826, "AttributeType"},
        { "values", 536870927, NULL },
        { NULL, 2, "AttributeValue"},
        { "AttributeType", 1073741836, NULL },
        { "AttributeValue", 1073741837, NULL },
        { "AttributeTypeAndValue", 1610612741, NULL },
        { "type", 1073741826, "AttributeType"},
        { "value", 2, "AttributeValue"},
        { "id-at", 1879048204, NULL },
        { "joint-iso-ccitt", 1073741825, "2"},
        { "ds", 1073741825, "5"},
        { NULL, 1, "4"},
        { "id-at-name", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "41"},
        { "id-at-surname", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "4"},
        { "id-at-givenName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "42"},
        { "id-at-initials", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "43"},
        { "id-at-generationQualifier", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "44"},
        { "X520name", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-name", 524298, "1"},
        { "id-at-commonName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "3"},
        { "X520CommonName", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-common-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-common-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-common-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-common-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-common-name", 524298, "1"},
        { "id-at-localityName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "7"},
        { "X520LocalityName", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-locality-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-locality-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-locality-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-locality-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-locality-name", 524298, "1"},
        { "id-at-stateOrProvinceName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "8"},
        { "X520StateOrProvinceName", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-state-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-state-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-state-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-state-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-state-name", 524298, "1"},
        { "id-at-organizationName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "10"},
        { "X520OrganizationName", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-organization-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-organization-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-organization-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-organization-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-organization-name", 524298, "1"},
        { "id-at-organizationalUnitName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "11"},
        { "X520OrganizationalUnitName", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-organizational-unit-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-organizational-unit-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-organizational-unit-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-organizational-unit-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-organizational-unit-name", 524298, "1"},
        { "id-at-title", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "12"},
        { "X520Title", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-title", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-title", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-title", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-title", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-title", 524298, "1"},
        { "id-at-dnQualifier", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "46"},
        { "X520dnQualifier", 1073741826, "PrintableString"},
        { "id-at-countryName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "6"},
        { "X520countryName", 1612709890, "PrintableString"},
        { NULL, 1048586, "2"},
        { "pkcs-9", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "rsadsi", 1073741825, "113549"},
        { "pkcs", 1073741825, "1"},
        { NULL, 1, "9"},
        { "emailAddress", 1880096780, "AttributeType"},
        { NULL, 1073741825, "pkcs-9"},
        { NULL, 1, "1"},
        { "Pkcs9email", 1612709890, "IA5String"},
        { "ub-emailaddress-length", 524298, "1"},
        { "Name", 1610612754, NULL },
        { "rdnSequence", 2, "RDNSequence"},
        { "RDNSequence", 1610612747, NULL },
        { NULL, 2, "RelativeDistinguishedName"},
        { "DistinguishedName", 1073741826, "RDNSequence"},
        { "RelativeDistinguishedName", 1612709903, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "AttributeTypeAndValue"},
        { "DirectoryString", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "MAX", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "MAX", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "MAX", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "MAX", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "MAX", 524298, "1"},
        { "Certificate", 1610612741, NULL },
        { "tbsCertificate", 1073741826, "TBSCertificate"},
        { "signatureAlgorithm", 1073741826, "AlgorithmIdentifier"},
        { "signature", 6, NULL },
        { "TBSCertificate", 1610612741, NULL },
        { "version", 1610653698, "Version"},
        { NULL, 1073741833, "v1"},
        { NULL, 2056, "0"},
        { "serialNumber", 1073741826, "CertificateSerialNumber"},
        { "signature", 1073741826, "AlgorithmIdentifier"},
        { "issuer", 1073741826, "Name"},
        { "validity", 1073741826, "Validity"},
        { "subject", 1073741826, "Name"},
        { "subjectPublicKeyInfo", 1073741826, "SubjectPublicKeyInfo"},
        { "issuerUniqueID", 1610637314, "UniqueIdentifier"},
        { NULL, 4104, "1"},
        { "subjectUniqueID", 1610637314, "UniqueIdentifier"},
        { NULL, 4104, "2"},
        { "extensions", 536895490, "Extensions"},
        { NULL, 2056, "3"},
        { "Version", 1610874883, NULL },
        { "v1", 1073741825, "0"},
        { "v2", 1073741825, "1"},
        { "v3", 1, "2"},
        { "CertificateSerialNumber", 1073741827, NULL },
        { "Validity", 1610612741, NULL },
        { "notBefore", 1073741826, "Time"},
        { "notAfter", 2, "Time"},
        { "Time", 1610612754, NULL },
        { "utcTime", 1090519057, NULL },
        { "generalTime", 8388625, NULL },
        { "UniqueIdentifier", 1073741830, NULL },
        { "SubjectPublicKeyInfo", 1610612741, NULL },
        { "algorithm", 1073741826, "AlgorithmIdentifier"},
        { "subjectPublicKey", 6, NULL },
        { "Extensions", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "Extension"},
        { "Extension", 1610612741, NULL },
        { "extnID", 1073741836, NULL },
        { "critical", 1610645508, NULL },
        { NULL, 131081, NULL },
        { "extnValue", 7, NULL },
        { "CertificateList", 1610612741, NULL },
        { "tbsCertList", 1073741826, "TBSCertList"},
        { "signatureAlgorithm", 1073741826, "AlgorithmIdentifier"},
        { "signature", 6, NULL },
        { "TBSCertList", 1610612741, NULL },
        { "version", 1073758210, "Version"},
        { "signature", 1073741826, "AlgorithmIdentifier"},
        { "issuer", 1073741826, "Name"},
        { "thisUpdate", 1073741826, "Time"},
        { "nextUpdate", 1073758210, "Time"},
        { "revokedCertificates", 1610629131, NULL },
        { NULL, 536870917, NULL },
        { "userCertificate", 1073741826, "CertificateSerialNumber"},
        { "revocationDate", 1073741826, "Time"},
        { "crlEntryExtensions", 16386, "Extensions"},
        { "crlExtensions", 536895490, "Extensions"},
        { NULL, 2056, "0"},
        { "AlgorithmIdentifier", 1610612741, NULL },
        { "algorithm", 1073741836, NULL },
        { "parameters", 541081613, NULL },
        { "algorithm", 1, NULL },
        { "pkcs-1", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "rsadsi", 1073741825, "113549"},
        { "pkcs", 1073741825, "1"},
        { NULL, 1, "1"},
        { "rsaEncryption", 1879048204, NULL },
        { NULL, 1073741825, "pkcs-1"},
        { NULL, 1, "1"},
        { "md2WithRSAEncryption", 1879048204, NULL },
        { NULL, 1073741825, "pkcs-1"},
        { NULL, 1, "2"},
        { "md5WithRSAEncryption", 1879048204, NULL },
        { NULL, 1073741825, "pkcs-1"},
        { NULL, 1, "4"},
        { "sha1WithRSAEncryption", 1879048204, NULL },
        { NULL, 1073741825, "pkcs-1"},
        { NULL, 1, "5"},
        { "id-dsa-with-sha1", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "x9-57", 1073741825, "10040"},
        { "x9algorithm", 1073741825, "4"},
        { NULL, 1, "3"},
        { "Dss-Sig-Value", 1610612741, NULL },
        { "r", 1073741827, NULL },
        { "s", 3, NULL },
        { "dhpublicnumber", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "ansi-x942", 1073741825, "10046"},
        { "number-type", 1073741825, "2"},
        { NULL, 1, "1"},
        { "DomainParameters", 1610612741, NULL },
        { "p", 1073741827, NULL },
        { "g", 1073741827, NULL },
        { "q", 1073741827, NULL },
        { "j", 1073758211, NULL },
        { "validationParms", 16386, "ValidationParms"},
        { "ValidationParms", 1610612741, NULL },
        { "seed", 1073741830, NULL },
        { "pgenCounter", 3, NULL },
        { "id-dsa", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "x9-57", 1073741825, "10040"},
        { "x9algorithm", 1073741825, "4"},
        { NULL, 1, "1"},
        { "Dss-Parms", 1610612741, NULL },
        { "p", 1073741827, NULL },
        { "q", 1073741827, NULL },
        { "g", 3, NULL },
        { "ORAddress", 1610612741, NULL },
        { "built-in-standard-attributes", 1073741826, "BuiltInStandardAttributes"},
        { "built-in-domain-defined-attributes", 1073758210, "BuiltInDomainDefinedAttributes"},
        { "extension-attributes", 16386, "ExtensionAttributes"},
        { "BuiltInStandardAttributes", 1610612741, NULL },
        { "country-name", 1073758210, "CountryName"},
        { "administration-domain-name", 1073758210, "AdministrationDomainName"},
        { "network-address", 1610637314, "NetworkAddress"},
        { NULL, 2056, "0"},
        { "terminal-identifier", 1610637314, "TerminalIdentifier"},
        { NULL, 2056, "1"},
        { "private-domain-name", 1610637314, "PrivateDomainName"},
        { NULL, 2056, "2"},
        { "organization-name", 1610637314, "OrganizationName"},
        { NULL, 2056, "3"},
        { "numeric-user-identifier", 1610637314, "NumericUserIdentifier"},
        { NULL, 2056, "4"},
        { "personal-name", 1610637314, "PersonalName"},
        { NULL, 2056, "5"},
        { "organizational-unit-names", 536895490, "OrganizationalUnitNames"},
        { NULL, 2056, "6"},
        { "CountryName", 1610620946, NULL },
        { NULL, 1073746952, "1"},
        { "x121-dcc-code", 1612709890, "NumericString"},
        { NULL, 1048586, "ub-country-name-numeric-length"},
        { "iso-3166-alpha2-code", 538968066, "PrintableString"},
        { NULL, 1048586, "ub-country-name-alpha-length"},
        { "AdministrationDomainName", 1610620946, NULL },
        { NULL, 1073744904, "2"},
        { "numeric", 1612709890, "NumericString"},
        { "ub-domain-name-length", 524298, "0"},
        { "printable", 538968066, "PrintableString"},
        { "ub-domain-name-length", 524298, "0"},
        { "NetworkAddress", 1073741826, "X121Address"},
        { "X121Address", 1612709890, "NumericString"},
        { "ub-x121-address-length", 524298, "1"},
        { "TerminalIdentifier", 1612709890, "PrintableString"},
        { "ub-terminal-id-length", 524298, "1"},
        { "PrivateDomainName", 1610612754, NULL },
        { "numeric", 1612709890, "NumericString"},
        { "ub-domain-name-length", 524298, "1"},
        { "printable", 538968066, "PrintableString"},
        { "ub-domain-name-length", 524298, "1"},
        { "OrganizationName", 1612709890, "PrintableString"},
        { "ub-organization-name-length", 524298, "1"},
        { "NumericUserIdentifier", 1612709890, "NumericString"},
        { "ub-numeric-user-id-length", 524298, "1"},
        { "PersonalName", 1610612750, NULL },
        { "surname", 1814044674, "PrintableString"},
        { NULL, 1073745928, "0"},
        { "ub-surname-length", 524298, "1"},
        { "given-name", 1814061058, "PrintableString"},
        { NULL, 1073745928, "1"},
        { "ub-given-name-length", 524298, "1"},
        { "initials", 1814061058, "PrintableString"},
        { NULL, 1073745928, "2"},
        { "ub-initials-length", 524298, "1"},
        { "generation-qualifier", 740319234, "PrintableString"},
        { NULL, 1073745928, "3"},
        { "ub-generation-qualifier-length", 524298, "1"},
        { "OrganizationalUnitNames", 1612709899, NULL },
        { "ub-organizational-units", 1074266122, "1"},
        { NULL, 2, "OrganizationalUnitName"},
        { "OrganizationalUnitName", 1612709890, "PrintableString"},
        { "ub-organizational-unit-name-length", 524298, "1"},
        { "BuiltInDomainDefinedAttributes", 1612709899, NULL },
        { "ub-domain-defined-attributes", 1074266122, "1"},
        { NULL, 2, "BuiltInDomainDefinedAttribute"},
        { "BuiltInDomainDefinedAttribute", 1610612741, NULL },
        { "type", 1612709890, "PrintableString"},
        { "ub-domain-defined-attribute-type-length", 524298, "1"},
        { "value", 538968066, "PrintableString"},
        { "ub-domain-defined-attribute-value-length", 524298, "1"},
        { "ExtensionAttributes", 1612709903, NULL },
        { "ub-extension-attributes", 1074266122, "1"},
        { NULL, 2, "ExtensionAttribute"},
        { "ExtensionAttribute", 1610612741, NULL },
        { "extension-attribute-type", 1611145219, NULL },
        { NULL, 1073743880, "0"},
        { "0", 10, "ub-extension-attributes"},
        { "extension-attribute-value", 541073421, NULL },
        { NULL, 1073743880, "1"},
        { "extension-attribute-type", 1, NULL },
        { "common-name", 1342177283, "1"},
        { "CommonName", 1612709890, "PrintableString"},
        { "ub-common-name-length", 524298, "1"},
        { "teletex-common-name", 1342177283, "2"},
        { "TeletexCommonName", 1612709890, "TeletexString"},
        { "ub-common-name-length", 524298, "1"},
        { "teletex-organization-name", 1342177283, "3"},
        { "TeletexOrganizationName", 1612709890, "TeletexString"},
        { "ub-organization-name-length", 524298, "1"},
        { "teletex-personal-name", 1342177283, "4"},
        { "TeletexPersonalName", 1610612750, NULL },
        { "surname", 1814044674, "TeletexString"},
        { NULL, 1073743880, "0"},
        { "ub-surname-length", 524298, "1"},
        { "given-name", 1814061058, "TeletexString"},
        { NULL, 1073743880, "1"},
        { "ub-given-name-length", 524298, "1"},
        { "initials", 1814061058, "TeletexString"},
        { NULL, 1073743880, "2"},
        { "ub-initials-length", 524298, "1"},
        { "generation-qualifier", 740319234, "TeletexString"},
        { NULL, 1073743880, "3"},
        { "ub-generation-qualifier-length", 524298, "1"},
        { "teletex-organizational-unit-names", 1342177283, "5"},
        { "TeletexOrganizationalUnitNames", 1612709899, NULL },
        { "ub-organizational-units", 1074266122, "1"},
        { NULL, 2, "TeletexOrganizationalUnitName"},
        { "TeletexOrganizationalUnitName", 1612709890, "TeletexString"},
        { "ub-organizational-unit-name-length", 524298, "1"},
        { "pds-name", 1342177283, "7"},
        { "PDSName", 1612709890, "PrintableString"},
        { "ub-pds-name-length", 524298, "1"},
        { "physical-delivery-country-name", 1342177283, "8"},
        { "PhysicalDeliveryCountryName", 1610612754, NULL },
        { "x121-dcc-code", 1612709890, "NumericString"},
        { NULL, 1048586, "ub-country-name-numeric-length"},
        { "iso-3166-alpha2-code", 538968066, "PrintableString"},
        { NULL, 1048586, "ub-country-name-alpha-length"},
        { "postal-code", 1342177283, "9"},
        { "PostalCode", 1610612754, NULL },
        { "numeric-code", 1612709890, "NumericString"},
        { "ub-postal-code-length", 524298, "1"},
        { "printable-code", 538968066, "PrintableString"},
        { "ub-postal-code-length", 524298, "1"},
        { "physical-delivery-office-name", 1342177283, "10"},
        { "PhysicalDeliveryOfficeName", 1073741826, "PDSParameter"},
        { "physical-delivery-office-number", 1342177283, "11"},
        { "PhysicalDeliveryOfficeNumber", 1073741826, "PDSParameter"},
        { "extension-OR-address-components", 1342177283, "12"},
        { "ExtensionORAddressComponents", 1073741826, "PDSParameter"},
        { "physical-delivery-personal-name", 1342177283, "13"},
        { "PhysicalDeliveryPersonalName", 1073741826, "PDSParameter"},
        { "physical-delivery-organization-name", 1342177283, "14"},
        { "PhysicalDeliveryOrganizationName", 1073741826, "PDSParameter"},
        { "extension-physical-delivery-address-components", 1342177283, "15"},
        { "ExtensionPhysicalDeliveryAddressComponents", 1073741826, "PDSParameter"},
        { "unformatted-postal-address", 1342177283, "16"},
        { "UnformattedPostalAddress", 1610612750, NULL },
        { "printable-address", 1814052875, NULL },
        { "ub-pds-physical-address-lines", 1074266122, "1"},
        { NULL, 538968066, "PrintableString"},
        { "ub-pds-parameter-length", 524298, "1"},
        { "teletex-string", 740311042, "TeletexString"},
        { "ub-unformatted-address-length", 524298, "1"},
        { "street-address", 1342177283, "17"},
        { "StreetAddress", 1073741826, "PDSParameter"},
        { "post-office-box-address", 1342177283, "18"},
        { "PostOfficeBoxAddress", 1073741826, "PDSParameter"},
        { "poste-restante-address", 1342177283, "19"},
        { "PosteRestanteAddress", 1073741826, "PDSParameter"},
        { "unique-postal-name", 1342177283, "20"},
        { "UniquePostalName", 1073741826, "PDSParameter"},
        { "local-postal-attributes", 1342177283, "21"},
        { "LocalPostalAttributes", 1073741826, "PDSParameter"},
        { "PDSParameter", 1610612750, NULL },
        { "printable-string", 1814052866, "PrintableString"},
        { "ub-pds-parameter-length", 524298, "1"},
        { "teletex-string", 740311042, "TeletexString"},
        { "ub-pds-parameter-length", 524298, "1"},
        { "extended-network-address", 1342177283, "22"},
        { "ExtendedNetworkAddress", 1610612754, NULL },
        { "e163-4-address", 1610612741, NULL },
        { "number", 1612718082, "NumericString"},
        { NULL, 1073743880, "0"},
        { "ub-e163-4-number-length", 524298, "1"},
        { "sub-address", 538992642, "NumericString"},
        { NULL, 1073743880, "1"},
        { "ub-e163-4-sub-address-length", 524298, "1"},
        { "psap-address", 536879106, "PresentationAddress"},
        { NULL, 2056, "0"},
        { "PresentationAddress", 1610612741, NULL },
        { "pSelector", 1610637319, NULL },
        { NULL, 2056, "0"},
        { "sSelector", 1610637319, NULL },
        { NULL, 2056, "1"},
        { "tSelector", 1610637319, NULL },
        { NULL, 2056, "2"},
        { "nAddresses", 538976271, NULL },
        { NULL, 1073743880, "3"},
        { "MAX", 1074266122, "1"},
        { NULL, 7, NULL },
        { "terminal-type", 1342177283, "23"},
        { "TerminalType", 1611137027, NULL },
        { "0", 10, "ub-integer-options"},
        { "teletex-domain-defined-attributes", 1342177283, "6"},
        { "TeletexDomainDefinedAttributes", 1612709899, NULL },
        { "ub-domain-defined-attributes", 1074266122, "1"},
        { NULL, 2, "TeletexDomainDefinedAttribute"},
        { "TeletexDomainDefinedAttribute", 1610612741, NULL },
        { "type", 1612709890, "TeletexString"},
        { "ub-domain-defined-attribute-type-length", 524298, "1"},
        { "value", 538968066, "TeletexString"},
        { "ub-domain-defined-attribute-value-length", 524298, "1"},
        { "ub-name", 1342177283, "32768"},
        { "ub-common-name", 1342177283, "64"},
        { "ub-locality-name", 1342177283, "128"},
        { "ub-state-name", 1342177283, "128"},
        { "ub-organization-name", 1342177283, "64"},
        { "ub-organizational-unit-name", 1342177283, "64"},
        { "ub-title", 1342177283, "64"},
        { "ub-match", 1342177283, "128"},
        { "ub-emailaddress-length", 1342177283, "128"},
        { "ub-common-name-length", 1342177283, "64"},
        { "ub-country-name-alpha-length", 1342177283, "2"},
        { "ub-country-name-numeric-length", 1342177283, "3"},
        { "ub-domain-defined-attributes", 1342177283, "4"},
        { "ub-domain-defined-attribute-type-length", 1342177283, "8"},
        { "ub-domain-defined-attribute-value-length", 1342177283, "128"},
        { "ub-domain-name-length", 1342177283, "16"},
        { "ub-extension-attributes", 1342177283, "256"},
        { "ub-e163-4-number-length", 1342177283, "15"},
        { "ub-e163-4-sub-address-length", 1342177283, "40"},
        { "ub-generation-qualifier-length", 1342177283, "3"},
        { "ub-given-name-length", 1342177283, "16"},
        { "ub-initials-length", 1342177283, "5"},
        { "ub-integer-options", 1342177283, "256"},
        { "ub-numeric-user-id-length", 1342177283, "32"},
        { "ub-organization-name-length", 1342177283, "64"},
        { "ub-organizational-unit-name-length", 1342177283, "32"},
        { "ub-organizational-units", 1342177283, "4"},
        { "ub-pds-name-length", 1342177283, "16"},
        { "ub-pds-parameter-length", 1342177283, "30"},
        { "ub-pds-physical-address-lines", 1342177283, "6"},
        { "ub-postal-code-length", 1342177283, "16"},
        { "ub-surname-length", 1342177283, "40"},
        { "ub-terminal-id-length", 1342177283, "24"},
        { "ub-unformatted-address-length", 1342177283, "180"},
        { "ub-x121-address-length", 268435459, "16"},
        { NULL, 0, NULL }
    };
    
    /* Base64 PEM certificate decoding (in DER) */
    byte *certificatDer = 0;
    byte *rootDer = 0;
    int sizeCert = pemToAsn(cert, certLen, &certificatDer);
    int sizeRoot = pemToAsn(myGLSSocket->m_certRoot, myGLSSocket->m_certRootSize, &rootDer);
    if (sizeCert < 0 || sizeRoot < 0) {
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if (rootDer != NULL) {
            free(rootDer);
            rootDer = 0;
        }
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error Base 64\n");
        printf("### checkCertificate() End ###\n\n");
        #endif
        
        /* return error */
        if (sizeCert < 0) return sizeCert;
        else return sizeRoot;
        
    }
    
    /* Certificate's structure creation */
    ASN1_TYPE certDef = ASN1_TYPE_EMPTY;
    char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    int result = asn1_array2tree(structCertificat, &certDef, errorDescription);
    if (result != ASN1_SUCCESS) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems creating structure asn1_array2tree\n");
        int i = 0;
        for (i = 0; i < ASN1_MAX_ERROR_DESCRIPTION_SIZE; i++) {
            printf("%c", errorDescription[i]);
        }
        printf("\n");
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if (rootDer != NULL) {
            free(rootDer);
            rootDer = 0;
        }
        asn1_delete_structure(&certDef);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### checkCertificate() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /* Certificate DER parsing to use it under certificate */
    ASN1_TYPE certificat = ASN1_TYPE_EMPTY;
    ASN1_TYPE root = ASN1_TYPE_EMPTY;
    char errorDescription2[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    asn1_create_element(certDef, "PKIX1Implicit88.Certificate", &certificat);
    asn1_create_element(certDef, "PKIX1Implicit88.Certificate", &root);
    result = asn1_der_decoding(&certificat, certificatDer, sizeCert, errorDescription);
    int result2 = asn1_der_decoding(&root, rootDer, sizeRoot, errorDescription2);
    if (result != ASN1_SUCCESS || result2 != ASN1_SUCCESS) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems with DER encoding\n");
        int i = 0;
        for (i = 0; i < ASN1_MAX_ERROR_DESCRIPTION_SIZE; i++) {
            
            if (result != ASN1_SUCCESS) printf("%c", errorDescription[i]);
            else printf("%c", errorDescription2[i]);
            
        }
        printf("\n");
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if (rootDer != NULL) {
            free(rootDer);
            rootDer = 0;
        }
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        asn1_delete_structure(&root);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### checkCertificate() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /*
     * From here we have :
     * certificat = the certificate to check
     * root = the root certificate
     * certDef = the X.509 certificate definition
     */
    
    /*
     * Type of verification :
     * - subjectUniqueId certificat is not in CRL
     * - Validity periode of certificate and root OK
     * - Certificate sign by root
     */
    
    /*
     * Check for certificate serial number not in CRL
     */
    
    int len = 0;
    int i = 0;
    byte serial[1024];
    len = sizeof (serial);
    result = asn1_read_value(certificat, "tbsCertificate.serialNumber", serial, &len);
    if (result != 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No Certificate Serial Number\n");
        #endif
        
        /* free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if (rootDer != NULL) {
            free(rootDer);
            rootDer = 0;
        }
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        asn1_delete_structure(&root);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### checkCertificate() End ###\n\n");
        #endif
        
        return GLS_ERROR_BADSERVERCERT;
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Result : %d\n", result);
    printf("Serial length : %d\n", len);
    printf("Serial : ");
    for (i = 0; i < len; i++) {
        printf("%2X ", serial[i]);
    }
    printf("\n\n");
    #endif
    
    /* Check serial in CRL */
    int serialIsOk = 1;
    for (i = 0; i < myGLSSocket->m_sizeCrl; i++) {
        
        byte* mySerial = (byte*) myGLSSocket->m_crl[i];
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("CRL Serial (%d) : ", mySerial[0]);
        int z = 0;
        for (z = 0; z < mySerial[0]; z++) {
            printf("%2X ", mySerial[z + 1]);
        }
        printf("\n\n");
        #endif
        
        int lenght = mySerial[0];
        
        int y = 0;
        for (y = 0; y < lenght && y < len; y++) {
            
            if (serial[y] != mySerial[y + 1]) break;
            
        }
        
        if (y == len) {
            serialIsOk = 0;
            break;
        }
        else {
            serialIsOk = 1;
        }
        
    }
    
    if (serialIsOk == 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error - Certificate in CRL\n");
        #endif
        
        /* free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if (rootDer != NULL) {
            free(rootDer);
            rootDer = 0;
        }
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        asn1_delete_structure(&root);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### checkCertificate() End ###\n\n");
        #endif
        
        return GLS_ERROR_BADSERVERCERT;
    }
    
    
    /*
     * Certificate and Root validity date check
     */
    
    /* Getting validity times */
    byte rootDateStart[1024];
    byte certDateStart[1024];
    byte rootDateEnd[1024];
    byte certDateEnd[1024];
    len = sizeof (rootDateStart);
    result = asn1_read_value(root, "tbsCertificate.validity.notBefore.utcTime", rootDateStart, &len);
    len = sizeof (rootDateEnd);
    result2 = asn1_read_value(root, "tbsCertificate.validity.notAfter.utcTime", rootDateEnd, &len);
    len = sizeof (certDateStart);
    int result3 = asn1_read_value(certificat, "tbsCertificate.validity.notBefore.utcTime", certDateStart, &len);
    len = sizeof (certDateEnd);
    int result4 = asn1_read_value(certificat, "tbsCertificate.validity.notAfter.utcTime", certDateEnd, &len);
    if (result != 0 || result2 != 0 || result3 != 0 || result4 != 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No Certificate Serial Number : ");
        if (result != 0 || result2 != 0) printf("Root error\n");
        else printf("Certificate error\n");
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if (rootDer != NULL) {
            free(rootDer);
            rootDer = 0;
        }
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        asn1_delete_structure(&root);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### checkCertificate() End ###\n\n");
        #endif
        
        if (result != 0 || result2 != 0) return GLS_ERROR_BADROOTCERT;
        else return GLS_ERROR_BADSERVERCERT;
        
    }
    
    /* Getting actual time */
    long actualTime = time(NULL);
    
    /* Converting time strings in long decimal */
    struct tm *tm = malloc(sizeof(struct tm));
    /* aparently strptime doesn't fill all the structure 
     and mktime don't like it so we do a memset 0 */
    memset(tm, 0, sizeof(struct tm));
    strptime((char*)rootDateStart, "%y%m%d%H%M%SZ", tm);
    long rootStart = mktime(tm);
    strptime((char*)rootDateEnd, "%y%m%d%H%M%SZ", tm);
    long rootEnd = mktime(tm);
    strptime((char*)certDateStart, "%y%m%d%H%M%SZ", tm);
    long certStart = mktime(tm);
    strptime((char*)certDateEnd, "%y%m%d%H%M%SZ", tm);
    long certEnd = mktime(tm); 
    free(tm);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Root Validity : %s - %s\n", rootDateStart, rootDateEnd);
    printf("%s ", ctime(&rootStart));
    printf("- %s\n", ctime(&rootEnd));
    printf("Certificate Validity : %s - %s\n", certDateStart, certDateEnd);
    printf("%s ", ctime(&certStart));
    printf("- %s\n", ctime(&certEnd));
    printf("Actual Time : %ld - %s\n\n", actualTime, ctime(&actualTime));
    #endif
    
    /* Check if validity is ok or return Error */
    if (actualTime > rootEnd || actualTime < rootStart || actualTime > certEnd || actualTime < certStart) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        if (actualTime > rootEnd || actualTime < rootStart) printf("Root Certificate expired\n");
        else printf("Certificate expired\n");
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if (rootDer != NULL) {
            free(rootDer);
            rootDer = 0;
        }
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        asn1_delete_structure(&root);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### checkCertificate() End ###\n\n");
        #endif
        
        if (actualTime > rootEnd || actualTime < rootStart) return GLS_ERROR_BADROOTCERT;
        else return GLS_ERROR_BADSERVERCERT;
        
    }
    
    /*
     * Check the certificate signature (by the root certificate) and also 
     * the root certificate signature by himself (with his private key).
     */
    
    /* We check if the signing algorithme is sha1 with RSA */
    byte str[1024], str2[1024];
    len = sizeof (str);
    result = asn1_read_value(certificat, "signatureAlgorithm.algorithm", str, &len);
    len = sizeof (str2);
    result2 = asn1_read_value(certDef, "PKIX1Implicit88.sha1WithRSAEncryption", str2, &len);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Signature Algo certificat : %s\n", str);
    printf("Definition SHA1 + RSA : %s\n", str2);
    #endif
    
    /* if it's SHA1 + RSA (strcmp return 0 if the chars are the same) */
    if (!strcmp((char *) str, (char *) str2) && result == 0 && result2 == 0) {				
        
        /* Get the certificate position */
        int start = 0;
        int end = 0;
        int rootStart = 0;
        int rootEnd = 0;
        result = asn1_der_decoding_startEnd(certificat, certificatDer, sizeCert, "tbsCertificate", &start, &end);
        result2 = asn1_der_decoding_startEnd(root, rootDer, sizeRoot, "tbsCertificate", &rootStart, &rootEnd);
        if (result != ASN1_SUCCESS || result2 != ASN1_SUCCESS) {
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Impossible to locate the certificate\n");
            #endif
            
            /* Free memory */
            if (certificatDer != NULL) {
                free(certificatDer);
                certificatDer = 0;
            }
            if (rootDer != NULL) {
                free(rootDer);
                rootDer = 0;
            }
            asn1_delete_structure(&certDef);
            asn1_delete_structure(&certificat);
            asn1_delete_structure(&root);
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### checkCertificate() End ###\n\n");
            #endif
            
            return GLS_ERROR_ASN1;
            
        }
        
        /* Getting certificate for verification */
        byte* tbsCert = malloc(sizeof(byte) * (end + 1 - start));
        byte* tbsRootCert = malloc(sizeof(byte) * (rootEnd + 1 - rootStart));
        if (tbsCert == NULL || tbsRootCert == NULL) {
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No memory\n");
            #endif
            
            /* Free memory */
            if (certificatDer != NULL) {
                free(certificatDer);
                certificatDer = 0;
            }
            if (rootDer != NULL) {
                free(rootDer);
                rootDer = 0;
            }
            if (tbsCert != NULL) {
                free(tbsCert);
                tbsCert = 0;
            }
            if (tbsRootCert != NULL) {
                free(tbsRootCert);
                tbsRootCert = 0;
            }
            asn1_delete_structure(&certDef);
            asn1_delete_structure(&certificat);
            asn1_delete_structure(&root);
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### checkCertificate() End ###\n\n");
            #endif
            
            return GLS_ERROR_NOMEM;
        }
        int i = 0;
        for (i = 0; i < (end + 1 - start); i++) {
            
            tbsCert[i] = certificatDer[start + i];
            
        }
        for (i = 0; i < (rootEnd + 1 - rootStart); i++) {
            
            tbsRootCert[i] = rootDer[rootStart + i];
            
        }
        
        /* Get the public key from the DER root certificate */
        int lenPubKeyDer = 2048;
        byte pubKeyDer[2048];
        result = asn1_read_value(root, "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey", pubKeyDer, &lenPubKeyDer);
        
        /* Get the certificate's signature to check */
        int lenSignature = 2048;
        byte signature[2048];
        result2 = asn1_read_value(certificat, "signature", signature, &lenSignature);
        
        /* Get the root certificate's signature to check */
        int lenSignatureRoot = 2048;
        byte signatureRoot[2048];
        int result3 = asn1_read_value(root, "signature", signatureRoot, &lenSignatureRoot);
        
        /* Error check */
        if (result != ASN1_SUCCESS || result2 != ASN1_SUCCESS || result3 != ASN1_SUCCESS) {
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            if (result != ASN1_SUCCESS) printf("Impossible to extract key from Root Certificate\n");
            else if (result2 != ASN1_SUCCESS) printf("Impossible to extract signature from certificate\n");
            else printf("Impossible to extract signature from ROOT certificate\n");
            #endif
            
            /* free memory */
            if (certificatDer != NULL) {
                free(certificatDer);
                certificatDer = 0;
            }
            if (rootDer != NULL) {
                free(rootDer);
                rootDer = 0;
            }
            if (tbsCert != NULL) {
                free(tbsCert);
                tbsCert = 0;
            }
            if (tbsRootCert != NULL) {
                free(tbsRootCert);
                tbsRootCert = 0;
            }
            asn1_delete_structure(&certDef);
            asn1_delete_structure(&certificat);
            asn1_delete_structure(&root);
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### checkCertificate() End ###\n\n");
            #endif
            
            return GLS_ERROR_ASN1;
            
        }
        
        /* Hash the certificates to compare the signatures */
        byte MAC[20];
        byte MACROOT[20];
        gcry_md_hash_buffer(GCRY_MD_SHA1, MAC, tbsCert, (end + 1 - start));
        gcry_md_hash_buffer(GCRY_MD_SHA1, MACROOT, tbsRootCert, (rootEnd + 1 - rootStart));
        
        /* Convertion public key DER in byte */
        gcry_sexp_t gcryPubKey = 0;
        int error = getPublicRsaFromDer(pubKeyDer, lenPubKeyDer, &gcryPubKey);
        if (error < 0) {
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Impossible to convert DER public key to byte\n");
            #endif
            
            /* Free memory */
            if (certificatDer != NULL) {
                free(certificatDer);
                certificatDer = 0;
            }
            if (rootDer != NULL) {
                free(rootDer);
                rootDer = 0;
            }
            if (tbsCert != NULL) {
                free(tbsCert);
                tbsCert = 0;
            }
            if (tbsRootCert != NULL) {
                free(tbsRootCert);
                tbsRootCert = 0;
            }
            if(gcryPubKey != 0){
                gcry_sexp_release(gcryPubKey);
                gcryPubKey = 0;
            }
            asn1_delete_structure(&certDef);
            asn1_delete_structure(&certificat);
            asn1_delete_structure(&root);
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### checkCertificate() End ###\n\n");
            #endif
            
            return error;
            
        }
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        char signBufferPublickKey[2048];
        int sizeSignPK = (int) gcry_sexp_sprint(gcryPubKey, GCRYSEXP_FMT_ADVANCED, signBufferPublickKey, 2048);
        printf("gcryPubKey : ");
        i = 0;
        for (i = 0; i < sizeSignPK; i++) {
            printf("%c", signBufferPublickKey[i]);
        }
        printf("\n");
        #endif
        
        /* Creating the S-Exp for gcrypt */
        gcry_sexp_t gcrySignature;
        gcry_sexp_t gcrySignatureRoot;
        gcry_sexp_t gcryCert;
        gcry_sexp_t gcryCertRoot;
        error = gcry_sexp_build(&gcrySignature, NULL, "(sig-val(rsa(s %b)))", (lenSignature / 8), signature);
        error += gcry_sexp_build(&gcrySignatureRoot, NULL, "(sig-val(rsa(s %b)))", (lenSignatureRoot / 8), signatureRoot);
        error += gcry_sexp_build(&gcryCert, NULL, "(data(flags pkcs1)(hash sha1 %b))", 20, MAC);
        error += gcry_sexp_build(&gcryCertRoot, NULL, "(data(flags pkcs1)(hash sha1 %b))", 20, MACROOT);
        if (error != 0) {
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("Error creating S-Exp for signature check\n");
            #endif
            
            /* Free memory */
            if (certificatDer != NULL) {
                free(certificatDer);
                certificatDer = 0;
            }
            if (rootDer != NULL) {
                free(rootDer);
                rootDer = 0;
            }
            if (tbsCert != NULL) {
                free(tbsCert);
                tbsCert = 0;
            }
            if (tbsRootCert != NULL) {
                free(tbsRootCert);
                tbsRootCert = 0;
            }
            if(gcryPubKey != 0){
                gcry_sexp_release(gcryPubKey);
                gcryPubKey = 0;
            }
            gcry_sexp_release(gcrySignature);
            gcry_sexp_release(gcrySignatureRoot);
            gcry_sexp_release(gcryCert);
            gcry_sexp_release(gcryCertRoot);
            asn1_delete_structure(&certDef);
            asn1_delete_structure(&certificat);
            asn1_delete_structure(&root);
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### checkCertificate() End ###\n\n");
            #endif
            
            return GLS_ERROR_CRYPTO;
            
        }
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("SHA1 certificat : ");
        i = 0;
        for (i = 0; i < 20; i++) {
            printf("%2X",  MAC[i]);
        }
        printf("\n");
        printf("SHA1 root certificat : ");
        i = 0;
        for (i = 0; i < 20; i++) {
            printf("%2X",  MACROOT[i]);
        }
        printf("\n");
        char keyBuffer[2048];
        int sizePubKey = (int) gcry_sexp_sprint(gcryPubKey, GCRYSEXP_FMT_ADVANCED, keyBuffer, 2048);
        printf("Root Public Key : ");
        for (i = 0; i < sizePubKey; i++) {
            printf("%c", keyBuffer[i]);
        }
        printf("\n");
        char hashBuffer[2048];
        int sizeHashBuffer = (int) gcry_sexp_sprint(gcryCert, GCRYSEXP_FMT_ADVANCED, hashBuffer, 2048);
        printf("Hash certificate : ");
        for (i = 0; i < sizeHashBuffer; i++) {
            printf("%c", hashBuffer[i]);
        }
        printf("\n");
        char hashBufferRoot[2048];
        int sizeHashBufferRoot = (int) gcry_sexp_sprint(gcryCertRoot, GCRYSEXP_FMT_ADVANCED, hashBufferRoot, 2048);
        printf("Hash root certificate : ");
        for (i = 0; i < sizeHashBufferRoot; i++) {
            printf("%c", hashBufferRoot[i]);
        }
        printf("\n");
        char signBuffer[2048];
        int sizeSign = (int) gcry_sexp_sprint(gcrySignature, GCRYSEXP_FMT_ADVANCED, signBuffer, 2048);
        printf("Signature certificate : ");
        for (i = 0; i < sizeSign; i++) {
            printf("%c", signBuffer[i]);
        }
        printf("\n");
        printf("Size Signature : %d bytes\n", (lenSignature/8));
        char signBufferRoot[2048];
        int sizeSignRoot = (int) gcry_sexp_sprint(gcrySignatureRoot, GCRYSEXP_FMT_ADVANCED, signBufferRoot, 2048);
        printf("Signature certificate ROOT : ");
        for (i = 0; i < sizeSignRoot; i++) {
            printf("%c", signBufferRoot[i]);
        }
        printf("\n");
        printf("Size Signature ROOT : %d bytes\n", (lenSignatureRoot/8));
        #endif
        
        /* signature check */
        error = gcry_pk_verify(gcrySignature, gcryCert, gcryPubKey);
        int error2 = gcry_pk_verify(gcrySignatureRoot, gcryCertRoot, gcryPubKey);        
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error Verify Certificate: %d\n", error);
        printf("%s\n", gcry_strerror(error));
        printf("Validation Root Certificate : %d\n", error2);
        printf("%s\n", gcry_strerror(error2));
        #endif
        
        if (error != 0 || error2 != 0) {
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            if (error != 0) printf("Error Certificate not valide\n");
            else printf("Error Root Certificate not valide\n");
            #endif
            
            /* Free memory */
            if (certificatDer != NULL) {
                free(certificatDer);
                certificatDer = 0;
            }
            if (rootDer != NULL) {
                free(rootDer);
                rootDer = 0;
            }
            if (tbsCert != NULL) {
                free(tbsCert);
                tbsCert = 0;
            }
            if (tbsRootCert != NULL) {
                free(tbsRootCert);
                tbsRootCert = 0;
            }
            if(gcryPubKey != 0){
                gcry_sexp_release(gcryPubKey);
                gcryPubKey = 0;
            }
            gcry_sexp_release(gcrySignature);
            gcry_sexp_release(gcrySignatureRoot);
            gcry_sexp_release(gcryCert);
            gcry_sexp_release(gcryCertRoot);
            asn1_delete_structure(&certDef);
            asn1_delete_structure(&certificat);
            asn1_delete_structure(&root);
            
            /* Debug Only */
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("### checkCertificate() End ###\n\n");
            #endif
            
            if (error != 0) return GLS_ERROR_BADSERVERCERT;
            else return GLS_ERROR_BADROOTCERT;
        }
        
        /* Free memory for if condition */
        if (tbsCert != NULL) {
            free(tbsCert);
            tbsCert = 0;
        }
        if (tbsRootCert != NULL) {
            free(tbsRootCert);
            tbsRootCert = 0;
        }
        if(gcryPubKey != 0){
            gcry_sexp_release(gcryPubKey);
            gcryPubKey = 0;
        }
        gcry_sexp_release(gcrySignature);
        gcry_sexp_release(gcrySignatureRoot);
        gcry_sexp_release(gcryCert);
        gcry_sexp_release(gcryCertRoot);
        
    }
    else {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Certificate signature != SHA1+RSA\n");
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if (rootDer != NULL) {
            free(rootDer);
            rootDer = 0;
        }
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        asn1_delete_structure(&root);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### checkCertificate() End ###\n\n");
        #endif
        
        return GLS_ERROR_BADSERVERCERT;
        
    }
    
    /* Free memory */
    if (certificatDer != NULL) {
        free(certificatDer);
        certificatDer = 0;
    }
    if (rootDer != NULL) {
        free(rootDer);
        rootDer = 0;
    }
    asn1_delete_structure(&certDef);
    asn1_delete_structure(&certificat);
    asn1_delete_structure(&root);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### checkCertificate() End ###\n\n");
    #endif
    
    return 0;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Extract Certificate Public key size. Return the size of key or a 
 negative number for an error.
 
 ---------------------------------------------------------*/

int getModulusSize(const byte *cert, const int certLen) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getModulusSize() Start ###\n");
    #endif
    
    /* argument check */
    if (certLen <= 0 || cert == NULL) return GLS_ERROR_NOCERT;
    
    /* Certificate structure definition */
    ASN1_ARRAY_TYPE structCertificat[] = {
        { "PKIX1Implicit88", 536875024, NULL },
        { NULL, 1610612748, NULL },
        { "iso", 1073741825, "1"},
        { "identified-organization", 1073741825, "3"},
        { "dod", 1073741825, "6"},
        { "internet", 1073741825, "1"},
        { "security", 1073741825, "5"},
        { "mechanisms", 1073741825, "5"},
        { "pkix", 1073741825, "7"},
        { "id-mod", 1073741825, "0"},
        { "id-pkix1-implicit-88", 1, "2"},
        { "id-ce", 1879048204, NULL },
        { "joint-iso-ccitt", 1073741825, "2"},
        { "ds", 1073741825, "5"},
        { NULL, 1, "29"},
        { "id-ce-authorityKeyIdentifier", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "35"},
        { "AuthorityKeyIdentifier", 1610612741, NULL },
        { "keyIdentifier", 1610637314, "KeyIdentifier"},
        { NULL, 4104, "0"},
        { "authorityCertIssuer", 1610637314, "GeneralNames"},
        { NULL, 4104, "1"},
        { "authorityCertSerialNumber", 536895490, "CertificateSerialNumber"},
        { NULL, 4104, "2"},
        { "KeyIdentifier", 1073741831, NULL },
        { "id-ce-subjectKeyIdentifier", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "14"},
        { "SubjectKeyIdentifier", 1073741826, "KeyIdentifier"},
        { "id-ce-keyUsage", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "15"},
        { "KeyUsage", 1610874886, NULL },
        { "digitalSignature", 1073741825, "0"},
        { "nonRepudiation", 1073741825, "1"},
        { "keyEncipherment", 1073741825, "2"},
        { "dataEncipherment", 1073741825, "3"},
        { "keyAgreement", 1073741825, "4"},
        { "keyCertSign", 1073741825, "5"},
        { "cRLSign", 1073741825, "6"},
        { "encipherOnly", 1073741825, "7"},
        { "decipherOnly", 1, "8"},
        { "id-ce-privateKeyUsagePeriod", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "16"},
        { "PrivateKeyUsagePeriod", 1610612741, NULL },
        { "notBefore", 1619025937, NULL },
        { NULL, 4104, "0"},
        { "notAfter", 545284113, NULL },
        { NULL, 4104, "1"},
        { "id-ce-certificatePolicies", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "32"},
        { "CertificatePolicies", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "PolicyInformation"},
        { "PolicyInformation", 1610612741, NULL },
        { "policyIdentifier", 1073741826, "CertPolicyId"},
        { "policyQualifiers", 538984459, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "PolicyQualifierInfo"},
        { "CertPolicyId", 1073741836, NULL },
        { "PolicyQualifierInfo", 1610612741, NULL },
        { "policyQualifierId", 1073741826, "PolicyQualifierId"},
        { "qualifier", 541065229, NULL },
        { "policyQualifierId", 1, NULL },
        { "PolicyQualifierId", 1073741836, NULL },
        { "CPSuri", 1073741826, "IA5String"},
        { "UserNotice", 1610612741, NULL },
        { "noticeRef", 1073758210, "NoticeReference"},
        { "explicitText", 16386, "DisplayText"},
        { "NoticeReference", 1610612741, NULL },
        { "organization", 1073741826, "DisplayText"},
        { "noticeNumbers", 536870923, NULL },
        { NULL, 3, NULL },
        { "DisplayText", 1610612754, NULL },
        { "visibleString", 1612709890, "VisibleString"},
        { "200", 524298, "1"},
        { "bmpString", 1612709890, "BMPString"},
        { "200", 524298, "1"},
        { "utf8String", 538968066, "UTF8String"},
        { "200", 524298, "1"},
        { "id-ce-policyMappings", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "33"},
        { "PolicyMappings", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 536870917, NULL },
        { "issuerDomainPolicy", 1073741826, "CertPolicyId"},
        { "subjectDomainPolicy", 2, "CertPolicyId"},
        { "id-ce-subjectAltName", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "17"},
        { "SubjectAltName", 1073741826, "GeneralNames"},
        { "GeneralNames", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "GeneralName"},
        { "GeneralName", 1610612754, NULL },
        { "otherName", 1610620930, "AnotherName"},
        { NULL, 4104, "0"},
        { "rfc822Name", 1610620930, "IA5String"},
        { NULL, 4104, "1"},
        { "dNSName", 1610620930, "IA5String"},
        { NULL, 4104, "2"},
        { "x400Address", 1610620930, "ORAddress"},
        { NULL, 4104, "3"},
        { "directoryName", 1610620930, "Name"},
        { NULL, 4104, "4"},
        { "ediPartyName", 1610620930, "EDIPartyName"},
        { NULL, 4104, "5"},
        { "uniformResourceIdentifier", 1610620930, "IA5String"},
        { NULL, 4104, "6"},
        { "iPAddress", 1610620935, NULL },
        { NULL, 4104, "7"},
        { "registeredID", 536879116, NULL },
        { NULL, 4104, "8"},
        { "AnotherName", 1610612741, NULL },
        { "type-id", 1073741836, NULL },
        { "value", 541073421, NULL },
        { NULL, 1073743880, "0"},
        { "type-id", 1, NULL },
        { "EDIPartyName", 1610612741, NULL },
        { "nameAssigner", 1610637314, "DirectoryString"},
        { NULL, 4104, "0"},
        { "partyName", 536879106, "DirectoryString"},
        { NULL, 4104, "1"},
        { "id-ce-issuerAltName", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "18"},
        { "IssuerAltName", 1073741826, "GeneralNames"},
        { "id-ce-subjectDirectoryAttributes", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "9"},
        { "SubjectDirectoryAttributes", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "Attribute"},
        { "id-ce-basicConstraints", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "19"},
        { "BasicConstraints", 1610612741, NULL },
        { "cA", 1610645508, NULL },
        { NULL, 131081, NULL },
        { "pathLenConstraint", 537411587, NULL },
        { "0", 10, "MAX"},
        { "id-ce-nameConstraints", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "30"},
        { "NameConstraints", 1610612741, NULL },
        { "permittedSubtrees", 1610637314, "GeneralSubtrees"},
        { NULL, 4104, "0"},
        { "excludedSubtrees", 536895490, "GeneralSubtrees"},
        { NULL, 4104, "1"},
        { "GeneralSubtrees", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "GeneralSubtree"},
        { "GeneralSubtree", 1610612741, NULL },
        { "base", 1073741826, "GeneralName"},
        { "minimum", 1610653698, "BaseDistance"},
        { NULL, 1073741833, "0"},
        { NULL, 4104, "0"},
        { "maximum", 536895490, "BaseDistance"},
        { NULL, 4104, "1"},
        { "BaseDistance", 1611137027, NULL },
        { "0", 10, "MAX"},
        { "id-ce-policyConstraints", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "36"},
        { "PolicyConstraints", 1610612741, NULL },
        { "requireExplicitPolicy", 1610637314, "SkipCerts"},
        { NULL, 4104, "0"},
        { "inhibitPolicyMapping", 536895490, "SkipCerts"},
        { NULL, 4104, "1"},
        { "SkipCerts", 1611137027, NULL },
        { "0", 10, "MAX"},
        { "id-ce-cRLDistributionPoints", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "31"},
        { "CRLDistPointsSyntax", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "DistributionPoint"},
        { "DistributionPoint", 1610612741, NULL },
        { "distributionPoint", 1610637314, "DistributionPointName"},
        { NULL, 4104, "0"},
        { "reasons", 1610637314, "ReasonFlags"},
        { NULL, 4104, "1"},
        { "cRLIssuer", 536895490, "GeneralNames"},
        { NULL, 4104, "2"},
        { "DistributionPointName", 1610612754, NULL },
        { "fullName", 1610620930, "GeneralNames"},
        { NULL, 4104, "0"},
        { "nameRelativeToCRLIssuer", 536879106, "RelativeDistinguishedName"},
        { NULL, 4104, "1"},
        { "ReasonFlags", 1610874886, NULL },
        { "unused", 1073741825, "0"},
        { "keyCompromise", 1073741825, "1"},
        { "cACompromise", 1073741825, "2"},
        { "affiliationChanged", 1073741825, "3"},
        { "superseded", 1073741825, "4"},
        { "cessationOfOperation", 1073741825, "5"},
        { "certificateHold", 1, "6"},
        { "id-ce-extKeyUsage", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "37"},
        { "ExtKeyUsageSyntax", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "KeyPurposeId"},
        { "KeyPurposeId", 1073741836, NULL },
        { "id-kp-serverAuth", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "1"},
        { "id-kp-clientAuth", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "2"},
        { "id-kp-codeSigning", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "3"},
        { "id-kp-emailProtection", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "4"},
        { "id-kp-ipsecEndSystem", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "5"},
        { "id-kp-ipsecTunnel", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "6"},
        { "id-kp-ipsecUser", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "7"},
        { "id-kp-timeStamping", 1879048204, NULL },
        { NULL, 1073741825, "id-kp"},
        { NULL, 1, "8"},
        { "id-pe-authorityInfoAccess", 1879048204, NULL },
        { NULL, 1073741825, "id-pe"},
        { NULL, 1, "1"},
        { "AuthorityInfoAccessSyntax", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "AccessDescription"},
        { "AccessDescription", 1610612741, NULL },
        { "accessMethod", 1073741836, NULL },
        { "accessLocation", 2, "GeneralName"},
        { "id-ce-cRLNumber", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "20"},
        { "CRLNumber", 1611137027, NULL },
        { "0", 10, "MAX"},
        { "id-ce-issuingDistributionPoint", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "28"},
        { "IssuingDistributionPoint", 1610612741, NULL },
        { "distributionPoint", 1610637314, "DistributionPointName"},
        { NULL, 4104, "0"},
        { "onlyContainsUserCerts", 1610653700, NULL },
        { NULL, 1073872905, NULL },
        { NULL, 4104, "1"},
        { "onlyContainsCACerts", 1610653700, NULL },
        { NULL, 1073872905, NULL },
        { NULL, 4104, "2"},
        { "onlySomeReasons", 1610637314, "ReasonFlags"},
        { NULL, 4104, "3"},
        { "indirectCRL", 536911876, NULL },
        { NULL, 1073872905, NULL },
        { NULL, 4104, "4"},
        { "id-ce-deltaCRLIndicator", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "27"},
        { "BaseCRLNumber", 1073741826, "CRLNumber"},
        { "id-ce-cRLReasons", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "21"},
        { "CRLReason", 1610874901, NULL },
        { "unspecified", 1073741825, "0"},
        { "keyCompromise", 1073741825, "1"},
        { "cACompromise", 1073741825, "2"},
        { "affiliationChanged", 1073741825, "3"},
        { "superseded", 1073741825, "4"},
        { "cessationOfOperation", 1073741825, "5"},
        { "certificateHold", 1073741825, "6"},
        { "removeFromCRL", 1, "8"},
        { "id-ce-certificateIssuer", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "29"},
        { "CertificateIssuer", 1073741826, "GeneralNames"},
        { "id-ce-holdInstructionCode", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "23"},
        { "HoldInstructionCode", 1073741836, NULL },
        { "holdInstruction", 1879048204, NULL },
        { "joint-iso-itu-t", 1073741825, "2"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "x9cm", 1073741825, "10040"},
        { NULL, 1, "2"},
        { "id-holdinstruction-none", 1879048204, NULL },
        { NULL, 1073741825, "holdInstruction"},
        { NULL, 1, "1"},
        { "id-holdinstruction-callissuer", 1879048204, NULL },
        { NULL, 1073741825, "holdInstruction"},
        { NULL, 1, "2"},
        { "id-holdinstruction-reject", 1879048204, NULL },
        { NULL, 1073741825, "holdInstruction"},
        { NULL, 1, "3"},
        { "id-ce-invalidityDate", 1879048204, NULL },
        { NULL, 1073741825, "id-ce"},
        { NULL, 1, "24"},
        { "InvalidityDate", 1082130449, NULL },
        { "VisibleString", 1610620935, NULL },
        { NULL, 4360, "26"},
        { "NumericString", 1610620935, NULL },
        { NULL, 4360, "18"},
        { "IA5String", 1610620935, NULL },
        { NULL, 4360, "22"},
        { "TeletexString", 1610620935, NULL },
        { NULL, 4360, "20"},
        { "PrintableString", 1610620935, NULL },
        { NULL, 4360, "19"},
        { "UniversalString", 1610620935, NULL },
        { NULL, 4360, "28"},
        { "BMPString", 1610620935, NULL },
        { NULL, 4360, "30"},
        { "UTF8String", 1610620935, NULL },
        { NULL, 4360, "12"},
        { "id-pkix", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "identified-organization", 1073741825, "3"},
        { "dod", 1073741825, "6"},
        { "internet", 1073741825, "1"},
        { "security", 1073741825, "5"},
        { "mechanisms", 1073741825, "5"},
        { "pkix", 1, "7"},
        { "id-pe", 1879048204, NULL },
        { NULL, 1073741825, "id-pkix"},
        { NULL, 1, "1"},
        { "id-qt", 1879048204, NULL },
        { NULL, 1073741825, "id-pkix"},
        { NULL, 1, "2"},
        { "id-kp", 1879048204, NULL },
        { NULL, 1073741825, "id-pkix"},
        { NULL, 1, "3"},
        { "id-ad", 1879048204, NULL },
        { NULL, 1073741825, "id-pkix"},
        { NULL, 1, "48"},
        { "id-qt-cps", 1879048204, NULL },
        { NULL, 1073741825, "id-qt"},
        { NULL, 1, "1"},
        { "id-qt-unotice", 1879048204, NULL },
        { NULL, 1073741825, "id-qt"},
        { NULL, 1, "2"},
        { "id-ad-ocsp", 1879048204, NULL },
        { NULL, 1073741825, "id-ad"},
        { NULL, 1, "1"},
        { "id-ad-caIssuers", 1879048204, NULL },
        { NULL, 1073741825, "id-ad"},
        { NULL, 1, "2"},
        { "Attribute", 1610612741, NULL },
        { "type", 1073741826, "AttributeType"},
        { "values", 536870927, NULL },
        { NULL, 2, "AttributeValue"},
        { "AttributeType", 1073741836, NULL },
        { "AttributeValue", 1073741837, NULL },
        { "AttributeTypeAndValue", 1610612741, NULL },
        { "type", 1073741826, "AttributeType"},
        { "value", 2, "AttributeValue"},
        { "id-at", 1879048204, NULL },
        { "joint-iso-ccitt", 1073741825, "2"},
        { "ds", 1073741825, "5"},
        { NULL, 1, "4"},
        { "id-at-name", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "41"},
        { "id-at-surname", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "4"},
        { "id-at-givenName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "42"},
        { "id-at-initials", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "43"},
        { "id-at-generationQualifier", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "44"},
        { "X520name", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-name", 524298, "1"},
        { "id-at-commonName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "3"},
        { "X520CommonName", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-common-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-common-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-common-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-common-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-common-name", 524298, "1"},
        { "id-at-localityName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "7"},
        { "X520LocalityName", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-locality-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-locality-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-locality-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-locality-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-locality-name", 524298, "1"},
        { "id-at-stateOrProvinceName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "8"},
        { "X520StateOrProvinceName", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-state-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-state-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-state-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-state-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-state-name", 524298, "1"},
        { "id-at-organizationName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "10"},
        { "X520OrganizationName", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-organization-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-organization-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-organization-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-organization-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-organization-name", 524298, "1"},
        { "id-at-organizationalUnitName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "11"},
        { "X520OrganizationalUnitName", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-organizational-unit-name", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-organizational-unit-name", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-organizational-unit-name", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-organizational-unit-name", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-organizational-unit-name", 524298, "1"},
        { "id-at-title", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "12"},
        { "X520Title", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "ub-title", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "ub-title", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "ub-title", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "ub-title", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "ub-title", 524298, "1"},
        { "id-at-dnQualifier", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "46"},
        { "X520dnQualifier", 1073741826, "PrintableString"},
        { "id-at-countryName", 1880096780, "AttributeType"},
        { NULL, 1073741825, "id-at"},
        { NULL, 1, "6"},
        { "X520countryName", 1612709890, "PrintableString"},
        { NULL, 1048586, "2"},
        { "pkcs-9", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "rsadsi", 1073741825, "113549"},
        { "pkcs", 1073741825, "1"},
        { NULL, 1, "9"},
        { "emailAddress", 1880096780, "AttributeType"},
        { NULL, 1073741825, "pkcs-9"},
        { NULL, 1, "1"},
        { "Pkcs9email", 1612709890, "IA5String"},
        { "ub-emailaddress-length", 524298, "1"},
        { "Name", 1610612754, NULL },
        { "rdnSequence", 2, "RDNSequence"},
        { "RDNSequence", 1610612747, NULL },
        { NULL, 2, "RelativeDistinguishedName"},
        { "DistinguishedName", 1073741826, "RDNSequence"},
        { "RelativeDistinguishedName", 1612709903, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "AttributeTypeAndValue"},
        { "DirectoryString", 1610612754, NULL },
        { "teletexString", 1612709890, "TeletexString"},
        { "MAX", 524298, "1"},
        { "printableString", 1612709890, "PrintableString"},
        { "MAX", 524298, "1"},
        { "universalString", 1612709890, "UniversalString"},
        { "MAX", 524298, "1"},
        { "utf8String", 1612709890, "UTF8String"},
        { "MAX", 524298, "1"},
        { "bmpString", 538968066, "BMPString"},
        { "MAX", 524298, "1"},
        { "Certificate", 1610612741, NULL },
        { "tbsCertificate", 1073741826, "TBSCertificate"},
        { "signatureAlgorithm", 1073741826, "AlgorithmIdentifier"},
        { "signature", 6, NULL },
        { "TBSCertificate", 1610612741, NULL },
        { "version", 1610653698, "Version"},
        { NULL, 1073741833, "v1"},
        { NULL, 2056, "0"},
        { "serialNumber", 1073741826, "CertificateSerialNumber"},
        { "signature", 1073741826, "AlgorithmIdentifier"},
        { "issuer", 1073741826, "Name"},
        { "validity", 1073741826, "Validity"},
        { "subject", 1073741826, "Name"},
        { "subjectPublicKeyInfo", 1073741826, "SubjectPublicKeyInfo"},
        { "issuerUniqueID", 1610637314, "UniqueIdentifier"},
        { NULL, 4104, "1"},
        { "subjectUniqueID", 1610637314, "UniqueIdentifier"},
        { NULL, 4104, "2"},
        { "extensions", 536895490, "Extensions"},
        { NULL, 2056, "3"},
        { "Version", 1610874883, NULL },
        { "v1", 1073741825, "0"},
        { "v2", 1073741825, "1"},
        { "v3", 1, "2"},
        { "CertificateSerialNumber", 1073741827, NULL },
        { "Validity", 1610612741, NULL },
        { "notBefore", 1073741826, "Time"},
        { "notAfter", 2, "Time"},
        { "Time", 1610612754, NULL },
        { "utcTime", 1090519057, NULL },
        { "generalTime", 8388625, NULL },
        { "UniqueIdentifier", 1073741830, NULL },
        { "SubjectPublicKeyInfo", 1610612741, NULL },
        { "algorithm", 1073741826, "AlgorithmIdentifier"},
        { "subjectPublicKey", 6, NULL },
        { "Extensions", 1612709899, NULL },
        { "MAX", 1074266122, "1"},
        { NULL, 2, "Extension"},
        { "Extension", 1610612741, NULL },
        { "extnID", 1073741836, NULL },
        { "critical", 1610645508, NULL },
        { NULL, 131081, NULL },
        { "extnValue", 7, NULL },
        { "CertificateList", 1610612741, NULL },
        { "tbsCertList", 1073741826, "TBSCertList"},
        { "signatureAlgorithm", 1073741826, "AlgorithmIdentifier"},
        { "signature", 6, NULL },
        { "TBSCertList", 1610612741, NULL },
        { "version", 1073758210, "Version"},
        { "signature", 1073741826, "AlgorithmIdentifier"},
        { "issuer", 1073741826, "Name"},
        { "thisUpdate", 1073741826, "Time"},
        { "nextUpdate", 1073758210, "Time"},
        { "revokedCertificates", 1610629131, NULL },
        { NULL, 536870917, NULL },
        { "userCertificate", 1073741826, "CertificateSerialNumber"},
        { "revocationDate", 1073741826, "Time"},
        { "crlEntryExtensions", 16386, "Extensions"},
        { "crlExtensions", 536895490, "Extensions"},
        { NULL, 2056, "0"},
        { "AlgorithmIdentifier", 1610612741, NULL },
        { "algorithm", 1073741836, NULL },
        { "parameters", 541081613, NULL },
        { "algorithm", 1, NULL },
        { "pkcs-1", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "rsadsi", 1073741825, "113549"},
        { "pkcs", 1073741825, "1"},
        { NULL, 1, "1"},
        { "rsaEncryption", 1879048204, NULL },
        { NULL, 1073741825, "pkcs-1"},
        { NULL, 1, "1"},
        { "md2WithRSAEncryption", 1879048204, NULL },
        { NULL, 1073741825, "pkcs-1"},
        { NULL, 1, "2"},
        { "md5WithRSAEncryption", 1879048204, NULL },
        { NULL, 1073741825, "pkcs-1"},
        { NULL, 1, "4"},
        { "sha1WithRSAEncryption", 1879048204, NULL },
        { NULL, 1073741825, "pkcs-1"},
        { NULL, 1, "5"},
        { "id-dsa-with-sha1", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "x9-57", 1073741825, "10040"},
        { "x9algorithm", 1073741825, "4"},
        { NULL, 1, "3"},
        { "Dss-Sig-Value", 1610612741, NULL },
        { "r", 1073741827, NULL },
        { "s", 3, NULL },
        { "dhpublicnumber", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "ansi-x942", 1073741825, "10046"},
        { "number-type", 1073741825, "2"},
        { NULL, 1, "1"},
        { "DomainParameters", 1610612741, NULL },
        { "p", 1073741827, NULL },
        { "g", 1073741827, NULL },
        { "q", 1073741827, NULL },
        { "j", 1073758211, NULL },
        { "validationParms", 16386, "ValidationParms"},
        { "ValidationParms", 1610612741, NULL },
        { "seed", 1073741830, NULL },
        { "pgenCounter", 3, NULL },
        { "id-dsa", 1879048204, NULL },
        { "iso", 1073741825, "1"},
        { "member-body", 1073741825, "2"},
        { "us", 1073741825, "840"},
        { "x9-57", 1073741825, "10040"},
        { "x9algorithm", 1073741825, "4"},
        { NULL, 1, "1"},
        { "Dss-Parms", 1610612741, NULL },
        { "p", 1073741827, NULL },
        { "q", 1073741827, NULL },
        { "g", 3, NULL },
        { "ORAddress", 1610612741, NULL },
        { "built-in-standard-attributes", 1073741826, "BuiltInStandardAttributes"},
        { "built-in-domain-defined-attributes", 1073758210, "BuiltInDomainDefinedAttributes"},
        { "extension-attributes", 16386, "ExtensionAttributes"},
        { "BuiltInStandardAttributes", 1610612741, NULL },
        { "country-name", 1073758210, "CountryName"},
        { "administration-domain-name", 1073758210, "AdministrationDomainName"},
        { "network-address", 1610637314, "NetworkAddress"},
        { NULL, 2056, "0"},
        { "terminal-identifier", 1610637314, "TerminalIdentifier"},
        { NULL, 2056, "1"},
        { "private-domain-name", 1610637314, "PrivateDomainName"},
        { NULL, 2056, "2"},
        { "organization-name", 1610637314, "OrganizationName"},
        { NULL, 2056, "3"},
        { "numeric-user-identifier", 1610637314, "NumericUserIdentifier"},
        { NULL, 2056, "4"},
        { "personal-name", 1610637314, "PersonalName"},
        { NULL, 2056, "5"},
        { "organizational-unit-names", 536895490, "OrganizationalUnitNames"},
        { NULL, 2056, "6"},
        { "CountryName", 1610620946, NULL },
        { NULL, 1073746952, "1"},
        { "x121-dcc-code", 1612709890, "NumericString"},
        { NULL, 1048586, "ub-country-name-numeric-length"},
        { "iso-3166-alpha2-code", 538968066, "PrintableString"},
        { NULL, 1048586, "ub-country-name-alpha-length"},
        { "AdministrationDomainName", 1610620946, NULL },
        { NULL, 1073744904, "2"},
        { "numeric", 1612709890, "NumericString"},
        { "ub-domain-name-length", 524298, "0"},
        { "printable", 538968066, "PrintableString"},
        { "ub-domain-name-length", 524298, "0"},
        { "NetworkAddress", 1073741826, "X121Address"},
        { "X121Address", 1612709890, "NumericString"},
        { "ub-x121-address-length", 524298, "1"},
        { "TerminalIdentifier", 1612709890, "PrintableString"},
        { "ub-terminal-id-length", 524298, "1"},
        { "PrivateDomainName", 1610612754, NULL },
        { "numeric", 1612709890, "NumericString"},
        { "ub-domain-name-length", 524298, "1"},
        { "printable", 538968066, "PrintableString"},
        { "ub-domain-name-length", 524298, "1"},
        { "OrganizationName", 1612709890, "PrintableString"},
        { "ub-organization-name-length", 524298, "1"},
        { "NumericUserIdentifier", 1612709890, "NumericString"},
        { "ub-numeric-user-id-length", 524298, "1"},
        { "PersonalName", 1610612750, NULL },
        { "surname", 1814044674, "PrintableString"},
        { NULL, 1073745928, "0"},
        { "ub-surname-length", 524298, "1"},
        { "given-name", 1814061058, "PrintableString"},
        { NULL, 1073745928, "1"},
        { "ub-given-name-length", 524298, "1"},
        { "initials", 1814061058, "PrintableString"},
        { NULL, 1073745928, "2"},
        { "ub-initials-length", 524298, "1"},
        { "generation-qualifier", 740319234, "PrintableString"},
        { NULL, 1073745928, "3"},
        { "ub-generation-qualifier-length", 524298, "1"},
        { "OrganizationalUnitNames", 1612709899, NULL },
        { "ub-organizational-units", 1074266122, "1"},
        { NULL, 2, "OrganizationalUnitName"},
        { "OrganizationalUnitName", 1612709890, "PrintableString"},
        { "ub-organizational-unit-name-length", 524298, "1"},
        { "BuiltInDomainDefinedAttributes", 1612709899, NULL },
        { "ub-domain-defined-attributes", 1074266122, "1"},
        { NULL, 2, "BuiltInDomainDefinedAttribute"},
        { "BuiltInDomainDefinedAttribute", 1610612741, NULL },
        { "type", 1612709890, "PrintableString"},
        { "ub-domain-defined-attribute-type-length", 524298, "1"},
        { "value", 538968066, "PrintableString"},
        { "ub-domain-defined-attribute-value-length", 524298, "1"},
        { "ExtensionAttributes", 1612709903, NULL },
        { "ub-extension-attributes", 1074266122, "1"},
        { NULL, 2, "ExtensionAttribute"},
        { "ExtensionAttribute", 1610612741, NULL },
        { "extension-attribute-type", 1611145219, NULL },
        { NULL, 1073743880, "0"},
        { "0", 10, "ub-extension-attributes"},
        { "extension-attribute-value", 541073421, NULL },
        { NULL, 1073743880, "1"},
        { "extension-attribute-type", 1, NULL },
        { "common-name", 1342177283, "1"},
        { "CommonName", 1612709890, "PrintableString"},
        { "ub-common-name-length", 524298, "1"},
        { "teletex-common-name", 1342177283, "2"},
        { "TeletexCommonName", 1612709890, "TeletexString"},
        { "ub-common-name-length", 524298, "1"},
        { "teletex-organization-name", 1342177283, "3"},
        { "TeletexOrganizationName", 1612709890, "TeletexString"},
        { "ub-organization-name-length", 524298, "1"},
        { "teletex-personal-name", 1342177283, "4"},
        { "TeletexPersonalName", 1610612750, NULL },
        { "surname", 1814044674, "TeletexString"},
        { NULL, 1073743880, "0"},
        { "ub-surname-length", 524298, "1"},
        { "given-name", 1814061058, "TeletexString"},
        { NULL, 1073743880, "1"},
        { "ub-given-name-length", 524298, "1"},
        { "initials", 1814061058, "TeletexString"},
        { NULL, 1073743880, "2"},
        { "ub-initials-length", 524298, "1"},
        { "generation-qualifier", 740319234, "TeletexString"},
        { NULL, 1073743880, "3"},
        { "ub-generation-qualifier-length", 524298, "1"},
        { "teletex-organizational-unit-names", 1342177283, "5"},
        { "TeletexOrganizationalUnitNames", 1612709899, NULL },
        { "ub-organizational-units", 1074266122, "1"},
        { NULL, 2, "TeletexOrganizationalUnitName"},
        { "TeletexOrganizationalUnitName", 1612709890, "TeletexString"},
        { "ub-organizational-unit-name-length", 524298, "1"},
        { "pds-name", 1342177283, "7"},
        { "PDSName", 1612709890, "PrintableString"},
        { "ub-pds-name-length", 524298, "1"},
        { "physical-delivery-country-name", 1342177283, "8"},
        { "PhysicalDeliveryCountryName", 1610612754, NULL },
        { "x121-dcc-code", 1612709890, "NumericString"},
        { NULL, 1048586, "ub-country-name-numeric-length"},
        { "iso-3166-alpha2-code", 538968066, "PrintableString"},
        { NULL, 1048586, "ub-country-name-alpha-length"},
        { "postal-code", 1342177283, "9"},
        { "PostalCode", 1610612754, NULL },
        { "numeric-code", 1612709890, "NumericString"},
        { "ub-postal-code-length", 524298, "1"},
        { "printable-code", 538968066, "PrintableString"},
        { "ub-postal-code-length", 524298, "1"},
        { "physical-delivery-office-name", 1342177283, "10"},
        { "PhysicalDeliveryOfficeName", 1073741826, "PDSParameter"},
        { "physical-delivery-office-number", 1342177283, "11"},
        { "PhysicalDeliveryOfficeNumber", 1073741826, "PDSParameter"},
        { "extension-OR-address-components", 1342177283, "12"},
        { "ExtensionORAddressComponents", 1073741826, "PDSParameter"},
        { "physical-delivery-personal-name", 1342177283, "13"},
        { "PhysicalDeliveryPersonalName", 1073741826, "PDSParameter"},
        { "physical-delivery-organization-name", 1342177283, "14"},
        { "PhysicalDeliveryOrganizationName", 1073741826, "PDSParameter"},
        { "extension-physical-delivery-address-components", 1342177283, "15"},
        { "ExtensionPhysicalDeliveryAddressComponents", 1073741826, "PDSParameter"},
        { "unformatted-postal-address", 1342177283, "16"},
        { "UnformattedPostalAddress", 1610612750, NULL },
        { "printable-address", 1814052875, NULL },
        { "ub-pds-physical-address-lines", 1074266122, "1"},
        { NULL, 538968066, "PrintableString"},
        { "ub-pds-parameter-length", 524298, "1"},
        { "teletex-string", 740311042, "TeletexString"},
        { "ub-unformatted-address-length", 524298, "1"},
        { "street-address", 1342177283, "17"},
        { "StreetAddress", 1073741826, "PDSParameter"},
        { "post-office-box-address", 1342177283, "18"},
        { "PostOfficeBoxAddress", 1073741826, "PDSParameter"},
        { "poste-restante-address", 1342177283, "19"},
        { "PosteRestanteAddress", 1073741826, "PDSParameter"},
        { "unique-postal-name", 1342177283, "20"},
        { "UniquePostalName", 1073741826, "PDSParameter"},
        { "local-postal-attributes", 1342177283, "21"},
        { "LocalPostalAttributes", 1073741826, "PDSParameter"},
        { "PDSParameter", 1610612750, NULL },
        { "printable-string", 1814052866, "PrintableString"},
        { "ub-pds-parameter-length", 524298, "1"},
        { "teletex-string", 740311042, "TeletexString"},
        { "ub-pds-parameter-length", 524298, "1"},
        { "extended-network-address", 1342177283, "22"},
        { "ExtendedNetworkAddress", 1610612754, NULL },
        { "e163-4-address", 1610612741, NULL },
        { "number", 1612718082, "NumericString"},
        { NULL, 1073743880, "0"},
        { "ub-e163-4-number-length", 524298, "1"},
        { "sub-address", 538992642, "NumericString"},
        { NULL, 1073743880, "1"},
        { "ub-e163-4-sub-address-length", 524298, "1"},
        { "psap-address", 536879106, "PresentationAddress"},
        { NULL, 2056, "0"},
        { "PresentationAddress", 1610612741, NULL },
        { "pSelector", 1610637319, NULL },
        { NULL, 2056, "0"},
        { "sSelector", 1610637319, NULL },
        { NULL, 2056, "1"},
        { "tSelector", 1610637319, NULL },
        { NULL, 2056, "2"},
        { "nAddresses", 538976271, NULL },
        { NULL, 1073743880, "3"},
        { "MAX", 1074266122, "1"},
        { NULL, 7, NULL },
        { "terminal-type", 1342177283, "23"},
        { "TerminalType", 1611137027, NULL },
        { "0", 10, "ub-integer-options"},
        { "teletex-domain-defined-attributes", 1342177283, "6"},
        { "TeletexDomainDefinedAttributes", 1612709899, NULL },
        { "ub-domain-defined-attributes", 1074266122, "1"},
        { NULL, 2, "TeletexDomainDefinedAttribute"},
        { "TeletexDomainDefinedAttribute", 1610612741, NULL },
        { "type", 1612709890, "TeletexString"},
        { "ub-domain-defined-attribute-type-length", 524298, "1"},
        { "value", 538968066, "TeletexString"},
        { "ub-domain-defined-attribute-value-length", 524298, "1"},
        { "ub-name", 1342177283, "32768"},
        { "ub-common-name", 1342177283, "64"},
        { "ub-locality-name", 1342177283, "128"},
        { "ub-state-name", 1342177283, "128"},
        { "ub-organization-name", 1342177283, "64"},
        { "ub-organizational-unit-name", 1342177283, "64"},
        { "ub-title", 1342177283, "64"},
        { "ub-match", 1342177283, "128"},
        { "ub-emailaddress-length", 1342177283, "128"},
        { "ub-common-name-length", 1342177283, "64"},
        { "ub-country-name-alpha-length", 1342177283, "2"},
        { "ub-country-name-numeric-length", 1342177283, "3"},
        { "ub-domain-defined-attributes", 1342177283, "4"},
        { "ub-domain-defined-attribute-type-length", 1342177283, "8"},
        { "ub-domain-defined-attribute-value-length", 1342177283, "128"},
        { "ub-domain-name-length", 1342177283, "16"},
        { "ub-extension-attributes", 1342177283, "256"},
        { "ub-e163-4-number-length", 1342177283, "15"},
        { "ub-e163-4-sub-address-length", 1342177283, "40"},
        { "ub-generation-qualifier-length", 1342177283, "3"},
        { "ub-given-name-length", 1342177283, "16"},
        { "ub-initials-length", 1342177283, "5"},
        { "ub-integer-options", 1342177283, "256"},
        { "ub-numeric-user-id-length", 1342177283, "32"},
        { "ub-organization-name-length", 1342177283, "64"},
        { "ub-organizational-unit-name-length", 1342177283, "32"},
        { "ub-organizational-units", 1342177283, "4"},
        { "ub-pds-name-length", 1342177283, "16"},
        { "ub-pds-parameter-length", 1342177283, "30"},
        { "ub-pds-physical-address-lines", 1342177283, "6"},
        { "ub-postal-code-length", 1342177283, "16"},
        { "ub-surname-length", 1342177283, "40"},
        { "ub-terminal-id-length", 1342177283, "24"},
        { "ub-unformatted-address-length", 1342177283, "180"},
        { "ub-x121-address-length", 268435459, "16"},
        { NULL, 0, NULL }
    };
    
    /* PEM certificate decoding (to DER) */
    byte *certificatDer = 0;
    int sizeCert = pemToAsn(cert, certLen, &certificatDer);
    if (sizeCert < 0) {
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error Base 64\n");
        printf("### getModulusSize() End ###\n\n");
        #endif
        
        /* Return error */
        return sizeCert;
        
    }
    
    /* Certificate structure creation */
    ASN1_TYPE certDef = ASN1_TYPE_EMPTY;
    char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    int result = asn1_array2tree(structCertificat, &certDef, errorDescription);
    if (result != ASN1_SUCCESS) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems creating structure asn1_array2tree\n");
        int i = 0;
        for (i = 0; i < ASN1_MAX_ERROR_DESCRIPTION_SIZE; i++) {
            printf("%c", errorDescription[i]);
        }
        printf("\n");
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        asn1_delete_structure(&certDef);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getModulusSize() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /* Certificate DER parsing for utilisation */
    ASN1_TYPE certificat = ASN1_TYPE_EMPTY;
    asn1_create_element(certDef, "PKIX1Implicit88.Certificate", &certificat);
    result = asn1_der_decoding(&certificat, certificatDer, sizeCert, errorDescription);
    if (result != ASN1_SUCCESS) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Problems with DER encoding\n");
        int i = 0;
        for (i = 0; i < ASN1_MAX_ERROR_DESCRIPTION_SIZE; i++) {
            
            printf("%c", errorDescription[i]);
            
        }
        printf("\n");
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getModulusSize() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /*
     * From here we have :
     * certificat = the certificate
     * certDef = the X.509 certificate definition
     */
    
    /* Get the public key from the DER certificate */
    int lenPubKeyDer = 2048;
    byte pubKeyDer[2048];
    result = asn1_read_value(certificat, "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey", pubKeyDer, &lenPubKeyDer);
    
    /* Check error */
    if (result != ASN1_SUCCESS) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Impossible to extract key from Certificate\n");
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getModulusSize() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /* DER Public key convertion (in bytes) */
    gcry_sexp_t gcryPubKey = 0;
    int error = getPublicRsaFromDer(pubKeyDer, lenPubKeyDer, &gcryPubKey);
    if (error < 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Impossible to convert DER public key to byte\n");
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if(gcryPubKey != NULL){
            gcry_sexp_release(gcryPubKey);
            gcryPubKey = 0;
        }
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### getModulusSize() End ###\n\n");
        #endif
        
        return error;
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Getting Modulus Size\n");
    #endif
    
    /* Getting the modulus size */
    int sizeModulus = gcry_pk_get_nbits(gcryPubKey);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Freeing memory\n");
    #endif
    
    /* Free memory */
    if (certificatDer != NULL) {
        free(certificatDer);
        certificatDer = 0;
    }
    if(gcryPubKey != NULL){
        gcry_sexp_release(gcryPubKey);
        gcryPubKey = 0;
    }
    asn1_delete_structure(&certDef);
    asn1_delete_structure(&certificat);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getModulusSize() End ###\n\n");
    #endif
    
    if (sizeModulus <= 0) return GLS_ERROR_BADSERVERCERT;
    else return sizeModulus;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Convert byte to hex char. Return the size of hex or a 
 negative number for an error.
 
 ---------------------------------------------------------*/

int byteToHex(const byte *buffer, const int sizeBuffer, char **hex) {
    
    /* two bytes of hex for one byte of buffer plus NULL terminator */
    char *temp = malloc(sizeBuffer * 2 + 1);
    if (temp == NULL) {
        
        return GLS_ERROR_NOMEM;
        
    }
    
    
    int i = 0;
    for (i = 0; i < (sizeBuffer * 2); i += 2) {
        
        sprintf(&temp[i], "%02X", buffer[i / 2]);
        
    }
    
    /* insertion NULL terminator */
    temp[sizeBuffer * 2] = '\0';
    
    (*hex) = temp;
    
    /* Debug Only */   
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("ByteToHex : %s\n", (*hex));
    #endif
    
    return sizeBuffer * 2;

}



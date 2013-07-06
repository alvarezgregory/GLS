/*
 *  Crypto.c
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
 
 PRIVATE
 
 Initialize encryption handlers. Return 0 for success or
 a negative number for an error.
 
 ---------------------------------------------------------*/

int initHandler(GLSSock* myGLSSocket){
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### initHandler() Start ###\n");
    #endif
    
    /* If no encryption key return an error */
    if (myGLSSocket->m_isCryptoKey == 0) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Handler initialisation error.\n");
        printf("### initHandler() End ###\n\n");
        #endif
        
        return GLS_ERROR_NOPASSWD;
    }
    
    /* Error handling */
    int error = 0;
    
    /* If the handlers aren't created we allocated them, otherwise 
     we only change the keys */
    if (myGLSSocket->m_isHandlerInit == 0) {
        
        /* Serpent (CTS, 256 bit) */
        /* Secure memory and CTS mode don't work together */
        error += gcry_cipher_open(&myGLSSocket->m_serpentHandlerCTS, GCRY_CIPHER_SERPENT256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
        error += gcry_cipher_setkey(myGLSSocket->m_serpentHandlerCTS, myGLSSocket->m_key1, 32);
        
        /* Twofish (CTS, 256 bit) */
        error += gcry_cipher_open(&myGLSSocket->m_twofishHandlerCTS, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
        error += gcry_cipher_setkey(myGLSSocket->m_twofishHandlerCTS, myGLSSocket->m_key2, 32);
        
        /* Serpent (ECB, 256 bit) */
        error += gcry_cipher_open(&myGLSSocket->m_serpentHandlerECB, GCRY_CIPHER_SERPENT256, GCRY_CIPHER_MODE_ECB, GCRY_CIPHER_SECURE);
        error += gcry_cipher_setkey(myGLSSocket->m_serpentHandlerECB, myGLSSocket->m_key1, 32);
        
        /* Twofish (ECB, 256 bit) */
        error += gcry_cipher_open(&myGLSSocket->m_twofishHandlerECB, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_ECB, GCRY_CIPHER_SECURE);
        error += gcry_cipher_setkey(myGLSSocket->m_twofishHandlerECB, myGLSSocket->m_key2, 32);
        
        myGLSSocket->m_isHandlerInit = 1;
        
    }
    else {
        
        /* Serpent (CTS, 256 bit) */
        error += gcry_cipher_setkey(myGLSSocket->m_serpentHandlerCTS, myGLSSocket->m_key1, 32);
        
        /* Twofish (CTS, 256 bit) */
        error += gcry_cipher_setkey(myGLSSocket->m_twofishHandlerCTS, myGLSSocket->m_key2, 32);
        
        /* Serpent (ECB, 256 bit) */
        error += gcry_cipher_setkey(myGLSSocket->m_serpentHandlerECB, myGLSSocket->m_key1, 32);
        
        /* Twofish (ECB, 256 bit) */
        error += gcry_cipher_setkey(myGLSSocket->m_twofishHandlerECB, myGLSSocket->m_key2, 32);
        
    }
    
    
    if(error != 0) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Handler initialisation error.\n");
        printf("### initHandler() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### initHandler() End ###\n\n");
    #endif
    
    return 0;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Generate 128 bits initialisation vectors.
 
 ---------------------------------------------------------*/

int getIV(byte* iv) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getIV() Start ###\n");
    #endif
    
    /* length in byte (16 bytes = 128 bits) */
    gcry_create_nonce(iv, 16);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### getIV() End ###\n\n");
    #endif
    
    return 0;
}




/*-------------------------------------------------------
 
 PRIVATE
 
 First message encryption.
 Return the ciphertext size or a negative number for an error.
 
 ---------------------------------------------------------*/

int firstEncrypt(GLSSock* myGLSSocket, const byte* plainText, const int size, byte** cypherText){
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### firstEncrypt() Start ###\n");
    #endif
    
    /* If the handlers aren't initialized or no encryption key is
     available return an error */
    if (myGLSSocket->m_isCryptoKey == 0 || myGLSSocket->m_isHandlerInit == 0) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No initial configuration firstEncrypt.\n");
        printf("### firstEncrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_NOPASSWD;
        
    }
    
    /* Temp and final memory allocation */
    byte (*tempPlainText) = 0;
    byte (*tempCypherText) = 0;
    byte (*tempCypherTextFinal) = 0;
    
    /* Check plaintext size and allocation */
    if (size > 0 && plainText != NULL) {
        
        /*
         * Memory allocation with the additional 768 bit from the GLS
         * protocol (IV1 + IV2 + MAC + IV3 + IV4) = 768 bits / 96 bytes
         * CypherText = (IV1 + IV2) + (MAC + IV3 + IV4) + tempCypherText
         */
        
        tempPlainText = malloc((size + 64) * sizeof(byte));
        tempCypherText = malloc((size + 64) * sizeof(byte));;
        tempCypherTextFinal = malloc((size + 64) * sizeof(byte));;
        *cypherText = malloc((size + 96) * sizeof(byte));;
        
        if (tempPlainText == NULL || tempCypherText == NULL || tempCypherTextFinal == NULL || *cypherText == NULL) {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No memory. FirstEncrypt\n");
            #endif
            
            return GLS_ERROR_NOMEM;
            
        }
        
    }
    else {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Bad argument FirstEncrypt (Size : %d).\n", size);
        if (plainText == NULL) printf("PlainText == NULL\n");
        printf("### firstEncrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_NOMESSAGE;
        
    }
    
    /* Error handling */
    int error = 0;
    int i = 0;
    
    /* Initialisation Vectors generation */
    error += getIV(myGLSSocket->m_iv1);
    error += getIV(myGLSSocket->m_iv2);
    error += getIV(myGLSSocket->m_iv3);
    error += getIV(myGLSSocket->m_iv4);
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("IV1 (FirstEncrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv1[i]);
    }
    printf("\n");
    
    /* Debug only */
    printf("IV2 (FirstEncrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv2[i]);
    }
    printf("\n");
    
    /* Debug only */
    printf("IV3 (FirstEncrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv3[i]);
    }
    printf("\n");
    
    /* Debug only */
    printf("IV4 (FirstEncrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv4[i]);
    }
    printf("\n");
    #endif
    
    /* IVS Reset and Configuration  */
    error += gcry_cipher_reset(myGLSSocket->m_serpentHandlerCTS);
    error += gcry_cipher_setiv(myGLSSocket->m_serpentHandlerCTS, myGLSSocket->m_iv1, 16);
    error += gcry_cipher_reset(myGLSSocket->m_twofishHandlerCTS);
    error += gcry_cipher_setiv(myGLSSocket->m_twofishHandlerCTS, myGLSSocket->m_iv2, 16);
    
    /* Temp variable for IVS encryption */
    byte tempIV1[16];
    byte tempIV2[16];
    byte tempIV1Final[16];
    byte tempIV2Final[16];
    
    /* IVS Encryption (IV1 and IV2 in ECB) */
    /* IV1 ECB */
    error += gcry_cipher_encrypt(myGLSSocket->m_serpentHandlerECB, tempIV1, 16, myGLSSocket->m_iv1, 16);
    error += gcry_cipher_encrypt(myGLSSocket->m_twofishHandlerECB, tempIV1Final, 16, tempIV1, 16);
    /* IV2 ECB */
    error += gcry_cipher_encrypt(myGLSSocket->m_serpentHandlerECB, tempIV2, 16, myGLSSocket->m_iv2, 16);
    error += gcry_cipher_encrypt(myGLSSocket->m_twofishHandlerECB, tempIV2Final, 16, tempIV2, 16);
    
    /* MAC generation (SHA-256) */
    /* MAC = IV3 + IV4 + Data */
    byte MAC[32];
    byte (*tempMACText);
    tempMACText = malloc((size + 32) * sizeof(byte));
    if (tempMACText == NULL) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No memory. FirstEncrypt\n");
        #endif
        
        return GLS_ERROR_NOMEM;
        
    }
    /* IV3 and IV4 */
    i = 0;
    for (i = 0; i < 16; i++) {
        tempMACText[i] = myGLSSocket->m_iv3[i];
        tempMACText[i + 16] = myGLSSocket->m_iv4[i];
    }
    /* Message */
    i = 0;
    for (i = 0; i < size; i++) {
        tempMACText[i + 32] = plainText[i];
    }
    gcry_md_hash_buffer(GCRY_MD_SHA256, MAC, tempMACText, (size + 32));
    free(tempMACText);
    tempMACText = 0;
    
    /* Filling tempPlainText (according to the GLS structure) to be encrypt in CTS mode */
    /* MAC */
    i = 0;
    for (i = 0; i < 32; i++) {
        tempPlainText[i] = MAC[i];
    }
    /* IV3 et IV4 */
    i = 0;
    for (i = 0; i < 16; i++) {
        tempPlainText[i + 32] = myGLSSocket->m_iv3[i];
        tempPlainText[i + 48] = myGLSSocket->m_iv4[i];
    }
    /* Message */
    i = 0;
    for (i = 0; i < size; i++) {
        tempPlainText[i + 64] = plainText[i];
    }
    
    /* tempPlainText encryption  */
    error += gcry_cipher_encrypt(myGLSSocket->m_serpentHandlerCTS, tempCypherText, (size + 64), tempPlainText, (size + 64));
    error += gcry_cipher_encrypt(myGLSSocket->m_twofishHandlerCTS, tempCypherTextFinal, (size + 64), tempCypherText, (size + 64));
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Message (FirstEncrypt) : ");
    i = 0;
    for (i = 0; i < size; i++) {
        printf("%c", plainText[i]);
    }
    printf("\n");
    printf("Message serpent (FirstEncrypt) : ");
    i = 0;
    for (i = 0; i < size; i++) {
        printf("%x", tempCypherText[i]);
    }
    printf("\n");
    #endif
    
    /* Filling cypherText according to the GLS structure */
    /* IV1 and IV2 (encrypted) */
    i = 0;
    for (i = 0; i < 16; i++) {
        (*cypherText)[i] = tempIV1Final[i];
        (*cypherText)[i + 16] = tempIV2Final[i];
    }
    /* MAC, IV3, IV4 and encrypted message */
    i = 0;
    for (i = 0; i < (size + 64); i++) {
        (*cypherText)[i + 32] = tempCypherTextFinal[i];
    }
    
    if(error != 0) {
        
        /* debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error %d : %s\n", error, gcry_strerror(error));
        #endif
        
        /* Free temp memory */
        free(tempPlainText);
        tempPlainText = 0;
        free(tempCypherText);
        tempCypherText = 0;
        free(tempCypherTextFinal);
        tempCypherTextFinal = 0;
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### firstEncrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
    
    /* Free temp memory */
    free(tempPlainText);
    tempPlainText = 0;
    free(tempCypherText);
    tempCypherText = 0;
    free(tempCypherTextFinal);
    tempCypherTextFinal = 0;
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### firstEncrypt() End ###\n\n");
    #endif
    
    return size + 96;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 First message decryption.
 Return the plaintext size or a negative number for an error.
 
 ---------------------------------------------------------*/

int firstDecrypt(GLSSock* myGLSSocket, const byte* cipherText, const int size, byte** plainText){
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### firstDecrypt() Start ###\n");
    #endif
    
    /* If the handlers aren't initialized or no encryption key is
     available return an error */
    if (myGLSSocket->m_isCryptoKey == 0 || myGLSSocket->m_isHandlerInit == 0) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Pas de configuration initial. FirstDecrypt\n");
        #endif
        
        return GLS_ERROR_NOPASSWD;
        
    }
    
    /* Temp and final memory allocation */
    byte (*cText) = 0;
    byte (*tempCypherText) = 0;
    byte (*tempCypherTextFinal) = 0;
    byte (*tempPlainText) = 0;
    
    
    /* Check if the message's size is at least highter than the header's size */
    if (size > 96 && cipherText != NULL) {
        
        /*
         * Memory allocation with the additional 768 bit from the GLS
         * protocol (IV1 + IV2 + MAC + IV3 + IV4) = 768 bits / 96 bytes
         */
        
        cText = malloc(sizeof(byte) * (size - 32));
        tempCypherText = malloc(sizeof(byte) * (size - 32));
        tempCypherTextFinal = malloc(sizeof(byte) * (size - 32));
        tempPlainText = malloc(sizeof(byte) * (size - 32));
        *plainText = malloc(sizeof(byte) * (size - 96));
        
        if (cText == NULL || tempPlainText == NULL || tempCypherText == NULL || tempCypherTextFinal == NULL || *plainText == NULL) {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No memory. FirstDecrypt\n");
            #endif
            
            return GLS_ERROR_NOMEM;
            
        }
        
    }
    else {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Bad argument FirstDecrypt (Size : %d).\n", size);
        if (cipherText == NULL) printf("CipherText == NULL\n");
        printf("### firstDecrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_UNKNOWN;
        
    }
    
    /* Error handling */
    int error = 0;
    
    /* Temp variable for IVS decryption */
    byte tempIV1[16];
    byte tempIV2[16];
    byte tempIV1Final[16];
    byte tempIV2Final[16];
    
    /* Getting IVS, data and MAC according to the GLS structure */
    /* Encrypted IV1 and IV2 */
    int i = 0;
    for (i = 0; i < 16; i++) {
        tempIV1[i] = cipherText[i];
        tempIV2[i] = cipherText[i + 16];
    }
    /* MAC, IV3, IV4 and encrypted message */
    i = 0;
    for (i = 0; i < (size - 32); i++) {
        cText[i] = cipherText[i + 32];
    }
    
    /* IVS decryption (IV1 and IV2 in ECB) */
    /* IV1 ECB */
    error += gcry_cipher_decrypt(myGLSSocket->m_twofishHandlerECB, tempIV1Final, 16, tempIV1, 16);
    error += gcry_cipher_decrypt(myGLSSocket->m_serpentHandlerECB, myGLSSocket->m_iv1, 16, tempIV1Final, 16);
    /* IV2 ECB */
    error += gcry_cipher_decrypt(myGLSSocket->m_twofishHandlerECB, tempIV2Final, 16, tempIV2, 16);
    error += gcry_cipher_decrypt(myGLSSocket->m_serpentHandlerECB, myGLSSocket->m_iv2, 16, tempIV2Final, 16);
    
    /* IVS Reset and Configuration  */
    error += gcry_cipher_reset(myGLSSocket->m_serpentHandlerCTS);
    error += gcry_cipher_setiv(myGLSSocket->m_serpentHandlerCTS, myGLSSocket->m_iv1, 16);
    error += gcry_cipher_reset(myGLSSocket->m_twofishHandlerCTS);
    error += gcry_cipher_setiv(myGLSSocket->m_twofishHandlerCTS, myGLSSocket->m_iv2, 16);
    
    /* Message decryption */
    error += gcry_cipher_decrypt(myGLSSocket->m_twofishHandlerCTS, tempCypherTextFinal, (size - 32), cText, (size - 32));
    error += gcry_cipher_decrypt(myGLSSocket->m_serpentHandlerCTS, tempPlainText, (size - 32), tempCypherTextFinal, (size - 32));
    
    /* MAC generation (SHA-256) */
    /* MAC = IV3 + IV4 + Data */
    byte MAC[32];
    byte cipherMAC[32];
    /* Fill MAC with the message's MAC */
    i = 0;
    for (i = 0; i < 32; i++) {
        MAC[i] = tempPlainText[i];
    }
    byte (*tempMACText);
    tempMACText = malloc(sizeof(byte) * (size - 64));
    if (tempMACText == NULL) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No memory. FirstDecrypt\n");
        #endif
        
        return GLS_ERROR_NOMEM;
        
    }
    /* IV3 and IV4 */
    i = 0;
    for (i = 0; i < 16; i++) {
        tempMACText[i] = tempPlainText[i + 32];
        tempMACText[i + 16] = tempPlainText[i + 48];
    }
    /* Message */
    i = 0;
    for (i = 0; i < (size - 96); i++) {
        tempMACText[i + 32] = tempPlainText[i + 64];
    }
    /* Generating the decrypted message's MAC (SHA-256) for comparison */
    gcry_md_hash_buffer(GCRY_MD_SHA256, cipherMAC, tempMACText, (size - 64));
    free(tempMACText);
    tempMACText = 0;
    
    /* Sending an error before comparing the MAC 
     because if bad decrypting = bad MAC */
    if(error != 0) {
        
        /* debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error %d : %s\n", error, gcry_strerror(error));
        #endif
        
        /* Free temp memory */
        free(cText);
        cText = 0;
        free(tempPlainText);
        tempPlainText = 0;
        free(tempCypherText);
        tempCypherText = 0;
        free(tempCypherTextFinal);
        tempCypherTextFinal = 0;
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### firstDecrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
    
    /* MAC comparison */
    i = 0;
    while (MAC[i] == cipherMAC[i] && i < 32) {
        i++;
    }
    if (!(i == 32)) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error : MAC error FirstDecrypt\n");
        #endif
        
        /* Free temp memory */
        free(cText);
        cText = 0;
        free(tempPlainText);
        tempPlainText = 0;
        free(tempCypherText);
        tempCypherText = 0;
        free(tempCypherTextFinal);
        tempCypherTextFinal = 0;
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### firstDecrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_MAC;
        
    }
    
    /* Get IV3, IV4 and message according to the GLS structure */
    /* IV3 and IV4 */
    i = 0;
    for (i = 0; i < 16; i++) {
        myGLSSocket->m_iv3[i] = tempPlainText[i + 32];
        myGLSSocket->m_iv4[i] = tempPlainText[i + 48];
    }
    /* Message */
    i = 0;
    for (i = 0; i < (size - 96); i++) {
        (*plainText)[i] = tempPlainText[i + 64];
    }
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Message serpent (FirstDecrypt) : ");
    i = 0;
    for (i = 0; i < (size - 96); i++) {
        printf("%x", tempCypherTextFinal[i]);
    }
    printf("\n");
    printf("IV1 (FirstDecrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv1[i]);
    }
    printf("\n");
    printf("IV2 (FirstDecrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv2[i]);
    }
    printf("\n");
    printf("IV3 (FirstDecrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv3[i]);
    }
    printf("\n");
    printf("IV4 (FirstDecrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv4[i]);
    }
    printf("\n");
        printf("Message (FirstDecrypt) : ");
    i = 0;
    for (i = 0; i < (size - 96); i++) {
        printf("%c", (*plainText)[i]);
    }
    printf("\n");
    #endif
    
    /* Free temp memory */
    free(cText);
    cText = 0;
    free(tempPlainText);
    tempPlainText = 0;
    free(tempCypherText);
    tempCypherText = 0;
    free(tempCypherTextFinal);
    tempCypherTextFinal = 0;
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### firstDecrypt() End ###\n\n");
    #endif
    
    return size - 96;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 
 
 Other message encryption.
 Return the ciphertext size or a negative number for an error.
 
 ---------------------------------------------------------*/

int allEncrypt(GLSSock* myGLSSocket, const byte* plainText, const int size, byte** cypherText){
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### encrypt() Start ###\n");
    #endif
    
    /* If the handlers aren't initialized or no encryption key is
     available return an error */
    if (myGLSSocket->m_isCryptoKey == 0 || myGLSSocket->m_isHandlerInit == 0) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No initial configuration firstEncrypt.\n");
        printf("### encrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_NOPASSWD;
        
    }
    
    /* Temp and final memory allocation */
    byte (*tempPlainText) = 0;
    byte (*tempCypherText) = 0;
    byte (*tempCypherTextFinal) = 0;
    
    /* Check plaintext size and allocation */
    if (size > 0 && plainText != NULL) {
        
        /*
         * Memory allocation with the additional 768 bit from the GLS
         * protocol (IV1 + IV2 + MAC + IV3 + IV4) = 768 bits / 96 bytes
         * CypherText = (MAC) + (IV1 + IV2 + IV3 + IV4) + plainText
         */
        tempPlainText = malloc(sizeof(byte) * (size + 64));
        tempCypherText = malloc(sizeof(byte) * (size + 96));
        tempCypherTextFinal = malloc(sizeof(byte) * (size + 96));
        *cypherText = malloc(sizeof(byte) * (size + 96));
        
        if (tempPlainText == NULL || tempCypherText == NULL || tempCypherTextFinal == NULL || *cypherText == NULL) {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No memory. Encrypt\n");
            #endif
            
            return GLS_ERROR_NOMEM;
            
        }
        
    }
    else {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Bad argument Encrypt (Size : %d).\n", size);
        if (plainText == NULL) printf("PlainText == NULL\n");
        printf("### encrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_NOMESSAGE;
        
    }
    
    /* Error handling */
    int error = 0;
    
    #if defined (GLS_DEBUG_TIME_MODE_ENABLE)
    struct timeval sTime;
    gettimeofday(&sTime, NULL);
    #endif
    
    /* IVS rotation */
    int i = 0;
    for (i = 0; i < 16; i++) {
        myGLSSocket->m_iv1[i] = myGLSSocket->m_iv3[i];
        myGLSSocket->m_iv2[i] = myGLSSocket->m_iv4[i];
    }
    /* next IVS generation */
    error += getIV(myGLSSocket->m_iv3);
    error += getIV(myGLSSocket->m_iv4);
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("IV1 (Encrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv1[i]);
    }
    printf("\n");
    printf("IV2 (Encrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv2[i]);
    }
    printf("\n");
    printf("IV3 (Encrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv3[i]);
    }
    printf("\n");
    printf("IV4 (Encrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv4[i]);
    }
    printf("\n");
    #endif
    
    /* IVS Reset and Configuration  */
    error += gcry_cipher_reset(myGLSSocket->m_serpentHandlerCTS);
    error += gcry_cipher_setiv(myGLSSocket->m_serpentHandlerCTS, myGLSSocket->m_iv1, 16);
    error += gcry_cipher_reset(myGLSSocket->m_twofishHandlerCTS);
    error += gcry_cipher_setiv(myGLSSocket->m_twofishHandlerCTS, myGLSSocket->m_iv2, 16);
    
    
    #if defined (GLS_DEBUG_TIME_MODE_ENABLE)
    struct timeval eTime;
    gettimeofday(&eTime, NULL);
    double tS = sTime.tv_sec*1000000 + (sTime.tv_usec);
    double tE = eTime.tv_sec*1000000  + (eTime.tv_usec);
    printf("IVs rotation : %f microSeconds\n", tE - tS);
    #endif
    
    
    
    /* MAC generation (SHA-256) */
    /* MAC = IV1 + IV2 + IV3 + IV4 + Data */
    byte MAC[32];
    /* IV1 and IV2 */
    i = 0;
    for (i = 0; i < 16; i++) {
        tempPlainText[i] = myGLSSocket->m_iv1[i];
        tempPlainText[i + 16] = myGLSSocket->m_iv2[i];
    }
    /* IV3 and IV4 */
    i = 0;
    for (i = 0; i < 16; i++) {
        tempPlainText[i + 32] = myGLSSocket->m_iv3[i];
        tempPlainText[i + 48] = myGLSSocket->m_iv4[i];
    }
    /* Message */
    i = 0;
    for (i = 0; i < size; i++) {
        tempPlainText[i + 64] = plainText[i];
    }
    
    #if defined (GLS_DEBUG_TIME_MODE_ENABLE)
    gettimeofday(&sTime, NULL);
    #endif
    
    gcry_md_hash_buffer(GCRY_MD_SHA256, MAC, tempPlainText, (size + 64));
    
    #if defined (GLS_DEBUG_TIME_MODE_ENABLE)
    gettimeofday(&eTime, NULL);
    tS = sTime.tv_sec*1000000 + (sTime.tv_usec);
    tE = eTime.tv_sec*1000000  + (eTime.tv_usec);
    printf("Mac generation : %f microSeconds\n", tE - tS);
    #endif
    
    /* Filling tempCypherText according to the GLS structure */
    /* MAC */
    i = 0;
    for (i = 0; i < 32; i++) {
        tempCypherText[i] = MAC[i];
    }
    /* IVs + Message */
    i = 0;
    for (i = 0; i < (size + 64); i++) {
        tempCypherText[i + 32] = tempPlainText[i];
    }
    
    #if defined (GLS_DEBUG_TIME_MODE_ENABLE)
    gettimeofday(&sTime, NULL);
    #endif
    
    /* tempPlainText encryption */
    error += gcry_cipher_encrypt(myGLSSocket->m_serpentHandlerCTS, tempCypherTextFinal, (size + 96), tempCypherText, (size + 96));
    
    #if defined (GLS_DEBUG_TIME_MODE_ENABLE)
    gettimeofday(&eTime, NULL);
    tS = sTime.tv_sec*1000000 + (sTime.tv_usec);
    tE = eTime.tv_sec*1000000  + (eTime.tv_usec);
    printf("Serpent encryption : %f microSeconds\n", tE - tS);
    gettimeofday(&sTime, NULL);
    #endif
    
    error += gcry_cipher_encrypt(myGLSSocket->m_twofishHandlerCTS, *cypherText, (size + 96), tempCypherTextFinal, (size + 96));
    
    #if defined (GLS_DEBUG_TIME_MODE_ENABLE)
    gettimeofday(&eTime, NULL);
    tS = sTime.tv_sec*1000000 + (sTime.tv_usec);
    tE = eTime.tv_sec*1000000  + (eTime.tv_usec);
    printf("Twofish encryption : %f microSeconds\n", tE - tS);
    #endif
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Message (Encrypt) : ");
    i = 0;
    for (i = 0; i < size; i++) {
        printf("%c", plainText[i]);
    }
    printf("\n");
    printf("Message serpent (Encrypt) : ");
    i = 0;
    for (i = 0; i < size; i++) {
        printf("%x", tempCypherText[i]);
    }
    printf("\n");
    #endif
    
    if(error != 0) {
        
        /* debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error %d : %s\n", error, gcry_strerror(error));
        #endif
        
        /* Free temp memory */
        free(tempPlainText);
        tempPlainText = 0;
        free(tempCypherText);
        tempCypherText = 0;
        free(tempCypherTextFinal);
        tempCypherTextFinal = 0;
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### encrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
    
    /* Free temp memory */
    free(tempPlainText);
    tempPlainText = 0;
    free(tempCypherText);
    tempCypherText = 0;
    free(tempCypherTextFinal);
    tempCypherTextFinal = 0;
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### encrypt() End ###\n\n");
    #endif
    
    return size + 96;
    
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Others decryption.
 Return the plaintext size or a negative number for an error.
 
 ---------------------------------------------------------*/

int allDecrypt(GLSSock* myGLSSocket, const byte* cipherText, const int size, byte** plainText){
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### decrypt() Start ###\n");
    #endif
    
    /* If the handlers aren't initialized or no encryption key is
     available return an error */
    if (myGLSSocket->m_isCryptoKey == 0 || myGLSSocket->m_isHandlerInit == 0) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Pas de configuration initial. Decrypt\n");
        printf("### decrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_NOPASSWD;
        
    }
    
    /* Temp and final memory allocation */
    byte (*tempCypherText) = 0;
    byte (*tempCypherTextFinal) = 0;
    byte (*tempPlainText) = 0;
    
    /* Check if the message's size is at least highter than the header's size */
    if (size > 96 && cipherText != NULL) {
        
        /*
         * Memory allocation with the additional 768 bit from the GLS
         * protocol (IV1 + IV2 + MAC + IV3 + IV4) = 768 bits / 96 bytes
         */
        
        tempCypherText = malloc(sizeof(byte) * size);
        tempCypherTextFinal = malloc(sizeof(byte) * size);
        tempPlainText = malloc(sizeof(byte) * (size - 32));
        *plainText = malloc(sizeof(byte) * (size - 96));
        if (tempPlainText == NULL || tempCypherText == NULL || tempCypherTextFinal == NULL || *plainText == NULL) {
            
            #if defined (GLS_DEBUG_MODE_ENABLE)
            printf("No memory. Decrypt\n");
            #endif
            
            return GLS_ERROR_NOMEM;
            
        }
        
    }
    else {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Bad argument Decrypt (Size : %d).\n", size);
        if (cipherText == NULL) printf("CipherText == NULL\n");
        printf("### decrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_UNKNOWN;
        
    }
    
    /* Error handling */
    int error = 0;
    
    /* IVS rotation */
    int i = 0;
    for (i = 0; i < 16; i++) {
        myGLSSocket->m_iv1[i] = myGLSSocket->m_iv3[i];
        myGLSSocket->m_iv2[i] = myGLSSocket->m_iv4[i];
    }
    
    /* IVS Reset and Configuration  */
    error += gcry_cipher_reset(myGLSSocket->m_serpentHandlerCTS);
    error += gcry_cipher_setiv(myGLSSocket->m_serpentHandlerCTS, myGLSSocket->m_iv1, 16);
    error += gcry_cipher_reset(myGLSSocket->m_twofishHandlerCTS);
    error += gcry_cipher_setiv(myGLSSocket->m_twofishHandlerCTS, myGLSSocket->m_iv2, 16);
    
    /* Message decryption */
    error += gcry_cipher_decrypt(myGLSSocket->m_twofishHandlerCTS, tempCypherText, size, cipherText, size);
    error += gcry_cipher_decrypt(myGLSSocket->m_serpentHandlerCTS, tempCypherTextFinal, size, tempCypherText, size);
    
    /* MAC generation (SHA-256) */
    /* MAC = IV1 + IV2 + IV3 + IV4 + Data */
    byte MAC[32];
    byte cipherMAC[32];
    /* Fill MAC with the message's MAC */
    i = 0;
    for (i = 0; i < 32; i++) {
        MAC[i] = tempCypherTextFinal[i];
    }
    /* IVS + Message */
    i = 0;
    for (i = 0; i < (size - 32); i++) {
        tempPlainText[i] = tempCypherTextFinal[i + 32];
    }
    /* Generating the decrypted message's MAC (SHA-256) for comparison */
    gcry_md_hash_buffer(GCRY_MD_SHA256, cipherMAC, tempPlainText, (size - 32));
    
    /* Sending an error before comparing the MAC 
     because if bad decrypting = bad MAC */
    if(error != 0) {
        
        /* debug only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error %d : %s\n", error, gcry_strerror(error));
        #endif
        
        /* suppression de la mémoire temporaire */
        free(tempPlainText);
        tempPlainText = 0;
        free(tempCypherText);
        tempCypherText = 0;
        free(tempCypherTextFinal);
        tempCypherTextFinal = 0;
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### decrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
    
    /* IVS synchronisation check before MAC because IVS desync = bad MAC but
     the contrary isn't true */
    int y = 0;
    while (myGLSSocket->m_iv1[y] == tempPlainText[y] && myGLSSocket->m_iv2[y] == tempPlainText[y + 16] && y < 16) {
        
        y++;
        
    }
    if (!(y == 16)) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error : Chainage error Decrypt\n");
        #endif
        
        /* Free memory */
        free(tempPlainText);
        tempPlainText = 0;
        free(tempCypherText);
        tempCypherText = 0;
        free(tempCypherTextFinal);
        tempCypherTextFinal = 0;
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### decrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_IVDESYNC;
        
    }
    
    /* MAC comparison */
    i = 0;
    while (MAC[i] == cipherMAC[i] && i < 32) {
        
        i++;
        
    }
    if (!(i == 32)) {
        
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error : MAC error Decrypt\n");
        #endif
        
        /* Free temp memory */
        free(tempPlainText);
        tempPlainText = 0;
        free(tempCypherText);
        tempCypherText = 0;
        free(tempCypherTextFinal);
        tempCypherTextFinal = 0;
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### decrypt() End ###\n\n");
        #endif
        
        return GLS_ERROR_MAC;
        
    }
    
    /* Get IV3, IV4 and message according to the GLS structure */
    /* IV3 and IV4 */
    i = 0;
    for (i = 0; i < 16; i++) {
        myGLSSocket->m_iv3[i] = tempPlainText[i + 32];
        myGLSSocket->m_iv4[i] = tempPlainText[i + 48];
    }
    /* Message */
    i = 0;
    for (i = 0; i < (size - 96); i++) {
        (*plainText)[i] = tempPlainText[i + 64];
    }
    
    /* Debug only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Message serpent (Decrypt) : ");
    i = 0;
    for (i = 0; i < (size - 96); i++) {
        printf("%x", tempCypherTextFinal[i]);
    }
    printf("\n");
    printf("IV1 (Decrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv1[i]);
    }
    printf("\n");
    printf("IV2 (Decrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv2[i]);
    }
    printf("\n");
    printf("IV3 (Decrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv3[i]);
    }
    printf("\n");
    printf("IV4 (Decrypt) : ");
    i = 0;
    for (i = 0; i < 16; i++) {
        printf("%2X",  myGLSSocket->m_iv4[i]);
    }
    printf("\n");
    printf("Message (Decrypt) : ");
    i = 0;
    for (i = 0; i < (size - 96); i++) {
        printf("%c", (*plainText)[i]);
    }
    printf("\n");
    #endif
    
    /* Free temp memory */
    free(tempPlainText);
    tempPlainText = 0;
    free(tempCypherText);
    tempCypherText = 0;
    free(tempCypherTextFinal);
    tempCypherTextFinal = 0;
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### decrypt() End ###\n\n");
    #endif
    
    return size - 96;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Wrapper for _encryptWithPk to handle packet size.
 Return the cypherText size or a negative number for an error.
 
 ---------------------------------------------------------*/

int encryptWithPK(const byte *cert, const int certLen, const byte* plainText, const int sizePlainText, byte** cypherText) {
    
    /* argument check */
    if (sizePlainText <= 0 || plainText == NULL) return GLS_ERROR_NOMESSAGE;
    if (certLen <= 0 || cert == NULL) return GLS_ERROR_NOCERT;
    
    /* Getting Key Size in bits */
    int keySize = getModulusSize(cert, certLen);
    if (keySize < 0) return keySize;
    
    /* getting OAEP Message size : ModulusSize(bytes) -2 -2 * hashTagLength */
    int messSize = (keySize / 8) -2 -(2 * (160 / 8));
    
    /* if the message can be encrypt with one round of PK encryption */
    if (messSize > sizePlainText) {
        
        return _encryptWithPK(cert, certLen, plainText, sizePlainText, cypherText);
        
    }
    else {
        
        int nbTour = (sizePlainText / messSize);
        int whileMax = 0;
        if (sizePlainText % messSize) nbTour += 1;
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("NbTour Original: %d\n", nbTour);
        printf("SizePlainTest : %d\n", sizePlainText);
        printf("messSize Original: %d\n", messSize);
        printf("last packet size: %d\n\n", (sizePlainText % messSize));
        #endif
        
        /* Data algorithme repartition to prevent having rounds with full data and 
         encrypting the last one with 1 bytes of data. */
        while ((sizePlainText % messSize) < (messSize / 3) && (sizePlainText % messSize) > 0) {
                
            messSize -= (messSize / 3);
            nbTour = (sizePlainText / messSize);
            if (sizePlainText % messSize) nbTour += 1;
            
            /* Security */
            if (whileMax == 3) {
                
                /* Debug Only */
                #if defined (GLS_DEBUG_MODE_ENABLE)
                printf("WhileMAx Break");
                #endif
                
                break;
            }
            else whileMax++;
            
        }
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("NbTour final: %d\n", nbTour);
        printf("SizePlainTest : %d\n", sizePlainText);
        printf("messSize final: %d\n", messSize);
        printf("last packet size: %d\n\n", (sizePlainText % messSize));
        #endif
        
        byte *tempCipherText = 0;
        int sizeCipherText = 0;
        
        /* Rounds for PK encryptions */
        int i = 0;
        for (i = 0; i < nbTour; i++) {
            
            /* size of the block to copy */
            int sizeBlock = 0;
            if (i == (nbTour - 1) && (sizePlainText % messSize) != 0) sizeBlock = (sizePlainText % messSize);
            else sizeBlock = messSize;
            
            byte *memtemp = malloc(messSize);
            if (memtemp == NULL) return GLS_ERROR_NOMEM;
            
            /* copy of the block to encrypt */
            int y = 0;
            for (y = 0; y < sizeBlock; y++) {
                
                memtemp[y] = plainText[(messSize * i) + y];
                
            }
            
            /* encryption */
            byte* cipher = 0;
            int sizeCipher = _encryptWithPK(cert, certLen, memtemp, sizeBlock, &cipher);
            if (sizeCipher < 0) {
               
                /* Free memory */
                if (memtemp != NULL) {
                    free(memtemp);
                    memtemp = 0;
                }
                if (cipher != NULL) {
                    free(cipher);
                    cipher = 0;
                }
                
                return sizeCipher;
                
            }
            
            /* adding cipher to temp memory */
            byte *temp = 0;
            temp = malloc(sizeCipherText + sizeCipher);
            if (temp == NULL) {
                
                /* Free memory */
                if (memtemp != NULL) {
                    free(memtemp);
                    memtemp = 0;
                }
                if (cipher != NULL) {
                    free(cipher);
                    cipher = 0;
                }
                
                return GLS_ERROR_NOMEM;
                
            }
            /* copy of old memory */
            for (y = 0; y < sizeCipherText; y++) {
                
                temp[y] = tempCipherText[y];
                
            }
            /* copy of new memory */
            for (y = 0; y < sizeCipher; y++) {
                
                temp[sizeCipherText + y] = cipher[y];
                
            }
            
            /* increment size */
            sizeCipherText += sizeCipher;
            
            /* free old memory */
            if (tempCipherText != NULL) {
                free(tempCipherText);
                tempCipherText = 0;
            }
            
            /* swap temp to tempCipherText */
            tempCipherText = temp;
            temp = 0;
            
            /* free memory */
            if (memtemp != NULL) {
                free(memtemp);
                memtemp = 0;
            }
            if (cipher != NULL) {
                free(cipher);
                cipher = 0;
            }
            
        }
        
        (*cypherText) = tempCipherText;
        
        return sizeCipherText;
        
    }
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Private Key encryption, return the cipherText size or 
 a negative number for an error.
 
 ---------------------------------------------------------*/

int _encryptWithPK(const byte *cert, const int certLen, const byte* plainText, const int sizePlainText, byte** cypherText) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### encryptWithPK() Start ###\n");
    #endif
    
    /* argument check */
    if (sizePlainText <= 0 || plainText == NULL) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        if (plainText == NULL) printf("Plaintext == NULL\n");
        if (sizePlainText <= 0) printf("sizePlainText <= 0\n");
        printf("No Message to encrypt\n");
        printf("### encryptWithPK() End ###\n\n");
        #endif

        return GLS_ERROR_NOMESSAGE;
    
    }
    if (certLen <= 0 || cert == NULL) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("No certificate\n");
        printf("### encryptWithPK() End ###\n\n");
        #endif

        return GLS_ERROR_NOCERT;
    
    }
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
    
    /* Base64 PEM certificate decoding (in DER) */
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
        printf("### encryptWithPK() End ###\n\n");
        #endif
        
        /* return error */
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
        printf("### encryptWithPK() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /* DER certificate parsing */
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
        printf("### encryptWithPK() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    /*
     * From here we have :
     * certificat = The certificate used to encrypt
     * certDef = X.509 certificate definition
     */
    
    /* Get the DER certificate public key */
    int lenPubKeyDer = 2048;
    byte pubKeyDer[2048];
    result = asn1_read_value(certificat, "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey", pubKeyDer, &lenPubKeyDer);
    
    /* Check for error */
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
        printf("### encryptWithPK() End ###\n\n");
        #endif
        
        return GLS_ERROR_ASN1;
        
    }
    
    
    /* Public key convertion from DER to bytes */
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
        printf("### encryptWithPK() End ###\n\n");
        #endif
        
        return error;
        
    }
    
    int i = 0;
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    char keyBuffer[2048];
    int sizePubKey = (int) gcry_sexp_sprint(gcryPubKey, GCRYSEXP_FMT_ADVANCED, keyBuffer, 2048);
    printf("Public Key : ");
    for (i = 0; i < sizePubKey; i++) {
        printf("%c", keyBuffer[i]);
    }
    printf("\n");
    #endif
    
    /* Creating S-Exp for gcrypt */
    gcry_sexp_t gcryPlainText = 0;
    error = gcry_sexp_build(&gcryPlainText, NULL, "(data(flags oaep)(value %b))", sizePlainText, plainText);
    if (error != 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error creating S-Exp for PK encryption\n");
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if(gcryPubKey != 0){
            gcry_sexp_release(gcryPubKey);
            gcryPubKey = 0;
        }
        gcry_sexp_release(gcryPlainText);
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### encryptWithPK() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    char cit[4096];
    int sizeCit = (int) gcry_sexp_sprint(gcryPlainText, GCRYSEXP_FMT_ADVANCED, cit, 4096);
    printf("PlainText : ");
    for (i = 0; i < sizeCit; i++) {
        printf("%c", cit[i]);
    }
    printf("\n");
    #endif
    
    /* Buffer encryption */
    gcry_sexp_t gcryCipherText = 0;
    error = gcry_pk_encrypt(&gcryCipherText, gcryPlainText, gcryPubKey);
    if (error != 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error encrypting plaintext\n");
        printf("Source : %s\n", gcry_strsource(error));
        printf("Error : %s\n", gcry_strerror(error));
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if(gcryPubKey != 0){
            gcry_sexp_release(gcryPubKey);
            gcryPubKey = 0;
        }
        gcry_sexp_release(gcryPlainText);
        gcry_sexp_release(gcryCipherText);
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### encryptWithPK() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("\n");
    char ci[4096];
    int sizeCi = (int) gcry_sexp_sprint(gcryCipherText, GCRYSEXP_FMT_ADVANCED, ci, 4096);
    printf("Cipher : ");
    for (i = 0; i < sizeCi; i++) {
        printf("%c", ci[i]);
    }
    printf("\n");
    #endif
    
    /* CipherText extraction */
    size_t valueSize = 0;
    gcry_sexp_t valueTemp = gcry_sexp_nth(gcryCipherText, 1);
    gcry_sexp_t valueTemp2 = gcry_sexp_nth(valueTemp, 1);
    const char *value = gcry_sexp_nth_data(valueTemp2, 1, &valueSize);
    (*cypherText) = malloc(valueSize);
    if ((*cypherText) == NULL || value == NULL) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error extracting value from S-EXP\n");
        #endif
        
        /* Free memory */
        if (certificatDer != NULL) {
            free(certificatDer);
            certificatDer = 0;
        }
        if(gcryPubKey != 0){
            gcry_sexp_release(gcryPubKey);
            gcryPubKey = 0;
        }
        if ((*cypherText) != NULL) {
            free(*cypherText);
            *cypherText = 0;
        }
        gcry_sexp_release(gcryPlainText);
        gcry_sexp_release(gcryCipherText);
        asn1_delete_structure(&certDef);
        asn1_delete_structure(&certificat);
        gcry_sexp_release(valueTemp);
        gcry_sexp_release(valueTemp2);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### encryptWithPK() End ###\n\n");
        #endif
        
        if ((*cypherText) == NULL) return GLS_ERROR_NOMEM;
        else return GLS_ERROR_CRYPTO;
        
    }
    
    for (i = 0; i < (valueSize); i++) {
        (*cypherText)[i] = value[i];
    }
    
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("Data : ");
    for (i = 0; i < sizePlainText; i++) {
        printf("%c", plainText[i]);
    }
    printf("\n");
    printf("Cipher Buffer : ");
    for (i = 0; i < (valueSize); i++) {
        printf("%02X", (*cypherText)[i]);
    }
    printf("\n");
    #endif
    
    /* Free memory */
    if (certificatDer != NULL) {
        free(certificatDer);
        certificatDer = 0;
    }
    if(gcryPubKey != 0){
        gcry_sexp_release(gcryPubKey);
        gcryPubKey = 0;
    }
    asn1_delete_structure(&certDef);
    asn1_delete_structure(&certificat);
    gcry_sexp_release(gcryPlainText);
    gcry_sexp_release(gcryCipherText);
    gcry_sexp_release(valueTemp);
    gcry_sexp_release(valueTemp2);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### encryptWithPK() End ###\n\n");
    #endif
    
    return (int) valueSize;
    
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Wrapper for _decryptWithPk to handle packet size.
 Return the cypherText size or a negative number for an error.
 
 ---------------------------------------------------------*/

int decryptWithPK(GLSSock* myGLSSocket, const byte* cipherText, const int sizeCipherText, byte** plainText) {
    
    /* argument check */
    if (sizeCipherText <= 0 || cipherText == NULL) return GLS_ERROR_NOMESSAGE;
    
    /* Getting Key Size in bits */
    int keySize = getModulusSize(myGLSSocket->m_publicCert, myGLSSocket->m_publicCertSize);
    if (keySize < 0) return keySize;
    
    /* if the message can be decrypt with one round of PK decryption */
    if ((keySize / 8) > sizeCipherText) {
        
        return _decryptWithPK(myGLSSocket, cipherText, sizeCipherText, plainText);
        
    }
    else {
        
        /* number of rounds to do */
        int nbTour = sizeCipherText / (keySize / 8);
        
        byte *tempPlainText = 0;
        int sizeTempPlainText = 0;
        
        int i = 0;
        for (i = 0; i < nbTour; i++) {
            
            /* size of the block to copy */
            int sizeBlock = (keySize / 8);
            
            byte *memtemp = malloc(sizeBlock);
            if (memtemp == NULL) return GLS_ERROR_NOMEM;
            
            /* copy of the block to decrypt */
            int y = 0;
            for (y = 0; y < sizeBlock; y++) {
                
                memtemp[y] = cipherText[(sizeBlock * i) + y];
                
            }
            
            /* decryption */
            byte* plain = 0;
            int sizePlain = _decryptWithPK(myGLSSocket, memtemp, sizeBlock, &plain);
            if (sizePlain < 0) {
                
                /* Free memory */
                if (memtemp != NULL) {
                    free(memtemp);
                    memtemp = 0;
                }
                if (plain != NULL) {
                    free(plain);
                    plain = 0;
                }
                
                return sizePlain;
                
            }
            
            /* adding plain to temp memory */
            byte *temp = 0;
            temp = malloc(sizeTempPlainText + sizePlain);
            if (temp == NULL) {
                
                /* Free memory */
                if (memtemp != NULL) {
                    free(memtemp);
                    memtemp = 0;
                }
                if (plain != NULL) {
                    free(plain);
                    plain = 0;
                }
                
                return GLS_ERROR_NOMEM;
                
            }
            /* copy of old memory */
            for (y = 0; y < sizeTempPlainText; y++) {
                
                temp[y] = tempPlainText[y];
                
            }
            /* copy of new memory */
            for (y = 0; y < sizePlain; y++) {
                
                temp[sizeTempPlainText + y] = plain[y];
                
            }
            
            /* increment size */
            sizeTempPlainText += sizePlain;
            
            /* free old memory */
            if (tempPlainText != NULL) {
                free(tempPlainText);
                tempPlainText = 0;
            }
            
            /* swap temp to tempCipherText */
            tempPlainText = temp;
            temp = 0;
            
            /* free memory */
            if (memtemp != NULL) {
                free(memtemp);
                memtemp = 0;
            }
            if (plain != NULL) {
                free(plain);
                plain = 0;
            }
            
        }
        
        (*plainText) = tempPlainText;
        
        return sizeTempPlainText;
        
    }
        
}




/*-------------------------------------------------------
 
 PRIVATE
 
 Private Key decryption, return the plainText size or a 
 negative number for an error.
 
 ---------------------------------------------------------*/

int _decryptWithPK(GLSSock* myGLSSocket, const byte* cipherText, const int sizeCipherText, byte** plainText) {
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### decryptWithPK() Start ###\n");
    #endif
    
    /* argument check */
    if (sizeCipherText <= 0 || cipherText == NULL) return GLS_ERROR_NOMESSAGE;
    
    /* Check if private key is set */
    if (myGLSSocket->m_privateKey == NULL) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error No private key\n");
        printf("### decryptWithPK() End ###\n\n");
        #endif
        
        return GLS_ERROR_NOCERT;
        
    }
    
    /* Base64 PEM certificate decoding (to DER) */
    byte *privateKeyDer = 0;
    int sizePriv = pemToAsn(myGLSSocket->m_privateKey, myGLSSocket->m_privateKeySize, &privateKeyDer);
    if (sizePriv < 0) {
        
        /* Free memory */
        if (privateKeyDer != NULL) {
            free(privateKeyDer);
            privateKeyDer = 0;
        }
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error Base 64\n");
        printf("### decryptWithPK() End ###\n\n");
        #endif
        
        /* Return error */
        return sizePriv;
        
    }
    
    /* DER Private key convertion to bytes */
    gcry_sexp_t gcryPrivKey = 0;
    int error = getPrivateRsaFromDer(privateKeyDer, sizePriv, &gcryPrivKey);
    if (error < 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Impossible to convert DER private key to byte\n");
        #endif
        
        /* Free memory */
        if (privateKeyDer != NULL) {
            free(privateKeyDer);
            privateKeyDer = 0;
        }
        if(gcryPrivKey != NULL){
            gcry_sexp_release(gcryPrivKey);
            gcryPrivKey = 0;
        }
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### decryptWithPK() End ###\n\n");
        #endif
        
        return error;
        
    }
    
    int i = 0;
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    char keyBuffer[2048];
    int sizePubKey = (int) gcry_sexp_sprint(gcryPrivKey, GCRYSEXP_FMT_ADVANCED, keyBuffer, 2048);
    printf("Public Key : ");
    for (i = 0; i < sizePubKey; i++) {
        printf("%c", keyBuffer[i]);
    }
    printf("\n\n");
    printf("Data : ");
    for (i = 0; i < sizeCipherText; i++) {
        printf("%2X", cipherText[i]);
    }
    printf("\n");
    #endif
    
    /* Creating the S-Exp for gcrypt */
    gcry_sexp_t gcryCipherText;
    error = gcry_sexp_build(&gcryCipherText, NULL, "(enc-val(flags oaep)(rsa(a %b)))", sizeCipherText, cipherText);
    if (error != 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error creating S-Exp for PK decryption\n");
        #endif
        
        /* Free memory */
        if (privateKeyDer != NULL) {
            free(privateKeyDer);
            privateKeyDer = 0;
        }
        if(gcryPrivKey != NULL){
            gcry_sexp_release(gcryPrivKey);
            gcryPrivKey = 0;
        }
        gcry_sexp_release(gcryCipherText);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### decryptWithPK() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
    
    /* Buffer decryption */
    gcry_sexp_t gcryPlainText;
    error = gcry_pk_decrypt(&gcryPlainText, gcryCipherText, gcryPrivKey);
    if (error != 0) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error Decrypting the cipherText\n");
        printf("Source : %s\n", gcry_strsource(error));
        printf("Error : %s\n", gcry_strerror(error));
        #endif
        
        /* Free memory */
        if (privateKeyDer != NULL) {
            free(privateKeyDer);
            privateKeyDer = 0;
        }
        if(gcryPrivKey != NULL){
            gcry_sexp_release(gcryPrivKey);
            gcryPrivKey = 0;
        }
        gcry_sexp_release(gcryPlainText);
        gcry_sexp_release(gcryCipherText);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### decryptWithPK() End ###\n\n");
        #endif
        
        return GLS_ERROR_CRYPTO;
        
    }
    
    /* Plaintext extraction */
    size_t valueSize = 0;
    const char *value = gcry_sexp_nth_data(gcryPlainText, 1, &valueSize);
    (*plainText) = malloc(valueSize);
    if ((*plainText) == NULL || value == NULL) {
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("Error extracting value from S-EXP\n");
        #endif
        
        /* Free memory */
        if (privateKeyDer != NULL) {
            free(privateKeyDer);
            privateKeyDer = 0;
        }
        if(gcryPrivKey != NULL){
            gcry_sexp_release(gcryPrivKey);
            gcryPrivKey = 0;
        }
        if((*plainText) != NULL){
            free(*plainText);
            (*plainText) = 0;
        }
        gcry_sexp_release(gcryPlainText);
        gcry_sexp_release(gcryCipherText);
        
        /* Debug Only */
        #if defined (GLS_DEBUG_MODE_ENABLE)
        printf("### decryptWithPK() End ###\n\n");
        #endif
        
        if ((*plainText) == NULL) return GLS_ERROR_NOMEM;
        else return GLS_ERROR_CRYPTO;
        
    }
    
    for (i = 0; i < (valueSize); i++) {
        (*plainText)[i] = value[i];
    }
    
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    char ci[4096];
    int sizeCi = (int) gcry_sexp_sprint(gcryPlainText, GCRYSEXP_FMT_CANON, ci, 4096);
    printf("PlainText : ");
    for (i = 0; i < sizeCi; i++) {
        printf("%c", ci[i]);
    }
    printf("\n");
    printf("PlainText Buffer : ");
    for (i = 0; i < (valueSize); i++) {
        printf("%c", (*plainText)[i]);
    }
    printf("\n");
    #endif
    
    /* Free memory */
    if (privateKeyDer != NULL) {
        free(privateKeyDer);
        privateKeyDer = 0;
    }
    if(gcryPrivKey != NULL){
        gcry_sexp_release(gcryPrivKey);
        gcryPrivKey = 0;
    }
    gcry_sexp_release(gcryPlainText);
    gcry_sexp_release(gcryCipherText);
    
    /* Debug Only */
    #if defined (GLS_DEBUG_MODE_ENABLE)
    printf("### decryptWithPK() End ###\n\n");
    #endif
    
    return (int) valueSize;
    
}




Libgls - Goswell Layer Security Library
===

This is the first public release of the GLS library, it is open source under the GNU Lesser General Public License. **This is an alpha version**. The objective was to demonstrate that it worked, optimized it will be the subject of a next release. See the «What’s next ?» part for more information.

GLS, acronym for Goswell Layer Security, is a secure communication protocol developed by the Goswell company to respond to the actual secure connexion protocol’s problems by removing key exchange. See full documentation for more information.

[![Build Status](https://travis-ci.org/goswell/GLS.png?branch=master)](https://travis-ci.org/goswell/GLS)

How to use it :
---

**Simple connexion**
```c
#include <stdio.h>
#include "libgls.h"

int main (int argc, const char * argv[])
{
  /* Initialize the socket */
  GLSSock* myConnexion = GLSSocket();

  /* Set the user's ID */
  setUserId(myConnexion, "myUserId");

  /* Add the user's password */
  addKey(myConnexion, "myPassword", 0);

  /* Connect to the server, you can use an IP or a domain name */
  connexion(myConnexion, "www.server.com", "443");

  /* You are now connected to the server using the GLS Protocol
  you can send and receive message with the function gslSend() and glsRecv() */

  /* Sending a message */
  byte *myMessage = "this is a message";
  glsSend(myConnexion, myMessage, strlen(myMessage));

  /* Receiving a message, this is a blocking function */
  byte *anotherMessage = 0;
  int sizeMessage = glsRecv(myConnexion, &anotherMessage);

  /* You are responsible for deallocating the received message */
  free(anotherMessage);

  /* Close the connexion and free the GLS Socket */
  freeGLSSocket(myConnexion);
  
  return 0;
}
```
**Simple server**
```c
#include <stdio.h>
#include "libgls.h"

int main (int argc, const char * argv[])
{
  /* Allocate the server */
  GLSServerSock* myServer = GLSServer();

  /* Initialize the server with 10 waiting queue on the port 443 */
  initServer(myServer, "443", 10, 0);

  /* Wait for a client */
  GLSSock *myClient = 0;
  waitForClient(myServer, &myClient);

  /* Once you have a connexion, you will have to retrieve
  the user password from your database */

  /* Get the user's ID, this allocate new memory for the char */
  char *userID = 0;
  getUserId(myClient, &userID);

  /*
   * Some function to retrieve the user's password from the database
   */

  /* Free the userID once done with it */
  free(userID);

  /* Set the password, in this case is a SHA-512 so we set isSha = 1 */
  /* If your server uses a different hashing system, add it as a password
  and don't forget to also hash the user's password on the client */
  addKey(myClient, "752c14ea195c4...60bac3c3b789697", 1);

  /* Finish the handshake */
  finishHandShake(myClient);
  
  /* You are now connected with the client using the GLS Protocol
  you can send and receive message with the function gslSend() and glsRecv() */

  /* Sending a message */
  byte *myMessage = "this is a message";
  glsSend(myClient, myMessage, strlen(myMessage));

  /* Receiving a message, this is a blocking function */
  byte *anotherMessage = 0;
  int sizeMessage = glsRecv(myClient, &anotherMessage);

  /* You are responsible for deallocating the received message */
  free(anotherMessage);
   
  /* Close the connexion and free the GLS Socket */
  freeGLSSocket(myClient);

  /* Close the server and free the GLS Socket Server */
  freeGLSServer(myServer);

  return 0; 
}
```
**Register an user**
```c
#include <stdio.h>
#include "libgls.h"

int main (int argc, const char * argv[])
{
  /* Initialize the socket */
  GLSSock* myConnexion = GLSSocket();

  /* Add the root certificate, be careful the current
  library only support RSA + SHA1 certificates */
  addRootCertificateFromFile(myConnexion, "./ca.crt");

  /* If you need to revocate some certificate
  add their ID to the CRL */
  addToCrl(myConnexion, "009D61A449B6BF4539");
  addToCrl(myConnexion, "00F7524FE8D6780e26");

  /* Create the register message */
  byte *message = "user's information to register";

  /* Send the register message to the server */
  sendRegister(myConnexion, "www.server.com", "443", message, strlen(message));

  /* Free the GLS Socket */
  freeGLSSocket(myConnexion);

  return 0;
}
```
**Register an user (server side)**
```c
#include <stdio.h>
#include "libgls.h"

int main (int argc, const char * argv[])
{
  /* Allocate the server */
  GLSServerSock* myServer = GLSServer();
  
  /* Initialize the server with 10 waiting queue on the port 443 */
  initServer(myServer, "443", 10, 0);
  
  /* Add the server's certificates, be careful the current
  library only support RSA + SHA1 certificates */
  addServerCertificateFromFile(myServer, "./publicCert.crt", "./privateKey.key");
  
  /* Wait for a client */
  GLSSock *myClient = 0;
  waitForClient(myServer, &myClient);
  
  /* Get the register message from the client */
  byte *message = 0;
  int sizeMessage = getRegisterMessage(myClient, &message);
  
  /* You are responsible for deallocating the received message */
  free(message);
  
  /* Free the GLS Socket */
  freeGLSSocket(myClient);
  
  /* Close the server and free the GLS Socket Server */
  freeGLSServer(myServer);

  return 0;
}
```
**Differentiate connexions**
```c
#include <stdio.h>
#include "libgls.h"

int main (int argc, const char * argv[])
{
  /* Allocate the server */
  GLSServerSock* myServer = GLSServer();
  
  /* Initialize the server with 10 waiting queue on the port 443 */
  initServer(myServer, "443", 10, 0);
  
  /* Add the server's certificates */
  addServerCertificateFromFile(myServer, "./publicCert.crt", "./PrivateKey.key");
  
  /* Wait for a client */
  GLSSock *myClient = 0;
  waitForClient(myServer, &myClient);
  
  /* Differentiate a standard from a register connexion */
  if(getTypeConnexion(myClient) == GLS_CONNEXION_STANDARD) {
  
    /* Handle a standard connexion with the client */
  
  }
  else if(getTypeConnexion(myClient) == GLS_CONNEXION_REGISTER) {
        
    /* Handle a register connexion with the client */
  
  } 
  else {

    /* Error */

  }
  
  /* Free the GLS Socket */
  freeGLSSocket(myClient);
  
  /* Close the server and free the GLS Socket Server */
  freeGLSServer(myServer);

  return 0;
}
```
**Handling errors**
```c
#include <stdio.h>
#include "libgls.h"

int main (int argc, const char * argv[])
{
  /* Initialize the socket */
  GLSSock* myConnexion = GLSSocket();
  if (myConnexion == NULL) return GLS_ERROR_NOMEM;
      
  /* Set the user's ID */
  int error = setUserId(myConnexion, "myUserId");
  if (error < 0) {
    /* Free memory */
    freeGLSSocket(myConnexion);
    
    /* Return the error */
    return error;
  }
       
  /* Add the user's password */
  error = addKey(myConnexion, "myPassword", 0);
  if (error < 0) {
    /* Free memory */
    freeGLSSocket(myConnexion);
    
    /* Return the error */
    return error;
  }
  
  /* Connect to the server, you can use an IP or a domain name */
  error = connexion(myConnexion, "www.server.com", "443");
  if (error < 0) {
    /* Free memory */
    freeGLSSocket(myConnexion);
    
    /* Return the error */
    return error;
  }

  /* You are now connected to the server using the GLS Protocol
  you can send and receive message with the function gslSend() and glsRecv() */

  /* Sending a message */
  byte *myMessage = "this is a message";
  error = glsSend(myConnexion, myMessage, strlen(myMessage));
  if (error < 0) {
    /* Free memory */
    freeGLSSocket(myConnexion);
    
    /* Return the error */
    return error;
  }
  
  /* Receiving a message, this is a blocking function */
  byte *anotherMessage = 0;
  int sizeMessage = glsRecv(myConnexion, &anotherMessage);
  if (sizeMessage <= 0) {
    /* Free memory */
    freeGLSSocket(myConnexion);
    if(anotherMessage != NULL) {
        free(anotherMessage);
        anotherMessage = 0;
    }
    
    /* Return the error */
    return error;
  }

  /* You are responsible for deallocating the received message */
  if(anotherMessage != NULL) {
    free(anotherMessage);
    anotherMessage = 0;
  }
  
  /* Close the connexion and free the GLS Socket */
  freeGLSSocket(myConnexion);

  return 0;
}
```
**Working with threads**
```c
#include <stdio.h>
#include "libgls.h"
#include <pthread.h>

void* handleClient(void* myClient);

int main (int argc, const char * argv[])
{
  /* Allocate the server */
  GLSServerSock* myServer = GLSServer();

  /* Initialize the server with 10 waiting queue on the port 443 */
  initServer(myServer, "443", 10, 0);
  
  while (1) {
    /* Init variable */
    GLSSock *myClient = 0;
    pthread_t thread;
    
    /* Wait for a client */
    waitForClient(myServer, &myClient);
    
    /* Create thread */
    pthread_create(&thread, NULL, handleClient, (void*)myClient);
  }
  
  /* Close the server and free the GLS Socket Server */
  freeGLSServer(myServer);
  
  return 0;
}

void* handleClient(void* myClient) {
   
  /*
   * Work with the client
   */
   
  /* Don't forget to free the GLS Socket */
  freeGLSSocket(myClient);
   
  return NULL;
}
```

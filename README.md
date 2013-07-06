Libgls - Goswell Layer Security Library
===

This is the first public release of the GLS library, it is open source under the GNU Lesser General Public License. This is an alpha version, ANSI C compliant. The objective was to demonstrate that it worked, optimized it will be the subject of a next release. See the «What’s next ?» part for more information.

GLS, acronym for Goswell Layer Security, is a secure communication protocol developed by the Goswell company to respond to the actual secure connexion protocol’s problems by removing key exchange. See full documentation for more information.

How to use it :
---

```c
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
```

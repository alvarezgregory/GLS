#include <iostream>
#include <exception>
#include "libgls.h"

class glsError : public std::exception {

	private:
		int _number;
		std::string _text;	

	public:
		glsError(int number=0, std::string const& text="") throw() :_number(number), _text(text) {}

		virtual const char* what() const throw() {
			return _text.c_str();
		}

		int getNumber() const throw() {
			return _number;
		}

		~glsError() throw() {}
};

class gls {

	protected:
		libgls::GLSSock* sock;

	public:
		gls();
		gls(const int secureMem, const int sizeMem);
		~gls();
		void setSocket(libgls::GLSSock * sock);
		void connexion(const char* address, const char* port);
		void sendRegister(const char* address, const char* port, const std::string buffer);
		std::string getRegisterMessage();
		void glsSend(const std::string buffer);
		std::string glsRecv();
		void addKey(const std::string key, bool isSha);
		void clearKey();
		int getTypeConnexion();
		std::string getUserId();
		void setUserId(const std::string userId);
		void finishHandShake();
		void addRootCertificate(const std::string cert);
		void addRootCertificateFromFile(const char* certFile);
		void addToCrl(const char* serial);
	

};

class glsServer {

	protected:
		libgls::GLSServerSock * sockServer;

	public:
		glsServer();
		glsServer(const int secureMem, const int sizeMem);
		~glsServer();
		void initServer(const char * port, const int waitQueue, const bool isReuse);
		gls * waitForClient();
		void addServerCertificate(const std::string publicCert, const std::string privateKey);
		void addServerCertificateFromFile(const char* publicCertFile, const char* privateKeyFile);
};

gls::gls() {

	this->sock = libgls::GLSSocket();
	if(this->sock == NULL) throw glsError(0, "Exception gls()");

}

gls::gls(const int secureMem, const int sizeMem) {

	this->sock = libgls::GLSSocketSecure(secureMem, sizeMem);
	if(this->sock == NULL) throw glsError(0, "Exception gls()");

}

gls::~gls() {

	libgls::freeGLSSocket(this->sock);

}
void gls::setSocket(libgls::GLSSock * sock) {

	this->sock = sock;

}

void gls::connexion(const char* address, const char* port) {

	int error = libgls::connexion(this->sock, address, port);
	if(error != 0) throw glsError(error, "Exception connexion()");
	else return;

}

void gls::sendRegister(const char* address, const char* port, const std::string buffer) {
	
	int error = libgls::sendRegister(this->sock, address, port, (byte*) buffer.c_str(), (int) buffer.size());
	if(error != 0) throw glsError(error, "Exception sendRegister()");
	else return;

}

std::string gls::getRegisterMessage() {

	byte *message = NULL;
	int error = libgls::getRegisterMessage(this->sock, &message);
	if(error < 0 || message == NULL) {
		if(message != NULL) free(message);
		throw glsError(error, "Exception getRegisterMessage()");
	}
	else {	
		std::string s ((char*) message,(size_t) error);
		free(message);
		return s;
	}
}

void gls::glsSend(const std::string buffer) {
	
	int error = libgls::glsSend(this->sock, (byte*) buffer.c_str(), (int) buffer.size());
	if(error != 0) throw glsError(error, "Exception glsSend()");
	else return;

}

std::string gls::glsRecv() {
	
	byte *message = NULL;
	int error = libgls::glsRecv(this->sock, &message);
	if(error < 0 || message == NULL) {
		if(message != NULL) free(message);
		throw glsError(error, "Exception glsRecv()");
	}
	else {	
		std::string s ((char*) message,(size_t) error);
		free(message);
		return s;
	}

}

void gls::addKey(const std::string key, bool isSha){
	
	int error = -1;
	if(isSha) error = libgls::addKey(this->sock, key.c_str(), 1);
	else error = libgls::addKey(this->sock, key.c_str(), 0);
	if(error != 0) throw glsError(error, "Exception addKey()");
	else return;

}

void gls::clearKey(){
	
	int error = libgls::clearKey(this->sock);
	if(error != 0) throw glsError(error, "Exception clearKey()");
	else return;
	
}

int gls::getTypeConnexion(){
	
	int error = libgls::getTypeConnexion(this->sock);
	if(error < 0) throw glsError(error, "Exception getTypeConnexion()");
	else return error;

}

std::string gls::getUserId(){
	
	char *user = NULL;
	int error = libgls::getUserId(this->sock, &user);
	if(error != 0 || user == NULL) {
		if(user != NULL) free(user);
		throw glsError(error, "Exception getUserId()");
	}
	else {	
		std::string s (user,(size_t) error);
		free(user);
		return s;
	}
}

void gls::setUserId(const std::string userId){
	
	int error = libgls::setUserId(this->sock, userId.c_str());
	if(error != 0) throw glsError(error, "Exception setUserId()");
	else return;

}

void gls::finishHandShake() {

	int error = libgls::finishHandShake(this->sock);
	if(error != 0) throw glsError(error, "Exception finishHandShake()");
	else return;

}

void gls::addRootCertificate(const std::string cert) {

	int error = libgls::addRootCertificate(this->sock, cert.c_str());
	if(error != 0) throw glsError(error, "Exception addRootCertificate()");
	else return;

}

void gls::addRootCertificateFromFile(const char* certFile) {

	int error = libgls::addRootCertificateFromFile(this->sock, certFile);
	if(error != 0) throw glsError(error, "Exception addRootCertificateFromFile()");
	else return;

}

void gls::addToCrl(const char* serial) {

	int error = libgls::addToCrl(this->sock, serial);
	if(error != 0) throw glsError(error, "Exception addToCrl()");
	else return;

}

glsServer::glsServer() {

	this->sockServer = libgls::GLSServer();
	if(this->sockServer == NULL) throw glsError(0, "Exception glsServer()");

}

glsServer::glsServer(const int secureMem, const int sizeMem) {

	this->sockServer = libgls::GLSServerSecure(secureMem, sizeMem);
	if(this->sockServer == NULL) throw glsError(0, "Exception glsServerSecure()");

}

glsServer::~glsServer(){

	libgls::freeGLSServer(this->sockServer);

}

void glsServer::initServer(const char * port, const int waitQueue, const bool isReuse){

	int error = -1;
	if(isReuse) error = libgls::initServer(this->sockServer, port, waitQueue, 1);
	else error = libgls::initServer(this->sockServer, port, waitQueue, 0);
	if(error != 0) throw glsError(error, "Exception initServer()");
	else return;

}

gls * glsServer::waitForClient() {

	libgls::GLSSock * s = NULL; 
	int error = libgls::waitForClient(this->sockServer, &s);
	if(error != 0 || s == NULL) throw glsError(error, "Exception waitForClient()");
	else {
		gls * g = new gls();
		g->setSocket(s);
		s = NULL;
		return g; 
	}
}

void glsServer::addServerCertificate(const std::string publicCert, const std::string privateKey) {

	int error = libgls::addServerCertificate(this->sockServer, publicCert.c_str(), privateKey.c_str());
	if(error != 0) throw glsError(error, "Exception addServerCertificate()");
	else return;

}

void glsServer::addServerCertificateFromFile(const char* publicCertFile, const char* privateKeyFile) {

	int error = libgls::addServerCertificateFromFile(this->sockServer, publicCertFile, privateKeyFile);
	if(error != 0) throw glsError(error, "Exception addServerCertificateFromFile()");
	else return;

}

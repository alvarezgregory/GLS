#include "gls.h"

using namespace v8;

gls::gls() {

	this->sock = libgls::GLSSocket();

}

gls::gls(const int secureMem, const int sizeMem) {

	this->sock = libgls::GLSSocketSecure(secureMem, sizeMem);

}

gls::~gls() {

	libgls::freeGLSSocket(this->sock);

}

void gls::Init(Handle<Object> exports) {
  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
  tpl->SetClassName(String::NewSymbol("gls"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);
  // Prototype
  tpl->PrototypeTemplate()->Set(String::NewSymbol("connexion"),
      FunctionTemplate::New(connexion)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("sendRegister"),
      FunctionTemplate::New(sendRegister)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("getRegisterMessage"),
      FunctionTemplate::New(getRegisterMessage)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("glsSend"),
      FunctionTemplate::New(glsSend)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("glsRecv"),
      FunctionTemplate::New(glsRecv)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("addKey"),
      FunctionTemplate::New(addKey)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("clearKey"),
      FunctionTemplate::New(clearKey)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("getTypeConnexion"),
      FunctionTemplate::New(getTypeConnexion)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("getUserId"),
      FunctionTemplate::New(getUserId)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("setUserId"),
      FunctionTemplate::New(setUserId)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("finishHandShake"),
      FunctionTemplate::New(finishHandShake)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("addRootCertificate"),
      FunctionTemplate::New(addRootCertificate)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("addRootCertificateFromFile"),
      FunctionTemplate::New(addRootCertificateFromFile)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("addToCrl"),
      FunctionTemplate::New(addToCrl)->GetFunction());

  Persistent<Function> constructor = Persistent<Function>::New(tpl->GetFunction());
  exports->Set(String::NewSymbol("gls"), constructor);
}

Handle<Value> gls::New(const Arguments& args) {
  HandleScope scope;

  gls* obj = new gls();
  obj->Wrap(args.This());

  return args.This();
}

// connexion(const char* address, const char* port)
static v8::Handle<v8::Value> gls::connexion(const Arguments& args) {
  HandleScope scope;
	gls* obj = ObjectWrap::Unwrap<gls>(args.This());

 if (args.Length() < 2) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments connexion()")));
    return scope.Close(Undefined());
  }

  std::string * address = args[0]->toString();
  std::string * port = args[1]->toString();

	int error = libgls::connexion(obj->sock, address.c_str(), port.c_str());
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception connexion()")));

	return scope.Close(Undefined());
}

// sendRegister(const char* address, const char* port, const std::string buffer)
static v8::Handle<v8::Value> gls::sendRegister(const Arguments& args) {
	HandleScope scope;
	gls* obj = ObjectWrap::Unwrap<gls>(args.This());

	if (args.Length() < 3) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments sendRegister()")));
    return scope.Close(Undefined());
  }

	std::string * address = args[0]->toString();
  std::string * port = args[1]->toString();
  std::string * buffer = args[2]->toString();

	int error = libgls::sendRegister(obj->sock, address.c_str(), port.c_str(), (byte*) buffer.c_str(), (int) buffer.size());
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception sendRegister()")));
	return scope.Close(Undefined());

}

// getRegisterMessage()
static v8::Handle<v8::Value> gls::getRegisterMessage(const Arguments& args) {
	HandleScope scope;
	gls* obj = ObjectWrap::Unwrap<gls>(args.This());

	byte *message = NULL;
	int error = libgls::getRegisterMessage(obj->sock, &message);
	if(error < 0 || message == NULL) {
		if(message != NULL) free(message);
		ThrowException(Exception::TypeError(String::New("Exception getRegisterMessage()")));
    return scope.Close(Undefined());
	}
	else {
		std::String s = std::String::New((char*) message,(size_t) error);
		if(s == NULL) {
			if(message != NULL) free(message);
			ThrowException(Exception::TypeError(String::New("Exception getRegisterMessage()")));
	    return scope.Close(Undefined());
		}
		free(message);
		return scope.Close(s);
	}
}

// glsSend(const std::string buffer)
static v8::Handle<v8::Value> gls::glsSend(const Arguments& args) {
	HandleScope scope;
	gls* obj = ObjectWrap::Unwrap<gls>(args.This());

	if (args.Length() < 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments glsSend()")));
    return scope.Close(Undefined());
  }

  std::string * buffer = args[0]->toString();

	int error = libgls::glsSend(obj->sock, (byte*) buffer.c_str(), (int) buffer.size());
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception glsSend()")));
	return scope.Close(Undefined());;

}

// glsRecv()
static v8::Handle<v8::Value> gls::glsRecv(const Arguments& args) {
  HandleScope scope;
  gls* obj = ObjectWrap::Unwrap<gls>(args.This());

	byte *message = NULL;
	int error = libgls::glsRecv(obj->sock, &message);
	if(error < 0 || message == NULL) {
		if(message != NULL) free(message);
		ThrowException(Exception::TypeError(String::New("Exception glsRecv()")));
    return scope.Close(Undefined());
	}
	else {
		std::String s = std::String::New((char*) message,(size_t) error);
    if(s == NULL) {
      if(message != NULL) free(message);
      ThrowException(Exception::TypeError(String::New("Exception glsRecv()")));
      return scope.Close(Undefined());
    }
		free(message);
		return scope.Close(s);
	}

}

// addKey(const std::string key, bool isSha)
static v8::Handle<v8::Value> gls::addKey(const Arguments& args){
  HandleScope scope;
  gls* obj = ObjectWrap::Unwrap<gls>(args.This());

  if (args.Length() < 2) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments addKey()")));
    return scope.Close(Undefined());
  }

  std::string * key = args[0]->toString();
  std::string * isSha = args[1]->toString();

	int error = -1;
	if(isSha == "true") error = libgls::addKey(obj->sock, key.c_str(), 1);
	else error = libgls::addKey(obj->sock, key.c_str(), 0);
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception addKey()")));
	return scope.Close(Undefined());

}

// clearKey()
static v8::Handle<v8::Value> gls::clearKey(const Arguments& args){
  HandleScope scope;
  gls* obj = ObjectWrap::Unwrap<gls>(args.This());

	int error = libgls::clearKey(obj->sock);
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception clearKey()")));
	return scope.Close(Undefined());

}

// getTypeConnexion()
static v8::Handle<v8::Value> gls::getTypeConnexion(const Arguments& args){
  HandleScope scope;
  gls* obj = ObjectWrap::Unwrap<gls>(args.This());

  int error = libgls::getTypeConnexion(obj->sock);
  if(error < 0) {
    ThrowException(Exception::TypeError(String::New("Exception getTypeConnexion()")));
    return scope.Close(Undefined());
  }
  else return scope.Close(UNumber::New(error));
}

// getUserId()
static v8::Handle<v8::Value> gls::getUserId(const Arguments& args){
  HandleScope scope;
  gls* obj = ObjectWrap::Unwrap<gls>(args.This());

	char *user = NULL;
	int error = libgls::getUserId(obj->sock, &user);
	if(error != 0 || user == NULL) {
		if(user != NULL) free(user);
		ThrowException(Exception::TypeError(String::New("Exception getUserId()")));
    return scope.Close(Undefined());
	}
	else {
    std::String s = std::String::New(user,(size_t) error);
    if(s == NULL) {
      if(user != NULL) free(user);
      ThrowException(Exception::TypeError(String::New("Exception getUserId()")));
      return scope.Close(Undefined());
    }
		free(user);
		return scope.Close(s);
	}
}

// setUserId(const std::string userId)
static v8::Handle<v8::Value> gls::setUserId(const Arguments& args){
  HandleScope scope;
  gls* obj = ObjectWrap::Unwrap<gls>(args.This());

  if (args.Length() < 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments setUserId()")));
    return scope.Close(Undefined());
  }

  std::string * userId = args[0]->toString();

	int error = libgls::setUserId(obj->sock, userId.c_str());
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception setUserId()")));
  return scope.Close(Undefined());

}

// finishHandShake()
static v8::Handle<v8::Value> gls::finishHandShake(const Arguments& args) {
  HandleScope scope;
  gls* obj = ObjectWrap::Unwrap<gls>(args.This());

	int error = libgls::finishHandShake(obj->sock);
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception finishHandShake()")));
  return scope.Close(Undefined());

}

// addRootCertificate(const std::string cert)
static v8::Handle<v8::Value> gls::addRootCertificate(const Arguments& args) {
  HandleScope scope;
  gls* obj = ObjectWrap::Unwrap<gls>(args.This());

  if (args.Length() < 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments addRootCertificate()")));
    return scope.Close(Undefined());
  }

  std::string * cert = args[0]->toString();

	int error = libgls::addRootCertificate(obj->sock, cert.c_str());
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception addRootCertificate()")));
  return scope.Close(Undefined());

}

// addRootCertificateFromFile(const char* certFile)
static v8::Handle<v8::Value> gls::addRootCertificateFromFile(const Arguments& args) {
  HandleScope scope;
  gls* obj = ObjectWrap::Unwrap<gls>(args.This());

  if (args.Length() < 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments addRootCertificateFromFile()")));
    return scope.Close(Undefined());
  }

  std::string * certFile = args[0]->toString();

	int error = libgls::addRootCertificateFromFile(obj->sock, certFile.c_str());
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception addRootCertificateFromFile()")));
  return scope.Close(Undefined());

}

// addToCrl(const char* serial)
static v8::Handle<v8::Value> gls::addToCrl(const Arguments& args) {
  HandleScope scope;
  gls* obj = ObjectWrap::Unwrap<gls>(args.This());

  if (args.Length() < 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments addToCrl()")));
    return scope.Close(Undefined());
  }

  std::string * serial = args[0]->toString();

	int error = libgls::addToCrl(obj->sock, serial.c_str());
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception addToCrl()")));
  return scope.Close(Undefined());

}

glsServer::glsServer() {

	this->sockServer = libgls::GLSServer();

}

glsServer::glsServer(const int secureMem, const int sizeMem) {

	this->sockServer = libgls::GLSServerSecure(secureMem, sizeMem);

}

glsServer::~glsServer(){

	libgls::freeGLSServer(this->sockServer);

}

void glsServer::Init(Handle<Object> exports) {
  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
  tpl->SetClassName(String::NewSymbol("glsServer"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);
  // Prototype
  tpl->PrototypeTemplate()->Set(String::NewSymbol("initServer"),
      FunctionTemplate::New(initServer)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("waitForClient"),
      FunctionTemplate::New(waitForClient)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("addServerCertificate"),
      FunctionTemplate::New(addServerCertificate)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("addServerCertificateFromFile"),
      FunctionTemplate::New(addServerCertificateFromFile)->GetFunction());

  Persistent<Function> constructor = Persistent<Function>::New(tpl->GetFunction());
  exports->Set(String::NewSymbol("glsServer"), constructor);
}

Handle<Value> glsServer::New(const Arguments& args) {
  HandleScope scope;

  glsServer* obj = new glsServer();
  obj->Wrap(args.This());

  return args.This();
}

// initServer(const char * port, const int waitQueue, const bool isReuse)
static v8::Handle<v8::Value> glsServer::initServer(const Arguments& args){
  HandleScope scope;
  glsServer* obj = ObjectWrap::Unwrap<glsServer>(args.This());

  if (args.Length() < 3) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments initServer()")));
    return scope.Close(Undefined());
  }

  std::string * port = args[0]->toString();
  int waitQueue = args[1]->NumberValue();
  std::string * isReuse = args[2]->toString();

	int error = -1;
	if(isReuse == "true") error = libgls::initServer(obj->sockServer, port.c_str(), waitQueue, 1);
	else error = libgls::initServer(obj->sockServer, port.c_str(), waitQueue, 0);
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception initServer()")));
  return scope.Close(Undefined());

}

// waitForClient()
static v8::Handle<v8::Value> glsServer::waitForClient(const Arguments& args) {
  HandleScope scope;
  glsServer* obj = ObjectWrap::Unwrap<glsServer>(args.This());

	libgls::GLSSock * s = NULL;
	int error = libgls::waitForClient(obj->sockServer, &s);
	if(error != 0 || s == NULL) {
    if(s != NULL) freeGLSSocket(s);
    ThrowException(Exception::TypeError(String::New("Exception waitForClient()")));
    return scope.Close(Undefined());
  }
	else {
		gls * g = new gls();
		freeGLSSocket(g->sock);
    g->sock = s;
		s = NULL;
		return g;
	}
}

// addServerCertificate(const std::string publicCert, const std::string privateKey)
static v8::Handle<v8::Value> glsServer::addServerCertificate(const Arguments& args) {
  HandleScope scope;
  glsServer* obj = ObjectWrap::Unwrap<glsServer>(args.This());

  if (args.Length() < 2) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments addServerCertificate()")));
    return scope.Close(Undefined());
  }

  std::string * publicCert = args[0]->toString();
  std::string * privateKey = args[1]->toString();

	int error = libgls::addServerCertificate(obj->sockServer, publicCert.c_str(), privateKey.c_str());
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception addServerCertificate()")));
  return scope.Close(Undefined());

}

// addServerCertificateFromFile(const char* publicCertFile, const char* privateKeyFile)
static v8::Handle<v8::Value> glsServer::addServerCertificateFromFile(const Arguments& args) {
  HandleScope scope;
  glsServer* obj = ObjectWrap::Unwrap<glsServer>(args.This());

  if (args.Length() < 2) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments addServerCertificateFromFile()")));
    return scope.Close(Undefined());
  }

  std::string * publicCertFile = args[0]->toString();
  std::string * privateKeyFile = args[1]->toString();

	int error = libgls::addServerCertificateFromFile(obj->sockServer, publicCertFile.c_str(), privateKeyFile.c_str());
	if(error != 0) ThrowException(Exception::TypeError(String::New("Exception addServerCertificateFromFile()")));
  return scope.Close(Undefined());

}
#endif

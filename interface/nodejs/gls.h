#ifndef GLSCPP_H
#define GLSCPP_H

#include <iostream>
#include <exception>
#include "libgls.h"
#include <node.h>

class gls : public node::ObjectWrap {

	private:
		gls();
		gls(const int secureMem, const int sizeMem);
		~gls();

	public:
		libgls::GLSSock* sock;

		static void Init(v8::Handle<v8::Object> exports);
		static v8::Handle<v8::Value> New(const v8::Arguments& args);

		static v8::Handle<v8::Value> connexion(const Arguments& args);
		static v8::Handle<v8::Value> sendRegister(const Arguments& args);
		static v8::Handle<v8::Value> getRegisterMessage(const Arguments& args);
		static v8::Handle<v8::Value> glsSend(cconst Arguments& args);
		static v8::Handle<v8::Value> glsRecv(const Arguments& args);
		static v8::Handle<v8::Value> addKey(const Arguments& args);
		static v8::Handle<v8::Value> clearKey(const Arguments& args);
		static v8::Handle<v8::Value> getTypeConnexion(const Arguments& args);
		static v8::Handle<v8::Value> getUserId(const Arguments& args);
		static v8::Handle<v8::Value> setUserId(const Arguments& args);
		static v8::Handle<v8::Value> finishHandShake(const Arguments& args);
		static v8::Handle<v8::Value> addRootCertificate(const Arguments& args);
		static v8::Handle<v8::Value> addRootCertificateFromFile(const Arguments& args);
		static v8::Handle<v8::Value> addToCrl(const Arguments& args);

};

class glsServer : public node::ObjectWrap {

	private:
		glsServer();
		glsServer(const int secureMem, const int sizeMem);
		~glsServer();

	public:
		libgls::GLSServerSock * sockServer;

		static void Init(v8::Handle<v8::Object> exports);
		static v8::Handle<v8::Value> New(const v8::Arguments& args);

		static v8::Handle<v8::Value> initServer(const Arguments& args);
		static v8::Handle<v8::Value> waitForClient(const Arguments& args);
		static v8::Handle<v8::Value> addServerCertificate(const Arguments& args);
		static v8::Handle<v8::Value> addServerCertificateFromFile(const Arguments& args);
};

#endif

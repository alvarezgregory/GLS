#define BUILDING_NODE_EXTENSION
#include <node.h>
#include "gls.h"

using namespace v8;

void InitAll(Handle<Object> exports) {
  gls::Init(exports);
}

NODE_MODULE(addon, InitAll)
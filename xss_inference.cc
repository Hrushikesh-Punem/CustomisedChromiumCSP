#include "xss_inference.h"

#include <onnxruntime_cxx_api.h>

#include <memory>
#include <string>
#include <vector>

namespace {

Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "xss-detector");
std::unique_ptr<Ort::Session> session;

void LoadONNXModel() {
  if (session) {
    return;  
  }
  Ort::SessionOptions session_options;
  session_options.SetIntraOpNumThreads(1);
  session = std::make_unique<Ort::Session>(
      env, "D:/Chromium/chromium/src/onnx/xss_model.onnx", session_options);
}

}  // namespace

bool RunONNXInference(const std::string& body) {
  LoadONNXModel();


  return false;
}

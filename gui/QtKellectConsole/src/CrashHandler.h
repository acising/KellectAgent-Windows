// src/CrashHandler.h
#pragma once

namespace CrashHandler {
void install();                              // qInstallMessageHandler + std::set_terminate
void write(const char* source, const char* msg); // 追加 crash.log(exe 同目录)
}

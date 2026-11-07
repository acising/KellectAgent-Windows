// Console agent entry point.
//
// The collector itself lives in kellect_core (source/runtime/collector.cpp);
// this file only prepares the console (UTF-8 + a font that can render Chinese)
// and hands argv over. The GUI product (KellectConsole.exe) launches this exe
// as a child process; the service product (KellectService.exe) links the same
// core directly.
#include "runtime/collector.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include <string>
#include <vector>

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Change the console code page so UTF-8 event data renders correctly, and
    // pick a font that has CJK glyphs.
    // Reference: http://m.blog.csdn.net/article/details?id=52789570
    SetConsoleOutputCP(65001);
    CONSOLE_FONT_INFOEX info = { 0 };
    info.cbSize = sizeof(info);
    info.dwFontSize.Y = 16;   // leave X as zero
    info.FontWeight = FW_NORMAL;
    wcscpy(info.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), NULL, &info);
#endif

    std::vector<std::string> args;
    args.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i)
        args.emplace_back(argv[i]);

    return kellect::RunCollector(args);
}

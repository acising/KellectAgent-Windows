// Test double for kellect.exe used by the supervisor smoke test.
// It honours --stop-event <name> so the supervisor can stop it gracefully.
#include <windows.h>

#include <cstring>
#include <string>

int main(int argc, char** argv) {
    std::string stopEventName;
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--stop-event") == 0)
            stopEventName = argv[++i];
    }

    if (stopEventName.empty()) {
        Sleep(600000);
        return 0;
    }

    HANDLE stop = CreateEventA(nullptr, TRUE, FALSE, stopEventName.c_str());
    if (stop == nullptr) {
        Sleep(600000);
        return 0;
    }
    WaitForSingleObject(stop, INFINITE);
    CloseHandle(stop);
    return 0;
}

//
// Created by Administrator on 2023/4/9.
//
#include <iostream>
#include <windows.h>

typedef int(*Fun)(int argc, char** argv);

int main(int argc, char** argv){

    HMODULE hLib = LoadLibraryA("E:\\kellect\\bin\\kellect.exe");
    if (nullptr == hLib)
    {
        std::cout << "LoadLibraryA fail, error:" << GetLastError() << std::endl;
        return 0;
    }

    Fun fun = (Fun)GetProcAddress(hLib, "main");
    if (nullptr == fun)
    {
        std::cout << "GetProcAddress fail, error:" << GetLastError() << std::endl;
        return 0;
    }

    char* arg = "-e all -f 123.txt";
//    char* arg[] = {"-e","all","-f","123.txt"};
//    fun(4,arg);
    fun(1,{});

    std::cout << "Hello World!\n";
    getchar();
}

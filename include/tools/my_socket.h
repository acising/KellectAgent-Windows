//#include<WinSock2.h>	//win socket编程头文件
//#include<iostream>
//#include<stdlib.h>
//#include<stdio.h>
//#include<string>
//
//#pragma comment(lib,"ws2_32.lib") //链接ws2_32库
//
//using namespace std;
//
//// global para
//const int BUF_SIZE = 2048; //2KB BUFFERSIZE
//
//
//class MySocket {
//
//public:
//	MySocket();
//	MySocket(string ip, int port);
//	void connetServer(string ip, int port);
//	void sendMsg(string msg);
//	void closeSocket();
//	string receiveMsg();
//
//private:
//	SOCKET socket_serv = {0};
//	SOCKADDR_IN addr_serv = { 0 };
//	SOCKADDR_IN addr_clie = { 0 };
//	int nAddr = sizeof(SOCKADDR_IN);
//	int sendLen = 0;
//	int recvLen = 0;
//
//	bool bBreak = false;
//	char sendBuffer[BUF_SIZE] = { 0 };
//	char recvBuffer[BUF_SIZE] = { 0 };
//	char inputBuffer[BUF_SIZE] = { 0 };
//};
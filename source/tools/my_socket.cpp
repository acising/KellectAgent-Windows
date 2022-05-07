//#define _WINSOCK_DEPRECATED_NO_WARNINGS
//#include "my_socket.h"
//
//MySocket::MySocket(string ip, int port) {
//	connetServer(ip,port);
//}
//
//void MySocket::connetServer(string ip,int port) {
//	
//	//load socket lib
//	WSADATA ws;
//	if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) {
//		cout << "客户端载入socket库失败！" << endl;
//		system("pause");
//	}
//
//	//create socket
//	//socket_clie = socket(AF_INET, SOCK_STREAM, 0);
//	socket_serv = socket(AF_INET, SOCK_STREAM, 0);
//
//	addr_serv.sin_addr.S_un.S_addr = inet_addr(ip.c_str());  //change the format of oct addr to bin addr
//	addr_serv.sin_family = AF_INET;		//set the address family to IPV4
//	addr_serv.sin_port = htons(port);	//change the format of oct port to bin port
//
//	//connect the server,exit if connect failed
//	if (connect(socket_serv, (SOCKADDR*)&addr_serv, sizeof(addr_serv)) == SOCKET_ERROR)
//	{
//		cout << "服务器连接失败！" << endl;
//	}
//	else {
//		cout << "服务器连接成功！" << endl;
//	}
//
//
//}
//
//void MySocket::closeSocket() {
//	closesocket(socket_serv);	//close socket
//
//	WSACleanup();		//cleanup socket lib
//}
//
//void MySocket::sendMsg(string msg) {
//
//	//cout << "请输入发送到服务端的信息:";
//	//cin >> sendBuffer;
//	//if (!strcmp(sendBuffer, "exit")) {
//	//	cout << "客户端申请断开连接，即将关闭连接..." << endl;
//	//	bBreak = true;
//	//}
//	int len = strlen(msg.c_str());
//	sendLen = send(socket_serv, msg.c_str(), strlen(msg.c_str()), 0);
//	
//	cout << "json长度：" << len << endl;
//	if (sendLen < 0) {
//		cout << "发送失败！" << endl;
//	}
//}
//
//string MySocket::receiveMsg() {
//
//	recvLen = recv(socket_serv, recvBuffer, sizeof(recvBuffer), 0);
//	if (recvLen < 0) {
//		cout << "接收失败！" << endl;
//	}
//	else if (!strcmp(recvBuffer, "exit")) {
//		cout << "服务端申请断开连接，即将关闭连接..." << endl;
//		bBreak = true;
//		return 0L;
//	}
//	else {
//		cout << "接收到服务端信息:" << recvBuffer << endl;
//	}
//
//	return recvBuffer;
//}
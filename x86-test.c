#include <stdio.h>
#include <Windows.h>
#include <wchar.h>
void findGetProAddrByPeb(DWORD flag);
void BreakPoint();
typedef FARPROC(WINAPI *FunGetProAddr)  (HMODULE h, LPCSTR name);
typedef HMODULE(WINAPI *FunGetLoadLirA) (LPCSTR name);
typedef UINT   (WINAPI *FunWinExec)     (LPCSTR lpCmdLine, UINT uCmdShow);


void  shellcodeend()
{
	HMODULE        hKernel32;

	FunGetProAddr        fGetProAddr   = NULL;
	FunGetLoadLirA       fLoadLibraryA = NULL;
	FunWinExec	         fWinexec      = NULL;

	char kerStr[]       = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };       // kernel32.dll
	char winStr[]       = {'W', 'i', 'n', 'E', 'x', 'e', 'c', 0 };                                // WinExec
	char calcStr[]      = { 'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', 0 };                          // calc.exe


	__asm{ 
		push 2;
		call findGetProAddrByPeb;
		mov fGetProAddr, eax;      GetProAddress Address
		push 1;
		call findGetProAddrByPeb;
		mov fLoadLibraryA, eax;    LoadLibrary Addresss
	}

	hKernel32     = fLoadLibraryA(kerStr);
	

	fWinexec = (FunWinExec)fGetProAddr(hKernel32, winStr);
	fWinexec(calcStr,0);



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

	BreakPoint();
	shellcodeend();
	return 0; 
}
void BreakPoint()
{
	_asm{
		int 3;
	}
}
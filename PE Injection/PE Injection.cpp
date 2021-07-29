#include<Windows.h>
#include<stdio.h>
#include<string.h>
DWORD RVA_Convert(DWORD RVA, BYTE* data) {
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)data;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(data + dos_header->e_lfanew);
	int section = 0;
	//find section
	for (section = 0; section < nt_header->FileHeader.NumberOfSections; section++) {
		PIMAGE_SECTION_HEADER sec_header = (PIMAGE_SECTION_HEADER)(data + dos_header->e_lfanew + 248 + 40 * section);
		if (sec_header->VirtualAddress > RVA) break;
	}
	section -= 1;
	//calculate raw address from rva
	PIMAGE_SECTION_HEADER sec_header = (PIMAGE_SECTION_HEADER)(data + dos_header->e_lfanew + 248 + 40 * section);
	DWORD Raw = (RVA - sec_header->VirtualAddress) + sec_header->PointerToRawData;
	return Raw;
}
void LoadExe(BYTE* data){
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)data;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(data + dos_header->e_lfanew);
	//get current process handle
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	if (hProc == INVALID_HANDLE_VALUE) return;
	PVOID loc = VirtualAlloc(NULL, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (loc == NULL) return;
	//write header 
	memcpy(loc, data, nt_header->OptionalHeader.SizeOfHeaders);

	//fixing .reloc table
	DWORD deltaImageBase = (DWORD)loc - nt_header->OptionalHeader.ImageBase;
	DWORD relocRVA = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD relocRaw = RVA_Convert(relocRVA, data);
	
	PIMAGE_BASE_RELOCATION relocTable = (PIMAGE_BASE_RELOCATION)(data + relocRaw);
	while (relocTable->SizeOfBlock > 0) {
		DWORD entryCount = (relocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		for (DWORD entry = 0; entry < entryCount; entry += 1) {
			PWORD item = (PWORD)((DWORD)relocTable + sizeof(IMAGE_BASE_RELOCATION) + 2 * entry);
			if ((*item & 0x0fff) == 0) {
				continue;
			}
			DWORD RVA = relocTable->VirtualAddress + ((*(PWORD)((DWORD)relocTable + sizeof(IMAGE_BASE_RELOCATION) + 2 * entry)) & 0x0FFF);
			PDWORD addr = (PDWORD)(data + RVA_Convert(RVA, data));
			*addr += deltaImageBase;
		}
		relocTable = (PIMAGE_BASE_RELOCATION)((DWORD)relocTable + relocTable->SizeOfBlock);
	}
	//fixing IAT
	DWORD importRVA = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD importRaw = RVA_Convert(importRVA, data);
	PIMAGE_IMPORT_DESCRIPTOR importTable = (PIMAGE_IMPORT_DESCRIPTOR)(data + importRaw);
	while (importTable->Name > 0) {
		DWORD lib_raw = RVA_Convert(importTable->FirstThunk, data);
		DWORD name_raw = RVA_Convert(importTable->Name, data);
		HMODULE lib = LoadLibraryA((char*)(data + name_raw));
		PDWORD func = (DWORD*)(data + lib_raw);
		while (*func > 0) {
			DWORD func_name_raw = RVA_Convert(*func, data);
			char* func_name = (char*)(data + func_name_raw + 2);
			DWORD patch = (DWORD)GetProcAddress(lib, func_name);
			*func = patch;
			func = (DWORD*)((BYTE*)func + 4);
		}
		importTable = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)importTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	//write sections
	for (int section = 0; section < nt_header->FileHeader.NumberOfSections; section++) {
		PIMAGE_SECTION_HEADER sec_header = (PIMAGE_SECTION_HEADER)(data + dos_header->e_lfanew + 248 + 40 * section);
		memcpy((PVOID)((DWORD)loc + sec_header->VirtualAddress), (PVOID)((DWORD)data + sec_header->PointerToRawData),
			sec_header->SizeOfRawData);
		if (sec_header->Characteristics & 0x40000000) //read
			VirtualProtect((PVOID)((DWORD)loc + sec_header->VirtualAddress), sec_header->SizeOfRawData, PAGE_READONLY, NULL);
		if (sec_header->Characteristics & 0x60000000) //read-execute
			VirtualProtect((PVOID)((DWORD)loc + sec_header->VirtualAddress), sec_header->SizeOfRawData, PAGE_EXECUTE_READ, NULL);
		if (sec_header->Characteristics & 0xC0000000) //read
			VirtualProtect((PVOID)((DWORD)loc + sec_header->VirtualAddress), sec_header->SizeOfRawData, PAGE_READWRITE, NULL);
	}
	DWORD threadId = 0;
	PVOID startup = (PVOID)((DWORD)loc + nt_header->OptionalHeader.AddressOfEntryPoint);
	((void(*)())startup)();		//execute
	CloseHandle(hProc);
}
int main() {
	HANDLE hFile = CreateFileA("shellcode.exe", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open file\n");
		return 1;
	}
	DWORD shellcodeSize = GetFileSize(hFile, NULL);
	BYTE* shellcode = (BYTE*)malloc(shellcodeSize + 1);
	memset(shellcode, 0, shellcodeSize + 1);
	DWORD read;
	ReadFile(hFile, shellcode, shellcodeSize, &read, NULL);
	CloseHandle(hFile);

	LoadExe(shellcode);
}

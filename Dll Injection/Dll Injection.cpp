#include<Windows.h>
#include<stdio.h>
#include<Psapi.h>
#pragma warning (disable : 4996)
int main(int argc, char** argv) {
	if (argc != 3) {
		printf("Useage : \"Dll Injection.exe\" [Dll file] [target process id]");
		return 1;
	}
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[2]));
	if (hProc == INVALID_HANDLE_VALUE) {
		printf("Cannot open process id %d\n", atoi(argv[2]));
		return 1;
	}
	PVOID addr = VirtualAllocEx(hProc, NULL, strlen(argv[1]) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (addr == NULL) {
		printf("Cannot alloc memory\n");
		return 1;
	}
	if (!WriteProcessMemory(hProc, addr, argv[1], 1+ strlen(argv[1]), NULL)) {
		printf("Cannot write to target\n");
		return 1;
	}
	HMODULE hlib = GetModuleHandleA("kernel32.dll");
	FARPROC funcaddr = GetProcAddress(hlib, "LoadLibraryA");
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)funcaddr, addr, NULL, NULL);
	if (hThread == NULL) {
		printf("Cannot create remote thread");
		return 1;
	}
	printf("Inject success");
	CloseHandle(hThread);
	CloseHandle(hProc);
 }

#include<stdio.h>
#include<Windows.h>
int main() {
	char name[128] = { 0 };
	GetModuleFileNameA(NULL, name, 128);
	MessageBoxA(NULL, name, "phongpt14", 0);
}
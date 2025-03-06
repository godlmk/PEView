// kml_shell.h: 标准系统包含文件的包含文件
// 或项目特定的包含文件。

#pragma once
#define _CRT_SECURE_NO_WARNINGS

// TODO: 在此处引用程序需要的其他标头。
#include <windows.h>
#include <string>

int Align(int origin, int alignment);
PIMAGE_DOS_HEADER GetDosHeader(LPVOID pImageBuffer);
PIMAGE_NT_HEADERS GetNTHeader(LPVOID pImageBuffer, PIMAGE_DOS_HEADER dosHeader);
DWORD ReadFileBuffer(const char* filename, void** pBuffer);
PVOID FileBuffer2MemoryBuffer(IN PVOID pFileBuffer);
BOOL GetPEInfoFromFile(IN PVOID pFileBuffer, OUT PDWORD pImageBase,
	OUT PDWORD pSizeOfImage,
	OUT PDWORD pEOP
);

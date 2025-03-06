#include <cassert>
#include <print>
#include "kml_shell.h"
int Align(int origin, int alignment)
{
	return ((origin + alignment - 1) / alignment) * alignment;
}

PIMAGE_DOS_HEADER GetDosHeader(LPVOID pImageBuffer)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::println("Invalid DOS signature in GetDosHeader");
		return NULL;
	}
	return dosHeader;
}
PIMAGE_NT_HEADERS GetNTHeader(LPVOID pImageBuffer, PIMAGE_DOS_HEADER dosHeader)
{
	const PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		std::println("Invalid NT signature");
		return NULL;
	}
	return ntHeader;
}
DWORD ReadFileBuffer(const char* filename, void** pBuffer) {
	FILE* fp = fopen(filename, "rb");
	if (fp == NULL)
	{
		std::println("fread failed, because:{}", strerror(errno));
		exit(-1);
	}
	fseek(fp, 0, SEEK_END);
	long bytes = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	unsigned char* buffer = (unsigned char*)malloc(bytes);
	if (!buffer) {
		std::println("malloc failed, because:{}", strerror(errno));
		fclose(fp);
		exit(-1);
	}
	int ret = fread(buffer, bytes, 1, fp);
	if (ret != 1) {
		std::println("fread failed, because:{}", strerror(errno));
		free(buffer);
		fclose(fp);
		exit(-1);
	}
	fclose(fp);
	*pBuffer = buffer;
	return bytes;
}

PVOID FileBuffer2MemoryBuffer(IN PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		free(pFileBuffer);
		std::println("Invalid DOS signature in filebuffeer2memory\n");
		return NULL;
	}
	PIMAGE_NT_HEADERS const ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)pFileBuffer + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		std::println("Invalid NT signature\n");
		return NULL;
	}
	PIMAGE_OPTIONAL_HEADER const optionalHeader =
		&ntHeader->OptionalHeader;// ntHeader->OptionalHeader;
	const DWORD ImageSize = optionalHeader->SizeOfImage;
	PBYTE const ImageBuffer = (PBYTE)malloc(ImageSize);
	if (!ImageBuffer) {
		free(pFileBuffer);
		std::println("malloc failed, because:{}", strerror(errno));
		return NULL;
	}
	memset(ImageBuffer, 0, ImageSize);
	// 拷贝所有的头和节表
	const DWORD sizeOfHeaderAndSection = optionalHeader->SizeOfHeaders;
	memcpy(ImageBuffer, pFileBuffer, sizeOfHeaderAndSection);
	// 拷贝每一节的数据到应该在的位置
	const PIMAGE_SECTION_HEADER const firstSection = IMAGE_FIRST_SECTION(ntHeader);
	const int sectionCount = ntHeader->FileHeader.NumberOfSections;
	for (int i = 0; i < sectionCount; ++i) {
		PIMAGE_SECTION_HEADER curSection = firstSection + i;
		const DWORD offsetInMemoty = curSection->VirtualAddress;
		const DWORD offsetInFile = curSection->PointerToRawData;
		const DWORD sectionSizeInFile = curSection->SizeOfRawData;
		memcpy(ImageBuffer + offsetInMemoty, (PBYTE)pFileBuffer + offsetInFile, sectionSizeInFile);
	}
	return ImageBuffer;
}

BOOL GetPEInfoFromFile(IN PVOID pFileBuffer, OUT PDWORD pImageBase,
	OUT PDWORD pSizeOfImage,
	OUT PDWORD pEOP)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::println("Invalid DOS signature in getpeinfo");
		return FALSE;
	}
	PIMAGE_NT_HEADERS nt_headers = GetNTHeader(pFileBuffer, dosHeader);
	*pImageBase = nt_headers->OptionalHeader.ImageBase;
	*pSizeOfImage = nt_headers->OptionalHeader.SizeOfImage;
	*pEOP = nt_headers->OptionalHeader.AddressOfEntryPoint;
	return TRUE;
}

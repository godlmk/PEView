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
		std::println("Invalid DOS signature");
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

PBYTE LoadMemoryImage(const char* filename) {
	unsigned char* buffer;
	DWORD size = ReadFileBuffer(filename, (void**)&buffer);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		free(buffer);
		std::println("Invalid DOS signature\n");
		return NULL;
	}
	const PIMAGE_NT_HEADERS const ntHeader = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		free(buffer);
		std::println("Invalid NT signature\n");
		return NULL;
	}
	const PIMAGE_OPTIONAL_HEADER const optionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)ntHeader
		+ sizeof(ntHeader->Signature)
		+ sizeof(ntHeader->FileHeader));// ntHeader->OptionalHeader;
	std::println("offset is {:X}, use & is {:X}", (DWORD)optionalHeader, (DWORD)&ntHeader->OptionalHeader);
	assert(optionalHeader == &ntHeader->OptionalHeader);
	const DWORD ImageSize = optionalHeader->SizeOfImage;
	PBYTE const ImageBuffer = (PBYTE)malloc(ImageSize);
	if (!ImageBuffer) {
		free(buffer);
		std::println("malloc failed, because:{}", strerror(errno));
		return NULL;
	}
	memset(ImageBuffer, 0, ImageSize);
	// 拷贝所有的头和节表
	const DWORD sizeOfHeaderAndSection = optionalHeader->SizeOfHeaders;
	memcpy(ImageBuffer, buffer, sizeOfHeaderAndSection);
	// 拷贝每一节的数据到应该在的位置
	const PIMAGE_SECTION_HEADER const firstSection = IMAGE_FIRST_SECTION(ntHeader);
	const int sectionCount = ntHeader->FileHeader.NumberOfSections;
	for (int i = 0; i < sectionCount; ++i) {
		PIMAGE_SECTION_HEADER curSection = firstSection + i;
		const DWORD offsetInMemoty = curSection->VirtualAddress;
		const DWORD offsetInFile = curSection->PointerToRawData;
		const DWORD sectionSizeInFile = curSection->SizeOfRawData;
		memcpy(ImageBuffer + offsetInMemoty, buffer + offsetInFile, sectionSizeInFile);
	}
	free(buffer);
	return ImageBuffer;
}
bool SaveImageToFile(PBYTE pMemBuffer, const char* destPath) {
	const PIMAGE_DOS_HEADER const dosHeader = (PIMAGE_DOS_HEADER)pMemBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::println("has not dos format");
		return false;
	}
	const PIMAGE_NT_HEADERS const ntHeader = (PIMAGE_NT_HEADERS)((DWORD)pMemBuffer + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		std::println("Invalid NT signature");
		return false;
	}
	const PIMAGE_OPTIONAL_HEADER const optionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)ntHeader
		+ sizeof(ntHeader->Signature)
		+ sizeof(ntHeader->FileHeader));// ntHeader->OptionalHeader;
	assert(optionalHeader == &ntHeader->OptionalHeader, "optionalHeader != ntHeader->OptionalHeader");
	DWORD fileSize = 0;
	// 加上所有header和节表的大小
	fileSize += optionalHeader->SizeOfHeaders;
	//	加上每一节的大小
	const size_t sectionCount = ntHeader->FileHeader.NumberOfSections;
	const PIMAGE_SECTION_HEADER const firstSection = IMAGE_FIRST_SECTION(ntHeader);
	for (size_t i = 0; i < sectionCount; ++i) {
		const PIMAGE_SECTION_HEADER const curSection = firstSection + i;
		fileSize += curSection->SizeOfRawData;
	}
	PBYTE pFileBuffer = (PBYTE)malloc(fileSize);
	if (!pFileBuffer) {
		std::println("malloc failed, because:{}", strerror(errno));
		return false;
	}
	memset(pFileBuffer, 0, fileSize);
	// 拷贝所有的头和节表
	memcpy(pFileBuffer, pMemBuffer, optionalHeader->SizeOfHeaders);
	for (size_t i = 0; i < sectionCount; ++i) {
		const PIMAGE_SECTION_HEADER const curSection = firstSection + i;
		const DWORD offsetInMemry = curSection->VirtualAddress;
		const DWORD offsetInFile = curSection->PointerToRawData;
		const DWORD curSectionSizeinFile = curSection->SizeOfRawData;
		PBYTE dest = pFileBuffer + offsetInFile;
		PBYTE src = pMemBuffer + offsetInMemry;
		memcpy(dest, src, curSectionSizeinFile);
	}
	FILE* fp = fopen(destPath, "wb");
	if (!fp) {
		std::println("fopen failed, because:{}", strerror(errno));
		return false;
	}
	size_t ret = fwrite(pFileBuffer, fileSize, 1, fp);
	if (ret != 1) {
		std::println("fwrite failed, because:{}", strerror(errno));
		fclose(fp);
		return false;
	}
	fclose(fp);
	free(pFileBuffer);
	return true;
}
PVOID FileBuffer2MemoryBuffer(IN PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		free(pFileBuffer);
		std::println("Invalid DOS signature\n");
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
DWORD RVA2FOA(IN LPVOID pMemoryBuffer, IN DWORD Rva)
{
	auto const dosHeader = GetDosHeader(pMemoryBuffer);
	if (dosHeader == NULL) return -1;
	auto const ntHeader = GetNTHeader(pMemoryBuffer, dosHeader);
	if (ntHeader == NULL) return -1;
	auto const optionalHeader = &ntHeader->OptionalHeader;
	// 如果偏移量还在头部，那么直接返回即可
	if (Rva < optionalHeader->SizeOfHeaders)
	{
		return Rva;
	}
	auto const sectionCount = ntHeader->FileHeader.NumberOfSections;
	auto const firstSection = IMAGE_FIRST_SECTION(ntHeader);
	for (int i = 0; i < sectionCount; ++i)
	{
		auto const curSection = firstSection + i;
		auto const virtualAddress = curSection->VirtualAddress;
		auto const ptoRawData = curSection->PointerToRawData;
		auto const sectionSize = curSection->SizeOfRawData;
		if (Rva >= virtualAddress && Rva < virtualAddress + sectionSize)
		{
			auto const ans = ptoRawData + (Rva - virtualAddress);
			//std::println("the foa is {:X}", ans);
			return ans;
		}
	}
	return 0;
}
DWORD FOA2RVA(IN LPVOID pMemoryBuffer, IN DWORD Foa)
{
	auto const dosHeader = GetDosHeader(pMemoryBuffer);
	if (dosHeader == NULL) return -1;
	auto const ntHeader = GetNTHeader(pMemoryBuffer, dosHeader);
	if (ntHeader == NULL) return -1;
	auto const optionalHeader = &ntHeader->OptionalHeader;
	// 如果偏移量还在头部，那么直接返回即可
	if (Foa < optionalHeader->SizeOfHeaders)
	{
		return Foa;
	}
	auto const sectionCount = ntHeader->FileHeader.NumberOfSections;
	auto const firstSection = IMAGE_FIRST_SECTION(ntHeader);
	for (int i = 0; i < sectionCount; ++i)
	{
		auto const curSection = firstSection + i;
		auto const virtualAddress = curSection->VirtualAddress;
		auto const ptoRawData = curSection->PointerToRawData;
		auto const sectionSize = curSection->SizeOfRawData;
		if (Foa >= ptoRawData && Foa < ptoRawData + sectionSize)
		{
			auto const ans = virtualAddress + (Foa - ptoRawData);
			//std::println("the rva is {:X}", ans);
			return ans;
		}
	}
	return 0;
}
// 写入内存中的数据到对应文件名
bool write_file(IN void* buffer, IN const char* filename, IN const DWORD size)
{
	FILE* fp = fopen(filename, "wb");
	auto ans = fwrite(buffer, size, 1, fp);
	if (ans == -1)
	{
		std::println("fwrite fail, becase:", strerror(errno));
		return false;
	}
	fclose(fp);
	return true;
}

DWORD Offset(PVOID buffer, PVOID addr)
{
	return (DWORD)(addr)-(DWORD)buffer;
}

void* GetBufferAddr(PVOID buffer, DWORD rva)
{
	DWORD foa = RVA2FOA(buffer, rva);
	return (PVOID)((PBYTE)buffer + foa);
}

BOOL GetPEInfoFromFile(IN PVOID pFileBuffer, OUT PDWORD pImageBase,
	OUT PDWORD pSizeOfImage,
	OUT PDWORD pEOP)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::println("Invalid DOS signature");
		return FALSE;
	}
	PIMAGE_NT_HEADERS nt_headers = GetNTHeader(pFileBuffer, dosHeader);
	*pImageBase = nt_headers->OptionalHeader.ImageBase;
	*pSizeOfImage = nt_headers->OptionalHeader.SizeOfImage;
	*pEOP = nt_headers->OptionalHeader.AddressOfEntryPoint;
	return TRUE;
}

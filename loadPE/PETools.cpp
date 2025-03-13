#include "PETools.h"
#include <print>
#include <cassert>
#include <format>
#include <tchar.h>

char errStr[0x20];

DWORD Align(int origin, int alignment)
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
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)pImageBuffer + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		std::println("Invalid NT signature");
		return NULL;
	}
	return ntHeader;
}
DWORD ReadFileBuffer(LPCTSTR filename, void** pBuffer) {
	FILE* fp;
	errno_t err = _wfopen_s(&fp, filename, L"rb");
	if (fp == NULL)
	{
		strerror_s(errStr, 0x20, errno);
		std::println("fread failed, because:{}", errStr);
		exit(-1);
	}
	fseek(fp, 0, SEEK_END);
	long bytes = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	unsigned char* buffer = (unsigned char*)malloc(bytes);
	if (!buffer) {
		strerror_s(errStr, 0x20, errno);
		std::println("malloc failed, because:{}", errStr);
		fclose(fp);
		exit(-1);
	}
	int ret = fread(buffer, bytes, 1, fp);
	if (ret != 1) {
		strerror_s(errStr, 0x20, errno);
		std::println("fread failed, because:{}", errStr);
		free(buffer);
		fclose(fp);
		exit(-1);
	}
	fclose(fp);
	*pBuffer = buffer;
	return bytes;
}

bool ImageMemory2File(PBYTE pMemBuffer, const wchar_t* destPath) {
	const PIMAGE_DOS_HEADER const dosHeader = (PIMAGE_DOS_HEADER)pMemBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::println("has not dos format");
		return false;
	}
	const PIMAGE_NT_HEADERS const ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)pMemBuffer + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		std::println("Invalid NT signature");
		return false;
	}
	PIMAGE_OPTIONAL_HEADER32 const optionalHeader = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)ntHeader
		+ sizeof(ntHeader->Signature)
		+ sizeof(ntHeader->FileHeader));// ntHeader->OptionalHeader;
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
		strerror_s(errStr, 0x20, errno);
		std::println("malloc failed, because:{}", errStr);
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
	FILE* fp;
	errno_t err = _wfopen_s(&fp, destPath, L"wb");
	if (!fp) {
		strerror_s(errStr, 0x20, errno);
		std::println("fopen failed, because:{}", errStr);
		return false;
	}
	size_t ret = fwrite(pFileBuffer, fileSize, 1, fp);
	if (ret != 1) {
		strerror_s(errStr, 0x20, errno);
		std::println("fwrite failed, because:{}", errStr);
		fclose(fp);
		return false;
	}
	fclose(fp);
	free(pFileBuffer);
	return true;
}

PBYTE ReadMemoryImage(LPCTSTR filename) {
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
	PIMAGE_OPTIONAL_HEADER32 const optionalHeader = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)ntHeader
		+ sizeof(ntHeader->Signature)
		+ sizeof(ntHeader->FileHeader));// ntHeader->OptionalHeader;
	const DWORD ImageSize = optionalHeader->SizeOfImage;
	PBYTE const ImageBuffer = (PBYTE)malloc(ImageSize);
	if (!ImageBuffer) {
		free(buffer);
		strerror_s(errStr, 0x20, errno);
		std::println("malloc failed, because:{}", errStr);
		return NULL;
	}
	memset(ImageBuffer, 0, ImageSize);
	// 拷贝所有的头和节表
	DWORD sizeOfHeaderAndSection = optionalHeader->SizeOfHeaders;
	memcpy(ImageBuffer, buffer, sizeOfHeaderAndSection);
	// 拷贝每一节的数据到应该在的位置
	const PIMAGE_SECTION_HEADER const firstSection = IMAGE_FIRST_SECTION(ntHeader);
	const int sectionCount = ntHeader->FileHeader.NumberOfSections;
	for (int i = 0; i < sectionCount; ++i) {
		PIMAGE_SECTION_HEADER curSection = firstSection + i;
		DWORD offsetInMemoty = curSection->VirtualAddress;
		DWORD offsetInFile = curSection->PointerToRawData;
		const DWORD sectionSizeInFile = curSection->SizeOfRawData;
		memcpy(ImageBuffer + offsetInMemoty, buffer + offsetInFile, sectionSizeInFile);
	}
	free(buffer);
	return ImageBuffer;
}
bool ImageMemory2File(PBYTE pMemBuffer, const char* destPath) {
	const PIMAGE_DOS_HEADER const dosHeader = (PIMAGE_DOS_HEADER)pMemBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::println("has not dos format");
		return false;
	}
	const PIMAGE_NT_HEADERS const ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)pMemBuffer + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		std::println("Invalid NT signature");
		return false;
	}
	const PIMAGE_OPTIONAL_HEADER32 const optionalHeader = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)ntHeader
		+ sizeof(ntHeader->Signature)
		+ sizeof(ntHeader->FileHeader));// ntHeader->OptionalHeader;
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
		strerror_s(errStr, 0x20, errno);
		std::println("malloc failed, because:{}", errStr);
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

	FILE* fp;
	errno_t err = fopen_s(&fp, destPath, "wb");
	if (!fp) {
		strerror_s(errStr, 0x20, errno);
		std::println("fopen failed, because:{}", errStr);
		return false;
	}
	size_t ret = fwrite(pFileBuffer, fileSize, 1, fp);
	if (ret != 1) {
		strerror_s(errStr, 0x20, errno);
		std::println("fwrite failed, because:{}", errStr);
		fclose(fp);
		return false;
	}
	fclose(fp);
	free(pFileBuffer);
	return true;
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
	FILE* fp;
	errno_t err = fopen_s(&fp, filename, "wb");
	if (err != 0 || fp == NULL) {
		// Handle error, e.g., log the error or return false
		return false;
	}
	auto ans = fwrite(buffer, 1, size, fp);
	fclose(fp);
	return ans == 1;
}


DWORD Offset(PVOID buffer, PVOID addr)
{
	return (PBYTE)(addr)-(PBYTE)buffer;
}

void* GetBufferAddr(PVOID buffer, DWORD rva)
{
	DWORD foa = RVA2FOA(buffer, rva);
	return (PVOID)((PBYTE)buffer + foa);
}


// 新增一个节，大小为0x1000 字节的节，之后返回新增节的FOA

bool AddNewSection(IN  LPCTSTR infilename, OUT PVOID* newFileBuffer, OUT PDWORD pOldSize,
	OUT PDWORD size_src)
{
	// 1. 获取相关信息
	PVOID file_buffer;
	DWORD size = ReadFileBuffer(infilename, &file_buffer);
	PIMAGE_DOS_HEADER dos_header = GetDosHeader(file_buffer);
	PIMAGE_NT_HEADERS nt_headers = GetNTHeader(file_buffer, dos_header);
	PIMAGE_FILE_HEADER file_header = &nt_headers->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 op_header = (PIMAGE_OPTIONAL_HEADER32)&nt_headers->OptionalHeader;
	op_header->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

	// 2. 是否能够放下一张新的节表
	const int freebytes = op_header->SizeOfHeaders - (dos_header->e_lfanew +
		sizeof(IMAGE_NT_HEADERS) + file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	if (freebytes < sizeof(IMAGE_SECTION_HEADER))
	{
		std::println("该文件的headers空闲区域无法放下一张节表");
		return false;
	}

	// 3. 复制第一张表到新的节表
	const int oldSectionNumber = file_header->NumberOfSections;
	PIMAGE_SECTION_HEADER first_section = IMAGE_FIRST_SECTION(nt_headers);
	PIMAGE_SECTION_HEADER cur_section = first_section + oldSectionNumber;
	memcpy(cur_section, first_section, sizeof(IMAGE_SECTION_HEADER));

	// 4. 在最后的节表位置设置一个全0的节表
	memset(cur_section + 1, 0, sizeof(IMAGE_SECTION_HEADER));

	// 5. 修改新增节表的属性
	// 名字
	const char* name = ".new";
	memset(cur_section->Name, 0, sizeof(cur_section->Name));
	memcpy(cur_section->Name, name, strlen(name));

	// 对齐新的节大小
	DWORD new_section_size = Align(*size_src, op_header->FileAlignment);
	cur_section->Misc.VirtualSize = Align(*size_src, op_header->SectionAlignment);
	PIMAGE_SECTION_HEADER pre_section = cur_section - 1;
	DWORD t_add = 0;
	if (pre_section->Misc.VirtualSize < pre_section->SizeOfRawData)
	{
		t_add = Align(pre_section->SizeOfRawData, op_header->SectionAlignment);
	}
	else
	{
		t_add = Align(pre_section->Misc.VirtualSize, op_header->SectionAlignment);
	}
	cur_section->VirtualAddress = pre_section->VirtualAddress + t_add;
	cur_section->SizeOfRawData = new_section_size;
	cur_section->PointerToRawData = pre_section->PointerToRawData + pre_section->SizeOfRawData;
	cur_section->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	// 修改节表数量
	file_header->NumberOfSections += 1;
	// 7. 更新可选头的大小
	op_header->SizeOfImage = Align(cur_section->VirtualAddress + cur_section->Misc.VirtualSize,
		op_header->SectionAlignment);
	*pOldSize = size + new_section_size;
	*size_src = new_section_size;


	// 6. 分配新的文件缓冲区并复制原始数据
	*newFileBuffer = malloc(size + new_section_size);
	if (!*newFileBuffer) {
		strerror_s(errStr, 0x20, errno);
		std::println("malloc failed, because:{}", errStr);
		free(file_buffer);
		return false;
	}
	memcpy(*newFileBuffer, file_buffer, size);
	memset((PBYTE)*newFileBuffer + size, 0, new_section_size);


	free(file_buffer);
	return true;
}

bool BigerSection(IN LPCTSTR infilename, IN const char* outfilename)
{
	/*
		读取到内存中
		计算出新建节后memoryImage的大小
		重新申请内存并且拷贝原来的数据到新的内存中
		填充最后一个节新的空闲区域
		修改节表
		修改节表属性
		修改SizeOfImage
	*/
	void* memoryImage = ReadMemoryImage(infilename);
	assert(memoryImage);
	PIMAGE_NT_HEADERS ntHeaders = GetNTHeader(memoryImage, GetDosHeader(memoryImage));
	int const imageSize = ntHeaders->OptionalHeader.SizeOfImage + ntHeaders->OptionalHeader.SectionAlignment;
	void* newMemoryImage = calloc(1, imageSize);
	assert(newMemoryImage);
	memcpy(newMemoryImage, memoryImage, ntHeaders->OptionalHeader.SizeOfImage);
	free(memoryImage);

	PIMAGE_DOS_HEADER dosHeader = GetDosHeader(newMemoryImage);
	ntHeaders = GetNTHeader(newMemoryImage, dosHeader);
	PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 opHeader = (PIMAGE_OPTIONAL_HEADER32)&ntHeaders->OptionalHeader;

	int const sectionCount = fileHeader->NumberOfSections;
	PIMAGE_SECTION_HEADER lastSection = IMAGE_FIRST_SECTION(ntHeaders) + (sectionCount - 1);
	lastSection->Misc.VirtualSize = imageSize - lastSection->VirtualAddress;
	lastSection->SizeOfRawData = lastSection->Misc.VirtualSize;
	opHeader->SizeOfImage = imageSize;
	ImageMemory2File((PBYTE)newMemoryImage, outfilename);
	return true;
}
BOOL RebaseRelocation(PVOID pImageBuffer, DWORD dwNewImageBase) {
	PIMAGE_DOS_HEADER pDosHeader = GetDosHeader(pImageBuffer);
	PIMAGE_NT_HEADERS pNtHeaders = GetNTHeader(pImageBuffer, pDosHeader);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)&pNtHeaders->OptionalHeader;

	// 获取重定位表
	DWORD relocDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (relocDirRVA == 0) {
		pOptionalHeader->ImageBase = dwNewImageBase;
		return TRUE;
	}

	PIMAGE_BASE_RELOCATION pRelocationTable = (PIMAGE_BASE_RELOCATION)((PBYTE)pImageBuffer + relocDirRVA);
	LONG_PTR lImageBaseDelta = (LONG_PTR)dwNewImageBase - (LONG_PTR)pOptionalHeader->ImageBase;

	// 遍历重定位块
	while (pRelocationTable->VirtualAddress && pRelocationTable->SizeOfBlock) {
		if (pRelocationTable->SizeOfBlock < 8) break;

		DWORD entryCount = (pRelocationTable->SizeOfBlock - 8) / 2;
		PWORD pEntries = (PWORD)((PBYTE)pRelocationTable + 8);

		for (DWORD i = 0; i < entryCount; ++i) {
			WORD entry = pEntries[i];
			BYTE type = entry >> 12;
			WORD offset = entry & 0x0FFF;

			if (type != IMAGE_REL_BASED_HIGHLOW) continue;

			// 计算重定位地址
			DWORD_PTR relocRVA = pRelocationTable->VirtualAddress + offset;
			PDWORD pRelocAddr = (PDWORD)((PBYTE)pImageBuffer + relocRVA);

			// 修正地址
			*pRelocAddr += (DWORD)lImageBaseDelta; // 注意32/64位差异
		}

		// 移动到下一个块
		pRelocationTable = (PIMAGE_BASE_RELOCATION)((PBYTE)pRelocationTable + pRelocationTable->SizeOfBlock);
	}

	// 更新基址
	pOptionalHeader->ImageBase = dwNewImageBase;
	return true;
}
BOOL RestoreIAT(LPVOID pImageBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pImageBuffer + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

	// 判断PE架构（32/64位）
	BOOL is64Bit = FALSE;
	IMAGE_OPTIONAL_HEADER* pOptionalHeader = &pNtHeaders->OptionalHeader;
	if (pOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		is64Bit = TRUE;
	}

	// 获取导入表目录
	DWORD importRVA = is64Bit
		? ((PIMAGE_OPTIONAL_HEADER64)pOptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
		: ((PIMAGE_OPTIONAL_HEADER32)pOptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD importSize = is64Bit
		? ((PIMAGE_OPTIONAL_HEADER64)pOptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size
		: ((PIMAGE_OPTIONAL_HEADER32)pOptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	if (importRVA == 0 || importSize == 0) return FALSE; // 无导入表

	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pImageBuffer + importRVA);

	// 遍历每个DLL
	while (pImport->Name != 0) {
		// 加载DLL
		LPCSTR dllName = (LPCSTR)((PBYTE)pImageBuffer + pImport->Name);
		HMODULE hModule = LoadLibraryA(dllName);
		if (!hModule) return FALSE;

		// 获取INT和IAT的指针
		UINT* pThunk = (UINT*)((PBYTE)pImageBuffer + pImport->OriginalFirstThunk);
		UINT* pIAT = (UINT*)((PBYTE)pImageBuffer + pImport->FirstThunk);

		// 遍历函数
		DWORD dwOldProtect;
		SIZE_T regionSize = 0;
		for (; *pThunk; ++pThunk, ++pIAT) {
			// 修改内存保护属性
			if (!VirtualProtect(pIAT, sizeof(UINT), PAGE_READWRITE, &dwOldProtect)) {
				FreeLibrary(hModule);
				return FALSE;
			}

			// 处理序号/名称导入
			if (is64Bit ? (*pThunk & IMAGE_ORDINAL_FLAG64) : (*pThunk & IMAGE_ORDINAL_FLAG32)) {
				// 按序号导入
				UINT ordinal = is64Bit
					? (*pThunk & 0xFFFF)
					: (*pThunk & 0x7FFFFFFF);
				FARPROC pFunc = GetProcAddress(hModule, (LPCSTR)ordinal);
				if (!pFunc) {
					VirtualProtect(pIAT, sizeof(UINT), dwOldProtect, &dwOldProtect);
					FreeLibrary(hModule);
					return FALSE;
				}
				*pIAT = (ULONGLONG)pFunc;
			}
			else {
				// 按名称导入
				PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pImageBuffer + *pThunk);
				FARPROC pFunc = GetProcAddress(hModule, pImportName->Name);
				if (!pFunc) {
					VirtualProtect(pIAT, sizeof(UINT), dwOldProtect, &dwOldProtect);
					FreeLibrary(hModule);
					return FALSE;
				}
				*pIAT = (UINT)pFunc;
			}

			// 恢复保护属性
			VirtualProtect(pIAT, sizeof(UINT), dwOldProtect, &dwOldProtect);
		}

		++pImport;
	}
	return TRUE;
}
std::string RelocatedTable(PVOID pFileBuffer)
{
	/*
	找到重定向表
	打印对应的结构
	*/
	std::string output;
	PIMAGE_DOS_HEADER dosHeader = GetDosHeader(pFileBuffer);
	PIMAGE_NT_HEADERS ntHeaders = GetNTHeader(pFileBuffer, dosHeader);
	PIMAGE_OPTIONAL_HEADER32 opHeader = (PIMAGE_OPTIONAL_HEADER32)&ntHeaders->OptionalHeader;
	// 重定向表的rva
	DWORD relocate_table_rva = opHeader->DataDirectory[5].VirtualAddress;
	if (relocate_table_rva == 0)
	{
		return output;
	}
	// 重定向表的foa
	DWORD relocate_table_foa = RVA2FOA(pFileBuffer, relocate_table_rva);
	// 重定向表的第一个指针
	PIMAGE_BASE_RELOCATION first_relocation_table = (PIMAGE_BASE_RELOCATION)((PBYTE)pFileBuffer + relocate_table_foa),
		cur_table = first_relocation_table;


	//循环所有的重定向块
	int i = 0;
	while (cur_table->SizeOfBlock != 0)
	{
		++i;
		DWORD base = cur_table->VirtualAddress, size = cur_table->SizeOfBlock;
		int item_count = (size - 8) / 2;
		output += std::format("第{}块，基址为0x{:X},块大小为{} bytes，子项数量为{}\n", i, base, size, item_count);
		PWORD pItem = (PWORD)((PBYTE)cur_table + 8);
		WORD first4 = 0xf000, last12 = 0x0fff;
		for (int j = 0; j < item_count; ++j)
		{
			WORD value = pItem[j];
			// 前4bit
			int type = (value & first4) >> 12;
			// 后12bit
			WORD rva_offset = value & last12;
			if (type != 0)
			{
				output += std::format("第{}项，类型是{}，rva是0x{:X}\n", j + 1, type, base + rva_offset);
			}
			else {
				output += std::format("第{}项，类型是{}, rva: N/A\n", j + 1, type);
			}
		}
		cur_table = (PIMAGE_BASE_RELOCATION)((PBYTE)cur_table + size);
	}
	free(pFileBuffer);
	return output;
}
std::string ExportTable(PVOID fileImage)
{
	/*
	找到导出表
	找到名字表
	打印所有名字
	*/
	std::string output;
	PIMAGE_DOS_HEADER dosHeader = GetDosHeader(fileImage);
	if (dosHeader == NULL)
	{
		output += std::format("dosHeader is invalid\n");
		return output;;
	}
	PIMAGE_NT_HEADERS ntHeaders = GetNTHeader(fileImage, dosHeader);
	PIMAGE_OPTIONAL_HEADER32 opHeader = (PIMAGE_OPTIONAL_HEADER32)&ntHeaders->OptionalHeader;
	// 导出表是第一张表
	IMAGE_DATA_DIRECTORY exportDataDict = opHeader->DataDirectory[0];
	// 导出表的RVA
	DWORD exportTable_rva = exportDataDict.VirtualAddress;
	if (exportTable_rva == 0)
	{
		return output;
	}
	// 导出表的FOA
	DWORD exportTable_foa = RVA2FOA(fileImage, exportTable_rva);
	// 导出表的指针
	PIMAGE_EXPORT_DIRECTORY pExporttable = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)fileImage + exportTable_foa);
	// 打印一些信息
	DWORD name_foa = RVA2FOA(fileImage, pExporttable->Name);
	const char* name = (const char*)((PBYTE)fileImage + name_foa);
	output += std::format("Name:{}\nBase:{}\nNumberOfFunctions:{}\nNumberOfNames:{}\n------------\n",
		name, pExporttable->Base, pExporttable->NumberOfFunctions, pExporttable->NumberOfNames);

	//导出表的函数名字表的RVA
	DWORD nameTable_rva = pExporttable->AddressOfNames;
	// 导出表的函数名字表的FOA
	DWORD nameTable_foa = RVA2FOA(fileImage, nameTable_rva);
	// 函数名字表的指针
	PDWORD pNameTable = (PDWORD)((PBYTE)fileImage + nameTable_foa);

	// ordinal表的rva
	DWORD ordinal_table_rva = pExporttable->AddressOfNameOrdinals;
	// ordinal表的foa
	DWORD ordinal_table_foa = RVA2FOA(fileImage, ordinal_table_rva);
	// ordinal表
	PWORD ordinal_table = (PWORD)((PBYTE)fileImage + ordinal_table_foa);
	// 打印ordinals表和names表
	output += std::format("functions' name and ordinals\n");
	for (DWORD i = 0; i < pExporttable->NumberOfNames; ++i)
	{
		// 函数名的rva
		DWORD funcName_rva = pNameTable[i];
		// 函数名字的foa
		DWORD funcName_foa = RVA2FOA(fileImage, funcName_rva);
		//打印函数名
		const char* funcName = (const char*)((PBYTE)fileImage + funcName_foa);
		output += std::format("ordinal为{}的函数名为{}, foa is {:X}\n",
			(ordinal_table[i]), funcName, funcName_foa);
	}
	DWORD func_table_rva = pExporttable->AddressOfFunctions;
	DWORD func_table_foa = RVA2FOA(fileImage, func_table_rva);
	PDWORD func_table = (PDWORD)((PBYTE)fileImage + func_table_foa);
	output += std::format("functions' address \n");
	for (DWORD i = 0; i < pExporttable->NumberOfFunctions; ++i)
	{
		output += std::format("下表为{}的函数的rva是{:X}\n", i, func_table[i]);
	}
	free(fileImage);
	return output;
}
std::string ImportTable(PVOID file_buffer)
{
	/*
	找到导入表
	找到各个dll
	打印各个成员
	*/
	// 导入表的rva
	std::string output;
	PIMAGE_DOS_HEADER dos_header = GetDosHeader(file_buffer);
	PIMAGE_NT_HEADERS nt_headers = GetNTHeader(file_buffer, dos_header);
	PIMAGE_OPTIONAL_HEADER32 op_headers = (PIMAGE_OPTIONAL_HEADER32)&nt_headers->OptionalHeader;

	DWORD import_table_rva = op_headers->DataDirectory[1].VirtualAddress;
	DWORD import_table_foa = RVA2FOA(file_buffer, import_table_rva);
	PIMAGE_IMPORT_DESCRIPTOR first_import_table = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)file_buffer + import_table_foa);
	PIMAGE_IMPORT_DESCRIPTOR cur_import_table = first_import_table;

	while (cur_import_table->Name != 0)
	{
		// 输出dll名字
		DWORD dll_name_rva = cur_import_table->Name;
		DWORD dll_name_foa = RVA2FOA(file_buffer, dll_name_rva);
		const char* dll_name = (PCSTR)((PBYTE)file_buffer + dll_name_foa);
		output += std::format("------ now dll name is {} -------\n", dll_name);
		// 没有绑定时的情况
		//遍历INT
		PDWORD cur_INT = (PDWORD)GetBufferAddr(file_buffer, cur_import_table->OriginalFirstThunk);
		constexpr DWORD first_1 = 1 << 31, last_31 = first_1 - 1;
		output += std::format("----INT 表如下----\n");
		while (*cur_INT != 0)
		{
			DWORD value = *cur_INT;
			if ((value & first_1) == first_1)
			{
				// 导出序号
				output += std::format("INT表中该函数序号为{:X}\n", value & last_31);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME import_name = (PIMAGE_IMPORT_BY_NAME)GetBufferAddr(file_buffer, value);
				PCSTR name = (PCSTR)import_name->Name;
				output += std::format("INT表中该函数名为hit/name:0x{:X}---{}\n", import_name->Hint, name);
			}
			cur_INT++;
		}
		// 遍历FirstThunkkk
		if (cur_import_table->TimeDateStamp == -1)
		{
			output += std::format("这是一个已经绑定的IAT表,跳过\n");
			continue;
		}
		output += std::format("----IAT 表如下----\n");
		PDWORD cur_IAT = (PDWORD)GetBufferAddr(file_buffer, cur_import_table->FirstThunk);
		while (*cur_IAT != 0)
		{
			DWORD value = *cur_IAT;
			if ((value & first_1) == first_1)
			{
				output += std::format("IAT表该函数序号为{:X}\n", value & last_31);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME import_name = (PIMAGE_IMPORT_BY_NAME)GetBufferAddr(file_buffer, value);
				PCSTR name = (PCSTR)import_name->Name;
				output += std::format("IAT表中该函数的名字为hit/name:0x{:X}---{}\n", import_name->Hint, name);
			}
			cur_IAT++;
		}
		cur_import_table++;
	}
	free(file_buffer);
	return output;
}
std::string BoundImportTable(PVOID file_buffer)
{
	std::string output;
	PIMAGE_DOS_HEADER dos_header = GetDosHeader(file_buffer);
	PIMAGE_NT_HEADERS nt_headers = GetNTHeader(file_buffer, dos_header);
	PIMAGE_OPTIONAL_HEADER32 op_header = (PIMAGE_OPTIONAL_HEADER32)&nt_headers->OptionalHeader;
	if (op_header->DataDirectory[11].VirtualAddress == 0)
	{
		output += std::format("该PE文件没有绑定导入表\n");
		return output;
	}
	PIMAGE_BOUND_IMPORT_DESCRIPTOR first_bound_import_desc = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)GetBufferAddr(file_buffer,
		op_header->DataDirectory[11].VirtualAddress);
	PIMAGE_BOUND_IMPORT_DESCRIPTOR cur_bound_import_desc = first_bound_import_desc;
	if (cur_bound_import_desc == NULL) return output;

	int index = 0;
	while (cur_bound_import_desc->OffsetModuleName != 0 && cur_bound_import_desc->TimeDateStamp != 0)
	{
		// 打印名字和时间戳
		index = 0;
		PCSTR dll_name = (PCSTR)((PBYTE)first_bound_import_desc + cur_bound_import_desc->OffsetModuleName);
		output += std::format("---该dll的时间戳为{:X}, 函数名为{}\n", cur_bound_import_desc->TimeDateStamp, dll_name);

		// 打印依赖的名字和时间戳
		if (cur_bound_import_desc->NumberOfModuleForwarderRefs > 0)
		{
			output += std::format("该dll的依赖dll有{}个，如下：\n", cur_bound_import_desc->NumberOfModuleForwarderRefs);
			for (int i = 0; i < cur_bound_import_desc->NumberOfModuleForwarderRefs; ++i)
			{
				++index;
				PIMAGE_BOUND_FORWARDER_REF bound_forwarder = (PIMAGE_BOUND_FORWARDER_REF)(cur_bound_import_desc + 1 + i);
				dll_name = (PCSTR)((PBYTE)first_bound_import_desc + bound_forwarder->OffsetModuleName);
				output += std::format("依赖{}---该dll的时间戳为{:X}, 函数名为{}\n", i + 1, bound_forwarder->TimeDateStamp, dll_name);
			}
		}
		else
		{
			output += std::format("该dll没有依赖的dll\n");
		}

		++index;
		// 移动到下一个绑定导入描述符
		cur_bound_import_desc += index;
	}
	free(file_buffer);
	return output;
}
std::string PrintResourceDirectory(PIMAGE_RESOURCE_DIRECTORY res_directory, void* file_buffer, int level, void* res_addr)
{
	std::string output;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY res_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)
		((PBYTE)res_directory + sizeof(IMAGE_RESOURCE_DIRECTORY));
	int count = res_directory->NumberOfIdEntries + res_directory->NumberOfNamedEntries;

	for (int i = 0; i < count; ++i)
	{
		PIMAGE_RESOURCE_DIRECTORY_ENTRY cur_entry = res_entry + i;
		for (int j = 0; j < level; ++j)output += std::format("   ");  // Indent based on level
		if (cur_entry->NameIsString)
		{
			// Handle named entries if necessary
			output += std::format("Name: {}\n", (PCHAR)(GetBufferAddr(file_buffer, cur_entry->Name)));
		}
		else
		{
			//cout << "ID: " << cur_entry->Name << endl;
			output += std::format("ID: {}\n", cur_entry->Name);
		}

		if (cur_entry->DataIsDirectory)
		{
			PIMAGE_RESOURCE_DIRECTORY sub_directory = (PIMAGE_RESOURCE_DIRECTORY)
				((PBYTE)res_addr + (cur_entry->OffsetToDirectory & 0x7FFFFFFF));
			output += PrintResourceDirectory(sub_directory, file_buffer, level + 1, res_addr);
		}
		else
		{
			PIMAGE_RESOURCE_DATA_ENTRY data_entry = (PIMAGE_RESOURCE_DATA_ENTRY)
				((PBYTE)res_addr + cur_entry->OffsetToData);
			for (int j = 0; j < level; ++j)output += std::format("   "); // Indent based on level
			output += std::format("RVA is 0x{:X}, size is 0x{:X}\n", data_entry->OffsetToData,
				data_entry->Size);
		}
	}
	return output;
}
std::string ResourceTable(PVOID file_buffer)
{
	/* 找到资源表首地址
	根据type找到第一层需要解析的项
	找到所有第二层的项并打印资源编号
	找到第三层所有的项并打印代码页
	根据第三层找到rva和size
	*/
	PIMAGE_DOS_HEADER dos_header = GetDosHeader(file_buffer);
	PIMAGE_NT_HEADERS nt_headers = GetNTHeader(file_buffer, dos_header);
	PIMAGE_OPTIONAL_HEADER32 op_header = (PIMAGE_OPTIONAL_HEADER32)&nt_headers->OptionalHeader;
	// 第一层
	PIMAGE_RESOURCE_DIRECTORY res_directory = (PIMAGE_RESOURCE_DIRECTORY)GetBufferAddr(file_buffer,
		op_header->DataDirectory[2].VirtualAddress);
	// 如果type是-1，打印所有的类型
	std::string ans = PrintResourceDirectory(res_directory, file_buffer, 0, res_directory);
	return ans;
}

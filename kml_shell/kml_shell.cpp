#include <string>
#include <tchar.h>
#include <windows.h>
#include "kml_shell.h"
#include <print>
#include <winternl.h>

using namespace std;

int main()
{
	// 读取自己的filebuffer
	// 得到当前的路径
	TCHAR path[MAX_PATH] = { 0 };
	if (GetModuleFileName(NULL, path, MAX_PATH) == 0)
	{
		println("读取当前path失败，");
		return -1;
	}
	void* file_buffer;
	ReadFileBuffer(path, &file_buffer);

	// 读取src的数据，储存在最后一个节里
	PIMAGE_DOS_HEADER dos_header = GetDosHeader(file_buffer);
	PIMAGE_NT_HEADERS nt_headers = GetNTHeader(file_buffer, dos_header);
	PIMAGE_FILE_HEADER file_header = &nt_headers->FileHeader;
	PIMAGE_OPTIONAL_HEADER op_header = &nt_headers->OptionalHeader;
	int section_count = file_header->NumberOfSections;
	PIMAGE_SECTION_HEADER last_section = IMAGE_FIRST_SECTION(nt_headers) + (section_count - 1);

	// 读取出来保存到另一块区域
	void* src_file_buffer = malloc(last_section->SizeOfRawData);
	memcpy(src_file_buffer, ((PBYTE)file_buffer + last_section->PointerToRawData), last_section->SizeOfRawData);

	// 以挂起方式创建该shell进程
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi;
	si.cb = sizeof(si);
	if (!CreateProcess(NULL, path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		println("CreateProcess failed, error: {}", GetLastError());
		return -1;
	}
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(pi.hThread, &context))
	{
		println("GetThreadContext failed, error: {}", GetLastError());
		return -1;
	}

	// 卸载创建出进程的壳，也就是取消映射,需要手动从动态库中找到该函数
	HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));
	if (ntdll == NULL)
	{
		println("LoadLibrary ntdll failed");
		return -1;
	}
	using NtUnmapViewOfSectionfn = ULONG(WINAPI*)(HANDLE ProcessHandle, PVOID BaseAddress);
	NtUnmapViewOfSectionfn fn = (NtUnmapViewOfSectionfn)GetProcAddress(ntdll, "NtUnmapViewOfSection");
	if (fn == NULL)
	{
		println("GetProcAddress NtUnmapViewOfSection failed");
		return -1;
	}
	DWORD dwVictimBaseAddr{ 0 };
	if (ReadProcessMemory(pi.hProcess, (LPCVOID)(context.Ebx + 8),
		&dwVictimBaseAddr, sizeof(PVOID), NULL) == 0)
	{
		println("ReadProcessMemory  failed");
		return -1;
	}
	ULONG status = fn(pi.hProcess, (PVOID)dwVictimBaseAddr);
	println("Unmap status: {}", status);

	// 在shell的src位置分配足够的空间
	DWORD src_sizeOfImage, src_imageBase, src_eop;
	BOOL ans = GetPEInfoFromFile(src_file_buffer, &src_imageBase, &src_sizeOfImage, &src_eop);
	if (!ans)
	{
		println("GetPEInfoFromFile failed");
		return -1;
	}
	std::println("imagebase is 0x{:X}, sizeofimage is 0x{:X}, eop is 0x{:X}", src_imageBase, src_sizeOfImage,
		src_eop);
	PVOID allocBase = VirtualAllocEx(pi.hProcess, (PVOID)src_imageBase, src_sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (allocBase == NULL)
	{
		println("VirtualAllocEx failed, error: {}", GetLastError());
		return -1;
	}

	// 拷贝拉伸后的src
	void* src_memory_buffer = FileBuffer2MemoryBuffer(src_file_buffer);
	if (src_memory_buffer == NULL)
	{
		println("FileBuffer2MemoryBuffer failed");
		return -1;
	}
	if (!WriteProcessMemory(pi.hProcess, (PVOID)src_imageBase, src_memory_buffer, src_sizeOfImage, NULL))
	{
		println("WriteProcessMemory failed, error: {}", GetLastError());
		return -1;
	}

	// 修改context
	// 替换PEB中的基地址

	DWORD dwImageBase = op_header->ImageBase;
	BOOL bRet = WriteProcessMemory(pi.hProcess, (PVOID)(context.Ebx + 8),
		(LPCVOID)&dwImageBase, sizeof(PVOID), NULL);
	if (!bRet)
	{
		return -1;
	}

	// 设置入口点
	context.Eax = dwImageBase + op_header->AddressOfEntryPoint;

	// 设置回context
	if (!SetThreadContext(pi.hThread, &context))
	{
		println("SetThreadContext failed, error: {}", GetLastError());
		return -1;
	}

	// 恢复线程
	if (ResumeThread(pi.hThread) == -1)
	{
		println("ResumeThread failed, error: {}", GetLastError());
		return -1;
	}

	println("Process resumed successfully");
	return 0;
}


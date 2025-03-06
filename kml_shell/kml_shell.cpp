#include <string>
#include <tchar.h>
#include <windows.h>
#include "kml_shell.h"
#include <print>
#include <winternl.h>

using namespace std;

int main()
{
	//--------------------------------------解密过程--------------------------------------
	//获取当前程序运行路径
	char FilePathSelf[255] = { 0 };
	GetModuleFileName(NULL, FilePathSelf, 255);

	// 1、读取当前壳子程序本身 数据
	PVOID file_buffer_shell;
	DWORD size_shell = ReadFileBuffer(FilePathSelf, &file_buffer_shell);
	PIMAGE_DOS_HEADER dos_header_shell = GetDosHeader(file_buffer_shell);
	if (dos_header_shell == NULL)
	{
		std::println("dos_header_shell failed");
		return -1;
	}
	PIMAGE_NT_HEADERS nt_header_shell = GetNTHeader(file_buffer_shell, dos_header_shell);
	if (nt_header_shell == NULL)
	{
		std::println("nt_header_shell failed");
		return -1;
	}
	PIMAGE_OPTIONAL_HEADER optional_header_shell = &nt_header_shell->OptionalHeader;
	PIMAGE_SECTION_HEADER last_section_shell = IMAGE_FIRST_SECTION(nt_header_shell) +
		(nt_header_shell->FileHeader.NumberOfSections - 1);
	DWORD dwImageBase_shell = optional_header_shell->ImageBase;

	// 2、解密源文件,获取源文件的imagebase sizeofimage数据
	DWORD dwImageBase_src, dwSizeOfImage_src, dwEOP_src;
	PVOID file_buffer_src = (PVOID)((PBYTE)file_buffer_shell + last_section_shell->PointerToRawData);
	BOOL bRet = GetPEInfoFromFile(file_buffer_src, &dwImageBase_src, &dwSizeOfImage_src, &dwEOP_src);

	// 3、拉伸PE  
	PVOID pImageBufferSrc = FileBuffer2MemoryBuffer(file_buffer_src);
	if (pImageBufferSrc == NULL)
	{
		std::println("file2memory failed");
		return -1;
	}

	// 4、以挂起方式运行壳程序进程
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };
	::CreateProcess(FilePathSelf, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	std::println("create process error is {}", GetLastError());


	//5、卸载外壳程序的文件镜像
	using NtUnmapViewOfSectionFn = LONG(WINAPI*)(HANDLE, PVOID);
	HMODULE hNtModule = LoadLibrary("ntdll.dll");
	NtUnmapViewOfSectionFn NtUnmapViewOfSection = (NtUnmapViewOfSectionFn)GetProcAddress(hNtModule, "NtUnmapViewOfSection");
	if (NtUnmapViewOfSection == NULL)
	{
		std::println("get NtUnmapViewOfSectionFn failed");
		return -1;
	}
	CONTEXT cont;
	cont.ContextFlags = CONTEXT_FULL;
	::GetThreadContext(pi.hThread, &cont);
	DWORD dwProcessBaseAddr = 0;
	int ret = ReadProcessMemory(pi.hProcess, (LPVOID)(cont.Ebx + 8),
		&dwProcessBaseAddr, sizeof(PVOID), NULL);
	if (ret == 0)
	{
		std::println("read failed,{}", GetLastError());
		return -1;
	}
	if (NtUnmapViewOfSection(pi.hProcess, (PVOID)dwProcessBaseAddr) != 0)
	{
		std::println("NtUnmapViewOfSectionFn failed, {}", GetLastError());
		//return -1;
	}
	//using pfnZwUnmapViewOfSection = unsigned long(__stdcall*)(unsigned long, unsigned long);
	//pfnZwUnmapViewOfSection zw = (pfnZwUnmapViewOfSection)GetProcAddress(hNtModule, "ZwUnmapViewOfSection");
	//if (zw((unsigned long)pi.hProcess, dwImageBase_shell) != 0)
	//{
	//	std::println("zwunmapviewofsection failed, {}", GetLastError());
	//	return -1;
	//}
	//6、在指定的位置(src的ImageBase)申请指定大小(src的SizeOfImage)的内存(VirtualAllocEx)
	LPVOID status = VirtualAllocEx(pi.hProcess, (PVOID)dwImageBase_src, dwSizeOfImage_src,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (status == NULL)
	{
		std::println("alloc fail, {}", GetLastError());
		std::println("imagebase is 0x{:X}, sizeofimage is 0x{:X}",
			dwImageBase_src, dwSizeOfImage_src);
		return -1;
	}
	//7、如果成功，将Src的PE文件拉伸 复制到该空间中
	bRet = ::WriteProcessMemory(pi.hProcess, (PVOID)dwImageBase_src, pImageBufferSrc, dwSizeOfImage_src, NULL);
	if (!bRet)
	{
		std::println("WriteProcessMemory fail");
		return -1;
	}
	//8、如果申请空间失败，但有重定位表：在任意位置申请空间，然后将PE文件拉伸、复制、修复重定位表。
	//	// 9、如果第6步申请空间失败，并且还没有重定位表，直接返回：失败.

	// 10、修改外壳程序的Context:
	std::println("10");
	// 设置imagebase
	DWORD theOep = cont.Eax + 8;
	::WriteProcessMemory(pi.hProcess, &theOep, &dwImageBase_src, 4, NULL);
	// 设置eop
	cont.Eax = dwImageBase_src + dwEOP_src;
	::SetThreadContext(pi.hThread, &cont);
	//恢复线程
	::ResumeThread(pi.hThread);
	std::println("resume success");
	::ExitProcess(0);
	return 0;
}


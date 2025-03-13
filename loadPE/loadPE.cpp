// loadPE.cpp : 定义应用程序的入口点。
//

#include "framework.h"
#include "loadPE.h"

#include <stdio.h>
#include <commctrl.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <commdlg.h>
#include <string>
#include <format>
#include <print>
#include <psapi.h> // 需要链接 Psapi.lib
#include "PETools.h"
// 全局变量:
HINSTANCE hInst;                                // 当前实例
TCHAR filePath[MAX_PATH];						// 选中的文件名
DWORD directoryType[16] = {
IDC_EDIT_EXPORT,
 IDC_EDIT_IMPORT                 ,
 IDC_EDIT_RESOURCE        ,
 IDC_EDIT_EXCEPTION     ,
 IDC_EDIT_SECURITY     ,
 IDC_EDIT_RELOCATION  ,
 IDC_EDIT_DEBUG       ,
 IDC_EDIT_ARCH        ,
 IDC_EDIT_RVAOFGP     ,
 IDC_EDIT_TLS         ,
 IDC_EDIT_LOADCONFIG  ,
 IDC_EDIT_BOUNDIMPORT ,
 IDC_EDIT_IAT         ,
 IDC_EDIT_DELAYIMPORT ,
 IDC_EDIT_COM         ,
 IDC_EDIT_REVERSE
};
DWORD directoryType2[16] = {
IDC_EDIT_EXPORT2,
 IDC_EDIT_IMPORT2                 ,
 IDC_EDIT_RESOURCE2        ,
 IDC_EDIT_EXCEPTION2     ,
 IDC_EDIT_SECURITY2     ,
 IDC_EDIT_RELOCATION2  ,
 IDC_EDIT_DEBUG2       ,
 IDC_EDIT_ARCH2        ,
 IDC_EDIT_RVAOFGP2     ,
 IDC_EDIT_TLS2         ,
 IDC_EDIT_LOADCONFIG2  ,
 IDC_EDIT_BOUNDIMPORT2 ,
 IDC_EDIT_IAT2         ,
 IDC_EDIT_DELAYIMPORT2 ,
 IDC_EDIT_COM2         ,
 IDC_EDIT_REVERSE2
};

#ifdef _DEBUG  
#define DbgPrintfA   OutputDebugStringF  
#define DbgPrintfW   OutputDebugStringFW
#else  
#define DbgPrintfA
#define DbgPrintfW
#endif 

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	hInst = hInstance;
	DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProcMain);
	return 0;
}

INT_PTR CALLBACK DialogProcMain(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	HICON  hSmallIcon;
	switch (Msg)
	{
	case WM_INITDIALOG:
	{
		//MessageBox(NULL, TEXT("WM_INITDIALOG"), TEXT("INIT"), MB_OK);
		// 获取图标
		hSmallIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_ICON_SMALL));
		// 设置图标
		SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (DWORD)hSmallIcon);
		InitProcessListView(hwndDlg);
		InitModulesListView(hwndDlg);
		return TRUE;
	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	case WM_NOTIFY:
	{
		NMHDR* pNMHDR = (NMHDR*)lParam;
		if (wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_CLICK)
		{
			EnumModules(GetDlgItem(hwndDlg, IDC_LIST_PROCESS),
				GetDlgItem(hwndDlg, IDC_LIST_MOUDLE));
		}
		break;
	}
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case   IDC_BUTTON_ABOUT:
		{
			return TRUE;
		}
		case   IDC_BUTTON_OPEN:
		{
			DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG_PE), hwndDlg, DialogProcPE);
			return TRUE;
		}
		case   IDC_BUTTON_QUIT:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		case IDC_BUTTON_INJECT:
		{
			DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG_INJECT), hwndDlg, DialogProcInject);
			return TRUE;
		}
		case IDC_BUTTON_ADDSHELL:
		{
			TCHAR srcPath[MAX_PATH], shellPath[MAX_PATH];
			if (!OpenFileDialog(hwndDlg, srcPath, MAX_PATH)) {
				MessageBox(hwndDlg, TEXT("open failed"), TEXT("Select File"), MB_OK);
				return true;
			}
			if (!OpenFileDialog(hwndDlg, shellPath, MAX_PATH)) {
				MessageBox(hwndDlg, TEXT("open failed"), TEXT("Select File"), MB_OK);
				return true;
			}
			AddShell(srcPath, shellPath);
			return TRUE;
		}
		}
		break;
	}
	}
	return FALSE;
}

INT_PTR CALLBACK DialogProcPE(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
	case WM_INITDIALOG:
	{
		if (!OpenFileDialog(hwndDlg, filePath, MAX_PATH))
		{
			MessageBox(hwndDlg, TEXT("open failed"), TEXT("Select File"), MB_OK);
			return true;
		}
		InitPEView(hwndDlg);
		return TRUE;
	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case   IDC_BUTTON_QUIT:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		case IDC_BUTTON_SECTION:
		{
			DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG_SECTION), hwndDlg, DialogProcSection);
			return TRUE;
		}
		case IDC_BUTTON_DIRECTORY:
		{
			DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG_DIRECTORY), hwndDlg, DialogProcDirectory);
			return TRUE;
		}
		}
		break;
	}
	}
	return FALSE;
}

INT_PTR CALLBACK DialogProcSection(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
	case WM_INITDIALOG:
	{
		InitSectionView(hwndDlg);
		PopulateSectionView(hwndDlg);
		return TRUE;
	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	}
	return FALSE;
}

INT_PTR CALLBACK DialogProcDirectory(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
	case WM_INITDIALOG:
	{
		InitDirectoryView(hwndDlg);
		return TRUE;
	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_EXPORT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG_DETAILS), hwndDlg, DialogProcExport);
			return TRUE;
		case IDC_BUTTON_IMPORT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG_DETAILS), hwndDlg, DialogProcImport);
			return TRUE;
		case IDC_BUTTON_RESOURCE:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG_DETAILS), hwndDlg, DialogProcResource);
			return TRUE;
		case IDC_BUTTON_RELOCATION:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG_DETAILS), hwndDlg, DialogProcRelocation);
			return TRUE;
		case IDC_BUTTON_BOUND_IMPORT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG_DETAILS), hwndDlg, DialogProcBoundImport);
			return TRUE;
		}
		break;
	}
	}
	return FALSE;
}

void InitProcessListView(HWND hDlg)
{
	LV_COLUMN lv;
	HWND hListProcess;

	// 初始化
	memset(&lv, 0, sizeof(LV_COLUMN));
	//获取process句柄
	hListProcess = GetDlgItem(hDlg, IDC_LIST_PROCESS);
	if (hListProcess == NULL) {
		MessageBox(hDlg, TEXT("Failed to get ListView handle"), TEXT("Error"), MB_OK);
		return;
	}
	// 设置整行选中
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE,
		LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	// 第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = (LPWSTR)TEXT("进程"); // 列标题
	lv.cx = 200;
	lv.iSubItem = 0;
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	ListView_InsertColumn(hListProcess, 0, &lv);
	// 第二列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = (LPWSTR)TEXT("PID"); // 列标题
	lv.cx = 200;
	lv.iSubItem = 1;
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
	ListView_InsertColumn(hListProcess, 1, &lv);

	// 第三列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = (LPWSTR)TEXT("镜像基址"); // 列标题
	lv.cx = 200;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListProcess, 2, &lv);
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	// 第四列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = (LPWSTR)TEXT("镜像大小"); // 列标题
	lv.cx = 200;
	lv.iSubItem = 3;
	ListView_InsertColumn(hListProcess, 3, &lv);
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 3, (DWORD)&lv);
	EnumProcess(hListProcess);
}
BOOL IsProcess64Bit(DWORD pid) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	BOOL isWow64 = FALSE;
	if (hProcess) {
		IsWow64Process(hProcess, &isWow64);
		CloseHandle(hProcess);
		// 若进程是 64 位，isWow64 为 FALSE（因为 64 位进程不会运行在 WOW64 下）
		return !isWow64;
	}
	return FALSE;
}

// 定义未公开的 NtQueryInformationProcess 函数
using PNtQueryInformationProcess = LONG(*)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

// 获取进程模块信息（支持跨架构）
BOOL GetProcessModules(DWORD pid, HWND hListModules) {
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE, pid
	);
	if (!hProcess) return FALSE;

	HMODULE hMods[1024];
	DWORD cbNeeded;
	if (EnumProcessModulesEx(
		hProcess,
		hMods,
		sizeof(hMods),
		&cbNeeded,
		LIST_MODULES_ALL
	)) {
		for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			LV_ITEM lvItem;
			TCHAR szModName[MAX_PATH];
			GetModuleFileNameEx(hProcess, hMods[i], szModName, MAX_PATH);
			lvItem.iItem = ListView_GetItemCount(hListModules);
			lvItem.iSubItem = 0;
			lvItem.pszText = szModName;
			ListView_InsertItem(hListModules, &lvItem);

			lvItem.mask = LVIF_TEXT;
			lvItem.iSubItem = 1;
			TCHAR szBaseAddr[0x20];
			_stprintf_s(szBaseAddr, 0x20, TEXT("0x%016lX"), (DWORD_PTR)hMods[i]);
			lvItem.pszText = szBaseAddr;
			ListView_SetItem(hListModules, &lvItem);
		}
	}
	CloseHandle(hProcess);
	return TRUE;
}
void EnumProcess(HWND hListProcess)
{
	LV_ITEM lvitem;
	HANDLE hProcessSnap;
	HANDLE hModuleSnap;
	PROCESSENTRY32 pe32;
	MODULEENTRY32 me32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		MessageBox(hListProcess, TEXT("CreateToolhelp32Snapshot failed."), TEXT("ERROR"), MB_OK);
		return;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return;
	}
	int n = 0;
	do {
		// 创建模块快照
		++n;
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe32.th32ProcessID);
		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			DbgPrintfA(" creatnap first failed :%d, error %d", n, GetLastError());
		}
		me32.dwSize = sizeof(MODULEENTRY32);
		if (!Module32First(hModuleSnap, &me32)) {
			DbgPrintfA(" Module first failed :%d", n);
			CloseHandle(hModuleSnap);
		}
		// 进程名
		lvitem.mask = LVIF_TEXT;
		lvitem.iItem = ListView_GetItemCount(hListProcess);
		lvitem.iSubItem = 0;
		lvitem.pszText = pe32.szExeFile;
		ListView_InsertItem(hListProcess, &lvitem);
		// pid
		lvitem.iSubItem = 1;
		TCHAR szPID[0x32];
		_stprintf_s(szPID, 0x32, TEXT("%u"), pe32.th32ProcessID);
		lvitem.pszText = szPID;
		ListView_SetItem(hListProcess, &lvitem);
		// imagebase
		lvitem.iSubItem = 2;
		TCHAR szBaseAddr[0x32];
		_stprintf_s(szBaseAddr, 0x32, TEXT("0x%08X"), (DWORD)me32.modBaseAddr);
		lvitem.pszText = szBaseAddr;
		ListView_SetItem(hListProcess, &lvitem);

		// imagesize
		lvitem.iSubItem = 3;
		TCHAR szBaseSize[0x32];
		_stprintf_s(szBaseSize, 0x32, TEXT("%u"), me32.modBaseSize);
		lvitem.pszText = szBaseSize;
		ListView_SetItem(hListProcess, &lvitem);
		// 关闭模块快照
		CloseHandle(hModuleSnap);
	} while (Process32Next(hProcessSnap, &pe32));
	DbgPrintfA("module number :%d", n);
	CloseHandle(hProcessSnap);
}

void InitModulesListView(HWND hDlg)
{
	LV_COLUMN lv = { 0 };
	HWND hListModules = GetDlgItem(hDlg, IDC_LIST_MOUDLE);

	// 设置整行选中
	SendMessage(hListModules, LVM_SETEXTENDEDLISTVIEWSTYLE,
		LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	// 第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = (LPWSTR)TEXT("模块名称");
	lv.cx = 400;
	lv.iSubItem = 0;
	ListView_InsertColumn(hListModules, 0, &lv);

	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = (LPWSTR)TEXT("模块位置");
	lv.cx = 400;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListModules, 1, &lv);
}

void EnumModules(HWND hListProcess, HWND hListModules)
{
	// 获取选择的行下标
	//DWORD dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	DWORD dwRowId = ListView_GetNextItem(hListProcess, -1, LVNI_SELECTED);
	if (dwRowId == -1)
	{
		MessageBox(NULL, TEXT("请选择进程"), TEXT("出错了"), MB_OK);
		return;
	}
	// 获取选择的行的信息
	LV_ITEM item = { 0 };
	TCHAR szPid[0x20] = { 0 };
	item.iSubItem = 1;
	item.pszText = szPid;
	item.cchTextMax = 0x20;
	// 拿到了PId
	ListView_GetItemText(hListProcess, dwRowId, 1, szPid, 0x20);

	DWORD dwPid = _ttoi(szPid);
	// 清空原来的信息
	ListView_DeleteAllItems(hListModules);
	// 列出所有的模块
	//ListProcessModules(dwPid, hListModules);
	GetProcessModules(dwPid, hListModules);
}

void ListProcessModules(DWORD dwPid, HWND hListModules)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	// 模块快照
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPid);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, TEXT("创建模块快照失败"), TEXT("Error"), MB_OK);
		return;
	}
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))
	{
		MessageBox(NULL, TEXT("获取快照模块信息失败"), TEXT("Error"), MB_OK);
		CloseHandle(hModuleSnap);
		return;
	}
	// 遍历模块
	do {
		LV_ITEM lvItem;
		lvItem.mask = LVIF_TEXT;
		lvItem.iItem = ListView_GetItemCount(hListModules);
		lvItem.iSubItem = 0;
		lvItem.pszText = me32.szModule;
		ListView_InsertItem(hListModules, &lvItem);

		lvItem.iSubItem = 1;
		TCHAR szBaseAddr[0x20];
		_stprintf_s(szBaseAddr, 0x20, TEXT("0x%016lX"), (DWORD_PTR)me32.modBaseAddr);
		lvItem.pszText = szBaseAddr;
		ListView_SetItem(hListModules, &lvItem);

	} while (Module32Next(hModuleSnap, &me32));
	CloseHandle(hModuleSnap);
}

BOOL OpenFileDialog(HWND hwnd, LPTSTR filePath, DWORD filePathSize)
{
	OPENFILENAME ofn;
	TCHAR szFile[MAX_PATH] = { 0 };
	// 初始化ofn
	const TCHAR szFilter[] =
		TEXT("Executable Files (*.exe, *.dll, *.scr, *.drv, *.sys)\0")
		TEXT("*.exe;*.dll;*.scr;*.drv;*.sys\0")
		TEXT("All Files (*.*)\0*.*\0\0"); // 末尾两个空字符
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = szFilter;
	ofn.nFilterIndex = 1;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;

	if (GetOpenFileName(&ofn) == TRUE)
	{
		_tcsncpy_s(filePath, filePathSize, ofn.lpstrFile, _TRUNCATE);
		return TRUE;
	}
	return FALSE;
}

void InitPEView(HWND hDlg)
{
	/*
	根据名字得到PE头文件
	为EditControl赋值
	*/
	void* file_buffer;
	DWORD size = ReadFileBuffer(filePath, &file_buffer);
	// doc头
	PIMAGE_DOS_HEADER dos_header = GetDosHeader(file_buffer);
	PIMAGE_NT_HEADERS32 nt_headers = (PIMAGE_NT_HEADERS32)GetNTHeader(file_buffer, dos_header);
	PIMAGE_FILE_HEADER file_header = &nt_headers->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 op_header = (PIMAGE_OPTIONAL_HEADER32)&nt_headers->OptionalHeader;
	if (op_header->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		MessageBox(hDlg, TEXT("不支持64位架构PE"), NULL, MB_OK);
		return;
	}
	// 入口点
	DWORD eop = op_header->AddressOfEntryPoint;
	DbgPrintfA("rva: %X, foa: %X", eop, RVA2FOA(file_buffer, eop));
	TCHAR szBuffer[0x20];
	size_t len = 0x20;
	_stprintf_s(szBuffer, len, L"%04X", eop);
	SetDlgItemText(hDlg, IDC_EDIT_ENTRY_POINT, szBuffer);
	// 镜像基址
	DWORD image_base = op_header->ImageBase;
	_stprintf_s(szBuffer, len, L"%08X", image_base);
	SetDlgItemText(hDlg, IDC_EDIT_IMAGEBASE, szBuffer);
	// 镜像大小
	DWORD image_size = op_header->SizeOfImage;
	_stprintf_s(szBuffer, len, L"%08X", image_size);
	SetDlgItemText(hDlg, IDC_EDIT_IMAGESIZE, szBuffer);
	// 代码基址
	DWORD code_base = op_header->BaseOfCode;
	_stprintf_s(szBuffer, len, L"%08X", code_base);
	SetDlgItemText(hDlg, IDC_EDIT_CODEBASE, szBuffer);
	// 数据基址
	DWORD data_base = op_header->BaseOfCode;
	_stprintf_s(szBuffer, len, L"%08X", data_base);
	SetDlgItemText(hDlg, IDC_EDIT_DATABASE, szBuffer);
	// 内存对齐
	DWORD section_alignment = op_header->SectionAlignment;
	_stprintf_s(szBuffer, len, L"%08X", section_alignment);
	SetDlgItemText(hDlg, IDC_EDIT_SECTIONALIGNMENT, szBuffer);
	// 文件对齐
	DWORD file_alignment = op_header->FileAlignment;
	_stprintf_s(szBuffer, len, L"%08X", file_alignment);
	SetDlgItemText(hDlg, IDC_EDIT_FILEALIGNMENT, szBuffer);
	// 属性值
	DWORD character = file_header->Characteristics;
	_stprintf_s(szBuffer, len, L"%08X", character);
	SetDlgItemText(hDlg, IDC_EDIT_CHARA, szBuffer);
	// 子系统
	DWORD sub_system = op_header->Subsystem;
	_stprintf_s(szBuffer, len, L"%08X", sub_system);
	SetDlgItemText(hDlg, IDC_EDIT_SUBSYSTEM, szBuffer);
	// 节数
	DWORD section_number = file_header->NumberOfSections;
	_stprintf_s(szBuffer, len, L"%08X", section_number);
	SetDlgItemText(hDlg, IDC_EDIT_SECTIONNUMBER, szBuffer);
	// 时间戳
	DWORD time_stamp = file_header->TimeDateStamp;
	_stprintf_s(szBuffer, len, L"%08X", time_stamp);
	SetDlgItemText(hDlg, IDC_EDIT_TIMESTAMP, szBuffer);
	// 头大小
	DWORD header_size = op_header->SizeOfHeaders;
	_stprintf_s(szBuffer, len, L"%08X", header_size);
	SetDlgItemText(hDlg, IDC_EDIT_PEHEADERSIZE, szBuffer);
	// 特征值
	DWORD thevalue = file_header->Machine;
	_stprintf_s(szBuffer, len, L"%08X", thevalue);
	SetDlgItemText(hDlg, IDC_EDIT_THEVALUE, szBuffer);
	// 校验和
	DWORD check_sum = op_header->CheckSum;
	_stprintf_s(szBuffer, len, L"%08X", check_sum);
	SetDlgItemText(hDlg, IDC_EDIT_CHECKSUM, szBuffer);
	// 可选PE头数量
	DWORD opheaders_count = file_header->SizeOfOptionalHeader;
	_stprintf_s(szBuffer, len, L"%08X", opheaders_count);
	SetDlgItemText(hDlg, IDC_EDIT_OPHEADER, szBuffer);
	// 目录项数目
	DWORD directory_count = op_header->NumberOfRvaAndSizes;
	_stprintf_s(szBuffer, len, L"%08X", directory_count);
	SetDlgItemText(hDlg, IDC_EDIT_DIRECTORYSIZE, szBuffer);
	free(file_buffer);
}

void InitSectionView(HWND hDlg)
{

	/*// 设置整行选中
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE,
		LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	// 第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = (LPWSTR)TEXT("进程"); // 列标题
	lv.cx = 200;
	lv.iSubItem = 0;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	*/
	LV_COLUMN lv = { 0 };
	HWND hListSection = GetDlgItem(hDlg, IDC_LIST_SECTION);
	// 整行选中
	ListView_SetExtendedListViewStyle(hListSection, LVS_EX_FULLROWSELECT);
	// 初始化列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	int ColIndex = 0;
	// 第一列
	lv.pszText = (LPWSTR)TEXT("节名");
	lv.cx = 50;
	lv.iSubItem = ColIndex;
	ListView_InsertColumn(hListSection, ColIndex, &lv);
	++ColIndex;

	lv.pszText = (LPWSTR)TEXT("文件偏移");
	lv.cx = 90;
	lv.iSubItem = ColIndex;
	ListView_InsertColumn(hListSection, ColIndex, &lv);
	++ColIndex;

	lv.pszText = (LPWSTR)TEXT("文件大小");
	lv.cx = 90;
	lv.iSubItem = ColIndex;
	ListView_InsertColumn(hListSection, ColIndex, &lv);
	++ColIndex;

	lv.pszText = (LPWSTR)TEXT("内存偏移");
	lv.cx = 100;
	lv.iSubItem = ColIndex;
	ListView_InsertColumn(hListSection, ColIndex, &lv);
	++ColIndex;

	lv.pszText = (LPWSTR)TEXT("内存大小");
	lv.cx = 100;
	lv.iSubItem = ColIndex;
	ListView_InsertColumn(hListSection, ColIndex, &lv);
	++ColIndex;

	lv.pszText = (LPWSTR)TEXT("节区属性");
	lv.cx = 100;
	lv.iSubItem = ColIndex;
	ListView_InsertColumn(hListSection, ColIndex, &lv);
	++ColIndex;

}

void PopulateSectionView(HWND hDlg)
{
	HWND hListSection = GetDlgItem(hDlg, IDC_LIST_SECTION);
	void* file_buffer;
	DWORD size = ReadFileBuffer(filePath, &file_buffer);
	if (file_buffer == NULL) {
		return;
	}
	PIMAGE_DOS_HEADER dos_header = GetDosHeader(file_buffer);
	PIMAGE_NT_HEADERS nt_headers = GetNTHeader(file_buffer, dos_header);
	PIMAGE_OPTIONAL_HEADER32 opt_header = (PIMAGE_OPTIONAL_HEADER32)&nt_headers->OptionalHeader;
	if (opt_header->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		MessageBox(hDlg, TEXT("不支持非32位的架构"), NULL, MB_OK);
		return;
	}

	PIMAGE_SECTION_HEADER first_section_header = IMAGE_FIRST_SECTION(nt_headers);
	DWORD sectionCount = nt_headers->FileHeader.NumberOfSections;
	TCHAR szBuffer[0x20];
	for (DWORD i = 0; i < sectionCount; ++i)
	{
		LV_ITEM lvItem;
		lvItem.mask = LVIF_TEXT;
		lvItem.iItem = i;
		// 名字
		lvItem.iSubItem = 0;
		char sectionName[9] = { 0 };
		strncpy_s(sectionName, (char*)first_section_header[i].Name, 8);
		//sectionName[8] = 0;
		_stprintf_s(szBuffer, 0x9, TEXT("%hs"), sectionName);
		lvItem.pszText = szBuffer;
		ListView_InsertItem(hListSection, &lvItem);
		// 文件偏移
		lvItem.iSubItem = 1;
		_stprintf_s(szBuffer, 0x20, TEXT("0x%08X"), first_section_header[i].PointerToRawData);
		lvItem.pszText = szBuffer;
		ListView_SetItem(hListSection, &lvItem);

		// 文件大小
		lvItem.iSubItem = 2;
		_stprintf_s(szBuffer, 0x20, TEXT("0x%08X"), first_section_header[i].SizeOfRawData);
		lvItem.pszText = szBuffer;
		ListView_SetItem(hListSection, &lvItem);
		// 内存偏移
		lvItem.iSubItem = 3;
		_stprintf_s(szBuffer, 0x20, TEXT("0x%08X"), first_section_header[i].VirtualAddress);
		lvItem.pszText = szBuffer;
		ListView_SetItem(hListSection, &lvItem);
		// 内存大小
		lvItem.iSubItem = 4;
		_stprintf_s(szBuffer, 0x20, TEXT("0x%08X"), first_section_header[i].Misc.VirtualSize);
		lvItem.pszText = szBuffer;
		ListView_SetItem(hListSection, &lvItem);
		// 节区属性
		lvItem.iSubItem = 5;
		_stprintf_s(szBuffer, 0x20, TEXT("0x%08X"), first_section_header[i].Characteristics);
		lvItem.pszText = szBuffer;
		ListView_SetItem(hListSection, &lvItem);
	}
	free(file_buffer);
}

void InitDirectoryView(HWND hDlg)
{
	void* file_buffer;
	DWORD size = ReadFileBuffer(filePath, &file_buffer);
	// dos头
	PIMAGE_DOS_HEADER dos_header = GetDosHeader(file_buffer);
	PIMAGE_NT_HEADERS nt_headers = GetNTHeader(file_buffer, dos_header);
	PIMAGE_OPTIONAL_HEADER32	optional_header = (PIMAGE_OPTIONAL_HEADER32)&nt_headers->OptionalHeader;
	TCHAR szBuffer[0x20];
	size_t len{ 0x20 };
	for (int i = 0; i < 16; ++i)
	{
		IMAGE_DATA_DIRECTORY cur = optional_header->DataDirectory[i];
		_stprintf_s(szBuffer, len, TEXT("0x%08X"), cur.VirtualAddress);
		SetDlgItemText(hDlg, directoryType[i], szBuffer);
		_stprintf_s(szBuffer, len, TEXT("0x%08X"), cur.Size);
		SetDlgItemText(hDlg, directoryType2[i], szBuffer);
	}
	free(file_buffer);
}

BOOL AddShell(LPTSTR srcPath, LPTSTR shellPath)
{
	PVOID src_file_buffer;
	DWORD src_size = ReadFileBuffer(srcPath, &src_file_buffer);
	PVOID shell_buffer;
	DWORD shell_buffer_size;

	bool ret = AddNewSection(shellPath, &shell_buffer, &shell_buffer_size, &src_size);
	if (!ret) {
		free(src_file_buffer);
		return ret;
	}

	// 计算新节的起始地址
	PBYTE new_section_start = (PBYTE)shell_buffer + shell_buffer_size - src_size;

	// 将源文件内容复制到新节
	memcpy(new_section_start, src_file_buffer, src_size);

	// 写入新文件
	const char* new_name = "shell.exe";
	bool write_result = write_file(shell_buffer, new_name, shell_buffer_size);

	// 释放内存
	free(src_file_buffer);
	free(shell_buffer);

	return write_result;
}


INT_PTR CALLBACK DialogProcExport(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
	case WM_INITDIALOG:
	{
		SetDlgItemText(hwndDlg, IDC_EDIT, TEXT(""));
		void* file_buffer;
		DWORD size = ReadFileBuffer(filePath, &file_buffer);
		std::string content = ExportTable(file_buffer);
		int size_needed = MultiByteToWideChar(CP_ACP, 0, content.c_str(), -1, NULL, 0);
		std::wstring contentW(size_needed, L'\0');
		MultiByteToWideChar(CP_ACP, 0, content.c_str(), -1, &contentW[0], size_needed);
		std::wstring text = contentW; // 这是转换后的文本
		// 替换所有 "\n" 为 "\r\n"
		size_t pos = 0;
		while ((pos = text.find(L"\n", pos)) != std::wstring::npos)
		{
			text.replace(pos, 1, L"\r\n");
			pos += 2;
		}
		SetDlgItemText(hwndDlg, IDC_EDIT, text.c_str());
		return TRUE;
	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	}
	return 0;
}

INT_PTR CALLBACK DialogProcImport(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
		SetDlgItemText(hwndDlg, IDC_EDIT, TEXT(""));
	case WM_INITDIALOG:
	{
		void* file_buffer;
		DWORD size = ReadFileBuffer(filePath, &file_buffer);
		std::string content = ImportTable(file_buffer);
		int size_needed = MultiByteToWideChar(CP_ACP, 0, content.c_str(), -1, NULL, 0);
		std::wstring contentW(size_needed, L'\0');
		MultiByteToWideChar(CP_ACP, 0, content.c_str(), -1, &contentW[0], size_needed);
		std::wstring text = contentW; // 这是转换后的文本
		// 替换所有 "\n" 为 "\r\n"
		size_t pos = 0;
		while ((pos = text.find(L"\n", pos)) != std::wstring::npos)
		{
			text.replace(pos, 1, L"\r\n");
			pos += 2;
		}
		SetDlgItemText(hwndDlg, IDC_EDIT, text.c_str());
		return TRUE;
	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	}
	return FALSE;
}

INT_PTR CALLBACK DialogProcResource(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
		SetDlgItemText(hwndDlg, IDC_EDIT, TEXT(""));
	case WM_INITDIALOG:
	{
		void* file_buffer;
		DWORD size = ReadFileBuffer(filePath, &file_buffer);
		std::string content = ResourceTable(file_buffer);
		int size_needed = MultiByteToWideChar(CP_ACP, 0, content.c_str(), -1, NULL, 0);
		std::wstring contentW(size_needed, L'\0');
		MultiByteToWideChar(CP_ACP, 0, content.c_str(), -1, &contentW[0], size_needed);

		std::wstring text = contentW; // 这是转换后的文本
		// 替换所有 "\n" 为 "\r\n"
		size_t pos = 0;
		while ((pos = text.find(L"\n", pos)) != std::wstring::npos)
		{
			text.replace(pos, 1, L"\r\n");
			pos += 2;
		}
		SetDlgItemText(hwndDlg, IDC_EDIT, text.c_str());
		return TRUE;
	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	}
	return FALSE;
}

INT_PTR CALLBACK DialogProcRelocation(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
	case WM_INITDIALOG:
	{
		SetDlgItemText(hwndDlg, IDC_EDIT, TEXT(""));
		PVOID file_buffer;
		DWORD size = ReadFileBuffer(filePath, &file_buffer);
		std::string content = RelocatedTable(file_buffer);
		int size_needed = MultiByteToWideChar(CP_ACP, 0, content.c_str(), -1, NULL, 0);
		std::wstring contentW(size_needed, L'\0');
		MultiByteToWideChar(CP_ACP, 0, content.c_str(), -1, &contentW[0], size_needed);
		std::wstring text = contentW; // 这是转换后的文本
		// 替换所有 "\n" 为 "\r\n"
		size_t pos = 0;
		while ((pos = text.find(L"\n", pos)) != std::wstring::npos)
		{
			text.replace(pos, 1, L"\r\n");
			pos += 2;
		}
		SetDlgItemText(hwndDlg, IDC_EDIT, text.c_str());
		return TRUE;
	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	}
	return FALSE;
}

INT_PTR CALLBACK DialogProcBoundImport(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
	case WM_INITDIALOG:
	{
		SetDlgItemText(hwndDlg, IDC_EDIT, TEXT(""));
		void* file_buffer;
		DWORD size = ReadFileBuffer(filePath, &file_buffer);
		std::string content = BoundImportTable(file_buffer);
		int size_needed = MultiByteToWideChar(CP_ACP, 0, content.c_str(), -1, NULL, 0);
		std::wstring contentW(size_needed, L'\0');
		MultiByteToWideChar(CP_ACP, 0, content.c_str(), -1, &contentW[0], size_needed);
		std::wstring text = contentW; // 这是转换后的文本
		// 替换所有 "\n" 为 "\r\n"
		size_t pos = 0;
		while ((pos = text.find(L"\n", pos)) != std::wstring::npos)
		{
			text.replace(pos, 1, L"\r\n");
			pos += 2;
		}
		SetDlgItemText(hwndDlg, IDC_EDIT, text.c_str());
		return TRUE;
	}
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	}
	return FALSE;
}

INT_PTR CALLBACK DialogProcInject(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
	case WM_INITDIALOG:
		return TRUE;
	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_QUIT:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		case IDC_BUTTON_OPENFILE:
		{
			TCHAR dllPath[MAX_PATH];
			OpenFileDialog(hwndDlg, dllPath, MAX_PATH);
			SetDlgItemText(hwndDlg, IDC_EDIT_PATH, dllPath);
			return TRUE;
		}
		case IDC_BUTTON_REMOTE_INJECT:
		{
			TCHAR dllPath[MAX_PATH];
			GetDlgItemText(hwndDlg, IDC_EDIT_PATH, dllPath, MAX_PATH);
			DWORD pid;
			TCHAR tPid[0x20];
			GetDlgItemText(hwndDlg, IDC_EDIT_PID, tPid, MAX_PATH);
			pid = _ttoi(tPid);
			if (!RemoteInject(pid, dllPath))
			{
				MessageBox(hwndDlg, TEXT("注入失败"), TEXT("错误"), MB_OK);
			}
			return TRUE;
		}
		case IDC_BUTTON_WRITE_MEMORY:
		{
			TCHAR dllPath[MAX_PATH];
			GetDlgItemText(hwndDlg, IDC_EDIT_PATH, dllPath, MAX_PATH);
			DWORD pid;
			if (!LoadProcessInject(dllPath))
			{
				MessageBox(hwndDlg, TEXT("注入失败"), TEXT("错误"), MB_OK);
			}
			return TRUE;
		}
		case IDC_BUTTON_WRITE_PROCESS:
		{
			TCHAR tPid[0x20];
			GetDlgItemText(hwndDlg, IDC_EDIT_PID, tPid, MAX_PATH);
			if (!LoadMemoryInject(_ttoi(tPid)))
			{
				MessageBox(hwndDlg, TEXT("注入失败"), TEXT("错误"), MB_OK);
			}
			return TRUE;
		}
		}
	}
	}
	return FALSE;
}

BOOL RemoteInject(IN DWORD pid, IN LPCTSTR dllPath)
{
	/*
	1. 获取pid
	2.线程函数地址 LoadLibrary
	3. 写入模块名称
	4. 获取返回值
	5.释放dll名字
	6 关闭句柄
	*/
	size_t dllLen = (wcslen(dllPath) + 1) * sizeof(WCHAR);
	HANDLE hFg = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	HMODULE hMod = GetModuleHandle(L"kernel32.dll");
	LPTHREAD_START_ROUTINE lpLoadAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
	if (lpLoadAddress == NULL)
	{
		DbgPrintfA("GetAddress fail, %d", GetLastError());
		return FALSE;
	}
	PVOID mBuffer = ::VirtualAllocEx(hFg, NULL, dllLen, MEM_COMMIT, PAGE_READWRITE);
	int ret = ::WriteProcessMemory(hFg, mBuffer, dllPath, dllLen, NULL);
	if (ret == 0)
	{
		DbgPrintfA("write fail, %d", GetLastError());
		return FALSE;
	}
	HANDLE remote = ::CreateRemoteThread(hFg, NULL, 0, lpLoadAddress, mBuffer, 0, NULL);
	if (remote == NULL)
	{
		DbgPrintfA("create fail, %d", GetLastError());
		return FALSE;
	}
	WaitForSingleObject(remote, INFINITE);
	DWORD returnval;
	::GetExitCodeThread(remote, &returnval);
	DbgPrintfA("exitcode : %d", returnval);
	::VirtualFreeEx(hFg, mBuffer, dllLen, MEM_RELEASE);
	::CloseHandle(remote);
	return returnval != 0;
}
//BOOL LoadProcessInject(IN LPCTSTR exePath)
//{
//	// 1. 读取 EXE 文件到内存
//	HANDLE hFile = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
//	if (hFile == INVALID_HANDLE_VALUE) return FALSE;
//
//	DWORD fileSize = GetFileSize(hFile, NULL);
//	BYTE* pFileData = new BYTE[fileSize];
//	ReadFile(hFile, pFileData, fileSize, NULL, NULL);
//	CloseHandle(hFile);
//
//	// 2. 解析 PE 头
//	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileData;
//	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pFileData + pDosHeader->e_lfanew);
//	DWORD imageBase = pNtHeaders->OptionalHeader.ImageBase;
//	DWORD sizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
//
//	// 3. 分配内存（优先使用 EXE 的原始基址）
//	BYTE* pLocalImage = (BYTE*)VirtualAlloc((LPVOID)imageBase, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//	if (!pLocalImage) {
//		pLocalImage = (BYTE*)VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//		if (!pLocalImage) {
//			delete[] pFileData;
//			return FALSE;
//		}
//	}
//	// 授权
//	DWORD dwOldProtect;
//
//	// 4. 拉伸 PE 到内存
//	memcpy(pLocalImage, pFileData, pNtHeaders->OptionalHeader.SizeOfHeaders);
//
//	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
//	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
//		memcpy(
//			pLocalImage + pSection[i].VirtualAddress,
//			pFileData + pSection[i].PointerToRawData,
//			pSection[i].SizeOfRawData
//		);
//	}
//
//	// 5. 修复重定位表
//	DWORD delta = (DWORD_PTR)pLocalImage - pNtHeaders->OptionalHeader.ImageBase;
//	if (delta != 0) {
//		PIMAGE_DATA_DIRECTORY pRelocDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
//		if (pRelocDir->Size > 0) {
//			PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pLocalImage + pRelocDir->VirtualAddress);
//			while (pReloc->VirtualAddress) {
//				DWORD numEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
//				WORD* pEntry = (WORD*)((BYTE*)pReloc + sizeof(IMAGE_BASE_RELOCATION));
//				for (DWORD i = 0; i < numEntries; i++) {
//					if ((pEntry[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
//						DWORD_PTR* pAddr = (DWORD_PTR*)(pLocalImage + pReloc->VirtualAddress + (pEntry[i] & 0xFFF));
//						*pAddr += delta;
//					}
//				}
//				pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
//			}
//		}
//	}
//
//	// 6. 修复导入表（IAT）
//	PIMAGE_DATA_DIRECTORY pImportDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
//	if (pImportDir->Size > 0) {
//		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pLocalImage + pImportDir->VirtualAddress);
//		while (pImportDesc->Name) {
//			const char* dllName = (const char*)(pLocalImage + pImportDesc->Name);
//			HMODULE hModule = LoadLibraryA(dllName);
//			if (!hModule) {
//				VirtualFree(pLocalImage, 0, MEM_RELEASE);
//				delete[] pFileData;
//				return FALSE;
//			}
//
//			// 填充函数地址
//			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pLocalImage + pImportDesc->FirstThunk);
//			while (pThunk->u1.AddressOfData) {
//				if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
//					// 按序号导入
//					LPCSTR funcName = (LPCSTR)(pThunk->u1.Ordinal & 0xFFFF);
//					pThunk->u1.Function = (DWORD_PTR)GetProcAddress(hModule, funcName);
//				}
//				else {
//					// 按名称导入
//					PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(pLocalImage + pThunk->u1.AddressOfData);
//					pThunk->u1.Function = (DWORD_PTR)GetProcAddress(hModule, pImportName->Name);
//				}
//				pThunk++;
//			}
//			pImportDesc++;
//		}
//	}
//
//	// 7. 跳转到入口点执行
//	typedef void(*EXE_ENTRY_POINT)();
//	EXE_ENTRY_POINT entryPoint = (EXE_ENTRY_POINT)(pLocalImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
//
//	__try {
//		entryPoint(); // 调用 EXE 入口点
//	}
//	__except (EXCEPTION_EXECUTE_HANDLER) {
//		VirtualFree(pLocalImage, 0, MEM_RELEASE);
//		delete[] pFileData;
//		return FALSE;
//	}
//
//	// 8. 清理资源
//	VirtualFree(pLocalImage, 0, MEM_RELEASE);
//	delete[] pFileData;
//	return TRUE;
//}

BOOL LoadProcessInject(IN LPCTSTR dllPath)
{
	/*
	1. 加载程序，读取ImageBuffer
	2. 修复其iat表
	3. 申请空间，拷贝
	4. 跳转到eop
	*/
	PVOID pImageBuffer = ReadMemoryImage(dllPath);
	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)GetNTHeader(pImageBuffer, GetDosHeader(pImageBuffer));
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNtHeaders->OptionalHeader;
	DWORD dwSizeOfImage = pOptionalHeader->SizeOfImage;
	DWORD dwOEP = pOptionalHeader->AddressOfEntryPoint;
	DWORD dwImageBase = pOptionalHeader->ImageBase;

	PVOID pLocalImage = (PVOID)VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!pLocalImage) {
		DWORD errcode = GetLastError();
		return FALSE;
	}
	RebaseRelocation(pImageBuffer, (DWORD)pLocalImage);
	memcpy(pLocalImage, pImageBuffer, dwSizeOfImage);
	if (!RestoreIAT(pLocalImage)) {
		return FALSE;
	}


	DWORD entryPoint = (DWORD)pLocalImage + dwOEP;
	__asm {
		jmp entryPoint
	}

	VirtualFree(pLocalImage, 0, MEM_RELEASE);

	return TRUE;
}
BOOL InjectProc(PVOID pMemoryBuffer)
{
	// 纯手工修复IAT表
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMemoryBuffer;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pMemoryBuffer + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeaders->OptionalHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pMemoryBuffer +
		pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	// 遍历INT表来修复IAT表
	while (pImport->Characteristics != 0)
	{
		LPCSTR dllName = (LPCSTR)((PBYTE)pMemoryBuffer + pImport->Name);
		HMODULE hModule = LoadLibraryA(dllName);
		if (hModule == NULL)
		{
			return FALSE;
		}
		PDWORD pINT = (PDWORD)((PBYTE)pMemoryBuffer + pImport->OriginalFirstThunk);
		PDWORD pIAT = (PDWORD)((PBYTE)pMemoryBuffer + pImport->FirstThunk);
		DWORD dwOldProtect;
		DWORD dwFunOrdinal;
		for (; *pINT; ++pINT, ++pIAT)
		{
			VirtualProtect(pIAT, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect);
			if (*pINT & IMAGE_ORDINAL_FLAG32)
			{
				// 按序号导入
				dwFunOrdinal = IMAGE_ORDINAL32(*pINT);
				*pIAT = (INT_PTR)GetProcAddress(hModule, MAKEINTRESOURCEA(dwFunOrdinal));
			}
			else
			{
				// 按名字导入
				PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pMemoryBuffer + *pINT);
				*pIAT = (INT_PTR)GetProcAddress(hModule, pImportName->Name);
			}
			VirtualProtect(pIAT, sizeof(DWORD), dwOldProtect, &dwOldProtect);
		}
		++pImport;
	}
	// 修复之后来个MessageBox
	MessageBox(0, 0, 0, 0);
	return TRUE;
}

BOOL LoadMemoryInject(IN const DWORD pid)
{
	/*
	1. 获取自己的imagebase和memoryImage
	2. 修复image中的重定位表
	3. 获取目标进程句柄，申请空间写入image数据
	4. 创建远程线程执行函数修复IAT表
	*/
	// 获取自己的memoryBuffer
	PVOID pImageBase = (PVOID)GetModuleHandle(NULL);
	PIMAGE_NT_HEADERS pNtHeaders = GetNTHeader(pImageBase, GetDosHeader(pImageBase));
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeaders->OptionalHeader;
	DWORD dwSizeOfImage = pOptionalHeader->SizeOfImage;
	// 拷贝到新的位置
	PVOID pNewImageBuffer = malloc(dwSizeOfImage);
	memset(pNewImageBuffer, 0, dwSizeOfImage);
	memcpy(pNewImageBuffer, pImageBase, dwSizeOfImage);
	HANDLE hAim = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hAim == NULL)
	{
		return FALSE;
	}
	// 申请目标进程的空间
	PVOID pAimBase = VirtualAllocEx(hAim, NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	DWORD errCode;
	if (pAimBase == NULL)
	{
		errCode = GetLastError();
		return FALSE;
	}
	// 修复重定位表
	BOOL bRet = RebaseRelocation(pNewImageBuffer, (DWORD)pAimBase);
	if (!bRet)
	{
		return FALSE;
	}
	// 写入数据
	bRet = ::WriteProcessMemory(hAim, pAimBase, pNewImageBuffer, dwSizeOfImage, NULL);
	if (!bRet)
	{
		errCode = GetLastError();
		return FALSE;
	}
	// 找到注入函数在目标的位置
	DWORD dwProcAddr = ((DWORD)InjectProc - (DWORD)pImageBase + (DWORD)pAimBase);
	// 创建线程执行指定函数
	HANDLE remote = ::CreateRemoteThread(hAim, NULL, 0, (LPTHREAD_START_ROUTINE)dwProcAddr, pAimBase, 0, NULL);
	if (remote == NULL)
	{
		DbgPrintfA("create fail, %d", GetLastError());
		return FALSE;
	}
	WaitForSingleObject(remote, INFINITE);
	DWORD returnval;
	::GetExitCodeThread(remote, &returnval);
	DbgPrintfA("exitcode : %d", returnval);
	::CloseHandle(remote);
	return returnval == TRUE;
}

void __cdecl OutputDebugStringF(const char* format, ...)
{
	va_list vlArgs;
	char* strBuffer = (char*)GlobalAlloc(GPTR, 4096);

	if (strBuffer == NULL) {
		return; // Handle allocation failure
	}

	va_start(vlArgs, format);
	_vsnprintf_s(strBuffer, 4096, _TRUNCATE, format, vlArgs);
	va_end(vlArgs);
	strcat_s(strBuffer, 4096, "\n");
	OutputDebugStringA(strBuffer);
	GlobalFree(strBuffer);
	return;
}
void __cdecl OutputDebugStringFW(const wchar_t* format, ...)
{
	va_list vlArgs;
	wchar_t* strBuffer = (wchar_t*)GlobalAlloc(GPTR, 4096 * sizeof(wchar_t));
	if (strBuffer == NULL) { return; }

	va_start(vlArgs, format);
	_vsnwprintf_s(strBuffer, 4096, _TRUNCATE, format, vlArgs);
	va_end(vlArgs);
	wcscat_s(strBuffer, 4096, L"\n");
	OutputDebugStringW(strBuffer);
	return;
}

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
	do {
		// 创建模块快照
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			continue;
		}
		me32.dwSize = sizeof(MODULEENTRY32);
		if (!Module32First(hModuleSnap, &me32)) {
			CloseHandle(hModuleSnap);
			continue;
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
	ListProcessModules(dwPid, hListModules);
}

void ListProcessModules(DWORD dwPid, HWND hListModules)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	// 模块快照
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
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
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = TEXT("*.exe;*.dll;*.scr;*.drv;*.sys\0*.exe;*.dll;*.src;*.drv;*.sys\0All Files (*.*)\0*.*\0");
	ofn.nFilterIndex = 1;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

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
	PIMAGE_NT_HEADERS nt_headers = GetNTHeader(file_buffer, dos_header);
	PIMAGE_FILE_HEADER file_header = &nt_headers->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 op_header = (PIMAGE_OPTIONAL_HEADER32)&nt_headers->OptionalHeader;

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
		void* file_buffer;
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

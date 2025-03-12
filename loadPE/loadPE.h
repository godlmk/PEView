#pragma once

#include "resource.h"

void __cdecl OutputDebugStringF(const char* format, ...);
void __cdecl OutputDebugStringFW(const wchar_t* format, ...);
INT_PTR CALLBACK DialogProcMain(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcPE(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcSection(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcDirectory(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
// 初始化进程列
void InitProcessListView(HWND hDlg);
// 遍历进程
void EnumProcess(HWND hListProcess);
// 初始化模块列
void InitModulesListView(HWND hDlg);
// 遍历进程的模块
void EnumModules(HWND hListProcess, HWND hListModules);
// 显示进程的所有模块

void ListProcessModules(DWORD dwPid, HWND hListModules);
// 显示文件选择对话框并获取文件路径
BOOL OpenFileDialog(HWND hwnd, LPTSTR filePath, DWORD filePathSize);
// 根据文件名初始化PE查看器数据
void InitPEView(HWND hDlg);

// 初始化节信息
void InitSectionView(HWND hDlg);
// 填充节的相关信息
void PopulateSectionView(HWND hDlg);
// 填充目录项相关信息
void InitDirectoryView(HWND hDlg);

BOOL AddShell(LPTSTR srcPath, LPTSTR shellPath);

// 初始化目录的详细信息
INT_PTR CALLBACK DialogProcExport(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcImport(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcResource(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcRelocation(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcBoundImport(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);

// 注入界面
INT_PTR CALLBACK DialogProcInject(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
// 通过pid和dll路径注入
BOOL RemoteInject(IN DWORD pid, IN LPCTSTR dllPath);
// 通过在高地址运行然后在低地址运行目标来注入
BOOL LoadProcessInject(IN LPCTSTR dllPath);

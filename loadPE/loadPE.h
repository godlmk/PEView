#pragma once

#include "resource.h"

void __cdecl OutputDebugStringF(const char* format, ...);
void __cdecl OutputDebugStringFW(const wchar_t* format, ...);
INT_PTR CALLBACK DialogProcMain(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcPE(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcSection(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcDirectory(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
// ��ʼ��������
void InitProcessListView(HWND hDlg);
// ��������
void EnumProcess(HWND hListProcess);
// ��ʼ��ģ����
void InitModulesListView(HWND hDlg);
// �������̵�ģ��
void EnumModules(HWND hListProcess, HWND hListModules);
// ��ʾ���̵�����ģ��

void ListProcessModules(DWORD dwPid, HWND hListModules);
// ��ʾ�ļ�ѡ��Ի��򲢻�ȡ�ļ�·��
BOOL OpenFileDialog(HWND hwnd, LPTSTR filePath, DWORD filePathSize);
// �����ļ�����ʼ��PE�鿴������
void InitPEView(HWND hDlg);

// ��ʼ������Ϣ
void InitSectionView(HWND hDlg);
// ���ڵ������Ϣ
void PopulateSectionView(HWND hDlg);
// ���Ŀ¼�������Ϣ
void InitDirectoryView(HWND hDlg);

BOOL AddShell(LPTSTR srcPath, LPTSTR shellPath);

// ��ʼ��Ŀ¼����ϸ��Ϣ
INT_PTR CALLBACK DialogProcExport(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcImport(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcResource(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcRelocation(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProcBoundImport(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);

// ע�����
INT_PTR CALLBACK DialogProcInject(HWND hwndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
// ͨ��pid��dll·��ע��
BOOL RemoteInject(IN DWORD pid, IN LPCTSTR dllPath);
// ͨ���ڸߵ�ַ����Ȼ���ڵ͵�ַ����Ŀ����ע��
BOOL LoadProcessInject(IN LPCTSTR dllPath);

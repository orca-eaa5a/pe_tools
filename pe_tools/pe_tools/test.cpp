#include <Windows.h>
#include <stdio.h>
#include "pe_tool.h"

void ReadBinary(const char* file_name, BYTE* buf){
	DWORD numberOfBytesRead = 0;
	DWORD fp_offset = 0;
	HANDLE hFile = CreateFileA(file_name, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	do{
		ReadFile(hFile, (buf+fp_offset), 0x1000, &numberOfBytesRead, NULL);
		fp_offset +=numberOfBytesRead;
	}while(numberOfBytesRead != 0);
	CloseHandle(hFile);
}

int main(){
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	CONTEXT rCtx;
	DWORD numberOfBytesWritten;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&rCtx, sizeof(rCtx));
	si.cb = sizeof(si);

	WCHAR application[100] = TEXT("mspaint.exe");
	BOOL res = CreateProcessW(NULL, application, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	HANDLE hFil3 = CreateFile(L"C:\\Users\\dlfgu\\OneDrive\\Desktop\\test\\HelloWorld.exe", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD fileSize = GetFileSize(hFil3, NULL);
	BYTE* pe_bin3 = (BYTE*)calloc(fileSize, sizeof(BYTE));
	CloseHandle(hFil3);
	ReadBinary("C:\\Users\\dlfgu\\OneDrive\\Desktop\\test\\HelloWorld.exe", pe_bin3);
	PIMAGE_NT_HEADERS pNt_hdr = GetImageNtHeader(pe_bin3);
	DWORD szOfImg = pNt_hdr->OptionalHeader.SizeOfImage;
	BYTE* dst_pe = (BYTE*)calloc(szOfImg, sizeof(BYTE));
	BYTE* pe_img = ConvertToImage(pe_bin3);

	HANDLE hFil4 = CreateFile(L"C:\\Users\\dlfgu\\OneDrive\\Desktop\\test\\HelloWorld_img.bin", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFil4, pe_img, szOfImg, &numberOfBytesWritten,NULL);
	CloseHandle(hFil4);

	DWORD target_proc_img_base = (DWORD)GetProcessImageBase(pi.hProcess);
	RelocatePEImage(pe_img, target_proc_img_base);

	hFil4 = CreateFile(L"C:\\Users\\dlfgu\\OneDrive\\Desktop\\test\\HelloWorld_img_reloc.bin", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFil4, dst_pe, szOfImg, &numberOfBytesWritten, NULL);
	CloseHandle(hFil4);


	UnmapProcessImageFromVAS(pi.hProcess);

	PVOID rewritPEBase = VirtualAllocEx(pi.hProcess, (PVOID)target_proc_img_base, szOfImg, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, (PVOID)target_proc_img_base, pe_img, szOfImg, &numberOfBytesWritten);
	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;
	pContext->Eax = target_proc_img_base + (DWORD)pNt_hdr->OptionalHeader.AddressOfEntryPoint;

	if (!SetThreadContext(pi.hThread, pContext))
	{
		printf("Error setting context\r\n");
		return 0;
	}

	ResumeThread(pi.hThread);
	WaitForSingleObject(pi.hThread, INFINITE);
}
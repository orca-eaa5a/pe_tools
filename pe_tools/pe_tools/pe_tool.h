#include "pe_struct.h"

PIMAGE_DOS_HEADER GetImageDosHeader(BYTE* pe_file);
PIMAGE_NT_HEADERS GetImageNtHeader(BYTE* pe_file);
void GetImageNtHeader(_In_ HANDLE hProc, _Out_ PIMAGE_NT_HEADERS pNt_hdr);
PIMAGE_OPTIONAL_HEADER GetImageOptionalHeader(BYTE* pe_file);
PIMAGE_FILE_HEADER GetImageFileHeader(_In_ BYTE* pe_file);
DWORD GetNumberOfSections(BYTE* pe_file);
PIMAGE_SECTION_HEADER* GetSectionHeaders(BYTE* pe_file);
PIMAGE_SECTION_HEADER GetSectionHeaderByName(BYTE* pe_file, const char* name);
LPVOID GetSectionBaseRAW(BYTE* pe_file, const char* name);
LPVOID GetImageSectionBaseRVA(BYTE* pe_file, const char* name);
DWORD GetSizeOfSection(BYTE* pe_file, const char* name);
PIMAGE_DATA_DIRECTORY GetDataDirectory(BYTE* pe_file, int type);
BYTE* GetProcessImageBinary(HANDLE hProc);
BYTE* ConvertToImage(_In_ BYTE* pe_bin);
void RelocatePEImage(_Inout_ BYTE* old_pe_img, _In_ DWORD new_pe_img_base);
void RelocatePEImage(_Inout_ BYTE* old_pe_img, _In_ DWORD new_pe_img_base, _Out_ BYTE* new_pe_img);
LPVOID GetProcessImageBase(_In_ HANDLE hProc);
bool UnmapProcessImageFromVAS(_In_ HANDLE hProc);
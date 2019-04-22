#include <windows.h>
#include <TlHelp32.h>
#include <Winternl.h>
#include <string>
#include <stdlib.h>

typedef NTSTATUS(NTAPI *NTQUERYINFORMATIONPROCESS)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

__forceinline DWORD CompareStrings(const char* StringA, const wchar_t* StringB)
{
	const char *szIterA = StringA; const wchar_t *szIterB = StringB;

	while (*szIterA) {
		if (*szIterA++ != *szIterB++)
			return 1;
	}

	return 0;
}

int main()
{
	PEB Peb = { 0 };
	DWORD dwSize = 0;
	DWORD dwPID = 0;
	HANDLE hProcess = NULL;
	HANDLE hProcessSnap = NULL;
	WCHAR PsPath[MAX_PATH] = { 0 };
	WCHAR wszProcName[20] = L"chrome.exe";
	PROCESSENTRY32 PsEntry32 = { 0 };
	PROCESS_BASIC_INFORMATION PsBasicInfo = { 0 };
	RTL_USER_PROCESS_PARAMETERS RtlUserPsParams = { 0 };
	NTQUERYINFORMATIONPROCESS NtFunction = NULL;


	if ((hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) != INVALID_HANDLE_VALUE)
	{
		PsEntry32.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(hProcessSnap, &PsEntry32))
		{
			CloseHandle(hProcessSnap);
			return FALSE;
		}

		do
		{
			if (CompareStrings(PsEntry32.szExeFile, wszProcName) == 0)
			{
				hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PsEntry32.th32ProcessID);

				if (hProcess != INVALID_HANDLE_VALUE)
				{
					NtFunction = (NTQUERYINFORMATIONPROCESS)GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtQueryInformationProcess");

					if (NtFunction)
					{
						RTL_USER_PROCESS_PARAMETERS Rupp = { 0 };
						ReadProcessMemory(hProcess,
							Peb.ProcessParameters,
							&Rupp,
							sizeof(RTL_USER_PROCESS_PARAMETERS),
							&dwSize);
						PWSTR buffer = (PWSTR)calloc(sizeof(PEB), sizeof(WCHAR));

						if (NtFunction(hProcess, ProcessBasicInformation, &PsBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwSize) == ERROR_SUCCESS)
						{
							ReadProcessMemory(hProcess, PsBasicInfo.PebBaseAddress, &buffer, sizeof(PEB), (SIZE_T*)&dwSize);
							wprintf(L"PEB Adress = %s\n", std::wstring(buffer, sizeof(PEB) / sizeof(WCHAR)).c_str());
							free(buffer);
							buffer = (PWSTR)calloc(sizeof(RTL_USER_PROCESS_PARAMETERS), sizeof(WCHAR));

							ReadProcessMemory(hProcess, Peb.ProcessParameters, &buffer, sizeof(RTL_USER_PROCESS_PARAMETERS), (SIZE_T*)&dwSize);
							wprintf(L"Parameters = %s\n", std::wstring(buffer, sizeof(RTL_USER_PROCESS_PARAMETERS) / sizeof(WCHAR)).c_str());
							free(buffer);
							buffer = (PWSTR)calloc(RtlUserPsParams.ImagePathName.Length, sizeof(WCHAR));

							ReadProcessMemory(hProcess, RtlUserPsParams.ImagePathName.Buffer, &buffer, RtlUserPsParams.ImagePathName.Length, (SIZE_T*)&dwSize);
							wprintf(L"Image = %s\n", std::wstring(buffer, RtlUserPsParams.ImagePathName.Length / sizeof(WCHAR)).c_str());
							free(buffer);

							dwPID = PsEntry32.th32ProcessID;
						}

					}
					CloseHandle(hProcess);
				}
			}
		} while (Process32Next(hProcessSnap, &PsEntry32));

		CloseHandle(hProcessSnap);
	}

	return 0;
}
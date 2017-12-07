#include <ntifs.h>
#include <ntstrsafe.h>
#include "msg_file.h"

#define MAX_DEV 255

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
__in HANDLE ProcessHandle,
__in ULONG ProcessInformationClass,
__out_bcount_opt(ProcessInformationLength) PVOID ProcessInformation,
__in ULONG ProcessInformationLength,
__out_opt PULONG ReturnLength
);


NTSTATUS GetProcessImagePath(WCHAR **pPathName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	WCHAR ntBuf[255] = { 0 };
	WCHAR cmpBuf1[50] = { 0 };
	WCHAR cmpBuf2[50] = { 0 };
	WCHAR drvLetter = '\x41';
	WCHAR drvBuf[] = L"\\??\\A:";
	UNICODE_STRING ntInfo, dosInfo, drvLink, cmpPath1;
	HANDLE hProcess = NULL;
	HANDLE hLink = NULL;
	CLIENT_ID cId;
	OBJECT_ATTRIBUTES objAttr1, objAttr2;
	ULONG i = 0;
	ULONG bckCount = 0;
	ULONG chrCount = 0;
	errno_t memErr;
	WCHAR *pTmpName = NULL;
	BOOLEAN cmpRes = FALSE;
	
	cId.UniqueProcess = PsGetCurrentProcessId();
	cId.UniqueThread = NULL;
	InitializeObjectAttributes(
		&objAttr1,
		NULL,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
		
	RtlInitUnicodeString(&ntInfo, ntBuf);
	ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr1, &cId);
	status = ZwQueryInformationProcess(hProcess, 27, &ntBuf, sizeof(ntBuf), NULL);
	if (!NT_SUCCESS(status) || ntBuf[0] == 0) 
		return STATUS_UNSUCCESSFUL;
	if (hProcess) 
		ZwClose(hProcess);
	ntInfo.Length = ntBuf[0];
	ntInfo.MaximumLength = ntBuf[1];
	ntInfo.Buffer = &(ntBuf[8]);
	
	for (i=0; i < (ULONG)ntInfo.Length; i++) 
	{
		if (bckCount != 3) 
			chrCount++;
		else 
			break; 
		
		if (ntInfo.Buffer[i] == L'\\') 
			bckCount++;
	}
	
	chrCount--;
	memErr = memcpy_s(cmpBuf1, sizeof(cmpBuf1), ntInfo.Buffer, chrCount * sizeof(WCHAR));
	if (memErr)
		return STATUS_UNSUCCESSFUL;
	RtlInitUnicodeString(&cmpPath1, cmpBuf1);
		
	RtlInitUnicodeString(&drvLink, drvBuf);
	do 
	{
		InitializeObjectAttributes(
			&objAttr2,
			&drvLink,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);
			
		status = ZwOpenSymbolicLinkObject(&hLink, FILE_READ_DATA, &objAttr2);
		if (!NT_SUCCESS(status)) 
		{
			drvLetter++;
			drvBuf[4] = drvLetter;
			continue;
		}
		
		RtlInitEmptyUnicodeString(&dosInfo, cmpBuf2, sizeof(cmpBuf2));
		status = ZwQuerySymbolicLinkObject(hLink, &dosInfo, NULL);
		if (hLink) 
			ZwClose(hLink);
		cmpRes = RtlEqualUnicodeString(&cmpPath1, &dosInfo, FALSE);
		if (cmpRes == TRUE || drvLetter > 0x5B) 
			break;
		
	} while (TRUE);
		
	if (cmpRes == FALSE) 
		return STATUS_UNSUCCESSFUL;
	
	pTmpName = (WCHAR *)ExAllocatePoolWithTag(NonPagedPool, ntInfo.MaximumLength, 'lloC');
	if (!pTmpName) 
		return STATUS_MEMORY_NOT_ALLOCATED;
	
	RtlSecureZeroMemory(pTmpName, ntInfo.MaximumLength);
	pTmpName[0] = drvLetter;
	pTmpName[1] = L':';
	memErr = memcpy_s
		(pTmpName + sizeof(WCHAR), ntInfo.MaximumLength - sizeof(WCHAR), &(ntInfo.Buffer[chrCount]), ntInfo.MaximumLength - (sizeof(WCHAR) * (chrCount)));
	if (memErr)
		return STATUS_UNSUCCESSFUL;
	*pPathName = pTmpName;
	
	return STATUS_SUCCESS;
}


NTSTATUS LogDetection(UNICODE_STRING devBlock, BOOLEAN list)
{
	WCHAR buf[256] = { 0 };
	WCHAR *pPathName = NULL;
	
	if (list == TRUE)
	{
		RtlStringCchPrintfExW
			(buf, 255, NULL, NULL, STRSAFE_NULL_ON_FAILURE, L"Collision cannot create %wZ because it is configured in whitelist!", devBlock);
		EventWriteFunctionWhitelist(NULL, buf);
		return STATUS_SUCCESS;
	}
	else if (NT_SUCCESS(GetProcessImagePath(&pPathName)))
	{
		RtlStringCchPrintfExW
			(buf, 255, NULL, NULL, STRSAFE_NULL_ON_FAILURE, L"Process running at %s (Pid %llu) attempted to access %wZ", pPathName, (ULONGLONG)PsGetCurrentProcessId(), devBlock);
	}
	else
	{
		RtlStringCchPrintfExW
			(buf, 255, NULL, NULL, STRSAFE_NULL_ON_FAILURE, L"Pid %llu attempted to access %wZ", (ULONGLONG)PsGetCurrentProcessId(), devBlock);
	}
	
	EventWriteFunctionCollision(NULL, buf);
	if (pPathName) 
		ExFreePool(pPathName);
	return STATUS_SUCCESS;
}


ULONG numValues = 0;
ULONG numAudit = 0;


NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status;
	ULONG size = 0;
	POBJECT_NAME_INFORMATION objName;

	ObQueryNameString(pDevObj, NULL, 0, &size);
	objName = (POBJECT_NAME_INFORMATION) ExAllocatePoolWithTag(NonPagedPool, size, 'lloC');
	if (!objName)
		return STATUS_MEMORY_NOT_ALLOCATED;
	status = ObQueryNameString(pDevObj, objName, size, &size);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(objName);
		return status;
	}
	if (numAudit)
		LogDetection(objName->Name, FALSE);
	ExFreePool(objName);
	

	pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_NOT_SUPPORTED;

}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);
	NTSTATUS status;
	ULONG size, i, j;
	UNICODE_STRING keyName, blistName, wlistName, auditName;
	OBJECT_ATTRIBUTES objAttr;
	HANDLE hKey = NULL;
	PKEY_VALUE_PARTIAL_INFORMATION pAuditInfo, pBlistInfo, pWlistInfo;
	WCHAR *pBcurrEntry;
	WCHAR *pWcurrEntry;
	BOOLEAN found = FALSE;
	PDEVICE_OBJECT devElement;
	
	RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\Software\\Policies\\IA\\CollisionConfiguration");
	RtlInitUnicodeString(&auditName, L"Enforcement");
	RtlInitUnicodeString(&blistName, L"Blacklist");
	RtlInitUnicodeString(&wlistName, L"Whitelist");
	
	InitializeObjectAttributes(
		&objAttr,
		&keyName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	status = ZwOpenKey(&hKey, KEY_READ, &objAttr);
	if (!NT_SUCCESS(status)) 
		return STATUS_NOT_IMPLEMENTED;
	
	ZwQueryValueKey(hKey, &auditName, KeyValuePartialInformation, NULL, 0, &size);
	pAuditInfo = (PKEY_VALUE_PARTIAL_INFORMATION) ExAllocatePoolWithTag(NonPagedPool, size, 'lloC');
	if (!pAuditInfo) 
		return STATUS_MEMORY_NOT_ALLOCATED;
	status = ZwQueryValueKey(hKey, &auditName, KeyValuePartialInformation, pAuditInfo, size, &size);
	if (!NT_SUCCESS(status)) 
	{
		ExFreePool(pAuditInfo);
		return status;
	}
	numAudit = (ULONG)pAuditInfo->Data[0];
	if (numAudit != 1)
		numAudit = 0;
	ExFreePool(pAuditInfo);
	
	pDrvObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	EventRegisterCollision();
	
	ZwQueryValueKey(hKey, &blistName, KeyValuePartialInformation, NULL, 0, &size);
	pBlistInfo = (PKEY_VALUE_PARTIAL_INFORMATION) ExAllocatePoolWithTag(NonPagedPool, size, 'lloC');
	if (!pBlistInfo) 
		return STATUS_MEMORY_NOT_ALLOCATED;
	status = ZwQueryValueKey(hKey, &blistName, KeyValuePartialInformation, pBlistInfo, size, &size);
	if (!NT_SUCCESS(status)) 
	{
		ExFreePool(pBlistInfo);
		return status;
	}

	ZwQueryValueKey(hKey, &wlistName, KeyValuePartialInformation, NULL, 0, &size);
	pWlistInfo = (PKEY_VALUE_PARTIAL_INFORMATION) ExAllocatePoolWithTag(NonPagedPool, size, 'lloC');
	if (!pWlistInfo) 
		return STATUS_MEMORY_NOT_ALLOCATED;
	status = ZwQueryValueKey(hKey, &wlistName, KeyValuePartialInformation, pWlistInfo, size, &size);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pBlistInfo);
		ExFreePool(pWlistInfo);
		return status;
	}
	
	pBcurrEntry = (WCHAR *)(&pBlistInfo->Data[0]);
	for (i = 0; *pBcurrEntry != UNICODE_NULL && i < MAX_DEV; i++) 
	{
		UNICODE_STRING bnewEntry;
		RtlInitUnicodeString(&bnewEntry, pBcurrEntry);
		if (bnewEntry.Buffer[(bnewEntry.MaximumLength-1) / sizeof(WCHAR)] != UNICODE_NULL)
			bnewEntry.Buffer[(bnewEntry.MaximumLength-1) / sizeof(WCHAR)] = UNICODE_NULL;
		pWcurrEntry = (WCHAR *)(&pWlistInfo->Data[0]);
		for (j = 0; *pWcurrEntry != UNICODE_NULL; j++) 
		{
			UNICODE_STRING wnewEntry;
			RtlInitUnicodeString(&wnewEntry, pWcurrEntry);
			if (wnewEntry.Buffer[(wnewEntry.MaximumLength-1) / sizeof(WCHAR)] != UNICODE_NULL)
				wnewEntry.Buffer[(wnewEntry.MaximumLength-1) / sizeof(WCHAR)] = UNICODE_NULL;
			if (RtlEqualUnicodeString(&bnewEntry, &wnewEntry, TRUE)) 
			{
				found = TRUE; 
				break;
			}
			pWcurrEntry += (wnewEntry.Length + sizeof(UNICODE_NULL)) / sizeof(WCHAR);
		}
		if (!found)
		{
			status = IoCreateDevice(
				pDrvObj,
				0,
				&bnewEntry,
				FILE_DEVICE_UNKNOWN,
				FILE_DEVICE_SECURE_OPEN,
				TRUE,
				&devElement);
			if (NT_SUCCESS(status))
			{
				devElement->Flags &= ~DO_DEVICE_INITIALIZING;
				numValues++;
			}	
		}
		else 
		{
			found = FALSE;
			if (numAudit)
				LogDetection(bnewEntry, TRUE);
		}
		pBcurrEntry += (bnewEntry.Length + sizeof(UNICODE_NULL)) / sizeof(WCHAR);
	}
	
	ExFreePool(pBlistInfo);
	ExFreePool(pWlistInfo);
	ZwClose(hKey);
	return STATUS_SUCCESS;
	
}
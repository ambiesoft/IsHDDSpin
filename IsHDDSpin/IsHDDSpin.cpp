#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h>  // ★これを追加

#include <iostream>
#include <cstdio>
#include <string>

#include "../../lsMisc/GetDriveNumberFromDriveLetter.h"

using namespace Ambiesoft;

#pragma pack(push, 1)
typedef struct _ATA_PASS_THROUGH_EX_WITH_BUFFERS {
    ATA_PASS_THROUGH_EX Apt;
    UCHAR Buffer[512];
} ATA_PASS_THROUGH_EX_WITH_BUFFERS;
#pragma pack(pop)

bool CheckHddSpinState(int physicalDriveNumber) {
    char devicePath[64];
    sprintf_s(devicePath, "\\\\.\\PhysicalDrive%d", physicalDriveNumber);

    HANDLE hDevice = CreateFileA(
        devicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open drive: " << GetLastError() << "\n";
        return false;
    }

    ATA_PASS_THROUGH_EX_WITH_BUFFERS aptwb = { 0 };
    aptwb.Apt.Length = sizeof(ATA_PASS_THROUGH_EX);
    aptwb.Apt.AtaFlags = ATA_FLAGS_DATA_IN;
    aptwb.Apt.DataTransferLength = sizeof(aptwb.Buffer);
    aptwb.Apt.TimeOutValue = 5;
    aptwb.Apt.DataBufferOffset = offsetof(ATA_PASS_THROUGH_EX_WITH_BUFFERS, Buffer);

    // ATA CHECK POWER MODE command (0xE5)
    aptwb.Apt.CurrentTaskFile[6] = 0xE5;

    DWORD bytesReturned = 0;
    BOOL status = DeviceIoControl(
        hDevice,
        IOCTL_ATA_PASS_THROUGH,
        &aptwb,
        sizeof(aptwb),
        &aptwb,
        sizeof(aptwb),
        &bytesReturned,
        NULL
    );
	DWORD dwLastError = GetLastError();

    CloseHandle(hDevice);

    if (!status) {
        std::cerr << "DeviceIoControl failed: " << dwLastError << "\n";
        return false;
    }

    UCHAR sectorCount = aptwb.Apt.CurrentTaskFile[2]; // Sector Count register
    // 0x00 = active/spinning, 0x80 = standby/sleep
    if (sectorCount == 0x00) {
        std::cout << "Drive is spinning.\n";
        return true;
    }
    else if (sectorCount == 0x80) {
        std::cout << "Drive is in standby/sleep.\n";
        return false;
    }
    else {
        std::cout << "Unknown state: 0x" << std::hex << (int)sectorCount << "\n";
        return false;
    }
}

int main3() {
    int driveNumber = 3; // PhysicalDrive1 をチェック
    CheckHddSpinState(driveNumber);
    return 0;
}

bool IsDriveSpinning(const wchar_t driveLetter, bool* pIsSpinning, DWORD* pLastError)
{
	int deviceNumber = 0;
    if (!GetDriveNumberFromDriveLetter(driveLetter, &deviceNumber, pLastError))
        return false;

    std::wstring physicalPath = L"\\\\.\\PhysicalDrive" + std::to_wstring(deviceNumber);
    HANDLE hDisk = CreateFileW(physicalPath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE)
    {
        if(pLastError)
			*pLastError = GetLastError();
        return false;
    }

    ATA_PASS_THROUGH_EX apt = { 0 };
    apt.Length = sizeof(ATA_PASS_THROUGH_EX);
    apt.TimeOutValue = 10;
    apt.DataTransferLength = 0;
    apt.AtaFlags = ATA_FLAGS_DATA_IN;
    apt.CurrentTaskFile[6] = 0xE5; // ATA CHECK POWER MODE

    BYTE buffer[sizeof(ATA_PASS_THROUGH_EX) + 512] = { 0 };
    memcpy(buffer, &apt, sizeof(apt));
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDisk,
        IOCTL_ATA_PASS_THROUGH,
        buffer, sizeof(buffer),
        buffer, sizeof(buffer),
        &bytesReturned, NULL))
    {
        if(pLastError)
            *pLastError = GetLastError();
        CloseHandle(hDisk);
		return false;
    }

    CloseHandle(hDisk);

    ATA_PASS_THROUGH_EX* pApt = (ATA_PASS_THROUGH_EX*)buffer;
    BYTE sectorCount = pApt->CurrentTaskFile[1];

	// 0x00 → Sleep 0xFF/other → spinning
    *pIsSpinning = (sectorCount != 0x00);
    return true;
}

#pragma pack(push, 1)
typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS {
    SCSI_PASS_THROUGH spt;
    UCHAR sense[32];
    UCHAR data[512];
} SCSI_PASS_THROUGH_WITH_BUFFERS;
#pragma pack(pop)

bool CheckUsbHddSpinState(wchar_t driveLetter, bool* pIsSpinning, DWORD* pLastError)
{
    int deviceNumber = 0;
    if (!GetDriveNumberFromDriveLetter(driveLetter, &deviceNumber, pLastError))
        return false;

    std::wstring physicalPath = L"\\\\.\\PhysicalDrive" + std::to_wstring(deviceNumber);
    HANDLE hDevice = CreateFileW(
        physicalPath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        if (pLastError)
            *pLastError = GetLastError();
        return false;
    }

    SCSI_PASS_THROUGH_WITH_BUFFERS sptwb = { 0 };
    sptwb.spt.Length = sizeof(SCSI_PASS_THROUGH);
    sptwb.spt.CdbLength = 12; // In case of SAT, ATA Command is 12 bytes CDB
    sptwb.spt.SenseInfoLength = sizeof(sptwb.sense);
    sptwb.spt.DataIn = SCSI_IOCTL_DATA_IN;
    sptwb.spt.DataTransferLength = sizeof(sptwb.data);
    sptwb.spt.TimeOutValue = 5;
    sptwb.spt.DataBufferOffset = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS, data);
    sptwb.spt.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS, sense);

    // SAT formatted ATA PASS-THROUGH(12) CDB
    // CHECK POWER MODE = 0xE5
    UCHAR* cdb = sptwb.spt.Cdb;
    cdb[0] = 0xA1;       // ATA PASS-THROUGH(12)
    cdb[1] = 0x08;       // protocol = PIO Data-In
    cdb[2] = 0x00;       // flags
    cdb[3] = 0x00;       // features
    cdb[4] = 0x00;       // sector count
    cdb[5] = 0x00;       // LBA low
    cdb[6] = 0x00;       // LBA mid
    cdb[7] = 0x00;       // LBA high
    cdb[8] = 0x00;       // device
    cdb[9] = 0xE5;       // command (CHECK POWER MODE)
    cdb[10] = 0x00;      // reserved
    cdb[11] = 0x00;      // control

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(
        hDevice,
        IOCTL_SCSI_PASS_THROUGH,
        &sptwb,
        sizeof(sptwb),
        &sptwb,
        sizeof(sptwb),
        &bytesReturned,
        NULL
    ))
    {
        if (pLastError)
            *pLastError = GetLastError();
        CloseHandle(hDevice);
        return false;
    }

    CloseHandle(hDevice);

    // sector count (In case of ATA spec, it may return onto byte[5])
    UCHAR sectorCount = sptwb.data[0];
    if (sectorCount == 0x00) {
        *pIsSpinning = true;
        return true;
    }
    else if (sectorCount == 0x80) {
        *pIsSpinning = false;
        return true;
    }

    // "Unknown state: 0x" << std::hex << (int)sectorCount << "\n";
    return false;
}

int main() {
	bool isSpinning = false;
	DWORD lastError = 0;
	CheckUsbHddSpinState(L'V', &isSpinning, &lastError);
    return 0;
}

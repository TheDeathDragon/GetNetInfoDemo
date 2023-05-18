#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>

#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

std::string GetHostName()
{
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer);

    if (GetComputerNameA(buffer, &size))
    {
        return std::string(buffer);
    }

    return "";
}

std::string GetEthernetInfo()
{
    std::string info;

    IP_ADAPTER_INFO* adapterInfo;
    ULONG bufferSize = sizeof(IP_ADAPTER_INFO);
    adapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);

    if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW)
    {
        free(adapterInfo);
        adapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);
    }

    if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR)
    {
        IP_ADAPTER_INFO* adapter = adapterInfo;
        int count = 1;
        while (adapter)
        {
            info += "网卡" + std::to_string(count) + "：" + std::string(adapter->AdapterName) + "\n";
            info += "IP地址: " + std::string(adapter->IpAddressList.IpAddress.String) + "\n";
            info += "MAC地址: ";

            std::stringstream macStream;
            for (DWORD i = 0; i < adapter->AddressLength; i++)
            {
                if (i == adapter->AddressLength - 1)
                {
                    macStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(adapter->Address[i]);
                }
                else
                {
                    macStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(adapter->Address[i]) << "-";
                }
            }
            info += macStream.str();

            info += "\n\n";
            adapter = adapter->Next;
            count++;
        }
    }

    free(adapterInfo);

    return info;
}

int main()
{
    std::string hostname = GetHostName();
    std::string ethernetInfo = GetEthernetInfo();

    std::cout << "主机名: " << hostname << std::endl;
    std::cout << "\n网卡信息:\n\n" << ethernetInfo << std::endl;

    return 0;
}

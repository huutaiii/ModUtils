#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <mutex>

#include <windows.h>
#include <psapi.h>

#include "MinHook.h"

class ULog
{
    FILE* file = nullptr;
    std::mutex file_mtx;

    ULog(const ULog&) = delete;

    ULog(const char* filename) {
        std::lock_guard<std::mutex> lock(file_mtx);
        if (!file)
        {
            fopen_s(&file, filename, "w+");
        }
        if (file)
        {
            fclose(file);
            file = nullptr;
        }
    }

    ~ULog() {
        //if (file)
        //{
        //    fclose(file);
        //    file = nullptr;
        //}
    }

public:

    static std::string FileName;
    static bool bShowTime;

    static ULog& Get()
    {
        // Use a pointer to avoid calling the copy constructor
        static ULog *instance = new ULog(FileName.c_str());

        return *instance;
    }

    bool bFirst = true;

    void println(const char* fmt, va_list args)
    {
        //if (bFirst)
        //{
        //    bFirst = false;
        //    fopen_s(&file, FileName.c_str(), "w+");
        //}
        //else
        //{
        //    fopen_s(&file, FileName.c_str(), "a+");
        //}
        fopen_s(&file, FileName.c_str(), "a+");
        std::lock_guard<std::mutex> lock(file_mtx);
        if (file)
        {
            if (bShowTime)
            {
                SYSTEMTIME time;
                GetLocalTime(&time);
                fprintf(file, "[%02d-%02d-%02d %02d:%02d:%02d.%03d] ", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
            }
            vfprintf(file, fmt, args);
            fprintf(file, "\n");
            //fflush(file);

            fclose(file);
            file = nullptr;
        }
    }

    void println(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        println(fmt, args);
        va_end(args);
    }

#ifdef _DEBUG
    void dprintln(const char* fmt, ...)
    {
        std::string dfmt = "[debug] " + std::string(fmt);
        va_list args;
        va_start(args, fmt);
        println(dfmt.c_str(), args);
        va_end(args);
    }
#else
    void dprintln(const char* fmt, ...) {}
#endif
};

std::string ULog::FileName = "unknown_module.log";
bool ULog::bShowTime = true;

HMODULE GetBaseModule()
{
    static HMODULE hModule = 0;

    // For subsequent calls just return the first value we got
    if (hModule)
    {
        return hModule;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (!hProcess)
    {
        return 0;
    }

    DWORD dwSizeModules;
    // get The number of bytes required to store all module handles in the lphModule array
    EnumProcessModules(hProcess, nullptr, 0, &dwSizeModules);
    if (!dwSizeModules)
    {
        return 0;
    }

    HMODULE* Modules = (HMODULE*)malloc(dwSizeModules);
    if (Modules)
    {
        if (EnumProcessModules(hProcess, Modules, dwSizeModules, &dwSizeModules))
        {
            hModule = Modules[0];
        }
        free(Modules);
    }

    return hModule;
}

PVOID GetRelativeAddress(PVOID absAddr)
{
    return PVOID(UINT_PTR(absAddr) - UINT_PTR(GetBaseModule()));
}

std::vector<uint16_t> StringtoScanPattern(std::string patternString)
{
    std::vector<uint16_t> out;
    patternString.erase(std::remove_if(patternString.begin(), patternString.end(), ::isspace), patternString.end());
    if (patternString.size() % 2 != 0) patternString.erase(patternString.end());
    //ULog::Get().dprintln(patternString.c_str());
    for (size_t i = 0; i + 2 <= patternString.size(); i += 2)
    {
        std::string sbyte = std::string(&*(patternString.begin() + i), 2);
        if (sbyte.find('?') != std::string::npos)
        {
            out.push_back(0xFF00);
        }
        else
        {
            out.push_back(uint16_t(0x00FF) & (uint16_t)std::stoul(sbyte, nullptr, 16));
        }
    }
    out.shrink_to_fit();
    return out;
}

std::vector<LPVOID> MemPatternScan(LPVOID lpOptBase, std::vector<uint16_t> pattern, bool bScanAllModules = false, size_t MaxMatches = 0)
{
    if (!lpOptBase)
    {
        lpOptBase = GetBaseModule();
    }

    std::vector<LPVOID> OutMatches;
    LPBYTE lpRegionBase = (LPBYTE)lpOptBase;

    ULog& Log = ULog::Get();

    std::stringstream ssPattern;
    for (uint16_t byte : pattern)
    {
        if (byte > uint16_t(0xff))
        {
            ssPattern << "??";
        }
        else
        {
            ssPattern << std::setfill('0') << std::setw(2) << std::hex << byte;
        }
        ssPattern << " ";
    }
    Log.println("Searching for pattern: %s", ssPattern.str().c_str());

    LPBYTE currentAddress = 0;
    while (true)
    {
        MEMORY_BASIC_INFORMATION memoryInfo = { 0 };
        if (VirtualQuery((void*)lpRegionBase, &memoryInfo, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
        {
            if (OutMatches.size() > 0)
            {
                // Just stop quietly when something's already been found.
                break;
            }
            DWORD error = GetLastError();
            if (error == ERROR_INVALID_PARAMETER)
            {
                Log.println("Reached end of scannable memory.");
            }
            else
            {
                Log.println("VirtualQuery failed, error code: %i.", error);
            }
            break;
        }
        lpRegionBase = (LPBYTE)memoryInfo.BaseAddress;

        bool bIsValidMem = memoryInfo.State == MEM_COMMIT &&
            (memoryInfo.Protect & (0xFF/*PAGE_EXECUTE_READWRITE | PAGE_READWRITE | PAGE_READONLY | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY*/)) != 0;

        bool bShouldScan = bScanAllModules || memoryInfo.AllocationBase == lpOptBase;

        CHAR moduleName[100];
        GetModuleFileNameA((HMODULE)memoryInfo.AllocationBase, moduleName, 100);

        if (bIsValidMem && bShouldScan)
        {
            Log.println("Checking region: %p %d %s", lpRegionBase, memoryInfo.RegionSize, moduleName);
            currentAddress = lpRegionBase;
            while (currentAddress < (lpRegionBase + memoryInfo.RegionSize) - pattern.size())
            {
                for (size_t i = 0; i < pattern.size(); i++)
                {
                    uint8_t bitmask = ~uint8_t(pattern[i] >> 8);
                    bool bByteMatches = ((*(uint8_t*)currentAddress) & bitmask) == (uint8_t(pattern[i] & 0xff) & bitmask);
                    ++currentAddress;
                    if (!bByteMatches)
                    {
                        break;
                    }
                    if (i == pattern.size() - 1)
                    {
                        LPVOID lpMatch = currentAddress - pattern.size();
                        Log.println("Found signature at %p", lpMatch);
                        OutMatches.push_back(lpMatch);
                        break;
                    }
                }
            }
        }
        else
        {
            Log.dprintln("Skipped region: %p %d %d %s", lpRegionBase, bIsValidMem, bShouldScan, moduleName);
        }

        if (MaxMatches > 0 && OutMatches.size() >= MaxMatches)
        {
            break;
        }

        lpRegionBase += memoryInfo.RegionSize;
    }
    OutMatches.shrink_to_fit();

    return OutMatches;
}

// Find the target address of a call instruction
LPVOID FindCallTarget(LPVOID pOptBase, std::vector<uint16_t> pattern, int offset = 0, bool bScanAllModules = false)
{
    std::vector<LPVOID> pScan = MemPatternScan(pOptBase, pattern, bScanAllModules, 1);
    if (pScan.size() && pScan[0])
    {
        static constexpr SIZE_T CALL_SIZE = 5;
        static constexpr SIZE_T CALL_OP = 1;
        {
            UINT_PTR Call = UINT_PTR(pScan[0]) + offset;
            ULog::Get().println("Decoding call: %p", Call);
            INT32 RelAddr = *reinterpret_cast<INT32*>(Call + CALL_OP); // Must be signed
            LPVOID pTarget = reinterpret_cast<LPVOID>(Call + CALL_SIZE + RelAddr);
            ULog::Get().println("Call target: %p", pTarget);
            return pTarget;
        }
    }
    return nullptr;
}

// Find the target address of a call instruction
LPVOID FindCallTarget(LPVOID lpOptBase, std::string pattern, int offset = 0, bool bScanAllModules = false)
{
    return FindCallTarget(lpOptBase, StringtoScanPattern(pattern), offset, bScanAllModules);
}

// MinHook wrapper class
class UMinHook
{
    enum EError
    {
        SUCCESS = 0,
        PATTERN_NOT_FOUND,
        INVALID_POINTER,
        MINHOOK_ERROR
    } Error;

    MH_STATUS MHError;

    PVOID pTarget;
    std::string ID;

    void InitCommon(bool bEnableImmediately)
    {
        auto& log = ULog::Get();
        if (!Error)
        {
            log.println("Created hook: %s %p (base+%#x)", ID.c_str(), pTarget, GetRelativeAddress(pTarget));
        }
        else
        {
            log.println("Cannot create hook: %s %s", ID.c_str(), GetErrorString().c_str());
        }

        if (bEnableImmediately)
        {
            MH_QueueEnableHook(pTarget);
        }
    }
    
public:
    UMinHook(std::string ID, std::vector<uint16_t> pattern, PVOID pDetour, PVOID* ppTrampoline, bool bEnableImmediately = true)
        : ID(ID)
    {
        std::vector<PVOID> scan = MemPatternScan(nullptr, pattern, false, 1);
        if (!scan.empty())
        {
            pTarget = scan[0];
            MH_STATUS MHError = MH_CreateHook(pTarget, pDetour, (void**)ppTrampoline);
            Error = (MHError == MH_OK) ? SUCCESS : MINHOOK_ERROR;
        }
        else
        {
            Error = PATTERN_NOT_FOUND;
        }
        InitCommon(bEnableImmediately);
    }

    UMinHook(std::string ID, std::string pattern, PVOID pDetour, PVOID* ppTrampoline, bool bEnableImmediately = true)
    {
        UMinHook(ID, StringtoScanPattern(pattern), pDetour, ppTrampoline, bEnableImmediately);
    }

    UMinHook(std::string ID, LPVOID pTarget, LPVOID pDetour, PVOID* ppTrampoline, bool bEnableImmediately = true)
        : ID(ID), pTarget(pTarget)
    {
        if (pTarget == nullptr)
        {
            Error = INVALID_POINTER;
        }
        else
        {
            MH_STATUS MHError = MH_CreateHook(pTarget, pDetour, (void**)ppTrampoline);
            Error = (MHError == MH_OK) ? SUCCESS : MINHOOK_ERROR;
        }
        InitCommon(bEnableImmediately);
    }

    static void Commit()
    {
        MH_ApplyQueued();
    }

    void QueueEnable()
    {
        MH_QueueEnableHook(pTarget);
    }

    void QueueDisable()
    {
        MH_QueueDisableHook(pTarget);
    }

    void Enable()
    {
        MH_EnableHook(pTarget);
    }

    void Disable()
    {
        MH_DisableHook(pTarget);
    }

    std::string GetErrorString() const
    {
        switch (Error)
        {
        case SUCCESS:
            return "SUCCESS";
        case PATTERN_NOT_FOUND:
            return "PATTERN_NOT_FOUND";
        case MINHOOK_ERROR:
            return std::string("MINHOOK_ERROR") + "." + std::string(MH_StatusToString(MHError));
        default:
            return "UNKNOWN_ERROR";
        }
    }
};

template <size_t bufferSize = 1000>
std::string GetWinAPIString(DWORD(*func)(HMODULE, LPSTR, DWORD), HMODULE hModule = nullptr)
{
    CHAR buffer[bufferSize];
    func(hModule, buffer, bufferSize);
    return std::string(buffer);
}

template <size_t bufferSize = 1000>
std::string GetWinAPIString(DWORD(*func)(DWORD, LPSTR))
{
    CHAR buffer[bufferSize];
    func(bufferSize, buffer);
    return std::string(buffer);
}

template <size_t bufferSize = 1000>
std::string GetWinAPIString(UINT(WINAPI*func)(LPSTR, UINT))
{
    CHAR buffer[bufferSize];
    func(buffer, bufferSize);
    return std::string(buffer);
}

std::string GetFilenameFromPath(std::string path, bool bRemoveExtension = true)
{
    std::string filename = path;
    size_t pos;
    pos = filename.rfind('\\');
    if (pos != std::string::npos)
    {
        filename = filename.substr(pos + 1);
    }
    if (bRemoveExtension)
    {
        pos = filename.rfind('.');
        if (pos != std::string::npos)
        {
            filename = filename.substr(0, pos);
        }
    }
    return filename;
}

std::string GetDLLName(HMODULE hModule = nullptr)
{
    return GetFilenameFromPath(GetWinAPIString(GetModuleFileNameA, hModule));
}

template <typename T = void>
T* PtrByteOffset(void* p, int64_t offset)
{
    return reinterpret_cast<T*>(reinterpret_cast<char*>(p) + offset);
}

#define LOG_FIRST_CALL(fp, paramsFmt, ...)\
{\
    static bool bCalled_ ## fp = false;\
    if (!bCalled_ ## fp)\
    {\
        bCalled_ ## fp = true;\
        ULog::Get().println("First hook call: %p %s, arguments: " paramsFmt, fp, #fp, __VA_ARGS__);\
    }\
}

//#include <map>
//#include <set>
//#include <algorithm>
//
//class USortCalls
//{
//    std::map<void*, UINT64> frames = {};
//    std::map<void*, std::string> names = {};
//    std::vector<std::pair<void*, std::string>> calls = {};
//    size_t count;
//    bool bHasAllFn = false;
//    bool bFinished = false;
//public:
//    USortCalls(size_t count) : count(count) {}
//
//    void RecordCall(void* fp, std::string fnName, size_t frame)
//    {
//        if (bFinished) return;
//
//        if (calls.size() == count)
//        {
//            auto& log = ULog::Get();
//            log.dprintln("Call order:");
//            for (auto& c : calls)
//            {
//                log.dprintln("%p %s", c.first, c.second.c_str());
//            }
//        }
//
//        if (bHasAllFn)
//        {
//            if (std::find_if(calls.begin(), calls.end(), [fp](std::pair<void*, std::string> c) { return c.first == fp; }) != calls.end())
//            {
//                calls.push_back(std::make_pair(fp, fnName));
//            }
//        }
//
//        frames[fp] = frame;
//
//        std::set<size_t> s;
//        std::for_each(frames.begin(), frames.end(), [&s](size_t frame) { s.insert(frame); });
//        if (frames.size() == count && s.size() == 1)
//        {
//            bHasAllFn = true;
//        }
//    }
//};

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

    inline ULog(const ULog&) = delete;

    inline ULog(const char* filename) {
        if (!filename || !strlen(filename))
        {
            return;
        }
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

    inline ~ULog() {
        //if (file)
        //{
        //    fclose(file);
        //    file = nullptr;
        //}
    }

public:

    static std::string FileName;
    static bool bShowTime;

    inline static ULog& Get()
    {
        // Use a pointer to avoid calling the copy constructor
        static ULog *instance = new ULog(FileName.c_str());

        return *instance;
    }

    bool bFirst = true;

    inline void println(const char* fmt, va_list args)
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

    inline void println(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        println(fmt, args);
        va_end(args);
    }

#ifdef _DEBUG
    inline void dprintln(const char* fmt, ...)
    {
        std::string dfmt = "[DEBUG] " + std::string(fmt);
        va_list args;
        va_start(args, fmt);
        println(dfmt.c_str(), args);
        va_end(args);
    }
#else
    inline void dprintln(const char* fmt, ...) {}
#endif
};

//std::string ULog::FileName = "unknown_module.log";
//bool ULog::bShowTime = true;

inline HMODULE GetBaseModule(DWORD processId = 0)
{
    static HMODULE hModule = 0;

    // For subsequent calls just return the first value we got
    if (hModule)
    {
        return hModule;
    }

    if (processId == 0)
    {
        processId = GetCurrentProcessId();
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
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

inline MODULEINFO GetBaseModuleInfo()
{
    static MODULEINFO mod;
    static bool bHasInfo = false;
    if (bHasInfo)
    {
        return mod;
    }
    GetModuleInformation(OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId()), GetBaseModule(), &mod, sizeof(mod));
    bHasInfo = true;
    return mod;
}

// checks if address is in base module
inline bool IsBaseAddress(LPVOID p)
{
    MODULEINFO mod = GetBaseModuleInfo();
    return (UINT_PTR(p) > UINT_PTR(mod.lpBaseOfDll))
        && (UINT_PTR(p) < (UINT_PTR(mod.lpBaseOfDll) + UINT_PTR(mod.SizeOfImage)));
}

inline PVOID GetRelativeAddress(PVOID absAddr)
{
    return PVOID(UINT_PTR(absAddr) - UINT_PTR(GetBaseModule()));
}

inline std::vector<uint16_t> StringtoScanPattern(std::string patternString)
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

inline std::vector<LPVOID> MemPatternScan(LPVOID lpOptBase, std::vector<uint16_t> pattern, bool bScanAllModules = false, size_t MaxMatches = 0)
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
inline LPVOID FindCallTarget(LPVOID pOptBase, std::vector<uint16_t> pattern, int offset = 0, bool bScanAllModules = false)
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
inline LPVOID FindCallTarget(LPVOID lpOptBase, std::string pattern, int offset = 0, bool bScanAllModules = false)
{
    return FindCallTarget(lpOptBase, StringtoScanPattern(pattern), offset, bScanAllModules);
}

class UToggleable
{
protected:
    std::mutex Mutex;
    std::atomic<bool> bEnabled;
    inline virtual void EnableImpl() {}
    inline virtual void DisableImpl() {}
    inline UToggleable() {}
    inline UToggleable(const UToggleable& o)
    {
        bEnabled.store(o.bEnabled.load());
    }
    inline UToggleable(UToggleable&& o) noexcept
    {
        bEnabled.store(o.bEnabled.load());
    }
public:
    inline void Enable()
    {
        std::lock_guard<std::mutex> lock(Mutex);
        if (!bEnabled.load())
        {
            EnableImpl();
            bEnabled.store(true);
        }
    }
    inline void Disable()
    {
        std::lock_guard<std::mutex> lock(Mutex);
        if (!bEnabled.load())
        {
            DisableImpl();
            bEnabled.store(false);
        }
    }
    inline void Toggle()
    {
        bEnabled.load() ? Disable() : Enable();
    }
};

// MinHook wrapper class
class UMinHook : public UToggleable
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
    int depth = 0;

    inline void CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppTrampoline)
    {
        //ULog::Get().dprintln("Creating hook %s %p", ID.c_str(), pTarget);
        auto getOP = [&]() { return *reinterpret_cast<LPBYTE>(pTarget); };
        // check if the target function is aldeary hooked and follow them when necessary
        while (getOP() == 0xE9/*JMP*/ || getOP() == 0xE8/*CALL*/)
        {
            UINT_PTR targetAddr = reinterpret_cast<UINT_PTR>(pTarget);
            INT32 relAddr = *reinterpret_cast<INT32*>(targetAddr + 1);
            pTarget = reinterpret_cast<LPVOID>(targetAddr + 5 + relAddr);
            depth += int(!IsBaseAddress(pTarget));
        }

        if (depth > 0)
        {
            ULog::Get().println("Chaining hooks \"%s\", depth: %d", ID.c_str(), depth);
        }
        this->pTarget = pTarget;

        MH_STATUS MHError = MH_CreateHook(pTarget, pDetour, (void**)ppTrampoline);
        Error = (MHError == MH_OK) ? SUCCESS : MINHOOK_ERROR;
    }

    inline void InitCommon(bool bEnableImmediately)
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
            Enable();
        }
    }
    
public:
    //inline UMinHook(const UMinHook& o) : Error(o.Error), MHError(o.MHError), pTarget(o.pTarget), ID(o.ID), depth(o.depth) {}
    //inline UMinHook(const UMinHook&& o) noexcept : Error(o.Error), MHError(o.MHError), pTarget(o.pTarget), ID(o.ID), depth(o.depth) {}
    //inline UMinHook(const UMinHook&) = default;
    //inline UMinHook(UMinHook&&) = default;

    inline UMinHook(std::string ID, std::vector<uint16_t> pattern, PVOID pDetour, PVOID* ppTrampoline, bool bEnableImmediately = true)
        : ID(ID)
    {
        std::vector<PVOID> scan = MemPatternScan(nullptr, pattern, false, 1);
        if (!scan.empty())
        {
            CreateHook(scan[0], pDetour, ppTrampoline);
        }
        else
        {
            Error = PATTERN_NOT_FOUND;
        }
        InitCommon(bEnableImmediately);
    }

    inline UMinHook(std::string ID, std::string patternstr, PVOID pDetour, PVOID* ppTrampoline, bool bEnableImmediately = true)
        : ID(ID)
    {
        std::vector<UINT16> pattern = StringtoScanPattern(patternstr);
        std::vector<PVOID> scan = MemPatternScan(nullptr, pattern, false, 1);
        if (!scan.empty())
        {
            CreateHook(scan[0], pDetour, ppTrampoline);
        }
        else
        {
            Error = PATTERN_NOT_FOUND;
        }
        InitCommon(bEnableImmediately);
    }

    inline UMinHook(std::string ID, std::string patternstr, int offset, PVOID pDetour, PVOID* ppTrampoline, bool bEnableImmediately = true)
        : ID(ID)
    {
        std::vector<UINT16> pattern = StringtoScanPattern(patternstr);
        std::vector<PVOID> scan = MemPatternScan(nullptr, pattern, false, 1);
        if (!scan.empty())
        {
            CreateHook(reinterpret_cast<LPVOID>(UINT_PTR(scan[0]) + offset), pDetour, ppTrampoline);
        }
        else
        {
            Error = PATTERN_NOT_FOUND;
        }
        InitCommon(bEnableImmediately);
    }

    inline UMinHook(std::string ID, LPVOID pTarget, LPVOID pDetour, PVOID* ppTrampoline, bool bEnableImmediately = true)
        : ID(ID), pTarget(pTarget)
    {
        if (pTarget == nullptr)
        {
            Error = INVALID_POINTER;
        }
        else
        {
            CreateHook(pTarget, pDetour, ppTrampoline);
        }
        InitCommon(bEnableImmediately);
    }

    //static void Commit()
    //{
    //    MH_ApplyQueued();
    //}

    //void QueueEnable()
    //{
    //    MH_QueueEnableHook(pTarget);
    //}

    //void QueueDisable()
    //{
    //    MH_QueueDisableHook(pTarget);
    //}

    inline virtual void EnableImpl() override
    {
        MH_EnableHook(pTarget);
    }

    inline virtual void DisableImpl() override
    {
        MH_DisableHook(pTarget);
    }

    inline std::string GetErrorString() const
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
inline std::string GetWinAPIString(DWORD(*func)(HMODULE, LPSTR, DWORD), HMODULE hModule = nullptr)
{
    CHAR buffer[bufferSize];
    func(hModule, buffer, bufferSize);
    return std::string(buffer);
}

template <size_t bufferSize = 1000>
inline std::string GetWinAPIString(DWORD(*func)(DWORD, LPSTR))
{
    CHAR buffer[bufferSize];
    func(bufferSize, buffer);
    return std::string(buffer);
}

template <size_t bufferSize = 1000>
inline std::string GetWinAPIString(UINT(WINAPI*func)(LPSTR, UINT))
{
    CHAR buffer[bufferSize];
    func(buffer, bufferSize);
    return std::string(buffer);
}

inline std::string GetFilenameFromPath(std::string path, bool bRemoveExtension = true)
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

inline std::string GetDLLName(HMODULE hModule = nullptr)
{
    return GetFilenameFromPath(GetWinAPIString(GetModuleFileNameA, hModule));
}

inline std::string GetDLLDirectory(HMODULE hModule = nullptr)
{
    std::string path = GetWinAPIString(GetModuleFileNameA, hModule);
    size_t pos = path.rfind('\\');
    if (pos != std::string::npos)
    {
        path = path.substr(0, pos);
    }
    return path;
}

template <typename T = void>
inline T* PtrByteOffset(void* p, int64_t offset)
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


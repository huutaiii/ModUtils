#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <fstream>
#include <format>

#include <windows.h>
#include <psapi.h>

#ifdef MODUTILS_PADDING
    #define _CATIMPL(a, b) a ## b
    #define CAT(a, b) _CATIMPL(a, b)
    #define SEQ(pref) CAT(pref, __COUNTER__)
    #define PAD(size) char SEQ(_padding) [size];
#endif

#ifdef MODUTILS_MACROS
    #define _WTEXT_IMPL(s) L##s
    #define WTEXT(s) _WTEXT_IMPL(s)
    #define LOG ULog::Get()
#endif

class ULog
{
public: 
    enum class EItemType
    {
        LOG_INFO,
        LOG_DEBUG,
        LOG_WARNING,
        LOG_ERROR   // why tf is ERROR defined as a macro in winapi
    };

    struct LogType
    {
        EItemType Type;
        inline LogType(EItemType type) : Type(type) {}
    } NextItemType{EItemType::LOG_INFO};

protected:
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

#ifdef NDEBUG
    static constexpr bool IS_DEBUG = false;
#else
    static constexpr bool IS_DEBUG = true;
#endif

public:

    static std::string FileName;
    static bool bShowTime;

    inline static ULog& Get()
    {
        // Use a pointer to avoid calling the copy constructor
        static ULog *instance = new ULog(FileName.c_str());

        return *instance;
    }

    inline void println(const char* fmt, va_list args)
    {

        std::lock_guard<std::mutex> lock(file_mtx);
        fopen_s(&file, FileName.c_str(), "a+");
        if (file)
        {
            if (bShowTime)
            {
                SYSTEMTIME time;
                GetLocalTime(&time);
                fprintf(file, "%02d-%02d-%02d %02d:%02d:%02d.%03d - ", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
            }
            vfprintf(file, fmt, args);
            fprintf(file, "\n");
            //fflush(file);

            fclose(file);
            file = nullptr;
        }
    }

    inline void println(std::string fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        println(fmt.c_str(), args);
        va_end(args);
    }

    inline void eprintln(std::string fmt, ...)
    {
        std::string efmt = "[ERROR] " + (fmt);
        va_list args;
        va_start(args, fmt);
        println(efmt.c_str(), args);
        va_end(args);
    }

#ifdef _DEBUG
    inline void dprintln(std::string fmt, ...)
    {
        std::string dfmt = "[DEBUG] " + (fmt);
        va_list args;
        va_start(args, fmt);
        println(dfmt.c_str(), args);
        va_end(args);
    }
#else
    inline void dprintln(std::string fmt, ...) {}
#endif

    inline static LogType Debug() { return LogType(EItemType::LOG_DEBUG); }
    inline static LogType Warning() { return LogType(EItemType::LOG_WARNING); }
    inline static LogType Error() { return LogType(EItemType::LOG_ERROR); }

    // Writes a new line each call, use std::format or ULog::println to write more data on to one line
    template<typename T>
    inline ULog& operator<<(T value)
    {
        if (NextItemType.Type == EItemType::LOG_DEBUG && !IS_DEBUG)
        {
            return *this;
        }
        std::lock_guard lock(file_mtx);
        std::wfstream file(FileName, std::ios_base::app);
        if (bShowTime)
        {
            SYSTEMTIME time;
            GetLocalTime(&time);
            file << std::format(L"{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} - ", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
        }
        switch (NextItemType.Type)
        {
        default:
        case EItemType::LOG_INFO:
            break;
        case EItemType::LOG_DEBUG:
            file << "[DEBUG] ";
            break;
        case EItemType::LOG_WARNING:
            file << "[WARNING] ";
            break;
        case EItemType::LOG_ERROR:
            file << "[ERROR] ";
            break;
        }
        file << value << std::endl;
        file.close();
        NextItemType = LogType(EItemType::LOG_INFO);
        return *this;
    }

    template<>
    inline ULog& operator<<<LogType>(LogType newType)
    {
        NextItemType = newType;
        return *this;
    }

    template<>
    inline ULog& operator<<<std::string>(std::string value)
    {
        return operator<<(value.c_str());
    }
};

inline std::string ULog::FileName = "unknown_module.log";
inline bool ULog::bShowTime = true;


template <size_t bufferSize = 1000, typename TChar, typename TSize, typename TParam>
inline std::basic_string<TChar> GetWinAPIString(TSize(*fp)(TParam, TChar*, TSize), TParam arg) // __stdcall aka. WINAPI is ignored on x64
{
    TChar buffer[bufferSize];
    TSize outSize = fp(arg, buffer, bufferSize);
    return std::basic_string<TChar>(buffer, outSize);
}

template <size_t bufferSize = 1000, typename TChar, typename TSize>
inline std::basic_string<TChar> GetWinAPIString(TSize(*fp)(TSize, TChar*))
{
    TChar buffer[bufferSize];
    TSize outSize = fp(bufferSize, buffer);
    return std::basic_string<TChar>(buffer, outSize);
}

template <size_t bufferSize = 1000, typename TChar, typename TSize>
inline std::basic_string<TChar> GetWinAPIString(TSize(*fp)(TChar*, TSize))
{
    TChar buffer[bufferSize];
    TSize outSize = fp(buffer, bufferSize);
    return std::basic_string<TChar>(buffer, outSize);
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
    return (UINT_PTR(p) >= UINT_PTR(mod.lpBaseOfDll))
        && (UINT_PTR(p) <= (UINT_PTR(mod.lpBaseOfDll) + UINT_PTR(mod.SizeOfImage)));
}

// checks if address is in current dll
inline bool IsCurrentModuleAddress(LPVOID p, HMODULE hModule)
{
    MODULEINFO mod;
    GetModuleInformation(OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId()), hModule, &mod, sizeof(mod));
    UINT_PTR addr = reinterpret_cast<UINT_PTR>(p);
    return (addr >= UINT_PTR(mod.lpBaseOfDll)) && (addr <= (UINT_PTR(mod.lpBaseOfDll) + UINT_PTR(mod.SizeOfImage)));
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
    Log.println("Search pattern: %s", ssPattern.str().c_str());

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
                Log.println("End of process memory.");
            }
            else
            {
                Log.println("VirtualQuery error: %i.", error);
            }
            break;
        }
        lpRegionBase = (LPBYTE)memoryInfo.BaseAddress;

        // https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
        bool bIsValidMem = memoryInfo.State == MEM_COMMIT &&
            (memoryInfo.Protect & 0xFF) != 0;

        bool bShouldScan = bScanAllModules || memoryInfo.AllocationBase == lpOptBase;

        //CHAR moduleName[100];
        //GetModuleFileNameA((HMODULE)memoryInfo.AllocationBase, moduleName, 100);
        std::string moduleName = GetFilenameFromPath(GetWinAPIString(GetModuleFileNameA, (HMODULE)memoryInfo.AllocationBase), false);

        if (bIsValidMem && bShouldScan)
        {
            Log.println("Searching region: %p %d %s", lpRegionBase, memoryInfo.RegionSize, moduleName.c_str());
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
            Log.dprintln("Skipping region: %p %d %d %s", lpRegionBase, bIsValidMem, bShouldScan, moduleName.c_str());
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

// 5 bytes call/jmp
inline LPVOID GetJumpTargetNear(LPVOID pInstruction)
{
    if (pInstruction == nullptr)
    {
        return nullptr;
    }
    UINT_PTR address = reinterpret_cast<UINT_PTR>(pInstruction);
    BYTE op = *reinterpret_cast<BYTE*>(address);
    if (op == 0xE8/*call*/ || op == 0xE9/*jmp*/)
    {
        INT32 offset = *reinterpret_cast<INT32*>(address + 1);
        return reinterpret_cast<LPVOID>(address + 5 + offset);
    }
    return nullptr;
}

inline LPVOID GetJumpTargetFar(LPVOID pInstruction)
{
    if (pInstruction == nullptr)
    {
        return nullptr;
    }
    UINT_PTR address = reinterpret_cast<UINT_PTR>(pInstruction);
    UINT16 op = *reinterpret_cast<UINT16*>(address);
    if (op == 0x25ff)
    {
        return *reinterpret_cast<LPVOID*>(address + 6);
    }
    return nullptr;
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

inline std::string GetDLLName(HMODULE hModule = nullptr)
{
    return GetFilenameFromPath(GetWinAPIString(GetModuleFileNameA, hModule));
}

// does not contain a trailing backslash
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

inline HWND LastHWnd = nullptr;
inline bool CheckWndText(HWND hwnd, std::wstring title)
{
    ULog::Get().dprintln("hwnd %s %p", GetWinAPIString(GetWindowTextA, hwnd).c_str(), reinterpret_cast<LPVOID>(hwnd));
    if (GetWinAPIString(GetWindowTextW, hwnd).find(title) != std::wstring::npos)
    {
        LastHWnd = hwnd;
        return true;
    }
    return false;
}

inline BOOL CALLBACK EnumWndCallback(HWND hwnd, LPARAM param)
{
    DWORD procID = 0;
    GetWindowThreadProcessId(hwnd, &procID);
    if (procID == GetCurrentProcessId())
    {
        if (CheckWndText(hwnd, *(std::wstring*)(param)))
        {
            return FALSE;
        }
    }
    return TRUE;
}

inline HWND FindWindowHandle(std::wstring title)
{
    EnumWindows(&EnumWndCallback, LPARAM(&title));
    return LastHWnd;
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


std::vector<uint8_t> UTF16ToAOB(std::u16string s16)
{
    std::vector<uint8_t> out;
    for (char16_t c : s16)
    {
        out.push_back(c & 0xff);
        out.push_back(c >> 8);
    }
    return out;
}


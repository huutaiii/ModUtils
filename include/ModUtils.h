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
#include <unordered_map>
#include <format>
#include <filesystem>
#include <algorithm>
#include <atomic>

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
    #define LOG (ULog::Get())
    #define LOG_INFO (ULog::UMessage(ULog::EItemType::LOG_TYPE_INFO))
    #define LOG_DEBUG (ULog::UMessage(ULog::EItemType::LOG_TYPE_DEBUG))
    #define LOG_WARNING (ULog::UMessage(ULog::EItemType::LOG_TYPE_WARNING))
    #define LOG_ERROR (ULog::UMessage(ULog::EItemType::LOG_TYPE_ERROR))
    #define LOG_PLAIN (ULog::UMessage(ULog::EItemType::LOG_TYPE_PLAIN))
#endif

#ifndef ULOG_WRITE_BATCHING
#define ULOG_WRITE_BATCHING 0
#endif


class ULog
{
public: 
    enum class EItemType
    {
        LOG_TYPE_INFO,
        LOG_TYPE_DEBUG,
        LOG_TYPE_WARNING,
        LOG_TYPE_ERROR,
        LOG_TYPE_PLAIN,
    };

protected:
    FILE* file = nullptr;
    std::mutex file_mtx;
    std::mutex fmt_mtx;

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
    static std::string ModuleName;
    static bool bShowTime;
    static bool bOutputToStdOut;

#if ULOG_WRITE_BATCHING
    std::wstringstream WriteBuffer = std::wstringstream();
#else
#endif

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

        if (bOutputToStdOut)
        {
            printf("[%s] ", ModuleName.c_str());
            vprintf(fmt, args);
            printf("\n");
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

    inline void Flush()
    {
#if ULOG_WRITE_BATCHING
        std::lock_guard lock(file_mtx);
        fopen_s(&file, FileName.c_str(), "a+");
        if (file)
        {
            fputws(WriteBuffer.str().c_str(), file);
            fclose(file);
            file = nullptr;
            std::wstringstream().swap(WriteBuffer);
        }
#endif
    }

    class UMessage
    {
        std::wstringstream MsgStream = std::wstringstream();
        EItemType Type;

    public:
        UMessage(EItemType type = EItemType::LOG_TYPE_INFO) : Type(type) {}

        ~UMessage()
        {
            std::wstring line;
            if (Type != EItemType::LOG_TYPE_PLAIN)
            {
                std::wstring timestamp;
                if (bShowTime)
                {
                    SYSTEMTIME time;
                    GetLocalTime(&time);
                    timestamp = std::format(L"{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
                }

                std::wstring tag = L"";
                switch (Type)
                {
                default:
                case EItemType::LOG_TYPE_INFO:
                    break;
                case EItemType::LOG_TYPE_DEBUG:
                    tag = L"[DEBUG] ";
                    break;
                case EItemType::LOG_TYPE_WARNING:
                    tag = L"[WARNING] ";
                    break;
                case EItemType::LOG_TYPE_ERROR:
                    tag = L"[ERROR] ";
                    break;
                }

                std::wstring message = MsgStream.str();
                line = std::format(L"{} - {}{}", timestamp, tag, message);

                if (bOutputToStdOut)
                {
                    std::wstring wModuleName(ModuleName.begin(), ModuleName.end());
                    std::wcout << std::format(L"[{}] {}{}", wModuleName, tag, message) << std::endl;
                }
            }
            else
            {
                line = MsgStream.str();
                if (bOutputToStdOut)
                {
                    std::wcout << MsgStream.str();
                }
            }

#if ULOG_WRITE_BATCHING
            ULog::Get().WriteBuffer << line << std::endl;
#else
            std::lock_guard lock(ULog::Get().file_mtx);
            std::wfstream file(FileName, std::ios_base::app);
            file << line << std::endl;
            file.close();
#endif
        }

        template <typename T>
        inline UMessage& operator<<(T);
    };
};

template<typename T>
inline ULog::UMessage& ULog::UMessage::operator<<(T value)
{
    MsgStream << value;
    return *this;
}

template<>
inline ULog::UMessage& ULog::UMessage::operator<<(std::string string)
{
    MsgStream << string.c_str();
    return *this;
}

inline std::string ULog::FileName = "unknown_module.log";
inline std::string ULog::ModuleName = "UnknownModule";
inline bool ULog::bShowTime = true;
inline bool ULog::bOutputToStdOut = true;


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
    patternString.erase(std::remove_if(patternString.begin(), patternString.end(), [](unsigned char c) { return std::isspace(c); }), patternString.end());
    //if (patternString.size() % 2 != 0) patternString.pop_back();
    std::vector<uint16_t> out(patternString.size() / 2);
    for (size_t i = 0; i < out.size(); ++i)
    {
        std::string sbyte = std::string(&*(patternString.begin() + i * 2), 2);
        if (sbyte.find('?') != std::string::npos)
        {
            out[i] = 0xFF00;
        }
        else
        {
            out[i] = uint16_t(0x00FF) & (uint16_t)std::stoul(sbyte, nullptr, 16);
        }
    }
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

// @return HMODULE Handle to the module that this function is executed in
inline HMODULE GetCurrentModule()
{
    HMODULE hModule = NULL;
    // seems hack-ish
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(&GetCurrentModule), &hModule);
    return hModule;
}

inline HMODULE LoadLibraryString(std::string libFileName)
{
    return LoadLibraryA(libFileName.c_str());
}

inline HMODULE LoadLibraryString(std::wstring libFileName)
{
    return LoadLibraryW(libFileName.c_str());
}

// Tries to loads a DLL and shows an error popup when failed.
// @param std::basic_string<TChar> filename: DLL path relative to current module
// @param HWND hwnd: window handle passed to MessageBox
// @return HMODULE The return value of LoadLibraryA|LoadLibraryW
template <typename TChar>
inline HMODULE TryLoadLibrary(const std::basic_string<TChar> filename, HWND hwnd = NULL)
{
    std::filesystem::path pathThis(GetWinAPIString(GetModuleFileNameW, GetCurrentModule()));
    HMODULE hModule = LoadLibraryString(pathThis.parent_path() / filename);
    if (!hModule)
    {
        DWORD error = GetLastError();
        std::wstring caption = pathThis.filename();
        MessageBoxW(hwnd, std::format(L"Failed to load \"{}\"", std::wstring(filename.begin(), filename.end()).c_str()).c_str(), caption.c_str(), (hwnd ? MB_APPLMODAL : MB_SYSTEMMODAL) | MB_ICONERROR);
        SetLastError(error);
    }
    return hModule;
}

inline HMODULE TryLoadLibrary(const char* pfilename, HWND hwnd = NULL)
{
    return TryLoadLibrary(std::string(pfilename), hwnd);
}

inline HMODULE TryLoadLibrary(const WCHAR* pfilename, HWND hwnd = NULL)
{
    return TryLoadLibrary(std::wstring(pfilename), hwnd);
}

// does not contain a trailing backslash
inline std::string GetDLLDirectory(HMODULE hModule = nullptr)
{
    static std::string path = "";
    if (!path.empty())
    {
        return path;
    }

    path = GetWinAPIString(GetModuleFileNameA, hModule);
    size_t pos = path.rfind('\\');
    if (pos != std::string::npos)
    {
        path = path.substr(0, pos);
    }
    return path;
}

struct UParamEnumWnd
{
    HWND LastHWnd;
    std::wstring Title;
};
inline bool CheckWndText(HWND hwnd, UParamEnumWnd *enumInfo)
{
    // check if the target window can process messages and wait till it can
    // however, this doesn't seem to work and the process hangs anyway
    for (; /*IsHungAppWindow(hwnd) || */!SendMessageTimeoutW(hwnd, WM_NULL, NULL, NULL, SMTO_NORMAL, 1000, NULL);)
    {
        ULog::Get().dprintln("waiting for window to become responsive");
        Sleep(4000);
    }
    ULog::Get().dprintln("hwnd %s %p", GetWinAPIString(GetWindowTextA, hwnd).c_str(), reinterpret_cast<LPVOID>(hwnd));
    if (GetWinAPIString(GetWindowTextW, hwnd).find(enumInfo->Title) != std::wstring::npos)
    {
        enumInfo->LastHWnd = hwnd;
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
        UParamEnumWnd* pInfo = (UParamEnumWnd*)param;
        if (pInfo->Title.size() == 0)
        {
            pInfo->LastHWnd = hwnd;
            return FALSE;
        }
        if (CheckWndText(hwnd, pInfo))
        {
            return FALSE;
        }
    }
    return TRUE;
}

// USE WITH CAUTION. This can cause any window in the current process to hang indefinitely if it's already unresponsive.
// @return HWND Handle to the first window with a matching title
// @param wstring title: can be an empty string, for which the function will return the first window belonging to the current process
inline HWND FindWindowHandle(std::wstring title = L"")
{
    static std::unordered_map<std::wstring, HWND> Results;
    if (title.size() && Results.contains(title))
    {
        return Results[title];
    }
    UParamEnumWnd info(nullptr, title);
    EnumWindows(&EnumWndCallback, LPARAM(&info));
    Results[title] = info.LastHWnd;
    return info.LastHWnd;
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


inline std::vector<uint8_t> UTF16ToAOB(std::u16string s16)
{
    std::vector<uint8_t> out;
    for (char16_t c : s16)
    {
        out.push_back(c & 0xff);
        out.push_back(c >> 8);
    }
    return out;
}


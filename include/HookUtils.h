#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <memory>
#include <functional>
#include <array>

#include "ModUtils.h"
#include "../extern/MinHook.h"

class UToggleable
{
protected:
    std::mutex Mutex;
    std::atomic<bool> bEnabled;
    inline virtual void EnableImpl() {}
    inline virtual void DisableImpl() {}
public:
    inline UToggleable() {}
    inline UToggleable(const UToggleable& o)
    {
        bEnabled.store(o.bEnabled.load());
    }
    inline UToggleable(UToggleable&& o) noexcept
    {
        bEnabled.store(o.bEnabled.load());
    }
    inline void Enable(bool force = false)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        if (force || !bEnabled.load())
        {
            EnableImpl();
            bEnabled.store(true);
        }
    }
    inline void Disable(bool force = false)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        if (force || !bEnabled.load())
        {
            DisableImpl();
            bEnabled.store(false);
        }
    }
    inline void Toggle()
    {
        bEnabled.load() ? Disable() : Enable();
    }
    inline bool IsEnabled()
    {
        return bEnabled.load();
    }
};


// See VirtualMAlloc::Get, VirtualMAlloc::Alloc
class MVirtualAlloc {
    DWORD processId = GetCurrentProcessId();
    DWORD_PTR baseAddress = (DWORD_PTR)GetBaseModule(GetCurrentProcessId());

private:
    SYSTEM_INFO sys;
    MVirtualAlloc()
    {
        GetSystemInfo(&sys);
        ULog::Get().dprintln("Process base address: %p", baseAddress);
        ULog::Get().dprintln("System page size: %u", sys.dwPageSize);
        ULog::Get().dprintln("System allocation granularity: %u", sys.dwAllocationGranularity);
    };

public:
    // Get instance
    static MVirtualAlloc& Get()
    {
        static MVirtualAlloc instance;
        return instance;
    }

private:
    LPBYTE lpScan = 0;
    MEMORY_BASIC_INFORMATION memInfo{0};

    LPVOID lpCurrent = 0;
    size_t bytesAllocated = 0;
    size_t currentPageSize = 0;

    LPVOID Scan()
    {
        lpScan = lpScan ? lpScan : (LPBYTE)baseAddress;
        SIZE_T numBytes;

        do
        {
            lpScan -= sys.dwAllocationGranularity;
            numBytes = VirtualQuery(lpScan, &memInfo, sizeof(memInfo));

            lpScan = static_cast<LPBYTE>(memInfo.BaseAddress);

            if (memInfo.State == MEM_FREE)
            {
                return lpScan;
            }
        } while (numBytes);

        return nullptr;
    }

private:
    std::mutex mtx;

public:

    // Allocate memory below process base address
    // This allows for memory hooks using shorter jump ops (eg. 0xE9)
    // Subsequent calls usually access the same memory page
    // see VirtualAlloc function
    // 
    // @param DWORD dwSize in [1..4096]
    LPVOID Alloc(SIZE_T dwSize, SIZE_T alignment = 1, DWORD flAllocType = MEM_RESERVE | MEM_COMMIT, DWORD flProtec = PAGE_EXECUTE_READWRITE)
    {
        std::lock_guard lock(mtx);
        size_t rem = bytesAllocated % alignment;
        size_t padding = rem ? 0 : alignment - (rem);

        bytesAllocated += padding + dwSize;

        if (!lpCurrent || bytesAllocated > currentPageSize)
        {
            LPVOID lpAlloc = Scan();

            if (!lpAlloc)
            {
                ULog::Get().eprintln("Cannot allocate memory");
                return nullptr;
            }

            ULog::Get().println("Allocating page at: %p", lpScan);

            // Preallocate a region equals to system page size (typically 4KiB)
            lpCurrent = VirtualAlloc(lpAlloc, sys.dwPageSize, flAllocType, flProtec);

            bytesAllocated = static_cast<size_t>(dwSize);
            currentPageSize = static_cast<size_t>(sys.dwPageSize);
        }

        return (LPBYTE)lpCurrent + bytesAllocated - dwSize;
    }

    // there's no deallocation 'cause we don't need it, for now
};


// MinHook wrapper class
class UMinHook : public UToggleable
{
    enum EError
    {
        SUCCESS = 0,
        PATTERN_NOT_FOUND,
        INVALID_POINTER,
        MINHOOK_ERROR,
        MUTEX_ERROR,
    } Error;

    MH_STATUS MHError;
    DWORD WindowsAPIError;

    PVOID pScanResult = nullptr;
    PVOID pTarget;
    std::string ID;
    int depth = 0;

    inline void CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppTrampoline)
    {
        if (!pTarget)
        {
            Error = INVALID_POINTER;
            return;
        }

        auto& log = ULog::Get();

        std::string mtxName = std::vformat("Local\\HOOK_{}", std::make_format_args(pTarget));
        SetLastError(0);
        HANDLE mutex = CreateMutexA(NULL, FALSE, mtxName.c_str());
        if (!mutex)
        {
            Error = MUTEX_ERROR;
            WindowsAPIError = GetLastError();
            return;
        }

        ULog::Get().dprintln("Locking mutex: %s", mtxName.c_str());

        SetLastError(0);
        switch (WaitForSingleObject(mutex, 10000))
        {
        case WAIT_OBJECT_0:
            break;
        case WAIT_ABANDONED:
        case WAIT_FAILED:
        case WAIT_TIMEOUT:
        default:
            Error = MUTEX_ERROR;
            WindowsAPIError = GetLastError();
            return;
        }

        //ULog::Get().dprintln("Creating hook %s %p", ID.c_str(), pTarget);
        auto getOP = [&]() { 
            DWORD oldProtect, dummy;
            VirtualProtect(pTarget, 1, PAGE_READONLY, &oldProtect);
            BYTE byte = *reinterpret_cast<LPBYTE>(pTarget);
            VirtualProtect(pTarget, 1, oldProtect, &dummy);
            return byte;
        };
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

        ULog::Get().println("Creating hook at %p", pTarget);
        MH_STATUS MHError = MH_CreateHook(pTarget, pDetour, (void**)ppTrampoline);
        Error = (MHError == MH_OK) ? SUCCESS : MINHOOK_ERROR;

        if (!Error)
        {
            log.println("Created hook: %s %p (base+%#x)", ID.c_str(), pTarget, GetRelativeAddress(pTarget));
        }
        else
        {
            log.eprintln("Cannot create hook: %s %s", ID.c_str(), GetErrorString().c_str());
        }

        Enable();
        ReleaseMutex(mutex);
    }

    inline void Scan(const std::vector<uint16_t>& pattern, int offset = 0)
    {
        std::vector<LPVOID> scan = MemPatternScan(nullptr, pattern, false, 1);
        if (!scan.empty())
        {
            pScanResult = reinterpret_cast<LPVOID>(reinterpret_cast<UINT_PTR>(scan[0]) + offset);
        }
        else
        {
            Error = PATTERN_NOT_FOUND;
        }
    }

public:
    //inline UMinHook(const UMinHook& o) : Error(o.Error), MHError(o.MHError), pTarget(o.pTarget), ID(o.ID), depth(o.depth) {}
    //inline UMinHook(const UMinHook&& o) noexcept : Error(o.Error), MHError(o.MHError), pTarget(o.pTarget), ID(o.ID), depth(o.depth) {}
    //inline UMinHook(const UMinHook&) = default;
    //inline UMinHook(UMinHook&&) = default;

    inline UMinHook(const std::string& ID, const std::vector<uint16_t>& pattern, PVOID pDetour, PVOID* ppTrampoline)
        : ID(ID)
    {
        Scan(pattern);
        CreateHook(pScanResult, pDetour, ppTrampoline);
    }

    inline UMinHook(const std::string& ID, const std::vector<uint16_t>& pattern, int offset, PVOID pDetour, PVOID* ppTrampoline)
        : ID(ID)
    {
        Scan(pattern, offset);
        CreateHook(pScanResult, pDetour, ppTrampoline);
    }

    inline UMinHook(const std::string& ID, const std::string& patternstr, PVOID pDetour, PVOID* ppTrampoline)
        : ID(ID)
    {
        std::vector<UINT16> pattern = StringtoScanPattern(patternstr);
        Scan(pattern);
        CreateHook(pScanResult, pDetour, ppTrampoline);
    }

    inline UMinHook(const std::string& ID, const std::string& patternstr, int offset, PVOID pDetour, PVOID* ppTrampoline)
        : ID(ID)
    {
        std::vector<UINT16> pattern = StringtoScanPattern(patternstr);
        Scan(pattern, offset);
        CreateHook(pScanResult, pDetour, ppTrampoline);
    }

    inline UMinHook(const std::string& ID, LPVOID pTarget, LPVOID pDetour, PVOID* ppTrampoline)
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
        case INVALID_POINTER:
            return "INVALID_POINTER";
        case MINHOOK_ERROR:
            return std::string("MINHOOK_ERROR") + "." + std::string(MH_StatusToString(MHError));
        case MUTEX_ERROR:
            return std::format("MUTEX_ERROR.{}", WindowsAPIError);
        default:
            return "UNKNOWN_ERROR";
        }
    }

    // returns final hook target
    inline LPVOID GetTarget()
    {
        return pTarget;
    }

    // @return LPVOID The scan result + offset if a scan was required for hook creation, is nullptr otherwise
    inline LPVOID GetScanResult()
    {
        return pScanResult;
    }

    inline std::string GetID()
    {
        return ID;
    }
};

// writes an absolute jump to destination at specified address (14 bytes)
class UHookAbsoluteNoCopy : public UToggleable
{
    static const uint16_t op = 0x25ff;

    LPVOID lpHook;
    LPVOID lpDest;

protected:
    inline void EnableImpl() override
    {
        if (lpHook && lpDest)
        {
            *static_cast<uint64_t*>(lpHook) = static_cast<uint64_t>(op);
            *reinterpret_cast<uint64_t*>(static_cast<uint8_t*>(lpHook) + 6) = reinterpret_cast<uint64_t>(lpDest);
        }
    }
public:

    UHookAbsoluteNoCopy(LPVOID lpHook = nullptr, LPVOID lpDestination = nullptr, size_t offset = 0) : lpDest(lpDestination)
    {
        this->lpHook = static_cast<LPBYTE>(lpHook) + offset;
    }

    inline std::string GetName() { return ""; }
};

// Creates or removes a hook using a relative jump (5 bytes)
// First jump to an intermediate address at which we then do an absolute jump to the custom code
// This way we don't have to determine the size of the custom asm
// We also copy the stolen bytes over to the intermediate location so the custom code can omit the original code
// TODO: add some error handling
class UHookInline : public UToggleable
{
public:
    static const uint8_t OpCall = 0xE8;
    static const uint8_t OpJmp = 0xE9;
    static const unsigned char RelJmpSize = 5;

private:
    MVirtualAlloc& allocator = MVirtualAlloc::Get();

    LPVOID lpHook = nullptr;
    LPVOID lpIntermediate = nullptr;
    bool bExecuteOriginal = true;

    LPVOID lpDestination;
    size_t numBytes;

    bool bUseCall = true;

    bool bCanHook = false;
    std::unique_ptr<UHookAbsoluteNoCopy> pJmpAbs;
    size_t JumpOffset;
    size_t StolenBytesOffset;

    std::function<void()> fnEnable = []() {};
    std::function<void()> fnDisable = []() {};

    //static const std::vector<uint8_t> RSPUp; // lea rsp,[rsp+8] (5B)
    //static const std::vector<uint8_t> RSPDown; // lea rsp,[rsp-8] (5B)

    static constexpr std::array<uint8_t, 5> RSPUp = { 0x48, 0x8D, 0x64, 0x24, 0x08 };
    static constexpr std::array<uint8_t, 5> RSPDown = { 0x48, 0x8D, 0x64, 0x24, 0xf8 };

    // Initialize the intermediate code that we can decide to jump to later
    inline void Init()
    {
        size_t SPDownOffset = RSPUp.size() + numBytes;

        // we still need to store the stolen code somewhere even when we don't want to execute it
        if (bUseCall)
        {
            lpIntermediate = allocator.Alloc(numBytes + 14 + RSPUp.size() + RSPDown.size()); // one 14B jump, two 3B adds
            JumpOffset = numBytes + RSPUp.size() + RSPDown.size();
            StolenBytesOffset = RSPUp.size();
        }
        else
        {
            lpIntermediate = allocator.Alloc(numBytes + 14);
            JumpOffset = numBytes;
            StolenBytesOffset = 0;
        }

        if (!lpIntermediate)
        {
            ULog::Get().eprintln("Cannot allocate memory for hook: %s", msg.c_str());
            return;
        }

        if (bUseCall)
        {
            // move stack pointer up so stolen instructions can access the stack
            memcpy(lpIntermediate, RSPUp.data(), RSPUp.size());
        }

        // copy to be stolen bytes to the imtermediate location
        memcpy(reinterpret_cast<LPVOID>(reinterpret_cast<uint64_t>(lpIntermediate) + StolenBytesOffset), (lpHook), numBytes);

        if (bUseCall)
        {
            // write an instruction to move the stack pointer back down
            memcpy(LPVOID(uintptr_t(lpIntermediate) + SPDownOffset), RSPDown.data(), RSPDown.size());
        }

        // create jump from intermediate code to custom code
        pJmpAbs = std::make_unique<UHookAbsoluteNoCopy>(lpIntermediate, lpDestination, JumpOffset);
        pJmpAbs->Enable();

        ULog::Get().println("Generated inline hook '%s' from %p to %p at %p", msg.c_str(), lpHook, lpDestination, lpIntermediate);
    }

private:

    inline void UHookRelativeIntermediate_Internal(std::vector<uint16_t> pattern, int offset, uintptr_t *pReturnAddress)
    {
        std::vector<void*> scan = MemPatternScan(nullptr, pattern, false, 1);
        if (scan.size())
        {
            lpHook = (void*)(uintptr_t(scan[0]) + offset);
        }
        bCanHook = lpHook != nullptr;
        bUseCall = pReturnAddress == nullptr;
        if (!bUseCall)
        {
            *pReturnAddress = reinterpret_cast<uintptr_t>((char*)lpHook + numBytes);
        }
    }

public:
    const std::string msg;

    UHookInline(UHookInline&) = delete;

    inline UHookInline(
        std::vector<uint16_t> signature,
        size_t numStolenBytes,
        LPVOID destination,
        int offset = 0,
        bool bExecuteOriginal = true,
        uintptr_t *pReturnAddress = nullptr,
        std::string msg = "UnknownHook",
        std::function<void()> enable = []() {},
        std::function<void()> disable = []() {}
    )
        : numBytes(numStolenBytes), lpDestination(destination), msg(msg), fnEnable(enable), fnDisable(disable), bExecuteOriginal(bExecuteOriginal)
    {
        UHookRelativeIntermediate_Internal(signature, offset, pReturnAddress);
    }

    inline UHookInline(
        std::string id,
        std::vector<uint16_t> signature,
        size_t numStolenBytes,
        LPVOID destination,
        int offset = 0
    )
        : numBytes(numStolenBytes), lpDestination(destination), msg(id)
    {
        UHookRelativeIntermediate_Internal(signature, offset, nullptr);
    }

    inline UHookInline(
        std::string id,
        std::vector<uint16_t> signature,
        size_t numStolenBytes,
        LPVOID destination,
        bool bExecuteOriginal,
        int offset = 0
    )
        : numBytes(numStolenBytes), lpDestination(destination), msg(id), bExecuteOriginal(bExecuteOriginal)
    {
        UHookRelativeIntermediate_Internal(signature, offset, nullptr);
    }

    inline UHookInline(
        std::string id,
        std::vector<uint16_t> signature,
        size_t numStolenBytes,
        LPVOID destination,
        uintptr_t* pReturnAddress,
        int offset = 0
    )
        : msg(id), numBytes(numStolenBytes), lpDestination(destination)
    {
        UHookRelativeIntermediate_Internal(signature, offset, pReturnAddress);
    }

    inline const bool HasFoundSignature() const { return bCanHook; }

    inline std::string GetName() { return msg; }

protected:
    inline virtual void EnableImpl() override
    {
        if (!lpIntermediate)
        {
            Init();
        }

        if (!bCanHook || !lpHook || !lpIntermediate)
        {
            ULog::Get().eprintln("Hook activation failed: " + msg);
            return;
        }

        ULog::Get().println("Enabling hook '%s' from %p to %p", msg.c_str(), lpHook, lpDestination);

        // pad the jump in case numBytes > jump instruction size
        DWORD oldProtect, dummy;
        VirtualProtect(lpHook, numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
        memset(lpHook, 0x90, numBytes);

        // write instruction at hook address
        *static_cast<uint8_t*>(lpHook) = bUseCall ? OpCall : OpJmp;
        uint32_t relOffset = static_cast<uint32_t>(static_cast<uint8_t*>(lpIntermediate) - static_cast<uint8_t*>(lpHook) - RelJmpSize);
        relOffset += uint32_t(bExecuteOriginal ? 0 : JumpOffset);

        *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(lpHook) + 1) = relOffset;

        VirtualProtect(lpHook, numBytes, oldProtect, &dummy);
        fnEnable();
    }
    inline virtual void DisableImpl() override
    {

        ULog::Get().println("Disabling hook '%s' from %p to %p", msg.c_str(), lpHook, lpDestination);

        DWORD oldProtect, dummy;
        VirtualProtect(lpHook, numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(lpHook, LPVOID(uintptr_t(lpIntermediate) + StolenBytesOffset), numBytes);
        VirtualProtect(lpHook, numBytes, oldProtect, &dummy);

        fnDisable();
    }
};

//
//class UMemReplace : public UModSwitch
//{
//    unsigned int Length;
//    LPVOID lpDestination = nullptr;
//    LPVOID lpBackup = nullptr;
//    std::string Msg;
//    std::vector<unsigned char> Replacement;
//
//public:
//    UMemReplace(std::string name, std::vector<uint16_t> signature, std::vector<uint8_t> replacement, unsigned int length, int offset = 0)
//        : Msg(name), Length(length), Replacement(replacement)
//    {
//        if (replacement.size() > length)
//        {
//            ModUtils::RaiseError(Msg + ": Invalid arguments");
//        }
//
//        lpDestination = reinterpret_cast<LPVOID>(ModUtils::SigScan(signature, Msg, true));
//        if (!lpDestination)
//        {
//            ModUtils::RaiseError("Cannot find signature for memory replacement: " + Msg);
//        }
//        else
//        {
//            lpDestination = LPBYTE(lpDestination) + offset;
//        }
//    }
//
//    std::string GetName() { return Msg; }
//
//    void Enable() override
//    {
//        if (IsEnabled()) { return; }
//
//        lpBackup = MVirtualAlloc::Get().Alloc(Length);
//        if (lpBackup)
//        {
//            ModUtils::MemCopy(uintptr_t(lpBackup), uintptr_t(lpDestination), Length);
//        }
//        else
//        {
//            ModUtils::RaiseError("Cannot allocate memory for: " + Msg);
//        }
//
//        ModUtils::MemSet(uintptr_t(lpDestination), 0x90, Length);
//        ModUtils::MemCopy(uintptr_t(lpDestination), uintptr_t(Replacement.data()), Replacement.size());
//
//        ModUtils::Log("(%s) replaced memory at %p", Msg.c_str(), lpDestination);
//
//        UModSwitch::Enable();
//    }
//
//    void Disable() override
//    {
//        if (!IsEnabled()) { return; }
//
//        if (!lpBackup)
//        {
//            return;
//        }
//
//        ModUtils::MemCopy(uintptr_t(lpDestination), uintptr_t(lpBackup), Length);
//
//        ModUtils::Log("(%s) restored memory at %p", Msg.c_str(), lpDestination);
//
//        UModSwitch::Disable();
//    }
//};
//

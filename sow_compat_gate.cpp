// Shadow of War Compatibility - one-shot ONLINE play compatibility gate.
//
// The engine only accepts entries in the reviewed build-profile table below.
// It never
// changes networking/firewall/services/registry, edits the installed package,
// or writes WGS.  Default invocation is inert.  The explicit controller mode
// enables the documented package-debug hook and opens a semantically verified
// official desktop app-link.  The user clicks Play in Xbox; Windows then starts this
// executable as debugger while the title's initial thread is still suspended.
//
// Safety order in the Windows-only --gate callback:
//   1. authenticate the controller journal and Windows-supplied PID/TID;
//   2. validate package/path/creation/architecture/PE/instruction contexts;
//   3. NOP only the pinned failing StoreConfiguration::IsStoreWebAccountId
//      call; the title's save, submit and delete paths remain original;
//   4. retain one helper-owned extra suspension throughout validation/patching,
//      verify the compatibility patch, then prove ResumeThread transitions
//      2->1 and 1->0;
//   5. publish PATCHED_RESUMED.  The package-debug hook stays owned until the
//      exact target exits.  A file-identity-verified System32 RuntimeBroker is
//      released without title IPC; replacement title activations are rejected
//      by the durable one-shot claim;
//   6. after exact target exit, terminate any package straggler and disable the
//      package-debug hook through the journaled recovery protocol.
//
// Every patch failure after exact target binding terminates that exact still-
// suspended process.  The patch is process-local and disappears at process
// exit.  WGS verification is read-only and belongs to the wrapper.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <aclapi.h>
#include <appmodel.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl_core.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wtsapi32.lib")

namespace {

using Microsoft::WRL::ComPtr;

struct BuildProfile {
    wchar_t const* id;
    wchar_t const* processName;
    wchar_t const* relativeImagePath;
    wchar_t const* packageFullName;
    wchar_t const* appUserModelId;
    char const* packageFullNameUtf8;
    std::array<std::uint8_t, 32> manifestSha256;
    DWORD timeDateStamp;
    DWORD sizeOfImage;
    std::uintptr_t storeAccountCallRva;
    std::array<std::uint8_t, 5> storeCallOriginal;
    std::array<std::uint8_t, 5> storeCallReplacement;
    std::uintptr_t writerContextRva;
    std::array<std::uint8_t, 32> writerContext;
    std::uintptr_t deleteContextRva;
    std::array<std::uint8_t, 32> deleteContext;
    std::uintptr_t storeContextRva;
    std::array<std::uint8_t, 32> storeContext;
};

// Adding a build requires an independently reviewed profile and release.  The
// engine never searches for a "close enough" instruction sequence.
constexpr BuildProfile kSupportedProfiles[] = {{
    L"sow-msstore-x64-1.0.28.2",
    L"ShadowOfWar.exe",
    L"UWP64\\ShadowOfWar.exe",
    L"WarnerBros.Interactive.WB-Kraken_1.0.28.2_x64__ktmk1xygcecda",
    L"WarnerBros.Interactive.WB-Kraken_ktmk1xygcecda!Kraken.D3D11.C",
    "WarnerBros.Interactive.WB-Kraken_1.0.28.2_x64__ktmk1xygcecda",
    {0x68, 0xF4, 0xA4, 0x61, 0xE8, 0xF1, 0x43, 0xFC,
     0x84, 0x76, 0xEF, 0x8B, 0xA4, 0xD5, 0xE2, 0x73,
     0xC6, 0xD9, 0xB3, 0xD9, 0xBD, 0x4A, 0xE3, 0x11,
     0xBD, 0xF0, 0x29, 0x6B, 0x71, 0xA0, 0x34, 0x94},
    0x5B7F59E8,
    0x03DCC000,
    0x00F60B15,
    {0xE8, 0xC6, 0xFA, 0xFF, 0xFF},
    {0x90, 0x90, 0x90, 0x90, 0x90},
    0x00E14450,
    {0x48, 0x8B, 0xC4, 0x57, 0x41, 0x54, 0x41, 0x55,
     0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0xC0,
     0x02, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x50,
     0xFE, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x58, 0x10},
    0x038110F0,
    {0x48, 0x89, 0xE0, 0x57, 0x48, 0x83, 0xEC, 0x70,
     0x48, 0xC7, 0x80, 0xB8, 0xFF, 0xFF, 0xFF, 0xFE,
     0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x58, 0x10, 0x48,
     0x89, 0x70, 0x18, 0x48, 0x8B, 0x05, 0x7E, 0x8B},
    0x00F60B09,
    {0x48, 0x8B, 0xCB, 0xE8, 0x77, 0xA3, 0xE7, 0xFF,
     0x90, 0x49, 0x8B, 0xCE, 0xE8, 0xC6, 0xFA, 0xFF,
     0xFF, 0x49, 0x8B, 0x8F, 0x68, 0x01, 0x00, 0x00,
     0x48, 0x8B, 0x01, 0xFF, 0x50, 0x28, 0x49, 0x89}}};

constexpr BuildProfile const& kProfile = kSupportedProfiles[0];
constexpr auto kProcessName = kProfile.processName;
constexpr auto kExpectedRelativeImagePath = kProfile.relativeImagePath;
constexpr auto kExpectedPackageFullName = kProfile.packageFullName;
constexpr auto kExpectedAppUserModelId = kProfile.appUserModelId;
constexpr auto kExpectedPackageFullNameUtf8 = kProfile.packageFullNameUtf8;
constexpr auto const& kExpectedManifestSha256 = kProfile.manifestSha256;
constexpr wchar_t kJournalFileName[] = L"active.journal";
constexpr wchar_t kStagingBaseName[] = L"SowCompat";
constexpr wchar_t kGateFileName[] = L"g.exe";
constexpr bool kReviewedRunnable = true;
constexpr wchar_t kMutexName[] =
    L"Global\\SowPackageGate-WB-Kraken-1.0.28.2";
constexpr std::size_t kMaxRegisteredDebuggerCommandChars = 1024;
constexpr std::size_t kWorstCaseWindowsPidTidSuffixChars = 34;

constexpr auto kExpectedTimeDateStamp = kProfile.timeDateStamp;
constexpr auto kExpectedSizeOfImage = kProfile.sizeOfImage;
constexpr auto kStoreAccountCallRva = kProfile.storeAccountCallRva;
constexpr auto const& kStoreCallOriginal = kProfile.storeCallOriginal;
constexpr auto const& kStoreCallNops = kProfile.storeCallReplacement;
constexpr auto kWriterContextRva = kProfile.writerContextRva;
constexpr auto const& kWriterContext = kProfile.writerContext;
constexpr auto kDeleteContextRva = kProfile.deleteContextRva;
constexpr auto const& kDeleteContext = kProfile.deleteContext;
constexpr auto kStoreContextRva = kProfile.storeContextRva;
constexpr auto const& kStoreContext = kProfile.storeContext;

constexpr DWORD kProcessAccess = PROCESS_QUERY_LIMITED_INFORMATION |
                                 PROCESS_QUERY_INFORMATION |
                                 PROCESS_VM_READ | PROCESS_VM_WRITE |
                                 PROCESS_VM_OPERATION | PROCESS_TERMINATE |
                                 SYNCHRONIZE;
constexpr DWORD kThreadAccess = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                THREAD_QUERY_INFORMATION | SYNCHRONIZE;
constexpr auto kControllerLaunchTimeout = std::chrono::minutes(10);
constexpr auto kPlaySessionTimeout = std::chrono::hours(24);
constexpr auto kExitUnmapGrace = std::chrono::seconds(3);
constexpr auto kPollInterval = std::chrono::milliseconds(50);

using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG,
                                                 PULONG);

struct RemoteProcessBasicInformation {
    LONG exitStatus;
    PVOID pebBaseAddress;
    ULONG_PTR affinityMask;
    LONG basePriority;
    ULONG_PTR uniqueProcessId;
    ULONG_PTR inheritedFromUniqueProcessId;
};

static_assert(sizeof(RemoteProcessBasicInformation) == 48);
static_assert(offsetof(RemoteProcessBasicInformation, pebBaseAddress) == 8);
static_assert(offsetof(RemoteProcessBasicInformation, uniqueProcessId) == 32);

struct Handle {
    HANDLE value = nullptr;
    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    Handle(Handle const&) = delete;
    Handle& operator=(Handle const&) = delete;
    Handle(Handle&& other) noexcept : value(other.value) {
        other.value = nullptr;
    }
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
            value = other.value;
            other.value = nullptr;
        }
        return *this;
    }
    ~Handle() {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
    }
    explicit operator bool() const {
        return value && value != INVALID_HANDLE_VALUE;
    }
};

struct OwnedMutex {
    Handle handle;
    bool owned = false;
    bool abandoned = false;
    OwnedMutex() = default;
    OwnedMutex(Handle&& value, bool hasOwnership, bool wasAbandoned)
        : handle(std::move(value)), owned(hasOwnership),
          abandoned(wasAbandoned) {}
    OwnedMutex(OwnedMutex const&) = delete;
    OwnedMutex& operator=(OwnedMutex const&) = delete;
    OwnedMutex(OwnedMutex&& other) noexcept
        : handle(std::move(other.handle)), owned(other.owned),
          abandoned(other.abandoned) {
        other.owned = false;
        other.abandoned = false;
    }
    ~OwnedMutex() {
        if (owned && handle) ReleaseMutex(handle.value);
    }
    explicit operator bool() const { return owned && static_cast<bool>(handle); }
};

struct CoInit {
    HRESULT status = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ~CoInit() {
        if (status == S_OK || status == S_FALSE) CoUninitialize();
    }
    bool ok() const { return status == S_OK || status == S_FALSE; }
};

struct Journal {
    std::string stage;
    std::string nonce;
    std::uint64_t armTime100ns = 0;
    std::wstring resultPath;
    std::wstring auxiliaryPath;
    DWORD controllerPid = 0;
    std::uint64_t controllerCreation100ns = 0;
    HRESULT lastHr = S_OK;
};

struct GateResult {
    std::string status;
    std::string nonce;
    std::string challenge;
    std::string message;
    DWORD code = 0;
    DWORD pid = 0;
    DWORD tid = 0;
    DWORD helperPid = 0;
    std::uint64_t targetCreation100ns = 0;
    std::uint64_t helperCreation100ns = 0;
};

struct GateClaim {
    std::string nonce;
    DWORD targetPid = 0;
    DWORD targetTid = 0;
    std::uint64_t targetCreation100ns = 0;
    DWORD helperPid = 0;
    std::uint64_t helperCreation100ns = 0;
};

struct RecoveryReceipt {
    std::string attemptNonce;
    std::string outcome;
    std::string nonce;
    std::string priorStage;
    std::string lastHr;
    DWORD recoveryPid = 0;
    std::uint64_t recoveryCreation100ns = 0;
    DWORD sessionId = 0;
};

std::atomic<bool> gCancelled{false};

BOOL WINAPI ConsoleControlHandler(DWORD control) {
    if (control == CTRL_C_EVENT || control == CTRL_BREAK_EVENT ||
        control == CTRL_CLOSE_EVENT || control == CTRL_LOGOFF_EVENT ||
        control == CTRL_SHUTDOWN_EVENT) {
        gCancelled.store(true, std::memory_order_relaxed);
        return TRUE;
    }
    return FALSE;
}

enum class InteractiveSessionCheck {
    onlyCurrent,
    otherPresent,
    error,
};

InteractiveSessionCheck CheckInteractiveSessions(DWORD* currentSessionOut = nullptr) {
    DWORD currentSession = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &currentSession))
        return InteractiveSessionCheck::error;
    if (currentSession == 0) return InteractiveSessionCheck::error;
    // Callers that must contain only identities from their own session still
    // need the verified current-session id when another interactive session is
    // present.  Publish it before the WTS policy decision below.
    if (currentSessionOut) *currentSessionOut = currentSession;
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions,
                               &count)) {
        return InteractiveSessionCheck::error;
    }
    bool currentInteractive = false;
    bool otherPresent = false;
    bool queryError = false;
    DWORD interactiveCount = 0;
    for (DWORD index = 0; index < count; ++index) {
        WTS_SESSION_INFOW const& session = sessions[index];
        if (session.State == WTSActive || session.State == WTSConnected) {
            ++interactiveCount;
            if (session.SessionId == currentSession) {
                currentInteractive = true;
            } else {
                otherPresent = true;
            }
        }
        if (session.SessionId != currentSession) {
            // Active/Connected are not the only states involved in an RDP or
            // Fast User Switching transition.  Treat ConnectQuery/Shadow as
            // conflicting even before a username is visible, and treat any
            // other named session as a retained interactive login.  A failed
            // username query is ambiguous and therefore fail-closed.
            if (session.State == WTSConnectQuery || session.State == WTSShadow)
                otherPresent = true;
            LPWSTR userName = nullptr;
            DWORD userNameBytes = 0;
            bool userQuery = WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE, session.SessionId, WTSUserName,
                &userName, &userNameBytes) != FALSE;
            if (!userQuery) {
                queryError = true;
            } else {
                if (userName && userNameBytes >= sizeof(wchar_t) &&
                    userName[0] != L'\0') {
                    otherPresent = true;
                }
            }
            if (userName) WTSFreeMemory(userName);
        }
    }
    WTSFreeMemory(sessions);
    if (queryError) return InteractiveSessionCheck::error;
    if (!currentInteractive || interactiveCount != 1)
        return otherPresent ? InteractiveSessionCheck::otherPresent
                            : InteractiveSessionCheck::error;
    return otherPresent ? InteractiveSessionCheck::otherPresent
                        : InteractiveSessionCheck::onlyCurrent;
}

std::wstring ErrorText(DWORD error = GetLastError()) {
    wchar_t* message = nullptr;
    DWORD count = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    std::wstring result = count && message ? std::wstring(message, count)
                                           : L"Win32 error " + std::to_wstring(error);
    if (message) LocalFree(message);
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n'))
        result.pop_back();
    return result;
}

std::wstring HresultText(HRESULT value) {
    std::wostringstream out;
    out << L"0x" << std::hex << std::uppercase
        << static_cast<unsigned long>(value) << L" ("
        << ErrorText(static_cast<DWORD>(value)) << L")";
    return out.str();
}

bool EqualInsensitive(std::wstring const& a, std::wstring const& b) {
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
}

std::optional<std::string> WideToUtf8(std::wstring const& value) {
    if (value.empty()) return std::string();
    int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                     static_cast<int>(value.size()), nullptr, 0,
                                     nullptr, nullptr);
    if (needed <= 0) return std::nullopt;
    std::string result(static_cast<std::size_t>(needed), '\0');
    int written = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), needed, nullptr, nullptr);
    if (written != needed) return std::nullopt;
    return result;
}

std::optional<std::wstring> Utf8ToWide(std::string const& value) {
    if (value.empty()) return std::wstring();
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                     static_cast<int>(value.size()), nullptr, 0);
    if (needed <= 0) return std::nullopt;
    std::wstring result(static_cast<std::size_t>(needed), L'\0');
    int written = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), needed);
    if (written != needed) return std::nullopt;
    return result;
}

std::optional<std::wstring> CurrentExecutablePath() {
    std::vector<wchar_t> buffer(32768);
    DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
                                      static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return std::nullopt;
    return std::wstring(buffer.data(), length);
}

std::optional<std::wstring> FullPath(std::wstring const& path) {
    std::vector<wchar_t> buffer(32768);
    DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()),
                                    buffer.data(), nullptr);
    if (length == 0 || length >= buffer.size()) return std::nullopt;
    return std::wstring(buffer.data(), length);
}

std::wstring ParentDirectory(std::wstring const& path) {
    auto slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
}

std::wstring JoinPath(std::wstring const& directory, std::wstring const& leaf) {
    if (directory.empty()) return leaf;
    if (directory.back() == L'\\' || directory.back() == L'/')
        return directory + leaf;
    return directory + L"\\" + leaf;
}

std::optional<std::wstring> EnvironmentValue(wchar_t const* name) {
    DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0 || needed > 32768) return std::nullopt;
    std::vector<wchar_t> buffer(needed);
    DWORD written = GetEnvironmentVariableW(name, buffer.data(), needed);
    if (written == 0 || written >= needed) return std::nullopt;
    return std::wstring(buffer.data(), written);
}

std::optional<std::wstring> StableStagingBaseForSelf() {
    auto self = CurrentExecutablePath();
    if (!self) return std::nullopt;
    return FullPath(ParentDirectory(ParentDirectory(*self)));
}

std::wstring JournalPathForSelf() {
    auto base = StableStagingBaseForSelf();
    return base ? JoinPath(*base, kJournalFileName) : std::wstring();
}

std::optional<std::wstring> ResultPathForExecutable(
    std::wstring const& executable, std::string const& nonce) {
    if (nonce.size() != 32 ||
        !std::all_of(nonce.begin(), nonce.end(), [](char value) {
            return (value >= '0' && value <= '9') ||
                   (value >= 'a' && value <= 'f');
        })) return std::nullopt;
    std::wstring nonceWide(nonce.begin(), nonce.end());
    return FullPath(JoinPath(
        ParentDirectory(executable),
        L"sow_online_play_result_" + nonceWide + L".txt"));
}

std::optional<std::vector<std::uint8_t>> CurrentUserSidBytes() {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
        return std::nullopt;
    Handle token(raw);
    DWORD needed = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0)
        return std::nullopt;
    std::vector<std::uint8_t> buffer(needed);
    if (!GetTokenInformation(token.value, TokenUser, buffer.data(), needed,
                             &needed)) {
        return std::nullopt;
    }
    auto user = reinterpret_cast<TOKEN_USER const*>(buffer.data());
    DWORD sidLength = GetLengthSid(user->User.Sid);
    std::vector<std::uint8_t> sid(sidLength);
    if (!CopySid(sidLength, sid.data(), user->User.Sid)) return std::nullopt;
    return sid;
}

std::optional<std::vector<std::uint8_t>> WellKnownSidBytes(
    WELL_KNOWN_SID_TYPE type) {
    DWORD size = SECURITY_MAX_SID_SIZE;
    std::vector<std::uint8_t> sid(size);
    if (!CreateWellKnownSid(type, nullptr, sid.data(), &size))
        return std::nullopt;
    sid.resize(size);
    return sid;
}

OwnedMutex AcquireProtectedGlobalMutex() {
    auto userSid = CurrentUserSidBytes();
    if (!userSid) return OwnedMutex();

    LPWSTR sidText = nullptr;
    if (!ConvertSidToStringSidW(
            reinterpret_cast<PSID>(userSid->data()), &sidText)) {
        return OwnedMutex();
    }
    std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;";
    sddl += sidText;
    sddl += L")";
    LocalFree(sidText);

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        return OwnedMutex();
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;
    Handle handle(CreateMutexW(&attributes, FALSE, kMutexName));
    LocalFree(descriptor);
    if (!handle) return OwnedMutex();

    DWORD wait = WaitForSingleObject(handle.value, 0);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED)
        return OwnedMutex();
    return OwnedMutex(std::move(handle), true, wait == WAIT_ABANDONED);
}

bool PrivateLocalDirectoryForSelf() {
    auto self = CurrentExecutablePath();
    if (!self) return false;
    auto canonicalSelf = FullPath(*self);
    auto directory = FullPath(ParentDirectory(*self));
    if (!canonicalSelf || !directory || directory->size() < 3 ||
        (*directory)[1] != L':' || (*directory)[2] != L'\\' ||
        directory->find(L':', 2) != std::wstring::npos ||
        directory->rfind(L"\\\\", 0) == 0 ||
        directory->rfind(L"\\\\?\\", 0) == 0) {
        return false;
    }
    auto localAppData = EnvironmentValue(L"LOCALAPPDATA");
    auto expectedBase = localAppData
        ? FullPath(JoinPath(*localAppData, kStagingBaseName)) : std::nullopt;
    auto actualBase = FullPath(ParentDirectory(*directory));
    auto slash = directory->find_last_of(L"\\/");
    auto selfSlash = canonicalSelf->find_last_of(L"\\/");
    std::wstring runName = slash == std::wstring::npos
        ? std::wstring() : directory->substr(slash + 1);
    std::wstring fileName = selfSlash == std::wstring::npos
        ? std::wstring() : canonicalSelf->substr(selfSlash + 1);
    bool runNameValid = runName.size() == 18 &&
        runName.rfind(L"r-", 0) == 0 &&
        std::all_of(runName.begin() + 2, runName.end(), [](wchar_t value) {
            return (value >= L'0' && value <= L'9') ||
                   (value >= L'a' && value <= L'f');
        });
    if (!expectedBase || !actualBase ||
        _wcsicmp(expectedBase->c_str(), actualBase->c_str()) != 0 ||
        !runNameValid || _wcsicmp(fileName.c_str(), kGateFileName) != 0) {
        return false;
    }

    DWORD dirAttributes = GetFileAttributesW(directory->c_str());
    DWORD baseAttributes = GetFileAttributesW(actualBase->c_str());
    DWORD exeAttributes = GetFileAttributesW(canonicalSelf->c_str());
    if (dirAttributes == INVALID_FILE_ATTRIBUTES ||
        !(dirAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (dirAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        baseAttributes == INVALID_FILE_ATTRIBUTES ||
        !(baseAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (baseAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        exeAttributes == INVALID_FILE_ATTRIBUTES ||
        (exeAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
        return false;
    }
    wchar_t volumeRoot[MAX_PATH]{};
    if (!GetVolumePathNameW(directory->c_str(), volumeRoot, MAX_PATH) ||
        GetDriveTypeW(volumeRoot) != DRIVE_FIXED) {
        return false;
    }

    auto user = CurrentUserSidBytes();
    auto system = WellKnownSidBytes(WinLocalSystemSid);
    auto admins = WellKnownSidBytes(WinBuiltinAdministratorsSid);
    if (!user || !system || !admins) return false;

    auto privateAcl = [&](std::wstring const& path) {
        PSID owner = nullptr;
        PACL dacl = nullptr;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        DWORD status = GetNamedSecurityInfoW(
            const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, nullptr, &dacl, nullptr, &descriptor);
        if (status != ERROR_SUCCESS || !descriptor || !owner || !dacl)
            return false;
        bool okay = true;
        SECURITY_DESCRIPTOR_CONTROL control{};
        DWORD revision = 0;
        if (!GetSecurityDescriptorControl(descriptor, &control, &revision) ||
            !(control & SE_DACL_PROTECTED) ||
            (!EqualSid(owner, user->data()) &&
             !EqualSid(owner, system->data()) &&
             !EqualSid(owner, admins->data()))) okay = false;
        bool sawUser = false;
        bool sawSystem = false;
        bool sawAdmins = false;
        ACL_SIZE_INFORMATION info{};
        if (okay && !GetAclInformation(
                dacl, &info, sizeof(info), AclSizeInformation)) okay = false;
        for (DWORD index = 0; okay && index < info.AceCount; ++index) {
            void* rawAce = nullptr;
            if (!GetAce(dacl, index, &rawAce)) { okay = false; break; }
            auto header = static_cast<ACE_HEADER*>(rawAce);
            if ((header->AceFlags & INHERITED_ACE) ||
                header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
                okay = false;
                break;
            }
            auto ace = static_cast<ACCESS_ALLOWED_ACE*>(rawAce);
            PSID sid = &ace->SidStart;
            bool matched = false;
            if (EqualSid(sid, user->data())) { sawUser = true; matched = true; }
            if (EqualSid(sid, system->data())) { sawSystem = true; matched = true; }
            if (EqualSid(sid, admins->data())) { sawAdmins = true; matched = true; }
            if (!matched) okay = false;
        }
        LocalFree(descriptor);
        return okay && sawUser && sawSystem && sawAdmins;
    };
    return privateAcl(*actualBase) && privateAcl(*directory);
}

std::string HexHresult(HRESULT value) {
    std::ostringstream out;
    out << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
        << static_cast<std::uint32_t>(value);
    return out.str();
}

bool ContainsLineDelimiter(std::string const& value) {
    return value.find('\r') != std::string::npos ||
           value.find('\n') != std::string::npos;
}

bool WriteAll(HANDLE file, char const* data, std::size_t size) {
    while (size != 0) {
        DWORD chunk = static_cast<DWORD>(
            std::min<std::size_t>(size, std::numeric_limits<DWORD>::max()));
        DWORD written = 0;
        if (!WriteFile(file, data, chunk, &written, nullptr) || written == 0)
            return false;
        data += written;
        size -= written;
    }
    return true;
}

bool AtomicWriteUtf8(std::wstring const& destination, std::string const& data) {
    std::array<unsigned char, 16> random{};
    if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return false;
    static constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring randomText;
    randomText.reserve(random.size() * 2);
    for (unsigned char byte : random) {
        randomText.push_back(hex[byte >> 4]);
        randomText.push_back(hex[byte & 0x0F]);
    }
    std::wstring temporary = destination + L".tmp." +
        std::to_wstring(GetCurrentProcessId()) + L"." + randomText;
    Handle file(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) return false;
    bool ok = WriteAll(file.value, data.data(), data.size()) &&
              FlushFileBuffers(file.value);
    if (!CloseHandle(file.value)) ok = false;
    file.value = nullptr;
    if (ok) {
        ok = false;
        for (unsigned attempt = 0; attempt != 80; ++attempt) {
            if (MoveFileExW(temporary.c_str(), destination.c_str(),
                            MOVEFILE_REPLACE_EXISTING |
                                MOVEFILE_WRITE_THROUGH)) {
                ok = true;
                break;
            }
            DWORD error = GetLastError();
            if (error != ERROR_SHARING_VIOLATION &&
                error != ERROR_LOCK_VIOLATION) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    }
    if (!ok) DeleteFileW(temporary.c_str());
    return ok;
}

std::optional<std::string> ReadSmallUtf8File(std::wstring const& path) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) return std::nullopt;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.value, &size) || size.QuadPart < 0 ||
        size.QuadPart > 64 * 1024) {
        return std::nullopt;
    }
    std::string result(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    if (!result.empty() &&
        (!ReadFile(file.value, result.data(), static_cast<DWORD>(result.size()),
                   &read, nullptr) || read != result.size())) {
        return std::nullopt;
    }
    return result;
}

std::optional<std::map<std::string, std::string>> ParseFields(
    std::string const& text) {
    if (text.empty() || text.back() != '\n' || text.find('\r') != std::string::npos)
        return std::nullopt;
    std::map<std::string, std::string> fields;
    std::size_t cursor = 0;
    while (cursor < text.size()) {
        auto end = text.find('\n', cursor);
        if (end == std::string::npos || end == cursor) return std::nullopt;
        auto line = text.substr(cursor, end - cursor);
        auto equals = line.find('=');
        if (equals == std::string::npos || equals == 0 ||
            line.find('=', equals + 1) != std::string::npos) {
            return std::nullopt;
        }
        auto key = line.substr(0, equals);
        auto value = line.substr(equals + 1);
        if (!fields.emplace(std::move(key), std::move(value)).second)
            return std::nullopt;
        cursor = end + 1;
    }
    return fields;
}

template <typename T>
std::optional<T> ParseUnsigned(std::string const& text, int base = 10) {
    if (text.empty()) return std::nullopt;
    T value{};
    auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (parsed.ec != std::errc() || parsed.ptr != text.data() + text.size())
        return std::nullopt;
    return value;
}

std::string SerializeJournal(Journal const& journal) {
    auto result = WideToUtf8(journal.resultPath);
    auto auxiliary = WideToUtf8(journal.auxiliaryPath);
    if (!result || !auxiliary || ContainsLineDelimiter(*result) ||
        ContainsLineDelimiter(*auxiliary)) {
        return {};
    }
    std::ostringstream out;
    out << "magic=SOW_PACKAGE_GATE_JOURNAL_V1\n"
        << "package=" << kExpectedPackageFullNameUtf8 << "\n"
        << "stage=" << journal.stage << "\n"
        << "nonce=" << journal.nonce << "\n"
        << "arm_100ns=" << journal.armTime100ns << "\n"
        << "result_utf8=" << *result << "\n"
        << "auxiliary_utf8=" << *auxiliary << "\n"
        << "controller_pid=" << journal.controllerPid << "\n"
        << "controller_creation_100ns=" << journal.controllerCreation100ns << "\n"
        << "last_hr=" << HexHresult(journal.lastHr) << "\n";
    return out.str();
}

std::optional<Journal> ParseJournal(std::string const& text) {
    auto fields = ParseFields(text);
    if (!fields || fields->size() != 10 ||
        (*fields)["magic"] != "SOW_PACKAGE_GATE_JOURNAL_V1" ||
        (*fields)["package"] != kExpectedPackageFullNameUtf8) {
        return std::nullopt;
    }
    static constexpr std::array<char const*, 10> keys = {
        "magic", "package", "stage", "nonce", "arm_100ns", "result_utf8",
        "auxiliary_utf8", "controller_pid", "controller_creation_100ns", "last_hr"};
    for (auto key : keys) if (!fields->count(key)) return std::nullopt;
    auto arm = ParseUnsigned<std::uint64_t>((*fields)["arm_100ns"]);
    auto hr = ParseUnsigned<std::uint32_t>((*fields)["last_hr"], 16);
    auto result = Utf8ToWide((*fields)["result_utf8"]);
    auto auxiliary = Utf8ToWide((*fields)["auxiliary_utf8"]);
    auto controllerPid = ParseUnsigned<DWORD>((*fields)["controller_pid"]);
    auto controllerCreation = ParseUnsigned<std::uint64_t>(
        (*fields)["controller_creation_100ns"]);
    if (!arm || !hr || !result || !auxiliary || !controllerPid ||
        !controllerCreation || *controllerPid == 0 || *controllerCreation == 0)
        return std::nullopt;
    Journal journal;
    journal.stage = (*fields)["stage"];
    journal.nonce = (*fields)["nonce"];
    journal.armTime100ns = *arm;
    journal.resultPath = *result;
    journal.auxiliaryPath = *auxiliary;
    journal.controllerPid = *controllerPid;
    journal.controllerCreation100ns = *controllerCreation;
    journal.lastHr = static_cast<HRESULT>(*hr);
    return journal;
}

bool WriteJournal(std::wstring const& path, Journal const& journal) {
    auto serialized = SerializeJournal(journal);
    return !serialized.empty() && AtomicWriteUtf8(path, serialized);
}

std::optional<Journal> ReadJournal(std::wstring const& path) {
    auto text = ReadSmallUtf8File(path);
    return text ? ParseJournal(*text) : std::nullopt;
}

std::string SanitizeMessage(std::string value) {
    for (char& character : value) {
        unsigned char byte = static_cast<unsigned char>(character);
        if (character == '\r' || character == '\n' || byte < 0x20 || byte > 0x7E)
            character = ' ';
    }
    if (value.size() > 400) value.resize(400);
    return value;
}

std::string SerializeResult(GateResult const& result) {
    std::ostringstream out;
    out << "magic=SOW_PACKAGE_GATE_RESULT_V1\n"
        << "nonce=" << result.nonce << "\n"
        << "challenge=" << result.challenge << "\n"
        << "status=" << result.status << "\n"
        << "code=" << result.code << "\n"
        << "pid=" << result.pid << "\n"
        << "tid=" << result.tid << "\n"
        << "helper_pid=" << result.helperPid << "\n"
        << "helper_creation_100ns=" << result.helperCreation100ns << "\n"
        << "target_creation_100ns=" << result.targetCreation100ns << "\n"
        << "message=" << SanitizeMessage(result.message) << "\n";
    return out.str();
}

std::optional<GateResult> ParseResult(std::string const& text) {
    auto fields = ParseFields(text);
    if (!fields || fields->size() != 11 ||
        (*fields)["magic"] != "SOW_PACKAGE_GATE_RESULT_V1") {
        return std::nullopt;
    }
    static constexpr std::array<char const*, 11> keys = {
        "magic", "nonce", "challenge", "status", "code", "pid", "tid",
        "helper_pid", "helper_creation_100ns", "target_creation_100ns",
        "message"};
    for (auto key : keys) if (!fields->count(key)) return std::nullopt;
    auto code = ParseUnsigned<DWORD>((*fields)["code"]);
    auto pid = ParseUnsigned<DWORD>((*fields)["pid"]);
    auto tid = ParseUnsigned<DWORD>((*fields)["tid"]);
    auto helperPid = ParseUnsigned<DWORD>((*fields)["helper_pid"]);
    auto helperCreation = ParseUnsigned<std::uint64_t>(
        (*fields)["helper_creation_100ns"]);
    auto targetCreation = ParseUnsigned<std::uint64_t>(
        (*fields)["target_creation_100ns"]);
    if (!code || !pid || !tid || !helperPid || !helperCreation ||
        !targetCreation || *helperPid == 0 || *helperCreation == 0)
        return std::nullopt;
    GateResult result;
    result.nonce = (*fields)["nonce"];
    result.challenge = (*fields)["challenge"];
    result.status = (*fields)["status"];
    result.message = (*fields)["message"];
    result.code = *code;
    result.pid = *pid;
    result.tid = *tid;
    result.helperPid = *helperPid;
    result.helperCreation100ns = *helperCreation;
    result.targetCreation100ns = *targetCreation;
    return result;
}

std::optional<GateResult> ReadResult(std::wstring const& path) {
    auto text = ReadSmallUtf8File(path);
    return text ? ParseResult(*text) : std::nullopt;
}

bool WriteResult(std::wstring const& path, GateResult const& result) {
    return AtomicWriteUtf8(path, SerializeResult(result));
}

bool ValidNonce(std::string const& nonce) {
    if (nonce.size() != 32) return false;
    return std::all_of(nonce.begin(), nonce.end(), [](char value) {
        return (value >= '0' && value <= '9') ||
               (value >= 'a' && value <= 'f');
    });
}

std::optional<GateClaim> ParseClaim(std::string const& text) {
    auto fields = ParseFields(text);
    if (!fields || fields->size() != 7 ||
        (*fields)["magic"] != "SOW_PACKAGE_GATE_CLAIM_V1") {
        return std::nullopt;
    }
    static constexpr std::array<char const*, 7> keys = {
        "magic", "nonce", "target_pid", "target_tid",
        "target_creation_100ns", "helper_pid", "helper_creation_100ns"};
    for (auto key : keys) if (!fields->count(key)) return std::nullopt;
    auto targetPid = ParseUnsigned<DWORD>((*fields)["target_pid"]);
    auto targetTid = ParseUnsigned<DWORD>((*fields)["target_tid"]);
    auto targetCreation = ParseUnsigned<std::uint64_t>(
        (*fields)["target_creation_100ns"]);
    auto helperPid = ParseUnsigned<DWORD>((*fields)["helper_pid"]);
    auto helperCreation = ParseUnsigned<std::uint64_t>(
        (*fields)["helper_creation_100ns"]);
    if (!ValidNonce((*fields)["nonce"]) || !targetPid || !targetTid ||
        !targetCreation || !helperPid || !helperCreation || *targetPid == 0 ||
        *targetTid == 0 || *targetCreation == 0 || *helperPid == 0 ||
        *helperCreation == 0) {
        return std::nullopt;
    }
    GateClaim claim;
    claim.nonce = (*fields)["nonce"];
    claim.targetPid = *targetPid;
    claim.targetTid = *targetTid;
    claim.targetCreation100ns = *targetCreation;
    claim.helperPid = *helperPid;
    claim.helperCreation100ns = *helperCreation;
    return claim;
}

std::optional<GateClaim> ReadClaim(std::wstring const& path) {
    auto text = ReadSmallUtf8File(path);
    return text ? ParseClaim(*text) : std::nullopt;
}

bool ValidRecoveryHresult(std::string const& value) {
    if (value == "none") return true;
    if (value.size() != 8) return false;
    return std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= '0' && character <= '9') ||
               (character >= 'A' && character <= 'F');
    });
}

bool RecoveryHresultIsFailure(std::string const& value) {
    if (!ValidRecoveryHresult(value) || value == "none") return false;
    auto parsed = ParseUnsigned<std::uint32_t>(value, 16);
    return parsed && ((*parsed & 0x80000000u) != 0);
}

bool ValidRecoveryReceipt(RecoveryReceipt const& receipt) {
    if (!ValidNonce(receipt.attemptNonce) || receipt.recoveryPid == 0 ||
        receipt.recoveryCreation100ns == 0 || receipt.sessionId == 0 ||
        !ValidRecoveryHresult(receipt.lastHr)) return false;
    if (receipt.outcome == "termination_only") {
        return receipt.nonce == "none" && receipt.priorStage == "absent" &&
               receipt.lastHr == "none";
    }
    if (!ValidNonce(receipt.nonce)) return false;
    if (receipt.outcome == "enable_failed_clean") {
        return receipt.priorStage == "enable_failed" &&
               RecoveryHresultIsFailure(receipt.lastHr);
    }
    if (receipt.outcome == "already_disabled") {
        return (receipt.priorStage == "disable_complete" ||
                receipt.priorStage == "disable_returned" ||
                receipt.priorStage == "disable_postcheck_failed") &&
               receipt.lastHr == "00000000";
    }
    if (receipt.outcome == "debug_disabled") {
        return (receipt.priorStage == "enabled" ||
                receipt.priorStage == "monitoring" ||
                receipt.priorStage == "cleanup_terminating") &&
               receipt.lastHr == "00000000";
    }
    return false;
}

std::string SerializeRecoveryReceipt(RecoveryReceipt const& receipt) {
    std::ostringstream out;
    out << "magic=SOW_PACKAGE_GATE_RECOVERY_RECEIPT_V1\n"
        << "attempt_nonce=" << receipt.attemptNonce << "\n"
        << "outcome=" << receipt.outcome << "\n"
        << "nonce=" << receipt.nonce << "\n"
        << "prior_stage=" << receipt.priorStage << "\n"
        << "last_hr=" << receipt.lastHr << "\n"
        << "recovery_pid=" << receipt.recoveryPid << "\n"
        << "recovery_creation_100ns=" << receipt.recoveryCreation100ns << "\n"
        << "session_id=" << receipt.sessionId << "\n";
    return out.str();
}

std::optional<RecoveryReceipt> ParseRecoveryReceipt(std::string const& text) {
    auto fields = ParseFields(text);
    if (!fields || fields->size() != 9 ||
        (*fields)["magic"] != "SOW_PACKAGE_GATE_RECOVERY_RECEIPT_V1") {
        return std::nullopt;
    }
    static constexpr std::array<char const*, 9> keys = {
        "magic", "attempt_nonce", "outcome", "nonce", "prior_stage",
        "last_hr", "recovery_pid", "recovery_creation_100ns", "session_id"};
    for (auto key : keys) if (!fields->count(key)) return std::nullopt;
    auto pid = ParseUnsigned<DWORD>((*fields)["recovery_pid"]);
    auto creation = ParseUnsigned<std::uint64_t>(
        (*fields)["recovery_creation_100ns"]);
    auto session = ParseUnsigned<DWORD>((*fields)["session_id"]);
    if (!pid || !creation || !session) return std::nullopt;
    RecoveryReceipt receipt;
    receipt.attemptNonce = (*fields)["attempt_nonce"];
    receipt.outcome = (*fields)["outcome"];
    receipt.nonce = (*fields)["nonce"];
    receipt.priorStage = (*fields)["prior_stage"];
    receipt.lastHr = (*fields)["last_hr"];
    receipt.recoveryPid = *pid;
    receipt.recoveryCreation100ns = *creation;
    receipt.sessionId = *session;
    return ValidRecoveryReceipt(receipt)
        ? std::optional<RecoveryReceipt>(receipt) : std::nullopt;
}

std::optional<RecoveryReceipt> ReadRecoveryReceipt(
    std::wstring const& path) {
    auto text = ReadSmallUtf8File(path);
    return text ? ParseRecoveryReceipt(*text) : std::nullopt;
}

std::string RecoveryReceiptLine(RecoveryReceipt const& receipt) {
    std::ostringstream out;
    out << "RECOVERY_COMPLETE attempt_nonce=" << receipt.attemptNonce
        << " outcome=" << receipt.outcome
        << " nonce=" << receipt.nonce
        << " prior_stage=" << receipt.priorStage
        << " last_hr=" << receipt.lastHr
        << " recovery_pid=" << receipt.recoveryPid
        << " recovery_creation_100ns=" << receipt.recoveryCreation100ns
        << " session_id=" << receipt.sessionId;
    return out.str();
}

std::optional<std::string> GenerateNonce() {
    std::array<unsigned char, 16> bytes{};
    NTSTATUS status = BCryptGenRandom(nullptr, bytes.data(),
                                     static_cast<ULONG>(bytes.size()),
                                     BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) return std::nullopt;
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0F]);
    }
    return result;
}

ULONGLONG FileTimeTicks(FILETIME const& value) {
    ULARGE_INTEGER ticks{};
    ticks.LowPart = value.dwLowDateTime;
    ticks.HighPart = value.dwHighDateTime;
    return ticks.QuadPart;
}

ULONGLONG CurrentFileTimeTicks() {
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    return FileTimeTicks(now);
}

std::optional<ULONGLONG> ProcessCreationTime100ns(HANDLE process) {
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process, &creation, &exit, &kernel, &user))
        return std::nullopt;
    return FileTimeTicks(creation);
}

bool IsAlive(HANDLE process) {
    DWORD code = 0;
    return GetExitCodeProcess(process, &code) && code == STILL_ACTIVE;
}

std::optional<std::vector<DWORD>> FindProcessIds() {
    std::vector<DWORD> result;
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) return std::nullopt;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.value, &entry)) return std::nullopt;
    do {
        if (_wcsicmp(entry.szExeFile, kProcessName) == 0)
            result.push_back(entry.th32ProcessID);
    } while (Process32NextW(snapshot.value, &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) return std::nullopt;
    std::sort(result.begin(), result.end());
    return result;
}

std::optional<std::vector<DWORD>> SnapshotThreadIds(DWORD pid) {
    std::vector<DWORD> result;
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot) return std::nullopt;
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot.value, &entry)) return std::nullopt;
    do {
        if (entry.th32OwnerProcessID == pid) result.push_back(entry.th32ThreadID);
    } while (Thread32Next(snapshot.value, &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) return std::nullopt;
    std::sort(result.begin(), result.end());
    if (std::adjacent_find(result.begin(), result.end()) != result.end())
        return std::nullopt;
    return result;
}

std::optional<std::wstring> PackageFullNameForProcess(HANDLE process) {
    UINT32 length = 0;
    LONG status = GetPackageFullName(process, &length, nullptr);
    if (status != ERROR_INSUFFICIENT_BUFFER || length == 0) return std::nullopt;
    std::vector<wchar_t> buffer(length);
    status = GetPackageFullName(process, &length, buffer.data());
    if (status != ERROR_SUCCESS) return std::nullopt;
    return std::wstring(buffer.data());
}

enum class PackageMatch {
    noPackage,
    otherPackage,
    exactPackage,
    queryFailed,
};

PackageMatch MatchExpectedPackage(HANDLE process) {
    UINT32 length = 0;
    LONG status = GetPackageFullName(process, &length, nullptr);
    if (status == APPMODEL_ERROR_NO_PACKAGE) return PackageMatch::noPackage;
    if (status != ERROR_INSUFFICIENT_BUFFER || length == 0)
        return WaitForSingleObject(process, 0) == WAIT_OBJECT_0
            ? PackageMatch::noPackage
            : PackageMatch::queryFailed;
    std::vector<wchar_t> buffer(length);
    status = GetPackageFullName(process, &length, buffer.data());
    if (status == APPMODEL_ERROR_NO_PACKAGE) return PackageMatch::noPackage;
    if (status != ERROR_SUCCESS)
        return WaitForSingleObject(process, 0) == WAIT_OBJECT_0
            ? PackageMatch::noPackage
            : PackageMatch::queryFailed;
    return EqualInsensitive(std::wstring(buffer.data()),
                            kExpectedPackageFullName)
        ? PackageMatch::exactPackage
        : PackageMatch::otherPackage;
}

std::optional<std::vector<Handle>> OpenExactPackageProcesses() {
    std::vector<Handle> result;
    DWORD currentSession = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &currentSession))
        return std::nullopt;
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) return std::nullopt;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.value, &entry)) return std::nullopt;
    do {
        DWORD pid = entry.th32ProcessID;
        if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) continue;
        Handle query(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                 FALSE, pid));
        if (!query) continue;
        PackageMatch match = MatchExpectedPackage(query.value);
        if (match == PackageMatch::queryFailed) continue;
        if (match != PackageMatch::exactPackage) continue;
        DWORD session = 0;
        if (!ProcessIdToSessionId(pid, &session)) {
            if (WaitForSingleObject(query.value, 0) == WAIT_OBJECT_0) continue;
            return std::nullopt;
        }
        if (session != currentSession) continue;

        Handle terminate(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                         PROCESS_TERMINATE | SYNCHRONIZE,
                                     FALSE, pid));
        if (!terminate) {
            if (WaitForSingleObject(query.value, 0) == WAIT_OBJECT_0) continue;
            return std::nullopt;
        }
        if (GetProcessId(terminate.value) != pid ||
            MatchExpectedPackage(terminate.value) !=
                PackageMatch::exactPackage) {
            if (WaitForSingleObject(query.value, 0) == WAIT_OBJECT_0) continue;
            return std::nullopt;
        }
        result.push_back(std::move(terminate));
    } while (Process32NextW(snapshot.value, &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) return std::nullopt;
    return result;
}

std::optional<std::wstring> ImagePathForProcess(HANDLE process) {
    std::vector<wchar_t> buffer(32768);
    DWORD length = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &length))
        return std::nullopt;
    return std::wstring(buffer.data(), length);
}

std::optional<std::wstring> ExpectedImagePath() {
    UINT32 length = 0;
    LONG status = GetPackagePathByFullName(kExpectedPackageFullName, &length,
                                           nullptr);
    if (status != ERROR_INSUFFICIENT_BUFFER || length == 0) return std::nullopt;
    std::vector<wchar_t> buffer(length);
    status = GetPackagePathByFullName(kExpectedPackageFullName, &length,
                                      buffer.data());
    if (status != ERROR_SUCCESS) return std::nullopt;
    return FullPath(JoinPath(std::wstring(buffer.data()),
                             kExpectedRelativeImagePath));
}

std::optional<std::wstring> ExpectedRuntimeBrokerPath() {
    std::array<wchar_t, MAX_PATH> systemDirectory{};
    UINT length = GetSystemDirectoryW(systemDirectory.data(),
                                      static_cast<UINT>(systemDirectory.size()));
    if (length == 0 ||
        length >= static_cast<UINT>(systemDirectory.size()))
        return std::nullopt;
    return FullPath(JoinPath(std::wstring(systemDirectory.data(), length),
                             L"RuntimeBroker.exe"));
}

bool SameFileIdentity(std::wstring const& first,
                      std::wstring const& second) {
    // GetPackagePathByFullName can return the logical
    // C:\Program Files\WindowsApps path while QueryFullProcessImageName returns
    // a physical package-volume path on another local drive.
    // String comparison therefore rejects one and the same executable.  Compare
    // the NTFS file identities behind both paths instead; this remains strict
    // across aliases and does not accept a different file with the same name.
    constexpr DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE |
                            FILE_SHARE_DELETE;
    Handle firstFile(CreateFileW(first.c_str(), 0, share, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    Handle secondFile(CreateFileW(second.c_str(), 0, share, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!firstFile || !secondFile) return false;

    BY_HANDLE_FILE_INFORMATION firstInfo{};
    BY_HANDLE_FILE_INFORMATION secondInfo{};
    if (!GetFileInformationByHandle(firstFile.value, &firstInfo) ||
        !GetFileInformationByHandle(secondFile.value, &secondInfo)) return false;
    if ((firstInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (secondInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) return false;

    return firstInfo.dwVolumeSerialNumber == secondInfo.dwVolumeSerialNumber &&
           firstInfo.nFileIndexHigh == secondInfo.nFileIndexHigh &&
           firstInfo.nFileIndexLow == secondInfo.nFileIndexLow;
}

bool PinnedManifestInvariantMatches() {
    UINT32 length = 0;
    LONG status = GetPackagePathByFullName(kExpectedPackageFullName, &length,
                                           nullptr);
    if (status != ERROR_INSUFFICIENT_BUFFER || length == 0) return false;
    std::vector<wchar_t> packagePath(length);
    status = GetPackagePathByFullName(kExpectedPackageFullName, &length,
                                      packagePath.data());
    if (status != ERROR_SUCCESS) return false;
    auto manifest = FullPath(JoinPath(std::wstring(packagePath.data()),
                                      L"AppxManifest.xml"));
    if (!manifest) return false;
    DWORD attributes = GetFileAttributesW(manifest->c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
        return false;
    Handle file(CreateFileW(manifest->c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.value, &size) || size.QuadPart <= 0 ||
        size.QuadPart > 1024 * 1024) return false;
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    if (!ReadFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()),
                  &read, nullptr) || read != bytes.size()) return false;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                    nullptr, 0) < 0) return false;
    std::array<std::uint8_t, 32> digest{};
    NTSTATUS hashStatus = BCryptHash(
        algorithm, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()),
        digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return hashStatus >= 0 && digest == kExpectedManifestSha256;
}

bool ShellLinkContainsExactlyOneAumid(
    std::vector<std::uint8_t> const& bytes) {
    constexpr std::array<std::uint8_t, 20> kShellLinkHeader = {
        0x4C, 0x00, 0x00, 0x00,
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
    if (bytes.size() < kShellLinkHeader.size() ||
        !std::equal(kShellLinkHeader.begin(), kShellLinkHeader.end(),
                    bytes.begin()))
        return false;
    std::vector<std::uint8_t> aumidBytes;
    for (wchar_t character : std::wstring(kExpectedAppUserModelId)) {
        aumidBytes.push_back(static_cast<std::uint8_t>(character & 0xFF));
        aumidBytes.push_back(static_cast<std::uint8_t>((character >> 8) & 0xFF));
    }
    std::size_t matches = 0;
    for (std::size_t offset = 0;
         offset + aumidBytes.size() <= bytes.size(); ++offset) {
        if (std::equal(aumidBytes.begin(), aumidBytes.end(),
                       bytes.begin() + offset))
            ++matches;
    }
    return matches == 1;
}

std::optional<std::wstring> SemanticallyVerifiedDesktopLaunchLink() {
    std::vector<std::wstring> desktopDirectories;
    for (KNOWNFOLDERID const* id : {&FOLDERID_Desktop, &FOLDERID_PublicDesktop}) {
        PWSTR raw = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(*id, KF_FLAG_DEFAULT, nullptr, &raw)) &&
            raw) {
            auto path = FullPath(raw);
            CoTaskMemFree(raw);
            if (path && std::none_of(desktopDirectories.begin(),
                                     desktopDirectories.end(),
                                     [&](std::wstring const& known) {
                                         return EqualInsensitive(known, *path);
                                     })) {
                desktopDirectories.push_back(*path);
            }
        }
    }

    std::vector<std::wstring> matches;
    for (auto const& directory : desktopDirectories) {
        WIN32_FIND_DATAW found{};
        HANDLE search = FindFirstFileW(JoinPath(directory, L"*.lnk").c_str(),
                                       &found);
        if (search == INVALID_HANDLE_VALUE) continue;
        do {
            if (found.dwFileAttributes &
                (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
                continue;
            auto path = FullPath(JoinPath(directory, found.cFileName));
            if (!path) continue;
            Handle file(CreateFileW(path->c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (!file) continue;
            LARGE_INTEGER size{};
            if (!GetFileSizeEx(file.value, &size) || size.QuadPart < 64 ||
                size.QuadPart > 64 * 1024)
                continue;
            std::vector<std::uint8_t> bytes(
                static_cast<std::size_t>(size.QuadPart));
            DWORD read = 0;
            if (!ReadFile(file.value, bytes.data(),
                          static_cast<DWORD>(bytes.size()), &read, nullptr) ||
                read != bytes.size())
                continue;
            if (ShellLinkContainsExactlyOneAumid(bytes)) matches.push_back(*path);
        } while (FindNextFileW(search, &found));
        DWORD enumerationError = GetLastError();
        FindClose(search);
        if (enumerationError != ERROR_NO_MORE_FILES) return std::nullopt;
    }
    if (matches.size() != 1) return std::nullopt;
    return matches[0];
}

template <typename T>
bool ReadExact(HANDLE process, std::uintptr_t address, T* destination,
               std::size_t size = sizeof(T)) {
    SIZE_T read = 0;
    return ReadProcessMemory(process, reinterpret_cast<void const*>(address),
                             destination, size, &read) && read == size;
}

std::optional<std::uintptr_t> MainImageBaseFromPeb(
    HANDLE process, DWORD expectedPid,
    NtQueryInformationProcessFn queryProcessInformation) {
    RemoteProcessBasicInformation basic{};
    ULONG returned = 0;
    LONG status = queryProcessInformation(process, 0, &basic, sizeof(basic),
                                          &returned);
    if (status < 0 || returned != sizeof(basic) || !basic.pebBaseAddress ||
        basic.uniqueProcessId != expectedPid) {
        return std::nullopt;
    }
    std::uintptr_t imageBase = 0;
    auto peb = reinterpret_cast<std::uintptr_t>(basic.pebBaseAddress);
    if (!ReadExact(process, peb + 0x10, &imageBase) || imageBase == 0)
        return std::nullopt;
    MEMORY_BASIC_INFORMATION memory{};
    SIZE_T queried = VirtualQueryEx(process,
                                    reinterpret_cast<void const*>(imageBase),
                                    &memory, sizeof(memory));
    if (queried != sizeof(memory) || memory.State != MEM_COMMIT ||
        memory.Type != MEM_IMAGE ||
        reinterpret_cast<std::uintptr_t>(memory.AllocationBase) != imageBase ||
        reinterpret_cast<std::uintptr_t>(memory.BaseAddress) != imageBase) {
        return std::nullopt;
    }
    return imageBase;
}

bool VerifyRemotePe(HANDLE process, std::uintptr_t base) {
    IMAGE_DOS_HEADER dos{};
    if (!ReadExact(process, base, &dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000) {
        return false;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadExact(process, base + static_cast<std::uintptr_t>(dos.e_lfanew),
                   &nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.FileHeader.TimeDateStamp != kExpectedTimeDateStamp ||
        nt.OptionalHeader.SizeOfImage != kExpectedSizeOfImage) {
        return false;
    }
    return true;
}

template <std::size_t N>
bool RemoteBytesEqual(HANDLE process, std::uintptr_t address,
                      std::array<std::uint8_t, N> const& expected) {
    std::array<std::uint8_t, N> actual{};
    return ReadExact(process, address, actual.data(), actual.size()) &&
           actual == expected;
}

template <std::size_t N>
bool ReplaceBytes(HANDLE process, std::uintptr_t address,
                  std::array<std::uint8_t, N> const& expected,
                  std::array<std::uint8_t, N> const& replacement) {
    if (address > std::numeric_limits<std::uintptr_t>::max() - N ||
        !RemoteBytesEqual(process, address, expected)) return false;
    auto executableProtection = [](DWORD protection) {
        DWORD base = protection & 0xFF;
        return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
               base == PAGE_EXECUTE_READWRITE ||
               base == PAGE_EXECUTE_WRITECOPY;
    };
    MEMORY_BASIC_INFORMATION before{};
    if (VirtualQueryEx(process, reinterpret_cast<void const*>(address), &before,
                       sizeof(before)) != sizeof(before) ||
        before.State != MEM_COMMIT || before.Type != MEM_IMAGE ||
        !executableProtection(before.Protect) ||
        address + N > reinterpret_cast<std::uintptr_t>(before.BaseAddress) +
                          before.RegionSize) {
        return false;
    }
    DWORD oldProtection = 0;
    if (!VirtualProtectEx(process, reinterpret_cast<void*>(address), N,
                          PAGE_EXECUTE_READWRITE, &oldProtection)) {
        return false;
    }
    SIZE_T written = 0;
    bool wrote = WriteProcessMemory(process, reinterpret_cast<void*>(address),
                                    replacement.data(), replacement.size(),
                                    &written) && written == replacement.size();
    bool flushed = wrote && FlushInstructionCache(
                                process, reinterpret_cast<void const*>(address), N);
    bool verified = flushed && RemoteBytesEqual(process, address, replacement);
    DWORD ignored = 0;
    bool restored = VirtualProtectEx(process, reinterpret_cast<void*>(address),
                                     N, oldProtection, &ignored) != FALSE;
    MEMORY_BASIC_INFORMATION after{};
    bool protectionVerified = restored &&
        VirtualQueryEx(process, reinterpret_cast<void const*>(address), &after,
                       sizeof(after)) == sizeof(after) &&
        after.State == MEM_COMMIT && after.Type == MEM_IMAGE &&
        after.AllocationBase == before.AllocationBase &&
        after.Protect == oldProtection && executableProtection(after.Protect) &&
        address + N <= reinterpret_cast<std::uintptr_t>(after.BaseAddress) +
                           after.RegionSize;
    return verified && protectionVerified;
}

bool NativeAmd64Process(HANDLE process) {
    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) return false;
    auto function = reinterpret_cast<IsWow64Process2Fn>(
        GetProcAddress(kernel32, "IsWow64Process2"));
    if (!function) return false;
    USHORT processMachine = 0;
    USHORT nativeMachine = 0;
    return function(process, &processMachine, &nativeMachine) &&
           processMachine == IMAGE_FILE_MACHINE_UNKNOWN &&
           nativeMachine == IMAGE_FILE_MACHINE_AMD64;
}

bool ExactSingleThreadCohort(DWORD pid, DWORD tid) {
    auto threads = SnapshotThreadIds(pid);
    return threads && threads->size() == 1 && threads->front() == tid;
}

bool ThreadControlContextReadable(HANDLE thread) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    return GetThreadContext(thread, &context) != FALSE && context.Rip != 0 &&
           context.Rsp != 0;
}

std::optional<DWORD> ParseDwordArgument(wchar_t const* argument) {
    if (!argument || !*argument) return std::nullopt;
    unsigned long long value = 0;
    for (wchar_t const* cursor = argument; *cursor; ++cursor) {
        if (*cursor < L'0' || *cursor > L'9') return std::nullopt;
        value = value * 10 + static_cast<unsigned>(*cursor - L'0');
        if (value > std::numeric_limits<DWORD>::max()) return std::nullopt;
    }
    if (value == 0) return std::nullopt;
    return static_cast<DWORD>(value);
}

bool GateArgumentShapeValid(int argc, wchar_t* const* argv) {
    return argc == 6 && argv && wcscmp(argv[1], L"--gate") == 0 &&
           wcscmp(argv[2], L"-p") == 0 &&
           wcscmp(argv[4], L"-tid") == 0 &&
           ParseDwordArgument(argv[3]).has_value() &&
           ParseDwordArgument(argv[5]).has_value();
}

std::optional<std::string> NarrowAscii(wchar_t const* value) {
    if (!value) return std::nullopt;
    std::string result;
    for (; *value; ++value) {
        if (*value < 0x20 || *value > 0x7E) return std::nullopt;
        result.push_back(static_cast<char>(*value));
    }
    return result;
}

bool IsElevated() {
    Handle token;
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
    token = Handle(raw);
    TOKEN_ELEVATION elevation{};
    DWORD returned = 0;
    return GetTokenInformation(token.value, TokenElevation, &elevation,
                               sizeof(elevation), &returned) &&
           returned == sizeof(elevation) && elevation.TokenIsElevated != 0;
}

bool IsMediumIntegrity() {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
    Handle token(raw);
    DWORD needed = 0;
    GetTokenInformation(token.value, TokenIntegrityLevel, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0)
        return false;
    std::vector<std::uint8_t> buffer(needed);
    if (!GetTokenInformation(token.value, TokenIntegrityLevel, buffer.data(),
                             needed, &needed)) return false;
    auto label = reinterpret_cast<TOKEN_MANDATORY_LABEL const*>(buffer.data());
    auto sid = label->Label.Sid;
    UCHAR count = *GetSidSubAuthorityCount(sid);
    if (count == 0) return false;
    DWORD rid = *GetSidSubAuthority(sid, count - 1);
    return rid >= SECURITY_MANDATORY_MEDIUM_RID &&
           rid < SECURITY_MANDATORY_HIGH_RID && !IsElevated();
}

std::wstring QuoteCommandLineArgument(std::wstring const& argument) {
    if (argument.find_first_of(L" \t\"") == std::wstring::npos)
        return argument;
    std::wstring result = L"\"";
    std::size_t slashes = 0;
    for (wchar_t character : argument) {
        if (character == L'\\') {
            ++slashes;
        } else if (character == L'\"') {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(L'\"');
            slashes = 0;
        } else {
            result.append(slashes, L'\\');
            slashes = 0;
            result.push_back(character);
        }
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

HRESULT CreatePackageDebugSettings(ComPtr<IPackageDebugSettings>& settings) {
    return CoCreateInstance(__uuidof(PackageDebugSettings), nullptr,
                            CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&settings));
}

[[noreturn]] void Usage() {
    std::wcerr
        << L"Inert by default. Explicit modes:\n"
        << L"  g.exe --arm-online-play\n"
        << L"  g.exe --recover-debug --receipt <32hex-attempt> <absolute-receipt-path>\n"
        << L"  g.exe --self-test  (strictly inert)\n"
        << L"--gate is reserved for the Windows package-debug launcher.\n";
    ExitProcess(64);
}

bool UnsafeGateRip(std::uintptr_t rip, std::uintptr_t moduleBase,
                   std::uintptr_t storeCall) {
    auto inRange = [rip, moduleBase](std::uintptr_t first,
                                     std::uintptr_t lastExclusive) {
        return rip >= moduleBase + first && rip < moduleBase + lastExclusive;
    };
    if (rip == storeCall) return false;
    if (rip > storeCall && rip < storeCall + kStoreCallNops.size()) return true;
    // The replaced call occupies [F60B15,F60B1A).  No title thread may
    // already be in the continuation/provider-activation portion.  Save and
    // delete code is intentionally untouched in play mode.
    return inRange(0x00F60B1A, 0x00F60DAC);
}

bool GateBytesMatch(HANDLE process, std::uintptr_t storeCall,
                    std::array<std::uint8_t, 5> const& expectedStore) {
    return RemoteBytesEqual(process, storeCall, expectedStore);
}

bool FileExists(std::wstring const& path) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

enum class RegularFileProbe {
    absent,
    present,
    error,
};

RegularFileProbe ProbeRegularNonReparseFile(std::wstring const& path) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
            ? RegularFileProbe::absent
            : RegularFileProbe::error;
    }
    if ((attributes & (FILE_ATTRIBUTE_DIRECTORY |
                       FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        return RegularFileProbe::error;
    }

    Handle file(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE |
                                FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL |
                                FILE_FLAG_OPEN_REPARSE_POINT,
                            nullptr));
    if (!file) {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
            ? RegularFileProbe::absent
            : RegularFileProbe::error;
    }
    BY_HANDLE_FILE_INFORMATION information{};
    if (GetFileType(file.value) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(file.value, &information) ||
        (information.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        return RegularFileProbe::error;
    }
    return RegularFileProbe::present;
}

bool PackageStateCanMeanQuiescent(PACKAGE_EXECUTION_STATE state) {
    // On this machine IPackageDebugSettings returns PES_UNKNOWN for an idle
    // packaged application.  UNKNOWN is never accepted on its own: the pinned
    // one-executable/no-background-task manifest plus two independent process
    // enumerations must both prove empty in the same pass.
    return state == PES_TERMINATED || state == PES_UNKNOWN;
}

bool IsAcceptedTitleExitCode(DWORD code) {
    // The first reviewed play session proved that this exact packaged title
    // returns 1 when the player closes it normally.  The matching local-time
    // interval contained no Application Error, WER or Application Hang event,
    // produced no crash dump, and completed a verified changed WGS backup.
    // Keep every other nonzero code fail-closed.
    return code == 0 || code == 1;
}

bool ExactNoProcessProof(IPackageDebugSettings* settings) {
    if (!PinnedManifestInvariantMatches()) return false;
    auto titlesBefore = FindProcessIds();
    auto packagedBefore = OpenExactPackageProcesses();
    if (!titlesBefore || !titlesBefore->empty() || !packagedBefore ||
        !packagedBefore->empty())
        return false;
    PACKAGE_EXECUTION_STATE state = PES_UNKNOWN;
    HRESULT status = settings->GetPackageExecutionState(
        kExpectedPackageFullName, &state);
    auto packagedAfter = OpenExactPackageProcesses();
    auto titlesAfter = FindProcessIds();
    return status == S_OK && PackageStateCanMeanQuiescent(state) &&
           packagedAfter && packagedAfter->empty() && titlesAfter &&
           titlesAfter->empty();
}

bool WaitForPackageQuiescent(IPackageDebugSettings* settings,
                             std::chrono::milliseconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    unsigned stablePasses = 0;
    for (;;) {
        if (ExactNoProcessProof(settings)) {
            ++stablePasses;
            if (stablePasses >= 2) return true;
        } else {
            stablePasses = 0;
        }
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(kPollInterval);
    }
}

bool TerminateKnownProcess(HANDLE process, UINT exitCode) {
    DWORD wait = WaitForSingleObject(process, 0);
    if (wait == WAIT_OBJECT_0) return true;
    if (wait != WAIT_TIMEOUT) return false;
    if (!TerminateProcess(process, exitCode) &&
        WaitForSingleObject(process, 0) != WAIT_OBJECT_0) {
        return false;
    }
    return WaitForSingleObject(process, 10000) == WAIT_OBJECT_0;
}

enum class OtherSessionTitleCheck {
    none,
    present,
    error,
};

OtherSessionTitleCheck CheckOtherSessionExactTitles() {
    auto expectedPath = ExpectedImagePath();
    if (!expectedPath) return OtherSessionTitleCheck::error;
    DWORD currentSession = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &currentSession))
        return OtherSessionTitleCheck::error;
    auto pids = FindProcessIds();
    if (!pids) return OtherSessionTitleCheck::error;
    for (DWORD pid : *pids) {
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                       SYNCHRONIZE,
                                   FALSE, pid));
        if (!process) {
            if (GetLastError() == ERROR_INVALID_PARAMETER) continue;
            return OtherSessionTitleCheck::error;
        }
        auto package = PackageFullNameForProcess(process.value);
        auto image = ImagePathForProcess(process.value);
        if ((!package || !image) &&
            WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0) continue;
        if (!package || !image) return OtherSessionTitleCheck::error;
        if (!EqualInsensitive(*package, kExpectedPackageFullName) ||
            !SameFileIdentity(*image, *expectedPath)) continue;
        DWORD session = 0;
        if (!ProcessIdToSessionId(pid, &session)) {
            if (WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0)
                continue;
            return OtherSessionTitleCheck::error;
        }
        if (session != currentSession) return OtherSessionTitleCheck::present;
    }
    return OtherSessionTitleCheck::none;
}

bool TerminateExactTitleProcesses(std::chrono::milliseconds timeout) {
    auto expectedPath = ExpectedImagePath();
    if (!expectedPath) return false;
    DWORD currentSession = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &currentSession))
        return false;
    auto deadline = std::chrono::steady_clock::now() + timeout;
    unsigned stablePasses = 0;
    for (;;) {
        auto pids = FindProcessIds();
        if (!pids) return false;
        bool foundExact = false;
        bool passOkay = true;
        for (DWORD pid : *pids) {
            Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                           PROCESS_TERMINATE | SYNCHRONIZE,
                                       FALSE, pid));
            if (!process) {
                if (GetLastError() == ERROR_INVALID_PARAMETER) continue;
                passOkay = false;
                continue;
            }
            auto package = PackageFullNameForProcess(process.value);
            auto image = ImagePathForProcess(process.value);
            if ((!package || !image) &&
                WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0) {
                continue;
            }
            if (!package || !image) {
                passOkay = false;
                continue;
            }
            if (!EqualInsensitive(*package, kExpectedPackageFullName)) continue;
            if (!SameFileIdentity(*image, *expectedPath)) {
                passOkay = false;
                continue;
            }
            DWORD candidateSession = 0;
            if (!ProcessIdToSessionId(pid, &candidateSession)) {
                if (WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0)
                    continue;
                passOkay = false;
                continue;
            }
            if (candidateSession != currentSession) {
                // Never terminate another logged-in/RDP session's title.  Its
                // presence makes local cleanup unprovable and requires recovery
                // from that session.
                passOkay = false;
                continue;
            }
            foundExact = true;
            if (!TerminateKnownProcess(process.value, ERROR_CANCELLED)) {
                passOkay = false;
            }
        }
        if (!passOkay) return false;
        if (!foundExact) {
            ++stablePasses;
            if (stablePasses >= 2) return true;
        } else {
            stablePasses = 0;
        }
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(kPollInterval);
    }
}

bool TerminateJournalBoundProcesses(Journal const& journal) {
    auto self = CurrentExecutablePath();
    if (!self || !ValidNonce(journal.nonce)) return false;
    DWORD currentSession = 0;
    if (CheckInteractiveSessions(&currentSession) ==
        InteractiveSessionCheck::error) return false;
    std::wstring nonceWide(journal.nonce.begin(), journal.nonce.end());
    auto expectedResult = FullPath(JoinPath(
        ParentDirectory(*self),
        L"sow_online_play_result_" + nonceWide + L".txt"));
    auto journalResult = FullPath(journal.resultPath);
    if (!expectedResult || !journalResult) return false;

    bool okay = EqualInsensitive(*expectedResult, *journalResult);
    std::wstring claimPath = *expectedResult + L".claim";
    RegularFileProbe resultProbe =
        ProbeRegularNonReparseFile(*expectedResult);
    RegularFileProbe claimProbe = ProbeRegularNonReparseFile(claimPath);
    if (resultProbe == RegularFileProbe::error ||
        claimProbe == RegularFileProbe::error) {
        okay = false;
    }

    auto result = resultProbe == RegularFileProbe::present
        ? ReadResult(*expectedResult) : std::nullopt;
    auto claim = claimProbe == RegularFileProbe::present
        ? ReadClaim(claimPath) : std::nullopt;
    if ((resultProbe == RegularFileProbe::present && !result) ||
        (claimProbe == RegularFileProbe::present && !claim)) {
        okay = false;
    }
    if (result && result->nonce != journal.nonce) okay = false;
    if (claim && claim->nonce != journal.nonce) okay = false;
    if (!result && !claim) return okay;
    if (result && claim &&
        (result->pid != claim->targetPid ||
         result->tid != claim->targetTid ||
         result->helperPid != claim->helperPid ||
         result->helperCreation100ns != claim->helperCreation100ns ||
         result->targetCreation100ns != claim->targetCreation100ns)) {
        okay = false;
    }

    auto expectedPath = ExpectedImagePath();
    if (!expectedPath) okay = false;

    auto terminateTarget = [&](DWORD pid, std::uint64_t expectedCreation) {
        Handle target(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                      PROCESS_TERMINATE | SYNCHRONIZE,
                                  FALSE, pid));
        if (!target) return GetLastError() == ERROR_INVALID_PARAMETER;
        auto creation = ProcessCreationTime100ns(target.value);
        if (!creation) return WaitForSingleObject(target.value, 0) == WAIT_OBJECT_0;
        if (*creation != expectedCreation) return true;  // PID was reused.
        auto package = PackageFullNameForProcess(target.value);
        auto image = ImagePathForProcess(target.value);
        if ((!package || !image) &&
            WaitForSingleObject(target.value, 0) == WAIT_OBJECT_0) return true;
        if (!expectedPath || !package || !image ||
            !EqualInsensitive(*package, kExpectedPackageFullName) ||
            !SameFileIdentity(*image, *expectedPath)) return false;
        DWORD targetSession = 0;
        if (!ProcessIdToSessionId(pid, &targetSession))
            return WaitForSingleObject(target.value, 0) == WAIT_OBJECT_0;
        return targetSession == currentSession &&
            TerminateKnownProcess(target.value, ERROR_CANCELLED);
    };
    auto terminateHelper = [&](DWORD pid,
                               std::uint64_t expectedCreation) {
        if (pid == GetCurrentProcessId()) return true;  // Stale PID reuse.
        Handle helper(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                      PROCESS_TERMINATE | SYNCHRONIZE,
                                  FALSE, pid));
        if (!helper) return GetLastError() == ERROR_INVALID_PARAMETER;
        auto creation = ProcessCreationTime100ns(helper.value);
        if (!creation)
            return WaitForSingleObject(helper.value, 0) == WAIT_OBJECT_0;
        if (*creation != expectedCreation) return true;  // PID was reused.
        auto image = ImagePathForProcess(helper.value);
        if (!image) return WaitForSingleObject(helper.value, 0) == WAIT_OBJECT_0;
        if (!EqualInsensitive(*image, *self)) return true;  // PID was reused.
        DWORD helperSession = 0;
        if (!ProcessIdToSessionId(pid, &helperSession))
            return WaitForSingleObject(helper.value, 0) == WAIT_OBJECT_0;
        return helperSession == currentSession &&
            TerminateKnownProcess(helper.value, ERROR_CANCELLED);
    };

    if (claim) {
        bool targetStopped = terminateTarget(claim->targetPid,
                                             claim->targetCreation100ns);
        bool helperStopped = terminateHelper(claim->helperPid,
                                             claim->helperCreation100ns);
        okay = targetStopped && helperStopped && okay;
    }
    bool resultDuplicatesClaim = result && claim &&
        result->pid == claim->targetPid &&
        result->helperPid == claim->helperPid &&
        result->helperCreation100ns == claim->helperCreation100ns &&
        result->targetCreation100ns == claim->targetCreation100ns;
    if (result && !resultDuplicatesClaim) {
        bool targetStopped = terminateTarget(result->pid,
                                             result->targetCreation100ns);
        bool helperStopped = terminateHelper(result->helperPid,
                                             result->helperCreation100ns);
        okay = targetStopped && helperStopped && okay;
    }
    return okay;
}

bool TerminateExactPackageProcessesAndProve(
    IPackageDebugSettings* settings, std::chrono::milliseconds timeout) {
    // This exact manifest hash pins the only Application executable to
    // UWP64\ShadowOfWar.exe and contains no background-task extensions.  With
    // that invariant, inaccessible unrelated current-session processes cannot
    // conceal an additional process belonging to this package; PES plus the
    // exact title scan closes the proof.  This also contains a package-bound
    // RuntimeBroker callback that can remain initially suspended after the
    // title exits even when TerminateAllProcesses itself returned S_OK.
    if (!PinnedManifestInvariantMatches()) return false;
    auto deadline = std::chrono::steady_clock::now() + timeout;
    unsigned stablePasses = 0;
    for (;;) {
        auto processes = OpenExactPackageProcesses();
        if (!processes) return false;
        bool terminatedOne = false;
        for (auto& process : *processes) {
            DWORD wait = WaitForSingleObject(process.value, 0);
            if (wait == WAIT_OBJECT_0) continue;
            if (wait != WAIT_TIMEOUT) return false;
            if (!TerminateProcess(process.value, ERROR_CANCELLED)) {
                if (WaitForSingleObject(process.value, 0) != WAIT_OBJECT_0)
                    return false;
            } else if (WaitForSingleObject(process.value, 10000) !=
                       WAIT_OBJECT_0) {
                return false;
            }
            terminatedOne = true;
        }

        auto remaining = OpenExactPackageProcesses();
        if (!remaining) return false;
        PACKAGE_EXECUTION_STATE state = PES_UNKNOWN;
        HRESULT stateHr = settings->GetPackageExecutionState(
            kExpectedPackageFullName, &state);
        auto titles = FindProcessIds();
        if (!terminatedOne && remaining->empty() && stateHr == S_OK &&
            PackageStateCanMeanQuiescent(state) && titles && titles->empty()) {
            ++stablePasses;
            if (stablePasses >= 2) return true;
        } else {
            stablePasses = 0;
        }
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(kPollInterval);
    }
}

struct CleanupResult {
    bool terminationProved = true;
    bool disableCalled = false;
    bool cleanupComplete = false;
    HRESULT terminateHr = S_OK;
    HRESULT disableHr = E_UNEXPECTED;
};

CleanupResult CleanupDebugSetting(IPackageDebugSettings* settings,
                                  std::wstring const& journalPath,
                                   Journal journal, bool terminateFirst,
                                   bool retainCompletedJournal = false) {
    CleanupResult result;
    if (CheckInteractiveSessions() != InteractiveSessionCheck::onlyCurrent ||
        CheckOtherSessionExactTitles() != OtherSessionTitleCheck::none) {
        std::wcerr
            << L"STOP: another Active/Connected interactive session exists "
               L"or session enumeration failed; package-wide cleanup is forbidden.\n";
        result.terminationProved = false;
        return result;
    }
    if (terminateFirst) {
        journal.stage = "cleanup_terminating";
        journal.lastHr = S_OK;
        if (!WriteJournal(journalPath, journal)) {
            std::wcerr << L"Could not publish cleanup intent; debug mode remains enabled.\n";
            result.terminationProved = false;
            return result;
        }
        if (CheckInteractiveSessions() !=
                InteractiveSessionCheck::onlyCurrent ||
            CheckOtherSessionExactTitles() !=
                OtherSessionTitleCheck::none) {
            std::wcerr
                << L"STOP: interactive-session state changed before package termination.\n";
            result.terminationProved = false;
            return result;
        }
        result.terminateHr = settings->TerminateAllProcesses(
            kExpectedPackageFullName);
        result.terminationProved = result.terminateHr == S_OK &&
            TerminateExactPackageProcessesAndProve(
                settings, std::chrono::seconds(15));
        if (!result.terminationProved) {
            std::wcerr
                << L"Refusing to disable package debugging: target termination "
                   L"could not be proved. The journal is retained for recovery.\n";
            return result;
        }
    }

    if (CheckInteractiveSessions() != InteractiveSessionCheck::onlyCurrent ||
        CheckOtherSessionExactTitles() != OtherSessionTitleCheck::none) {
        std::wcerr
            << L"STOP: interactive-session state changed before DisableDebugging; "
               L"cleanup remains retryable from the owning session.\n";
        result.terminationProved = false;
        return result;
    }

    // Persist the at-most-once claim before entering the COM call.  A crash in
    // the tiny claim->call window is inherently indistinguishable from a crash
    // just after the call; recovery therefore never repeats a claimed disable.
    journal.stage = "disable_claimed";
    journal.lastHr = S_OK;
    if (!WriteJournal(journalPath, journal)) {
        std::wcerr << L"Could not claim the one DisableDebugging call; it was not called.\n";
        return result;
    }

    result.disableCalled = true;
    result.disableHr = settings->DisableDebugging(kExpectedPackageFullName);

    // Preserve the actual COM result immediately.  Recovery must never confuse
    // a later containment failure with the outcome of DisableDebugging itself.
    journal.stage = "disable_returned";
    journal.lastHr = result.disableHr;
    if (!WriteJournal(journalPath, journal)) {
        std::wcerr
            << L"DisableDebugging returned but its exact HRESULT could not be "
               L"journaled. Do not call it again automatically.\n";
        return result;
    }

    // The WTS/title checks cannot make a package-wide COM call atomic with a
    // logon or user switch.  Reconcile immediately after the call and refuse a
    // success result if the single-interactive-session invariant changed.
    bool postDisableSessionSafe =
        CheckInteractiveSessions() == InteractiveSessionCheck::onlyCurrent &&
        CheckOtherSessionExactTitles() == OtherSessionTitleCheck::none;

    bool postDisableTerminated = postDisableSessionSafe;
    if (terminateFirst) {
        // Package-debug termination is no longer documented after Disable.
        // Close the activation race with documented process enumeration and
        // exact package-identity TerminateProcess calls instead.
        postDisableTerminated = postDisableTerminated &&
            TerminateExactPackageProcessesAndProve(
                settings, std::chrono::seconds(15));
    }

    journal.stage = postDisableTerminated
        ? "disable_complete" : "disable_postcheck_failed";
    journal.lastHr = result.disableHr;
    if (!WriteJournal(journalPath, journal)) {
        std::wcerr
            << L"DisableDebugging returned but its completion could not be journaled. "
               L"Do not call it again automatically.\n";
        return result;
    }
    result.terminationProved = result.terminationProved &&
                               postDisableTerminated;
    result.cleanupComplete = result.disableHr == S_OK &&
                             postDisableTerminated;
    if (result.cleanupComplete && !retainCompletedJournal) {
        if (!DeleteFileW(journalPath.c_str()) &&
            GetLastError() != ERROR_FILE_NOT_FOUND) {
            std::wcerr << L"Debug mode was disabled, but the completed journal could not be removed.\n";
            result.cleanupComplete = false;
        } else if (ProbeRegularNonReparseFile(journalPath) !=
                   RegularFileProbe::absent) {
            std::wcerr << L"Debug mode was disabled, but journal absence could not be proved.\n";
            result.cleanupComplete = false;
        }
    }
    return result;
}

bool FinishControllerCleanupAcknowledgement(
    Handle const& helperProcess, std::wstring const& journalPath,
    bool requireZeroHelperExit) {
    if (helperProcess) {
        if (WaitForSingleObject(helperProcess.value, 15000) != WAIT_OBJECT_0)
            return false;
        DWORD exitCode = 0;
        if (!GetExitCodeProcess(helperProcess.value, &exitCode) ||
            exitCode == STILL_ACTIVE ||
            (requireZeroHelperExit && exitCode != 0)) {
            return false;
        }
    } else if (requireZeroHelperExit) {
        return false;
    }
    if (!DeleteFileW(journalPath.c_str()) &&
        GetLastError() != ERROR_FILE_NOT_FOUND) {
        return false;
    }
    return ProbeRegularNonReparseFile(journalPath) ==
        RegularFileProbe::absent;
}

int RunOnlinePlayGate(int argc, wchar_t** argv) {
    // Windows appends these exact switches to the registered debugger command.
    if (!GateArgumentShapeValid(argc, argv)) return 70;
    FreeConsole();
    if (!PrivateLocalDirectoryForSelf()) return 71;

    auto pid = ParseDwordArgument(argv[3]);
    auto tid = ParseDwordArgument(argv[5]);
    auto self = CurrentExecutablePath();
    auto journalPath = JournalPathForSelf();
    auto journal = ReadJournal(journalPath);
    if (!pid || !tid || !self || journalPath.empty() || !journal ||
        !ValidNonce(journal->nonce)) return 72;

    std::string nonce = journal->nonce;
    auto expectedResult = ResultPathForExecutable(*self, nonce);
    auto journalResult = FullPath(journal->resultPath);
    if (!expectedResult || !journalResult ||
        !EqualInsensitive(*journalResult, *expectedResult)) return 73;
    auto claimPath = *expectedResult + L".claim";

    bool normalGateStage = journal->stage == "enabled" ||
                           journal->stage == "monitoring";
    bool containmentOnlyStage =
        journal->stage == "enable_intent" ||
        journal->stage == "enable_ambiguous" ||
        journal->stage == "enable_failed" ||
        journal->stage == "cleanup_terminating" ||
        journal->stage == "disable_claimed" ||
        journal->stage == "disable_returned" ||
        journal->stage == "disable_postcheck_failed" ||
        journal->stage == "disable_complete";
    if (!normalGateStage && !containmentOnlyStage) return 74;
    DWORD helperSession = 0;
    DWORD controllerSession = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &helperSession)) return 76;

    Handle controller(OpenProcess(SYNCHRONIZE |
                                      PROCESS_QUERY_LIMITED_INFORMATION,
                                  FALSE, journal->controllerPid));
    auto controllerCreation = controller
        ? ProcessCreationTime100ns(controller.value)
        : std::nullopt;
    bool controllerAuthenticated =
        controller && controllerCreation &&
        *controllerCreation == journal->controllerCreation100ns &&
        WaitForSingleObject(controller.value, 0) == WAIT_TIMEOUT &&
        ProcessIdToSessionId(journal->controllerPid, &controllerSession) &&
        helperSession == controllerSession;

    if (containmentOnlyStage || !controllerAuthenticated) {
        // The package-debug hook can outlive a crashed controller or enter an
        // intentionally non-retriable journal stage.  Never leave a later
        // callback's exact title suspended indefinitely: independently
        // re-authenticate the Windows-supplied PID/TID against the pinned
        // package/path/architecture/creation/session and terminate it.  A
        // monitoring-stage claim is expected for a replacement activation, but
        // its absence is not permission to run game code.
        Handle orphanProcess(OpenProcess(kProcessAccess, FALSE, *pid));
        Handle orphanThread(OpenThread(kThreadAccess, FALSE, *tid));
        auto package = orphanProcess
            ? PackageFullNameForProcess(orphanProcess.value) : std::nullopt;
        auto image = orphanProcess
            ? ImagePathForProcess(orphanProcess.value) : std::nullopt;
        auto expectedPath = ExpectedImagePath();
        auto expectedBrokerPath = ExpectedRuntimeBrokerPath();
        auto creation = orphanProcess
            ? ProcessCreationTime100ns(orphanProcess.value) : std::nullopt;
        DWORD targetSession = 0;
        ULONGLONG now = CurrentFileTimeTicks();
        auto existingClaim = ReadClaim(claimPath);
        bool claimConsistent = journal->stage != "monitoring" ||
            (existingClaim && existingClaim->nonce == nonce);
        bool exactSupportedImage = image &&
            ((expectedPath && SameFileIdentity(*image, *expectedPath)) ||
             (expectedBrokerPath &&
              SameFileIdentity(*image, *expectedBrokerPath)));
        bool exactOrphan = orphanProcess && orphanThread &&
            GetProcessId(orphanProcess.value) == *pid &&
            GetThreadId(orphanThread.value) == *tid &&
            GetProcessIdOfThread(orphanThread.value) == *pid &&
            IsAlive(orphanProcess.value) &&
            WaitForSingleObject(orphanThread.value, 0) == WAIT_TIMEOUT &&
            package && EqualInsensitive(*package, kExpectedPackageFullName) &&
            exactSupportedImage &&
            NativeAmd64Process(orphanProcess.value) && creation &&
            *creation >= journal->armTime100ns && *creation <= now &&
            ProcessIdToSessionId(*pid, &targetSession) &&
            targetSession == helperSession && PinnedManifestInvariantMatches();
        if (!exactOrphan) return 76;
        if (!claimConsistent)
            std::wcerr << L"Monitoring claim was absent or inconsistent after "
                          L"controller loss; terminating exact callback target.\n";
        if (!TerminateKnownProcess(orphanProcess.value, ERROR_CANCELLED))
            return 177;
        return 176;
    }
    auto controllerAlive = [&]() {
        return WaitForSingleObject(controller.value, 0) == WAIT_TIMEOUT;
    };
    auto journalBelongsToRun = [&](Journal const& current) {
        return current.nonce == nonce &&
               current.controllerPid == journal->controllerPid &&
               current.controllerCreation100ns ==
                   journal->controllerCreation100ns;
    };
    auto journalStillEnabled = [&]() {
        auto current = ReadJournal(journalPath);
        return current && journalBelongsToRun(*current) &&
               (current->stage == "enabled" ||
                current->stage == "monitoring") &&
               current->lastHr == S_OK;
    };

    DWORD helperPid = GetCurrentProcessId();
    auto helperCreation = ProcessCreationTime100ns(GetCurrentProcess());
    if (!helperCreation || *helperCreation == 0) return 76;
    DWORD reportedTid = *tid;
    std::uint64_t boundTargetCreation = 0;
    HANDLE verifiedTarget = nullptr;
    auto writeStatus = [&](std::string const& status, DWORD code,
                           std::string const& message) {
        GateResult result;
        result.status = status;
        result.nonce = nonce;
        result.message = message;
        result.code = code;
        result.pid = *pid;
        result.tid = reportedTid;
        result.helperPid = helperPid;
        result.helperCreation100ns = *helperCreation;
        result.targetCreation100ns = boundTargetCreation;
        return WriteResult(*expectedResult, result);
    };
    auto fail = [&](DWORD code, std::string const& message) {
        std::string finalMessage = message;
        bool targetExited = !verifiedTarget ||
            WaitForSingleObject(verifiedTarget, 0) == WAIT_OBJECT_0;
        if (verifiedTarget && !targetExited) {
            TerminateProcess(verifiedTarget, code);
            targetExited =
                WaitForSingleObject(verifiedTarget, 10000) == WAIT_OBJECT_0;
            finalMessage += targetExited
                ? "; exact target terminated"
                : "; exact-target termination not yet proved";
        }
        bool statusWritten = writeStatus("failure", code, finalMessage);
        // Never abandon an authenticated target merely because termination or
        // IPC was slow.  Keep retrying until the target object is signalled;
        // controller cleanup may concurrently use TerminateAllProcesses.
        while (verifiedTarget && !targetExited) {
            TerminateProcess(verifiedTarget, code);
            targetExited =
                WaitForSingleObject(verifiedTarget, 250) == WAIT_OBJECT_0;
            if (!statusWritten)
                statusWritten = writeStatus("failure", code, finalMessage);
        }
        return static_cast<int>(code);
    };

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto queryProcessInformation = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (!queryProcessInformation)
        return fail(77, "NtQueryInformationProcess unavailable");

    Handle process(OpenProcess(kProcessAccess, FALSE, *pid));
    Handle initialThread(OpenThread(kThreadAccess, FALSE, *tid));
    if (!process || !initialThread || GetProcessId(process.value) != *pid ||
        GetThreadId(initialThread.value) != *tid ||
        GetProcessIdOfThread(initialThread.value) != *pid ||
        !IsAlive(process.value) ||
        WaitForSingleObject(initialThread.value, 0) != WAIT_TIMEOUT)
        return fail(78, "PID/TID handles did not identify a live target");
    DWORD targetSession = 0;
    if (!ProcessIdToSessionId(*pid, &targetSession) ||
        targetSession != helperSession)
        return fail(78, "target/helper/controller session binding failed");

    auto package = PackageFullNameForProcess(process.value);
    auto imagePath = ImagePathForProcess(process.value);
    auto expectedPath = ExpectedImagePath();
    auto targetCreation = ProcessCreationTime100ns(process.value);
    ULONGLONG now = CurrentFileTimeTicks();
    bool exactPackageCallback = package &&
        EqualInsensitive(*package, kExpectedPackageFullName) && imagePath &&
        expectedPath && targetCreation &&
        *targetCreation >= journal->armTime100ns && *targetCreation <= now;
    if (exactPackageCallback &&
        !SameFileIdentity(*imagePath, *expectedPath)) {
        // Package debugging also invokes the callback for the package-bound
        // Windows RuntimeBroker.  V7 terminated this callback, and the captured
        // crash dump proved that the title then hit an INT3 while executing a
        // Windows.ApplicationModel package call.  The engine therefore releases only
        // the real System32 RuntimeBroker after proving the same Windows
        // initial-suspension invariant used for the title.  This helper never
        // writes the title's shared IPC tuple.
        auto expectedBrokerPath = ExpectedRuntimeBrokerPath();
        bool exactBroker = expectedBrokerPath &&
            SameFileIdentity(*imagePath, *expectedBrokerPath) &&
            NativeAmd64Process(process.value) &&
            PinnedManifestInvariantMatches();
        if (!exactBroker || !ExactSingleThreadCohort(*pid, *tid) ||
            !controllerAlive() || !journalStillEnabled()) {
            return TerminateKnownProcess(process.value, ERROR_CANCELLED)
                ? 176 : 177;
        }

        DWORD probePrevious = SuspendThread(initialThread.value);
        if (probePrevious != 1 ||
            !ThreadControlContextReadable(initialThread.value) ||
            !ExactSingleThreadCohort(*pid, *tid) ||
            !controllerAlive() || !journalStillEnabled()) {
            return TerminateKnownProcess(process.value, ERROR_CANCELLED)
                ? 176 : 177;
        }

        SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
        DWORD helperReleasePrevious = ResumeThread(initialThread.value);
        if (helperReleasePrevious != 2) {
            return TerminateKnownProcess(process.value, ERROR_INVALID_STATE)
                ? 176 : 177;
        }
        DWORD windowsReleasePrevious = ResumeThread(initialThread.value);
        if (windowsReleasePrevious != 1) {
            return TerminateKnownProcess(process.value, ERROR_INVALID_STATE)
                ? 176 : 177;
        }
        return 0;
    }
    if (!package || !EqualInsensitive(*package, kExpectedPackageFullName) ||
        !imagePath || !expectedPath ||
        !SameFileIdentity(*imagePath, *expectedPath) ||
        !NativeAmd64Process(process.value) || !targetCreation ||
        *targetCreation < journal->armTime100ns || *targetCreation > now)
        return fail(79, "package/path/native-AMD64/creation identity failed");
    verifiedTarget = process.value;
    boundTargetCreation = *targetCreation;
    if (!PinnedManifestInvariantMatches())
        return fail(79, "pinned package manifest invariant failed");
    if (!controllerAlive() || !journalStillEnabled())
        return fail(80, "controller died or cleanup began before target binding");

    Handle claim(CreateFileW(claimPath.c_str(), GENERIC_WRITE, 0, nullptr,
                             CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!claim)
        return fail(81, "one-shot gate claim already exists or could not be created");
    std::ostringstream claimText;
    claimText << "magic=SOW_PACKAGE_GATE_CLAIM_V1\nnonce=" << nonce
              << "\ntarget_pid=" << *pid << "\ntarget_tid=" << *tid
              << "\ntarget_creation_100ns=" << *targetCreation
              << "\nhelper_pid=" << helperPid
              << "\nhelper_creation_100ns=" << *helperCreation << "\n";
    auto claimData = claimText.str();
    if (!WriteAll(claim.value, claimData.data(), claimData.size()) ||
        !FlushFileBuffers(claim.value))
        return fail(82, "could not durably write one-shot gate claim");
    if (!CloseHandle(claim.value))
        return fail(127, "could not close durable one-shot gate claim");
    claim.value = nullptr;

    if (!ExactSingleThreadCohort(*pid, *tid))
        return fail(83, "target did not have exactly one initial thread");
    DWORD probePrevious = SuspendThread(initialThread.value);
    if (probePrevious == static_cast<DWORD>(-1))
        return fail(84, "initial SuspendThread probe failed");
    if (probePrevious != 1)
        return fail(85, "initial suspend count was not exactly one");
    // Keep this helper-owned second suspension until every patch and final
    // control/cohort check has succeeded.  No compensating suspend is ever used.

    auto moduleBase = MainImageBaseFromPeb(process.value, *pid,
                                            queryProcessInformation);
    if (!moduleBase || !VerifyRemotePe(process.value, *moduleBase))
        return fail(87, "PEB MEM_IMAGE base or exact remote PE identity failed");
    if (!RemoteBytesEqual(process.value, *moduleBase + kWriterContextRva,
                          kWriterContext) ||
        !RemoteBytesEqual(process.value, *moduleBase + kDeleteContextRva,
                          kDeleteContext) ||
        !RemoteBytesEqual(process.value, *moduleBase + kStoreContextRva,
                          kStoreContext) ||
        !ThreadControlContextReadable(initialThread.value) ||
        !ExactSingleThreadCohort(*pid, *tid))
        return fail(88, "remote instruction/thread context or cohort failed");

    auto storeCall = *moduleBase + kStoreAccountCallRva;
    CONTEXT initialContext{};
    initialContext.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(initialThread.value, &initialContext) ||
        initialContext.Rip == storeCall ||
        UnsafeGateRip(static_cast<std::uintptr_t>(initialContext.Rip),
                      *moduleBase, storeCall))
        return fail(89, "initial RIP was in or beyond a guarded patch path");
    if (!writeStatus("gate_started", 0,
                     "exact suspended target bound; installing play compatibility patch"))
        return fail(90, "could not publish helper start state");

    if (!controllerAlive() || !journalStillEnabled())
        return fail(91, "controller died or cleanup began before patching");
    if (!ReplaceBytes(process.value, storeCall, kStoreCallOriginal,
                      kStoreCallNops))
        return fail(94, "could not NOP the pinned failing Store call");
    if (!GateBytesMatch(process.value, storeCall, kStoreCallNops) ||
        !ExactSingleThreadCohort(*pid, *tid) ||
        !ThreadControlContextReadable(initialThread.value))
        return fail(95, "pre-release patch/cohort verification failed");
    if (!controllerAlive() || !journalStillEnabled())
        return fail(96, "controller died or cleanup began before exact resume");

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    DWORD helperReleasePrevious = ResumeThread(initialThread.value);
    if (helperReleasePrevious != 2)
        return fail(97, "helper suspension release was not the exact 2-to-1 transition");
    DWORD windowsReleasePrevious = ResumeThread(initialThread.value);
    if (windowsReleasePrevious != 1)
        return fail(97, "Windows initial suspension release was not the exact 1-to-0 transition");
    if (!writeStatus("patched_resumed", 0,
                     "Store-call NOP verified; save and delete paths remain original; title resumed"))
        return fail(98, "could not publish PATCHED_RESUMED");

    // The controller validates the durable claim/identity tuple, then changes
    // the journal to monitoring.  Package debugging deliberately remains
    // enabled: any replacement activation is suspended again, sees the
    // existing CREATE_NEW claim, and is terminated before game code can run.
    auto monitorAckDeadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(15);
    for (;;) {
        auto current = ReadJournal(journalPath);
        if (!current || !journalBelongsToRun(*current))
            return fail(97, "controller monitoring acknowledgement missing or changed identity");
        if (current->stage == "monitoring" && current->lastHr == S_OK) break;
        if (current->stage != "enabled" || current->lastHr != S_OK)
            return fail(99, "unexpected controller monitoring journal stage");
        if (!controllerAlive())
            return fail(100, "controller died before monitoring acknowledgement");
        DWORD targetWait = WaitForSingleObject(process.value, 0);
        if (targetWait == WAIT_TIMEOUT &&
            !GateBytesMatch(process.value, storeCall, kStoreCallNops))
            return fail(101, "process-local patch bytes changed before monitoring acknowledgement");
        if (targetWait != WAIT_TIMEOUT && targetWait != WAIT_OBJECT_0)
            return fail(102, "target wait failed before monitoring acknowledgement");
        if (std::chrono::steady_clock::now() >= monitorAckDeadline)
            return fail(103, "timed out waiting for monitoring acknowledgement");
        std::this_thread::sleep_for(kPollInterval);
    }

    if (!writeStatus("monitoring", 0,
                     "package debugging armed; helper monitoring exact title"))
        return fail(104, "could not publish monitoring state");

    for (;;) {
        if (!controllerAlive())
            return fail(105, "controller died while patched title was active");
        DWORD wait = WaitForSingleObject(process.value, 250);
        if (wait == WAIT_OBJECT_0) break;
        if (wait != WAIT_TIMEOUT)
            return fail(106, "exact target wait failed");
        if (!GateBytesMatch(process.value, storeCall, kStoreCallNops)) {
            if (WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0) break;
            // During normal packaged-title shutdown the image may be unmapped a
            // moment before the process object is signalled.  Allow only a
            // short bounded exit grace; a still-live target after that grace is
            // treated as patch tampering and terminated fail-closed.
            auto exitDeadline = std::chrono::steady_clock::now() +
                                kExitUnmapGrace;
            bool exitedDuringGrace = false;
            while (std::chrono::steady_clock::now() < exitDeadline) {
                if (WaitForSingleObject(process.value, 100) == WAIT_OBJECT_0) {
                    exitedDuringGrace = true;
                    break;
                }
                if (!controllerAlive())
                    return fail(105, "controller died during title exit grace");
            }
            if (exitedDuringGrace) break;
            return fail(107, "process-local Store-call NOP changed while title remained active");
        }
        auto current = ReadJournal(journalPath);
        if (!current || !journalBelongsToRun(*current) ||
            current->stage != "monitoring" ||
            current->lastHr != S_OK)
            return fail(108, "monitoring journal changed while title was active");
    }

    DWORD targetExitCode = STILL_ACTIVE;
    bool exitCodeKnown =
        GetExitCodeProcess(process.value, &targetExitCode) != FALSE &&
        targetExitCode != STILL_ACTIVE;
    verifiedTarget = nullptr;
    if (!exitCodeKnown) {
        if (!writeStatus("failure", ERROR_INVALID_DATA,
                         "exact patched title exited without a readable exit code"))
            return 109;
        return 110;
    }
    if (!IsAcceptedTitleExitCode(targetExitCode)) {
        std::ostringstream message;
        message << "exact patched title crashed or exited nonzero: 0x"
                << std::uppercase << std::hex << std::setw(8)
                << std::setfill('0') << targetExitCode;
        if (!writeStatus("failure", targetExitCode, message.str())) return 109;
        return 110;
    }
    std::string exitMessage = targetExitCode == 1
        ? "exact patched title exited with accepted title-specific code 1; process-local patches are gone"
        : "exact patched title exited cleanly; process-local patches are gone";
    if (!writeStatus("title_exited", 0, exitMessage))
        return 109;
    return 0;
}

int RunSelfTest() {
    auto nonce = GenerateNonce();
    auto self = CurrentExecutablePath();
    if (!nonce || !ValidNonce(*nonce) || !self) return 200;
    std::wstring sampleDebugger =
        L"\"C:\\Users\\u\\AppData\\Local\\SowCompat\\r-0123456789abcdef\\g.exe\" --gate";
    wchar_t gate0[] = L"g.exe";
    wchar_t gate1[] = L"--gate";
    wchar_t gate2[] = L"-p";
    wchar_t gate3[] = L"4294967295";
    wchar_t gate4[] = L"-tid";
    wchar_t gate5[] = L"1";
    wchar_t* validGateArgs[] = {gate0, gate1, gate2, gate3, gate4, gate5};
    wchar_t invalidPid[] = L"0";
    wchar_t* invalidGateArgs[] = {
        gate0, gate1, gate2, invalidPid, gate4, gate5};
    if (!PackageStateCanMeanQuiescent(PES_UNKNOWN) ||
        !PackageStateCanMeanQuiescent(PES_TERMINATED) ||
        PackageStateCanMeanQuiescent(PES_RUNNING) ||
        !IsAcceptedTitleExitCode(0) ||
        !IsAcceptedTitleExitCode(1) ||
        IsAcceptedTitleExitCode(2) ||
        IsAcceptedTitleExitCode(0x80000003) ||
        sampleDebugger.size() > kMaxRegisteredDebuggerCommandChars ||
        sampleDebugger.size() + kWorstCaseWindowsPidTidSuffixChars >=
            kMaxRegisteredDebuggerCommandChars ||
        !GateArgumentShapeValid(6, validGateArgs) ||
        GateArgumentShapeValid(6, invalidGateArgs) ||
        GateArgumentShapeValid(5, validGateArgs) ||
        kStoreCallOriginal.size() != 5 || kStoreCallNops.size() != 5 ||
        !std::all_of(kStoreCallNops.begin(), kStoreCallNops.end(),
                     [](std::uint8_t value) { return value == 0x90; }))
        return 213;
    constexpr std::array<std::uint8_t, 20> shellLinkHeader = {
        0x4C, 0x00, 0x00, 0x00,
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
    std::vector<std::uint8_t> syntheticLink(shellLinkHeader.begin(),
                                             shellLinkHeader.end());
    for (wchar_t character : std::wstring(kExpectedAppUserModelId)) {
        syntheticLink.push_back(static_cast<std::uint8_t>(character & 0xFF));
        syntheticLink.push_back(
            static_cast<std::uint8_t>((character >> 8) & 0xFF));
    }
    if (!ShellLinkContainsExactlyOneAumid(syntheticLink)) return 217;
    std::vector<std::uint8_t> secondAumid(syntheticLink.begin() + 20,
                                          syntheticLink.end());
    syntheticLink.insert(syntheticLink.end(), secondAumid.begin(),
                         secondAumid.end());
    if (ShellLinkContainsExactlyOneAumid(syntheticLink)) return 218;

    auto expectedBrokerPath = ExpectedRuntimeBrokerPath();
    auto canonicalSelf = FullPath(*self);
    if (!canonicalSelf || !EqualInsensitive(*canonicalSelf, *self) ||
        !SameFileIdentity(*canonicalSelf, *self) || !expectedBrokerPath ||
        !SameFileIdentity(*expectedBrokerPath, *expectedBrokerPath) ||
        SameFileIdentity(*canonicalSelf, *expectedBrokerPath)) return 201;
    auto derivedResult = ResultPathForExecutable(*self, *nonce);
    std::wstring expectedResultLeaf = L"sow_online_play_result_" +
        std::wstring(nonce->begin(), nonce->end()) + L".txt";
    if (!derivedResult ||
        !EqualInsensitive(ParentDirectory(*derivedResult),
                          ParentDirectory(*self)) ||
        derivedResult->substr(derivedResult->find_last_of(L"\\/") + 1) !=
            expectedResultLeaf) return 215;

    Journal journal;
    journal.stage = "enabled";
    journal.nonce = *nonce;
    journal.armTime100ns = 123456789;
    journal.resultPath = JoinPath(ParentDirectory(*self), L"result.txt");
    journal.auxiliaryPath = journal.resultPath + L".unused";
    journal.controllerPid = 1234;
    journal.controllerCreation100ns = 987654321;
    journal.lastHr = S_OK;
    auto parsedJournal = ParseJournal(SerializeJournal(journal));
    if (!parsedJournal || parsedJournal->stage != journal.stage ||
        parsedJournal->nonce != journal.nonce ||
        parsedJournal->resultPath != journal.resultPath ||
        parsedJournal->auxiliaryPath != journal.auxiliaryPath ||
        parsedJournal->controllerPid != journal.controllerPid ||
        parsedJournal->controllerCreation100ns !=
            journal.controllerCreation100ns) return 202;

    GateResult result;
    result.status = "patched_resumed";
    result.nonce = *nonce;
    result.challenge.clear();
    result.message = "self-test";
    result.code = 0;
    result.pid = 2222;
    result.tid = 3333;
    result.helperPid = 4444;
    result.helperCreation100ns = 444444;
    result.targetCreation100ns = 555555;
    auto parsedResult = ParseResult(SerializeResult(result));
    if (!parsedResult || parsedResult->status != result.status ||
        parsedResult->nonce != result.nonce ||
        parsedResult->challenge != result.challenge ||
        parsedResult->pid != result.pid || parsedResult->tid != result.tid ||
        parsedResult->helperPid != result.helperPid ||
        parsedResult->helperCreation100ns != result.helperCreation100ns ||
        parsedResult->targetCreation100ns != result.targetCreation100ns)
        return 203;

    GateResult crashResult = result;
    crashResult.status = "failure";
    crashResult.code = 0x80000003;
    crashResult.message = "exact patched title crashed or exited nonzero";
    auto parsedCrashResult = ParseResult(SerializeResult(crashResult));
    if (!parsedCrashResult || parsedCrashResult->status != "failure" ||
        parsedCrashResult->code != 0x80000003 ||
        parsedCrashResult->message != crashResult.message)
        return 216;

    std::ostringstream claimSerialization;
    claimSerialization << "magic=SOW_PACKAGE_GATE_CLAIM_V1\n"
                       << "nonce=" << *nonce << "\n"
                       << "target_pid=" << result.pid << "\n"
                       << "target_tid=" << result.tid << "\n"
                       << "target_creation_100ns="
                       << result.targetCreation100ns << "\n"
                       << "helper_pid=" << result.helperPid << "\n"
                       << "helper_creation_100ns="
                       << result.helperCreation100ns << "\n";
    auto parsedClaim = ParseClaim(claimSerialization.str());
    if (!parsedClaim || parsedClaim->nonce != *nonce ||
        parsedClaim->targetPid != result.pid ||
        parsedClaim->targetTid != result.tid ||
        parsedClaim->targetCreation100ns != result.targetCreation100ns ||
        parsedClaim->helperPid != result.helperPid ||
        parsedClaim->helperCreation100ns != result.helperCreation100ns)
        return 209;

    RecoveryReceipt recoveryReceipt;
    recoveryReceipt.attemptNonce = *nonce;
    recoveryReceipt.outcome = "debug_disabled";
    recoveryReceipt.nonce = *nonce;
    recoveryReceipt.priorStage = "enabled";
    recoveryReceipt.lastHr = "00000000";
    recoveryReceipt.recoveryPid = 6666;
    recoveryReceipt.recoveryCreation100ns = 777777;
    recoveryReceipt.sessionId = 1;
    auto parsedRecoveryReceipt = ParseRecoveryReceipt(
        SerializeRecoveryReceipt(recoveryReceipt));
    if (!parsedRecoveryReceipt ||
        parsedRecoveryReceipt->attemptNonce != recoveryReceipt.attemptNonce ||
        parsedRecoveryReceipt->outcome != recoveryReceipt.outcome ||
        parsedRecoveryReceipt->nonce != recoveryReceipt.nonce ||
        parsedRecoveryReceipt->priorStage != recoveryReceipt.priorStage ||
        parsedRecoveryReceipt->lastHr != recoveryReceipt.lastHr ||
        parsedRecoveryReceipt->recoveryPid != recoveryReceipt.recoveryPid ||
        parsedRecoveryReceipt->recoveryCreation100ns !=
            recoveryReceipt.recoveryCreation100ns ||
        parsedRecoveryReceipt->sessionId != recoveryReceipt.sessionId ||
        RecoveryReceiptLine(recoveryReceipt).find(
            "RECOVERY_COMPLETE attempt_nonce=" + *nonce) != 0) {
        return 210;
    }
    recoveryReceipt.outcome = "enable_failed_clean";
    recoveryReceipt.priorStage = "enable_failed";
    recoveryReceipt.lastHr = "00000001";  // S_FALSE is not definitive failure.
    if (ValidRecoveryReceipt(recoveryReceipt)) return 211;
    recoveryReceipt.lastHr = "80004005";  // E_FAIL is definitive failure.
    if (!ValidRecoveryReceipt(recoveryReceipt)) return 212;

    std::wstring testPath = JoinPath(
        ParentDirectory(*self), L"self_test_" +
        std::wstring(nonce->begin(), nonce->end()) + L".txt");
    if (ProbeRegularNonReparseFile(testPath) != RegularFileProbe::absent ||
        !AtomicWriteUtf8(testPath, "first\n") ||
        !AtomicWriteUtf8(testPath, "second\n") ||
        ProbeRegularNonReparseFile(testPath) != RegularFileProbe::present ||
        SameFileIdentity(*self, testPath))
        return 205;
    auto readBack = ReadSmallUtf8File(testPath);
    bool deleted = DeleteFileW(testPath.c_str()) != FALSE;
    if (!readBack || *readBack != "second\n" || !deleted ||
        ProbeRegularNonReparseFile(testPath) != RegularFileProbe::absent)
        return 206;

    std::wstring claimTestPath = JoinPath(
        ParentDirectory(*self), L"self_test_claim_" +
        std::wstring(nonce->begin(), nonce->end()) + L".txt");
    Handle claimTest(CreateFileW(claimTestPath.c_str(), GENERIC_WRITE, 0,
                                 nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                                 nullptr));
    constexpr char kClaimProbe[] = "claim-readable-after-close\n";
    if (!claimTest ||
        !WriteAll(claimTest.value, kClaimProbe, sizeof(kClaimProbe) - 1) ||
        !FlushFileBuffers(claimTest.value) ||
        !CloseHandle(claimTest.value)) return 207;
    claimTest.value = nullptr;
    auto claimReadBack = ReadSmallUtf8File(claimTestPath);
    bool claimDeleted = DeleteFileW(claimTestPath.c_str()) != FALSE;
    if (!claimReadBack || *claimReadBack != kClaimProbe || !claimDeleted ||
        ProbeRegularNonReparseFile(claimTestPath) != RegularFileProbe::absent)
        return 208;

    std::wcout << L"SELF_TEST_OK: profile table, callback command, semantic app-link parser, RuntimeBroker identity, title exit-code policy, crash/status/claim serialization, "
                  L"PES_UNKNOWN policy, NOP pin, "
                  L"nonce, path/file identity, and atomic-file checks passed.\n";
    return 0;
}

int RunRecovery(std::string const& attemptNonce,
                std::wstring const& suppliedReceiptPath) {
    if (!IsMediumIntegrity()) {
        std::wcerr << L"Recovery must run as the interactive user at medium integrity (not elevated).\n";
        return 120;
    }
    if (!PrivateLocalDirectoryForSelf()) {
        std::wcerr << L"Recovery executable directory is not a protected local non-reparse directory.\n";
        return 133;
    }
    OwnedMutex mutex = AcquireProtectedGlobalMutex();
    if (!mutex) {
        std::wcerr << L"Another controller/recovery operation is active.\n";
        return 121;
    }
    gCancelled.store(false, std::memory_order_relaxed);
    SetConsoleCtrlHandler(ConsoleControlHandler, TRUE);
    auto journalPath = JournalPathForSelf();
    if (journalPath.empty()) return 122;
    auto recoverySelf = CurrentExecutablePath();
    if (!recoverySelf || !ValidNonce(attemptNonce)) return 122;
    std::wstring attemptWide(attemptNonce.begin(), attemptNonce.end());
    auto expectedReceiptPath = FullPath(JoinPath(
        ParentDirectory(*recoverySelf),
        L"sow_package_gate_recovery_" + attemptWide + L".receipt"));
    auto canonicalSuppliedReceipt = FullPath(suppliedReceiptPath);
    if (!expectedReceiptPath || !canonicalSuppliedReceipt ||
        !EqualInsensitive(*expectedReceiptPath, *canonicalSuppliedReceipt)) {
        std::wcerr << L"Recovery receipt must be the nonce-derived direct child of the protected executable directory.\n";
        return 119;
    }
    std::wstring recoveryReceiptPath = *expectedReceiptPath;
    RegularFileProbe receiptProbe =
        ProbeRegularNonReparseFile(recoveryReceiptPath);
    if (receiptProbe == RegularFileProbe::error) return 144;
    std::optional<RecoveryReceipt> existingReceipt;
    if (receiptProbe == RegularFileProbe::present) {
        existingReceipt = ReadRecoveryReceipt(recoveryReceiptPath);
        if (!existingReceipt ||
            existingReceipt->attemptNonce != attemptNonce) return 144;
    }
    auto recoveryCreation = ProcessCreationTime100ns(GetCurrentProcess());
    if (!recoveryCreation) return 135;
    DWORD recoverySession = 0;
    InteractiveSessionCheck recoverySessionCheck =
        CheckInteractiveSessions(&recoverySession);
    if (existingReceipt) {
        // The receipt tuple identifies the historical producer.  WTS session
        // ids can legitimately change after logout or reboot, so do not compare
        // it to this reconciler's session.  The protected attempt path/nonce
        // bind the durable receipt; this process separately proved above that
        // it is now the sole allowed interactive session.
        Handle prior(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                 FALSE, existingReceipt->recoveryPid));
        if (prior) {
            auto priorCreation = ProcessCreationTime100ns(prior.value);
            if (!priorCreation) {
                if (WaitForSingleObject(prior.value, 0) != WAIT_OBJECT_0)
                    return 147;
            } else if (*priorCreation ==
                           existingReceipt->recoveryCreation100ns &&
                       WaitForSingleObject(prior.value, 0) != WAIT_OBJECT_0) {
                return 147;
            }
        } else if (GetLastError() != ERROR_INVALID_PARAMETER) {
            return 147;
        }
    }
    auto makeRecoveryReceipt = [&](char const* outcome,
                                   std::string const& nonce,
                                   std::string const& priorStage,
                                   std::string const& lastHr) {
        RecoveryReceipt receipt;
        receipt.attemptNonce = attemptNonce;
        receipt.outcome = outcome;
        receipt.nonce = nonce;
        receipt.priorStage = priorStage;
        receipt.lastHr = lastHr;
        receipt.recoveryPid = GetCurrentProcessId();
        receipt.recoveryCreation100ns = *recoveryCreation;
        receipt.sessionId = recoverySession;
        return receipt;
    };
    auto persistRecoveryReceipt = [&](RecoveryReceipt const& receipt) {
        return ValidRecoveryReceipt(receipt) &&
            AtomicWriteUtf8(recoveryReceiptPath,
                            SerializeRecoveryReceipt(receipt));
    };
    auto emitRecoveryComplete = [&](RecoveryReceipt const& receipt) {
        std::string line = RecoveryReceiptLine(receipt);
        std::wcout << std::wstring(line.begin(), line.end()) << L"\n"
                   << std::flush;
    };

    RegularFileProbe journalProbe =
        ProbeRegularNonReparseFile(journalPath);
    std::optional<Journal> journal;
    if (journalProbe == RegularFileProbe::present) {
        journal = ReadJournal(journalPath);
    }

    // Contain identities that can be authenticated without COM first.  This
    // remains effective if manifest hashing or PackageDebugSettings creation
    // subsequently fails.  Keep the two attempts independent so one bad
    // candidate never prevents the other set from being stopped.
    bool boundContained = true;
    if (journal) boundContained = TerminateJournalBoundProcesses(*journal);
    bool titleContained = TerminateExactTitleProcesses(
        std::chrono::seconds(15));
    OtherSessionTitleCheck otherSessionTitle =
        CheckOtherSessionExactTitles();

    if (recoverySessionCheck != InteractiveSessionCheck::onlyCurrent ||
        otherSessionTitle != OtherSessionTitleCheck::none) {
        std::wcerr
            << L"STOP: another Active/Connected interactive session exists "
               L", an exact title exists in another session, or session/process "
               L"enumeration failed. Current-session known processes were "
            << (boundContained && titleContained ? L"contained" : L"not fully contained")
            << L"; package-wide TerminateAllProcesses/DisableDebugging were not called.\n";
        return 141;
    }

    CoInit com;
    ComPtr<IPackageDebugSettings> settings;
    HRESULT createHr = com.ok() ? CreatePackageDebugSettings(settings)
                                : com.status;
    if (FAILED(createHr)) {
        std::wcerr << L"Could not create PackageDebugSettings; package termination cannot be proved: "
                   << HresultText(createHr)
                   << L". Known-process containment was "
                   << (boundContained && titleContained ? L"completed" : L"incomplete")
                   << L".\n";
        return 124;
    }
    HRESULT recoverySessionHr =
        settings->SetTargetSessionId(recoverySession);
    if (recoverySessionHr != S_OK) {
        std::wcerr << L"Could not bind package-debug recovery to the verified "
                      L"interactive session: "
                   << HresultText(recoverySessionHr) << L".\n";
        return 149;
    }
    auto exactTerminateAndProve = [&]() {
        bool titlesStopped = TerminateExactTitleProcesses(
            std::chrono::seconds(15));
        bool packageStopped = TerminateExactPackageProcessesAndProve(
            settings.Get(), std::chrono::seconds(15));
        return titlesStopped && packageStopped;
    };
    auto terminateAndProve = [&]() {
        if (CheckInteractiveSessions() !=
                InteractiveSessionCheck::onlyCurrent ||
            CheckOtherSessionExactTitles() !=
                OtherSessionTitleCheck::none) return false;
        settings->TerminateAllProcesses(kExpectedPackageFullName);
        bool terminated = exactTerminateAndProve();
        return terminated &&
            CheckInteractiveSessions() ==
                InteractiveSessionCheck::onlyCurrent &&
            CheckOtherSessionExactTitles() ==
                OtherSessionTitleCheck::none;
    };

    if (existingReceipt) {
        bool compatible = false;
        if (journalProbe == RegularFileProbe::absent) {
            // Mirror the fresh no-journal rule.  An abandoned package-global
            // owner could have left debug debt in another protected run
            // directory; a stale receipt must never mask that signal.
            compatible = !mutex.abandoned;
        } else if (journalProbe == RegularFileProbe::present && journal) {
            bool sameNonce = existingReceipt->nonce == journal->nonce;
            bool sameHr = existingReceipt->lastHr ==
                          HexHresult(journal->lastHr);
            if (existingReceipt->outcome == "enable_failed_clean") {
                compatible = journal->stage == "enable_failed" && sameNonce &&
                             sameHr;
            } else if (existingReceipt->outcome == "already_disabled" ||
                       existingReceipt->outcome == "debug_disabled") {
                bool completedStage =
                    journal->stage == "disable_complete" ||
                    journal->stage == "disable_returned" ||
                    journal->stage == "disable_postcheck_failed";
                compatible = completedStage && journal->lastHr == S_OK &&
                             sameNonce;
            }
        }
        if (!compatible || !boundContained || !titleContained ||
            !exactTerminateAndProve()) {
            std::wcerr
                << L"STOP: existing recovery receipt could not be reconciled safely.\n";
            return 148;
        }
        if (journalProbe == RegularFileProbe::present &&
            ((!DeleteFileW(journalPath.c_str()) &&
              GetLastError() != ERROR_FILE_NOT_FOUND) ||
             ProbeRegularNonReparseFile(journalPath) !=
                 RegularFileProbe::absent)) {
            return 149;
        }
        emitRecoveryComplete(*existingReceipt);
        return 0;
    }

    if (journalProbe == RegularFileProbe::error) {
        bool terminated = terminateAndProve();
        std::wcerr
            << L"The active journal path is inaccessible, a directory, or a reparse point. "
               L"Package termination "
            << (terminated ? L"was proved" : L"could not be proved")
            << L"; refusing to treat it as absent.\n";
        return 134;
    }
    if (journalProbe == RegularFileProbe::absent) {
        bool terminated = terminateAndProve();
        if (!titleContained || !terminated) {
            std::wcerr << L"No journal exists and package termination could not be proved.\n";
            return 136;
        }
        std::wcout << L"No package-debug journal exists; package termination was nevertheless proved. "
                      L"No DisableDebugging call was made.\n";
        if (mutex.abandoned) {
            std::wcerr
                << L"The package-global mutex was abandoned but this executable directory has no journal. "
                   L"Run recovery from the exact staged directory recorded by the supervisor.\n";
            return 137;
        }
        auto receiptLine = makeRecoveryReceipt(
            "termination_only", "none", "absent", "none");
        if (!persistRecoveryReceipt(receiptLine)) return 145;
        emitRecoveryComplete(receiptLine);
        return 0;
    }
    if (!journal) {
        bool terminated = terminateAndProve();
        std::wcerr << L"Journal exists but is malformed. Package termination "
                   << (terminated ? L"was proved" : L"could not be proved")
                   << L"; refusing DisableDebugging.\n";
        return 123;
    }

    if (!boundContained || !titleContained) {
        bool terminated = terminateAndProve();
        std::wcerr
            << L"Recovery could not contain every protected journal/claim/title identity. "
               L"Package termination "
            << (terminated ? L"was proved" : L"could not be proved")
            << L"; refusing automatic DisableDebugging.\n";
        return 140;
    }

    if (journal->stage == "enable_failed") {
        if (!FAILED(journal->lastHr)) {
            bool terminated = exactTerminateAndProve();
            std::wcerr << L"enable_failed journal carried a non-failure HRESULT; package termination "
                       << (terminated ? L"was proved" : L"could not be proved")
                       << L", but the journal is inconsistent.\n";
            return 142;
        }
        if (!exactTerminateAndProve()) return 138;
        auto receiptLine = makeRecoveryReceipt(
            "enable_failed_clean", journal->nonce, journal->stage,
            HexHresult(journal->lastHr));
        if (!persistRecoveryReceipt(receiptLine)) return 145;
        if ((!DeleteFileW(journalPath.c_str()) &&
             GetLastError() != ERROR_FILE_NOT_FOUND) ||
            ProbeRegularNonReparseFile(journalPath) !=
                RegularFileProbe::absent) return 125;
        std::wcout << L"Removed journal for an EnableDebugging call that returned failure.\n";
        emitRecoveryComplete(receiptLine);
        return 0;
    }
    if (journal->stage == "disable_complete" ||
        journal->stage == "disable_returned" ||
        journal->stage == "disable_postcheck_failed") {
        if (journal->lastHr == S_OK) {
            if (!exactTerminateAndProve()) return 139;
            auto receiptLine = makeRecoveryReceipt(
                "already_disabled", journal->nonce, journal->stage,
                HexHresult(journal->lastHr));
            if (!persistRecoveryReceipt(receiptLine)) return 145;
            if ((!DeleteFileW(journalPath.c_str()) &&
                 GetLastError() != ERROR_FILE_NOT_FOUND) ||
                ProbeRegularNonReparseFile(journalPath) !=
                    RegularFileProbe::absent) return 126;
            std::wcout << L"Removed already-completed cleanup journal.\n";
            emitRecoveryComplete(receiptLine);
            return 0;
        }
        std::wcerr
            << L"DisableDebugging was already called exactly once and failed ("
            << HresultText(journal->lastHr)
            << L"). Package termination "
            << (exactTerminateAndProve() ? L"was proved" : L"could not be proved")
            << L"; automatic retry is forbidden; use PLMDebug/manual inspection.\n";
        return 127;
    }
    if (journal->stage == "disable_claimed") {
        // It is impossible after a crash to know whether the COM call began.
        // Preserve at-most-once semantics and never decrement a debug reference
        // that may already have been decremented.
        bool terminated = exactTerminateAndProve();
        std::wcerr
            << L"Cleanup was claimed before a crash. Package termination "
            << (terminated ? L"was proved" : L"could not be proved")
            << L", "
               L"but DisableDebugging will not be repeated automatically. Inspect with PLMDebug.\n";
        return 128;
    }
    if (journal->stage == "enable_intent" ||
        journal->stage == "enable_ambiguous") {
        bool terminated = terminateAndProve();
        std::wcerr
            << L"EnableDebugging ownership is crash-window ambiguous. Exact "
               L"package termination "
            << (terminated ? L"was proved" : L"could not be proved")
            << L", but automatic DisableDebugging is forbidden because it "
               L"could decrement another owner's reference. Inspect with "
               L"PLMDebug/manual recovery; journal retained.\n";
        return 130;
    }
    if (journal->stage != "enable_intent" && journal->stage != "enabled" &&
        journal->stage != "monitoring" &&
        journal->stage != "cleanup_terminating") {
        bool terminated = terminateAndProve();
        std::wcerr << L"Unknown journal stage; package termination "
                   << (terminated ? L"was proved" : L"could not be proved")
                   << L"; refusing recovery.\n";
        return 129;
    }
    if (journal->lastHr != S_OK) {
        bool terminated = terminateAndProve();
        std::wcerr << L"Owned recovery journal carried a non-S_OK pre-cleanup HRESULT. "
                      L"Package termination "
                   << (terminated ? L"was proved" : L"could not be proved")
                   << L"; refusing automatic DisableDebugging.\n";
        return 143;
    }

    std::string priorStage = journal->stage;
    HRESULT priorLastHr = journal->lastHr;
    auto cleanup = CleanupDebugSetting(settings.Get(), journalPath, *journal,
                                       true, true);
    if (!cleanup.terminationProved || !cleanup.disableCalled ||
        !cleanup.cleanupComplete) {
        bool recoveryBoundStopped = TerminateJournalBoundProcesses(*journal);
        bool recoveryTitlesStopped = TerminateExactTitleProcesses(
            std::chrono::seconds(15));
        if (!recoveryBoundStopped || !recoveryTitlesStopped)
            std::wcerr << L"STOP: recovery containment could not be proved.\n";
        if (!cleanup.terminationProved) return 130;
        if (!cleanup.disableCalled) return 131;
        std::wcerr << L"DisableDebugging failed: "
                   << HresultText(cleanup.disableHr) << L".\n";
        return 132;
    }
    std::wcout << L"Recovery terminated the package and disabled debug mode once.\n";
    auto receiptLine = makeRecoveryReceipt(
        "debug_disabled", journal->nonce, priorStage,
        HexHresult(priorLastHr));
    if (!persistRecoveryReceipt(receiptLine)) return 145;
    if ((!DeleteFileW(journalPath.c_str()) &&
         GetLastError() != ERROR_FILE_NOT_FOUND) ||
        ProbeRegularNonReparseFile(journalPath) !=
            RegularFileProbe::absent) return 146;
    emitRecoveryComplete(receiptLine);
    return 0;
}

int RunOnlinePlayController() {
    if (!IsMediumIntegrity()) {
        std::wcerr
            << L"Run --arm-online-play as the interactive user at medium integrity (not elevated).\n";
        return 140;
    }
    if (!PrivateLocalDirectoryForSelf()) {
        std::wcerr
            << L"Refusing to arm: executable directory must be local, fixed, "
               L"non-reparse, inheritance-protected, and restricted to this "
               L"user, SYSTEM, and Administrators.\n";
        return 165;
    }

    DWORD controllerSession = 0;
    InteractiveSessionCheck sessionCheck =
        CheckInteractiveSessions(&controllerSession);
    if (sessionCheck != InteractiveSessionCheck::onlyCurrent) {
        std::wcerr
            << L"Refusing to arm: another interactive session exists or "
               L"session enumeration failed.\n";
        return sessionCheck == InteractiveSessionCheck::otherPresent ? 192 : 193;
    }

    OwnedMutex mutex = AcquireProtectedGlobalMutex();
    if (!mutex) {
        std::wcerr << L"Another controller/recovery operation is active.\n";
        return 141;
    }
    if (mutex.abandoned) {
        std::wcerr
            << L"A prior controller owner died. Resolve its protected journal "
               L"before arming a new run.\n";
        return 183;
    }

    gCancelled.store(false, std::memory_order_relaxed);
    SetConsoleCtrlHandler(ConsoleControlHandler, TRUE);
    auto self = CurrentExecutablePath();
    auto journalPath = JournalPathForSelf();
    if (!self || journalPath.empty()) return 142;
    if (ProbeRegularNonReparseFile(journalPath) != RegularFileProbe::absent) {
        std::wcerr
            << L"A prior journal exists or cannot be proved absent. Recovery "
               L"is required; this run will not arm.\n";
        return 143;
    }

    auto existing = FindProcessIds();
    if (!existing || !existing->empty()) {
        std::wcerr
            << L"ShadowOfWar.exe is running or process enumeration failed. "
               L"Close it before arming.\n";
        return 144;
    }

    auto nonce = GenerateNonce();
    if (!nonce) return 145;
    auto directory = ParentDirectory(*self);
    auto resultPathValue = ResultPathForExecutable(*self, *nonce);
    if (!resultPathValue) return 145;
    auto resultPath = *resultPathValue;
    auto claimPath = resultPath + L".claim";
    auto auxiliaryPath = resultPath + L".unused";
    if (FileExists(resultPath) || FileExists(claimPath) ||
        FileExists(auxiliaryPath)) {
        std::wcerr << L"Nonce-specific IPC path unexpectedly exists.\n";
        return 146;
    }

    CoInit com;
    ComPtr<IPackageDebugSettings> settings;
    HRESULT createHr = com.ok() ? CreatePackageDebugSettings(settings)
                                : com.status;
    if (FAILED(createHr)) {
        std::wcerr << L"Could not create PackageDebugSettings: "
                   << HresultText(createHr) << L".\n";
        return 147;
    }
    HRESULT targetSessionHr =
        settings->SetTargetSessionId(controllerSession);
    if (targetSessionHr != S_OK) {
        std::wcerr << L"Could not bind package debugging to this verified "
                      L"interactive session: "
                   << HresultText(targetSessionHr) << L".\n";
        return 198;
    }

    if (!WaitForPackageQuiescent(settings.Get(),
                                  std::chrono::milliseconds(500))) {
        std::wcerr
            << L"Package quiescence was not proved. PES_UNKNOWN is accepted "
               L"only with the pinned manifest and two stable empty exact-"
               L"process scans.\n";
        return 166;
    }

    Journal journal;
    journal.stage = "enable_intent";
    journal.nonce = *nonce;
    journal.armTime100ns = CurrentFileTimeTicks();
    journal.resultPath = resultPath;
    journal.auxiliaryPath = auxiliaryPath;
    journal.controllerPid = GetCurrentProcessId();
    auto ownCreation = ProcessCreationTime100ns(GetCurrentProcess());
    if (!ownCreation) return 167;
    journal.controllerCreation100ns = *ownCreation;
    journal.lastHr = S_OK;

    auto containCurrentRun = [&]() {
        bool boundStopped = TerminateJournalBoundProcesses(journal);
        bool titlesStopped =
            TerminateExactTitleProcesses(std::chrono::seconds(15));
        return boundStopped && titlesStopped;
    };
    if (!WriteJournal(journalPath, journal)) {
        std::wcerr << L"Could not write enable intent; EnableDebugging was not called.\n";
        return 148;
    }

    auto finishEnableNotCalled = [&](HRESULT reason,
                                     std::wstring const& diagnostic,
                                     int cleanExit, int retainedExit) {
        journal.stage = "enable_failed";
        journal.lastHr = reason;
        bool recorded = WriteJournal(journalPath, journal);
        bool removed =
            (DeleteFileW(journalPath.c_str()) != FALSE ||
             GetLastError() == ERROR_FILE_NOT_FOUND) &&
            ProbeRegularNonReparseFile(journalPath) ==
                RegularFileProbe::absent;
        std::wcerr << diagnostic << L"\n";
        if (removed) return cleanExit;
        std::wcerr
            << (recorded
                    ? L"EnableDebugging was not called; an enable_failed journal remains.\n"
                    : L"EnableDebugging was not called, but journal cleanup is unproved.\n");
        return retainedExit;
    };

    if (gCancelled.load(std::memory_order_relaxed)) {
        return finishEnableNotCalled(
            HRESULT_FROM_WIN32(ERROR_CANCELLED),
            L"Cancelled before EnableDebugging; no debug hook was requested.",
            184, 188);
    }

    std::wstring debuggerCommand =
        QuoteCommandLineArgument(*self) + L" --gate";
    std::size_t registeredChars = debuggerCommand.size();
    std::size_t worstCaseChars = registeredChars +
        kWorstCaseWindowsPidTidSuffixChars;
    std::wcout << L"DEBUGGER_COMMAND_CHARS registered=" << registeredChars
               << L" worst_case_with_windows_pid_tid=" << worstCaseChars
               << L"\n";
    if (registeredChars > kMaxRegisteredDebuggerCommandChars ||
        worstCaseChars >= kMaxRegisteredDebuggerCommandChars) {
        return finishEnableNotCalled(
            E_INVALIDARG,
            L"Short debugger command invariant failed; EnableDebugging was not called.",
            190, 191);
    }

    DWORD preEnableSession = 0;
    if (CheckInteractiveSessions(&preEnableSession) !=
            InteractiveSessionCheck::onlyCurrent ||
        preEnableSession != controllerSession ||
        CheckOtherSessionExactTitles() != OtherSessionTitleCheck::none ||
        !WaitForPackageQuiescent(settings.Get(),
                                  std::chrono::milliseconds(500))) {
        return finishEnableNotCalled(
            HRESULT_FROM_WIN32(ERROR_BUSY),
            L"Session/title/package state changed before EnableDebugging; "
            L"the hook was not enabled.",
            194, 195);
    }
    if (gCancelled.load(std::memory_order_relaxed)) {
        return finishEnableNotCalled(
            HRESULT_FROM_WIN32(ERROR_CANCELLED),
            L"Cancelled at the final pre-enable barrier; no hook was requested.",
            184, 188);
    }

    targetSessionHr = settings->SetTargetSessionId(controllerSession);
    if (targetSessionHr != S_OK) {
        return finishEnableNotCalled(
            targetSessionHr,
            L"Could not reassert the verified target session immediately "
            L"before EnableDebugging; the hook was not enabled.",
            198, 199);
    }

    HRESULT enableHr = settings->EnableDebugging(
        kExpectedPackageFullName, debuggerCommand.c_str(), nullptr);
    if (enableHr != S_OK) {
        journal.stage = FAILED(enableHr)
            ? "enable_failed" : "enable_ambiguous";
        journal.lastHr = enableHr;
        bool recorded = WriteJournal(journalPath, journal);
        bool contained = containCurrentRun();
        std::wcerr
            << L"EnableDebugging returned non-S_OK "
            << HresultText(enableHr)
            << (FAILED(enableHr)
                    ? L". The returned failure is journaled as enable_failed; "
                      L"DisableDebugging was not called. Journal "
                    : L". A non-S_OK success code is ownership-ambiguous; "
                      L"automatic DisableDebugging is forbidden. Journal ")
            << (recorded ? L"retained" : L"could not be updated")
            << L" and exact-process containment "
            << (contained ? L"was proved" : L"could not be proved") << L".\n";
        return recorded && contained ? 168 : 169;
    }

    journal.stage = "enabled";
    journal.lastHr = S_OK;
    if (!WriteJournal(journalPath, journal)) {
        std::wcerr
            << L"Could not journal successful enable; terminating and cleaning up.\n";
        auto cleanup =
            CleanupDebugSetting(settings.Get(), journalPath, journal, true);
        if (!cleanup.cleanupComplete && !containCurrentRun())
            std::wcerr << L"Current-run containment could not be proved.\n";
        return cleanup.cleanupComplete ? 150 : 151;
    }

    DWORD postEnableSession = 0;
    auto postEnableTitles = FindProcessIds();
    if (CheckInteractiveSessions(&postEnableSession) !=
            InteractiveSessionCheck::onlyCurrent ||
        postEnableSession != controllerSession ||
        CheckOtherSessionExactTitles() != OtherSessionTitleCheck::none ||
        !postEnableTitles || !postEnableTitles->empty()) {
        bool contained = containCurrentRun();
        std::wcerr
            << L"Session/title state changed during EnableDebugging; enabled "
               L"journal retained. Current-session containment "
            << (contained ? L"was proved" : L"could not be proved") << L".\n";
        return contained ? 196 : 197;
    }

    if (gCancelled.load(std::memory_order_relaxed)) {
        auto cleanup =
            CleanupDebugSetting(settings.Get(), journalPath, journal, true);
        if (cleanup.cleanupComplete)
            FinishControllerCleanupAcknowledgement(
                Handle(), journalPath, false);
        return cleanup.cleanupComplete ? 185 : 186;
    }

    std::wcout
        << L"ARMED_ONLINE_PLAY\n"
         << L"Opening the semantically verified Shadow of War Xbox app-link now.\n"
        << L"Click Play in the Xbox app when it appears.\n"
        << L"Normal play and saving are enabled. Use the recovered existing game.\n"
        << L"Network remains untouched and ONLINE. Waiting for the Windows "
           L"initial-suspension callback...\n"
        << std::flush;

    auto desktopLaunchLink = SemanticallyVerifiedDesktopLaunchLink();
    SHELLEXECUTEINFOW activationInfo{};
    activationInfo.cbSize = sizeof(activationInfo);
    activationInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC |
                           SEE_MASK_FLAG_NO_UI;
    activationInfo.lpVerb = L"open";
    activationInfo.lpFile = desktopLaunchLink
        ? desktopLaunchLink->c_str() : L"";
    activationInfo.nShow = SW_SHOWNORMAL;
    bool activationStarted = desktopLaunchLink &&
        ShellExecuteExW(&activationInfo) != FALSE;
    DWORD activationError = activationStarted ? ERROR_SUCCESS : GetLastError();
    Handle activationProcess(activationInfo.hProcess);
    if (!activationStarted) {
        std::wcerr << L"Exact shell package-app activation failed: "
                   << HresultText(HRESULT_FROM_WIN32(activationError)) << L".\n";
        auto failedCleanup = CleanupDebugSetting(
            settings.Get(), journalPath, journal, true, true);
        if (failedCleanup.cleanupComplete)
            FinishControllerCleanupAcknowledgement(
                Handle(), journalPath, false);
        return failedCleanup.cleanupComplete ? 200 : 201;
    }
    std::wcout << L"XBOX_APP_LINK_OPENED_CLICK_PLAY aumid="
               << kExpectedAppUserModelId << L"\n" << std::flush;

    std::optional<GateResult> patched;
    DWORD boundTargetPid = 0;
    DWORD boundTargetTid = 0;
    DWORD boundHelperPid = 0;
    std::uint64_t boundTargetCreation = 0;
    std::uint64_t boundHelperCreation = 0;
    Handle helperProcess;
    auto launchDeadline =
        std::chrono::steady_clock::now() + kControllerLaunchTimeout;

    auto resultTupleValid = [&](GateResult const& result) {
        return result.nonce == *nonce && result.challenge.empty() &&
               result.pid != 0 && result.tid != 0 &&
               result.helperPid != 0 &&
               ((result.status == "failure" && result.code != 0) ||
                (result.status != "failure" && result.code == 0)) &&
               result.targetCreation100ns >= journal.armTime100ns &&
               result.helperCreation100ns >= journal.armTime100ns;
    };

    for (;;) {
        if (gCancelled.load(std::memory_order_relaxed)) break;
        if (FileExists(resultPath)) {
            auto result = ReadResult(resultPath);
            if (!result || !resultTupleValid(*result)) {
                std::wcerr << L"Malformed or unauthenticated helper result.\n";
                break;
            }

            if (boundTargetPid == 0) {
                boundTargetPid = result->pid;
                boundTargetTid = result->tid;
                boundHelperPid = result->helperPid;
                boundTargetCreation = result->targetCreation100ns;
                boundHelperCreation = result->helperCreation100ns;
                DWORD targetSession = 0;
                if (!ProcessIdToSessionId(boundTargetPid, &targetSession) ||
                    targetSession != controllerSession) {
                    std::wcerr << L"Target session did not match controller.\n";
                    break;
                }
                helperProcess = Handle(OpenProcess(
                    SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE, boundHelperPid));
                auto helperImage = helperProcess
                    ? ImagePathForProcess(helperProcess.value)
                    : std::nullopt;
                auto helperCreated = helperProcess
                    ? ProcessCreationTime100ns(helperProcess.value)
                    : std::nullopt;
                DWORD helperSession = 0;
                if (!helperProcess || !helperImage ||
                    !EqualInsensitive(*helperImage, *self) ||
                    !helperCreated ||
                    *helperCreated != boundHelperCreation ||
                    !ProcessIdToSessionId(boundHelperPid, &helperSession) ||
                    helperSession != controllerSession) {
                    std::wcerr << L"Helper identity validation failed.\n";
                    break;
                }
            } else if (result->pid != boundTargetPid ||
                       result->tid != boundTargetTid ||
                       result->helperPid != boundHelperPid ||
                       result->targetCreation100ns != boundTargetCreation ||
                       result->helperCreation100ns != boundHelperCreation) {
                std::wcerr << L"Helper/target identity tuple changed.\n";
                break;
            }

            if (result->status == "failure") {
                std::wcerr << L"PATCH_FAILED: "
                           << Utf8ToWide(result->message).value_or(L"unknown")
                           << L".\n";
                break;
            }
            if (result->status == "patched_resumed") {
                patched = *result;
                break;
            }
            if (result->status != "gate_started") {
                std::wcerr << L"Unexpected pre-cleanup helper status.\n";
                break;
            }
        }

        if (helperProcess &&
            WaitForSingleObject(helperProcess.value, 0) != WAIT_TIMEOUT) {
            std::wcerr << L"Gate helper exited before PATCHED_RESUMED.\n";
            break;
        }
        if (std::chrono::steady_clock::now() >= launchDeadline) {
            std::wcerr << L"Timed out waiting for manual game launch/patch.\n";
            break;
        }
        std::this_thread::sleep_for(kPollInterval);
    }

    if (!patched) {
        auto cleanup = CleanupDebugSetting(settings.Get(), journalPath,
                                           journal, true, true);
        if (!cleanup.cleanupComplete) {
            if (!containCurrentRun())
                std::wcerr << L"Failure containment could not be proved.\n";
            return 156;
        }
        if (!FinishControllerCleanupAcknowledgement(
                helperProcess, journalPath, false))
            return 157;
        return gCancelled.load(std::memory_order_relaxed) ? 152 : 159;
    }

    auto claim = ReadClaim(claimPath);
    if (!claim || claim->nonce != *nonce ||
        claim->targetPid != boundTargetPid ||
        claim->targetTid != boundTargetTid ||
        claim->targetCreation100ns != boundTargetCreation ||
        claim->helperPid != boundHelperPid ||
        claim->helperCreation100ns != boundHelperCreation) {
        std::wcerr << L"Durable one-shot claim did not match PATCHED_RESUMED.\n";
        auto cleanup = CleanupDebugSetting(settings.Get(), journalPath,
                                           journal, true, true);
        if (cleanup.cleanupComplete)
            FinishControllerCleanupAcknowledgement(
                helperProcess, journalPath, false);
        return 179;
    }

    Handle target(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                  PROCESS_TERMINATE | SYNCHRONIZE,
                              FALSE, patched->pid));
    bool targetAlive = target &&
        WaitForSingleObject(target.value, 0) == WAIT_TIMEOUT;
    if (targetAlive) {
        auto package = PackageFullNameForProcess(target.value);
        auto image = ImagePathForProcess(target.value);
        auto expectedPath = ExpectedImagePath();
        auto creation = ProcessCreationTime100ns(target.value);
        DWORD targetSession = 0;
        if (!package || !EqualInsensitive(*package, kExpectedPackageFullName) ||
            !image || !expectedPath ||
            !SameFileIdentity(*image, *expectedPath) ||
            !creation || *creation != patched->targetCreation100ns ||
            !ProcessIdToSessionId(patched->pid, &targetSession) ||
            targetSession != controllerSession) {
            std::wcerr << L"PATCHED_RESUMED target identity failed.\n";
            // The PID may already have been reused.  Never terminate this raw
            // handle after an identity mismatch; cleanup below uses the
            // nonce-bound claim plus exact package/path/creation checks.
            auto cleanup = CleanupDebugSetting(
                settings.Get(), journalPath, journal, true, true);
            if (cleanup.cleanupComplete)
                FinishControllerCleanupAcknowledgement(
                    helperProcess, journalPath, false);
            return 160;
        }
    } else if (!WaitForPackageQuiescent(settings.Get(),
                                         std::chrono::milliseconds(500))) {
        std::wcerr
            << L"Patched target vanished without an exact no-process proof.\n";
        auto cleanup = CleanupDebugSetting(
            settings.Get(), journalPath, journal, true, true);
        if (cleanup.cleanupComplete)
            FinishControllerCleanupAcknowledgement(
                helperProcess, journalPath, false);
        return 162;
    }

    if (!helperProcess ||
        WaitForSingleObject(helperProcess.value, 0) != WAIT_TIMEOUT) {
        std::wcerr << L"Authenticated helper was not alive immediately before "
                      L"the monitoring acknowledgement.\n";
        if (target) TerminateKnownProcess(target.value, ERROR_INVALID_STATE);
        auto failedCleanup = CleanupDebugSetting(
            settings.Get(), journalPath, journal, true, true);
        if (failedCleanup.cleanupComplete)
            FinishControllerCleanupAcknowledgement(
                helperProcess, journalPath, false);
        return 163;
    }

    // Keep package debugging armed until this exact target exits.  The durable
    // CREATE_NEW claim makes every replacement callback fail closed while its
    // target is still at Windows initial suspension.
    journal.stage = "monitoring";
    journal.lastHr = S_OK;
    if (!WriteJournal(journalPath, journal)) {
        std::wcerr << L"Could not durably acknowledge monitoring.\n";
        if (target) TerminateKnownProcess(target.value, ERROR_INVALID_STATE);
        auto failedCleanup = CleanupDebugSetting(
            settings.Get(), journalPath, journal, true, true);
        if (failedCleanup.cleanupComplete)
            FinishControllerCleanupAcknowledgement(
                helperProcess, journalPath, false);
        return 164;
    }

    std::wcout
        << L"PATCHED_PLAY_MODE_ACTIVE\n"
        << L"Package debugging remains armed as a one-shot replacement guard. "
           L"The helper is monitoring the exact process and the single "
           L"process-local compatibility patch.\n"
        << L"Saving and Xbox cloud synchronization are enabled.\n"
        << std::flush;

    bool cancelled = false;
    bool finalSuccess = false;
    auto playDeadline =
        std::chrono::steady_clock::now() + kPlaySessionTimeout;
    auto targetExitProved = [&]() {
        if (target)
            return WaitForSingleObject(target.value, 0) == WAIT_OBJECT_0;
        return WaitForPackageQuiescent(settings.Get(),
                                         std::chrono::milliseconds(500));
    };
    auto authenticatedTitleExited = [&]() {
        auto finalResult = ReadResult(resultPath);
        return finalResult && resultTupleValid(*finalResult) &&
               finalResult->status == "title_exited" &&
               finalResult->pid == boundTargetPid &&
               finalResult->tid == boundTargetTid &&
               finalResult->helperPid == boundHelperPid &&
               finalResult->targetCreation100ns == boundTargetCreation &&
               finalResult->helperCreation100ns == boundHelperCreation &&
               targetExitProved();
    };
    for (;;) {
        if (gCancelled.load(std::memory_order_relaxed) && !cancelled) {
            cancelled = true;
            if (target) TerminateKnownProcess(target.value, ERROR_CANCELLED);
        }

        if (FileExists(resultPath)) {
            auto result = ReadResult(resultPath);
            if (!result || !resultTupleValid(*result) ||
                result->pid != boundTargetPid ||
                result->tid != boundTargetTid ||
                result->helperPid != boundHelperPid ||
                result->targetCreation100ns != boundTargetCreation ||
                result->helperCreation100ns != boundHelperCreation) {
                std::wcerr << L"Post-cleanup helper result failed authentication.\n";
                if (target) TerminateKnownProcess(
                    target.value, ERROR_INVALID_DATA);
                break;
            }
            if (result->status == "failure") {
                std::wcerr << L"PLAY_MODE_MONITOR_FAILED: "
                           << Utf8ToWide(result->message).value_or(L"unknown")
                           << L".\n";
                if (target) TerminateKnownProcess(
                    target.value, ERROR_INVALID_STATE);
                break;
            }
            if (result->status == "title_exited") {
                finalSuccess = targetExitProved();
                if (!finalSuccess)
                    std::wcerr << L"TITLE_EXITED lacked exact target-exit proof.\n";
                break;
            }
            if (result->status != "patched_resumed" &&
                result->status != "monitoring") {
                std::wcerr << L"Unexpected post-cleanup helper status.\n";
                if (target) TerminateKnownProcess(
                    target.value, ERROR_INVALID_STATE);
                break;
            }
        }

        if (helperProcess &&
            WaitForSingleObject(helperProcess.value, 0) != WAIT_TIMEOUT) {
            DWORD helperExit = STILL_ACTIVE;
            bool helperExitedZero =
                GetExitCodeProcess(helperProcess.value, &helperExit) &&
                helperExit == 0;
            // Close the atomic-result race: the helper can publish
            // title_exited and exit between the result read above and this
            // signalled-handle check.
            finalSuccess = helperExitedZero && authenticatedTitleExited();
            if (!finalSuccess) {
                std::wcerr << L"Monitoring helper exited without an authenticated "
                              L"TITLE_EXITED/target-exit proof.\n";
                if (target) TerminateKnownProcess(
                    target.value, ERROR_INVALID_STATE);
            }
            break;
        }
        if (std::chrono::steady_clock::now() >= playDeadline) {
            std::wcerr
                << L"24-hour play window expired; terminating exact target.\n";
            if (target) TerminateKnownProcess(target.value, ERROR_TIMEOUT);
            break;
        }
        std::this_thread::sleep_for(kPollInterval);
    }

    // Only now, after the exact target exited (or after a fail-closed
    // termination), end the package-debug ownership.  TerminateAllProcesses
    // closes replacement callbacks before the journaled DisableDebugging call.
    auto finalCleanup = CleanupDebugSetting(
        settings.Get(), journalPath, journal, true, true);
    if (!finalCleanup.cleanupComplete) {
        if (target) TerminateKnownProcess(target.value, ERROR_INVALID_STATE);
        containCurrentRun();
        std::wcerr
            << L"ONLINE_PLAY_FAILED_CLOSED. Package-debug cleanup was "
               L"not proved; journal retained for recovery.\n";
        return 164;
    }

    bool helperAck = FinishControllerCleanupAcknowledgement(
        helperProcess, journalPath, finalSuccess);
    if (!finalSuccess || !helperAck) {
        if (target) TerminateKnownProcess(target.value, ERROR_INVALID_STATE);
        std::wcerr << L"ONLINE_PLAY_FAILED_CLOSED. IPC evidence was retained.\n";
        return helperAck ? 181 : 189;
    }

    DeleteFileW(resultPath.c_str());
    DeleteFileW(claimPath.c_str());
    DeleteFileW(auxiliaryPath.c_str());

    std::wcout
        << L"TITLE_EXITED_OK: exact process exited; package debugging is "
           L"disabled and process-local patches are gone.\n";
    return cancelled ? 178 : 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && wcscmp(argv[1], L"--self-test") == 0)
        return RunSelfTest();
    if (argc >= 2 && wcscmp(argv[1], L"--gate") == 0)
        return RunOnlinePlayGate(argc, argv);
    if (argc == 5 && wcscmp(argv[1], L"--recover-debug") == 0 &&
        wcscmp(argv[2], L"--receipt") == 0) {
        auto attempt = NarrowAscii(argv[3]);
        if (!attempt) Usage();
        return RunRecovery(*attempt, argv[4]);
    }
    if (argc == 2 && wcscmp(argv[1], L"--arm-online-play") == 0) {
        if (!kReviewedRunnable) {
            std::wcerr << L"REVIEW_PENDING: native arm mode is hard-disabled.\n";
            return 191;
        }
        return RunOnlinePlayController();
    }
    Usage();
}


// mlxcore.cpp  -- hooks CWindowNode::RenderContent in dwmcore.dll to draw "MLX" text
//
// Build (x64, native tools command prompt):
//   MSBuild mlxcore.vcxproj /p:Platform=x64 /p:Configuration=Release
//
// /GUARD:CF is OFF (GuardCfOff) to match DWM's Control Flow Guard so any
// indirect call into our code validates, and because CIG is OFF (verified) so
// LoadLibrary injection is allowed (no driver / manual mapping needed).
//
// ---------------------------------------------------------------------------
// !! BUILD-SPECIFIC VALUES -- re-derive if dwmcore.dll changes (Windows update) !!
//   * RENDER_CONTENT_RVA : from IDA, RenderContent entry 0x180073770 - imagebase 0x180000000
//   * DRAW_TEXT_W_VTABLE_IDX : vtable index for DrawTextW (varies by build)
// ---------------------------------------------------------------------------
#include <errno.h>
#include <windows.h>
#include <dwmapi.h>
#include <dwrite.h>
#include <d2d1.h>
#include <stdio.h>
#include <stdarg.h>

// CWindowNode struct layout (partial, from reverse engineering)
// GetHwnd() returns HWND at offset 0x268
#pragma pack(push, 1)
typedef struct _CWindowNode {
    BYTE _pad0[0x268];      // 0x000
    HWND hwnd;              // 0x268  GetHwnd() returns this
    BYTE _pad1[0x1000 - 0x270]; // padding to known size
} CWindowNode;
#pragma pack(pop)

// CDrawingContext struct (partial, from reverse engineering)
// Has vtable at offset 0
#pragma pack(push, 1)
typedef struct _CDrawingContext {
    void* vtable;           // 0x000 - vtable pointer
    BYTE _pad0[0x1728 - 0x8]; // 0x008-0x1727
    void* drawListCacheSet; // 0x1728 - draw list cache set
    // ... many more fields
} CDrawingContext;
#pragma pack(pop)

// CVisual struct (partial, from reverse engineering)
#pragma pack(push, 1)
typedef struct _CVisual {
    BYTE _pad0[0x10];          // 0x000
    void* ptr0x10;              // 0x010
    BYTE _pad1[0x4F];          // 0x018-0x05F
    BYTE flags_0x5F;            // 0x05F  (bit 2 checked)
    // ... many more fields
} CVisual;
#pragma pack(pop)

// Minimal logging - just open file and write directly
static FILE* g_LogFile = NULL;

static void LogInit(void)
{
    errno_t err = fopen_s(&g_LogFile, "C:\\mlxcore.log", "w");
}

static void LogWrite(const char* fmt, ...)
{
    if (!g_LogFile) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(g_LogFile, fmt, args);
    fputc('\n', g_LogFile);
    fflush(g_LogFile);
    va_end(args);
}

static void LogCleanup(void)
{
    if (g_LogFile) {
        fclose(g_LogFile);
        g_LogFile = NULL;
    }
}

// Function pointers (resolved at runtime)
typedef HRESULT (WINAPI* DrawTextWFn)(
    void*           ctx,         // CDrawingContext*
    WCHAR*          text,        // WCHAR*
    UINT32          textLength,  // UINT32
    IDWriteTextFormat* format,   // IDWriteTextFormat*
    const D2D_RECT_F* rect,      // D2D_RECT_F*
    const D3DCOLORVALUE* color   // D3DCOLORVALUE*
);

typedef HRESULT (WINAPI* DWriteCreateFactoryFn)(
    DWRITE_FACTORY_TYPE factoryType,
    REFIID riid,
    IUnknown** factory
);

// RVAs
static const SIZE_T RENDER_CONTENT_RVA = 0x73770;
// Hook: steal 44 bytes (prologue up to first body instruction at 0x7379c)
// Prologue: register saves (23B) + sub rsp (4B) + security cookie (11B) + xor r12d (3B) + mov r13,r8 (3B) = 44B
static const SIZE_T HOOK_LEN = 44;
static const SIZE_T JUMP_BACK_OFFSET = 44;

// Function signatures
typedef HRESULT (WINAPI* RenderContentFn)(
    CWindowNode* self, void* ctx, BOOL* outRendered
);

static RenderContentFn g_OriginalRenderContent = NULL;
static DrawTextWFn g_DrawTextW = NULL;
static IDWriteTextFormat* g_TextFormat = NULL;
static BOOL g_TextFormatInitialized = FALSE;
static DWriteCreateFactoryFn g_DWriteCreateFactory = NULL;

// Hook state
static BYTE*  g_Target = NULL;
static BYTE   g_OriginalBytes[44] = { 0 };
static BOOL   g_Hooked = FALSE;

// Initialize logging on DLL load
static BOOL g_LogInitialized = FALSE;

// Write a 64-bit absolute JMP (mov rax, imm64; jmp rax) - 12 bytes
static void WriteAbsoluteJmp(BYTE* at, void* target)
{
    at[0] = 0x48;
    at[1] = 0xB8;
    *(UINT64*)(at + 2) = (UINT64)target;
    at[10] = 0xFF;
    at[11] = 0xE0;
}

// Allocate memory near a target address (within 2GB)
static BYTE* AllocateNear(BYTE* target, SIZE_T size)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE* minAddr = (BYTE*)((target > (BYTE*)si.lpMaximumApplicationAddress - (INT_PTR)0x80000000)
                            ? (BYTE*)si.lpMinimumApplicationAddress
                            : target - 0x80000000);
    BYTE* maxAddr = (BYTE*)((target < (BYTE*)si.lpMinimumApplicationAddress + (INT_PTR)0x80000000)
                            ? (BYTE*)si.lpMaximumApplicationAddress
                            : target + 0x80000000);

    for (BYTE* addr = target; addr >= minAddr; addr -= 0x10000) {
        BYTE* result = (BYTE*)VirtualAlloc(addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (result) return result;
    }
    for (BYTE* addr = target; addr <= maxAddr; addr += 0x10000) {
        BYTE* result = (BYTE*)VirtualAlloc(addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (result) return result;
    }
    return NULL;
}

// Resolve DirectWrite functions via GetProcAddress on dwrite.dll
static BOOL ResolveDirectWriteFunctions()
{
    if (g_DWriteCreateFactory) return TRUE;

    HMODULE hDWrite = GetModuleHandleW(L"dwrite.dll");
    if (!hDWrite) {
        hDWrite = LoadLibraryW(L"dwrite.dll");
        if (!hDWrite) {
            LogWrite("ResolveDirectWriteFunctions: LoadLibraryW(dwrite.dll) failed: %lu", GetLastError());
            return FALSE;
        }
        LogWrite("ResolveDirectWriteFunctions: dwrite.dll loaded at %p", hDWrite);
    } else {
        LogWrite("ResolveDirectWriteFunctions: dwrite.dll already loaded at %p", hDWrite);
    }

    g_DWriteCreateFactory = (DWriteCreateFactoryFn)GetProcAddress(hDWrite, "DWriteCreateFactory");
    if (!g_DWriteCreateFactory) {
        LogWrite("ResolveDirectWriteFunctions: GetProcAddress(DWriteCreateFactory) failed: %lu", GetLastError());
        return FALSE;
    }
    LogWrite("ResolveDirectWriteFunctions: DWriteCreateFactory = %p", g_DWriteCreateFactory);
    return TRUE;
}

// Initialize text format using DirectWrite via GetProcAddress
static BOOL InitializeTextFormat()
{
    if (g_TextFormatInitialized) return g_TextFormat != NULL;

    LogWrite("InitializeTextFormat: entry");

    if (!ResolveDirectWriteFunctions()) {
        LogWrite("InitializeTextFormat: ResolveDirectWriteFunctions failed");
        return FALSE;
    }

    IDWriteFactory* factory = NULL;
    LogWrite("InitializeTextFormat: calling DWriteCreateFactory");

    __try {
        HRESULT hr = g_DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), (IUnknown**)&factory);
        LogWrite("InitializeTextFormat: DWriteCreateFactory returned 0x%X, factory=%p", hr, factory);

        if (FAILED(hr) || !factory) {
            LogWrite("InitializeTextFormat: DWriteCreateFactory failed");
            return FALSE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogWrite("InitializeTextFormat: EXCEPTION in DWriteCreateFactory! code=0x%X", GetExceptionCode());
        return FALSE;
    }

    // Create text format: "Segoe UI", 12pt, normal
    LogWrite("InitializeTextFormat: calling CreateTextFormat");
    HRESULT hr = E_FAIL;
    __try {
        hr = factory->CreateTextFormat(
            L"Segoe UI", NULL,
            DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
            12.0f, L"en-us", &g_TextFormat
        );
        LogWrite("InitializeTextFormat: CreateTextFormat returned 0x%X, format=%p", hr, g_TextFormat);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogWrite("InitializeTextFormat: EXCEPTION in CreateTextFormat! code=0x%X", GetExceptionCode());
        factory->Release();
        return FALSE;
    }
    factory->Release();

    if (FAILED(hr) || !g_TextFormat) {
        LogWrite("InitializeTextFormat: CreateTextFormat failed: 0x%X", hr);
        return FALSE;
    }

    // Set alignment
    __try {
        g_TextFormat->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        g_TextFormat->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogWrite("InitializeTextFormat: EXCEPTION in SetAlignment! code=0x%X", GetExceptionCode());
        g_TextFormat->Release();
        g_TextFormat = NULL;
        return FALSE;
    }

    LogWrite("Text format created successfully");
    g_TextFormatInitialized = TRUE;
    return TRUE;
}

// Get DrawTextW from CDrawingContext vtable
// vtable index for DrawTextW varies by build; find it dynamically
static BOOL ResolveDrawTextWFromVtable()
{
    if (g_DrawTextW) return TRUE;

    HMODULE base = GetModuleHandleW(L"dwmcore.dll");
    if (!base) return FALSE;

    // We need a CDrawingContext instance to read its vtable
    // We can't easily get one without hooking, so use RVA as fallback
    // TODO: Find vtable index for DrawTextW by scanning for the function pattern
    LogWrite("ResolveDrawTextWFromVtable: using RVA fallback");
    return FALSE;
}

// Draw "test" at top-left of window
static void DrawTestText(void* ctx, CWindowNode* self)
{
    LogWrite("DrawTestText: entry, ctx=%p", ctx);

    if (!g_DrawTextW) {
        HMODULE base = GetModuleHandleW(L"dwmcore.dll");
        if (base) {
            // Use RVA as fallback since DrawTextW is not exported
            g_DrawTextW = (DrawTextWFn)((BYTE*)base + 0x1773b8);
            LogWrite("Resolved DrawTextW at %p (via RVA)", g_DrawTextW);
        }
    }

    if (!g_DrawTextW) {
        LogWrite("DrawTestText: DrawTextW not resolved");
        return;
    }

    if (!g_TextFormat) {
        LogWrite("DrawTestText: initializing text format");
        if (!InitializeTextFormat()) {
            LogWrite("DrawTestText: InitializeTextFormat failed");
            return;
        }
    }

    if (!g_TextFormat) {
        LogWrite("DrawTestText: g_TextFormat still NULL");
        return;
    }

    // Get window bounds from CWindowNode (GetHwnd at offset 0x268)
    RECT clientRect = {0};
    ///
       LogWrite("DrawTestText: hwnd=%p", self->hwnd);
       GetClientRect(self->hwnd, &clientRect);
       LogWrite("DrawTestText: client rect=(%d,%d,%d,%d)", clientRect.left, clientRect.top, clientRect.right, clientRect.bottom);

    // Draw "MLX" text at top-left of client area
    WCHAR text[] = L"MLX";
    D2D_RECT_F rect = { 0 };
    D3DCOLORVALUE textColor = { 1.0f, 0.0f, 0.0f, 1.0f }; // Bright red

    if (clientRect.right > clientRect.left && clientRect.bottom > clientRect.top) {
        // Use client area coordinates - draw at top-left with padding
        rect.left = 0.0f;
        rect.top = 0.0f;
        rect.right = (float)(clientRect.right - clientRect.left);
        rect.bottom = (float)(clientRect.bottom - clientRect.top);
    } else {
        // Fallback
        rect.left = 0.0f;
        rect.top = 0.0f;
        rect.right = 50.0f;
        rect.bottom = 30.0f;
    }

    LogWrite("DrawTestText: calling DrawTextW, rect=(%.1f,%.1f,%.1f,%.1f)", rect.left, rect.top, rect.right, rect.bottom);

    __try {
        HRESULT hr = g_DrawTextW(ctx, text, 3, g_TextFormat, &rect, &textColor);
        LogWrite("DrawTextW returned: 0x%X", hr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogWrite("DrawTestText: EXCEPTION in DrawTextW! code=0x%X", GetExceptionCode());
    }

    LogWrite("DrawTestText: exit");
}

// Our replacement for CWindowNode::RenderContent
// rcx = CWindowNode*, rdx = CDrawingContext*, r8 = BOOL* outRendered
static HRESULT WINAPI MyRenderContent(
    CWindowNode* self, CDrawingContext* ctx, BOOL* outRendered
)
{
    LogWrite("MyRenderContent: entry, self=%p, ctx=%p", self, ctx);

    // Call original to render the window normally
    HRESULT hr = 0;
    __try {
        hr = g_OriginalRenderContent(self, ctx, outRendered);
        LogWrite("MyRenderContent: original returned 0x%X", hr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogWrite("MyRenderContent: EXCEPTION in original! code=0x%X", GetExceptionCode());
        return 0;
    }

    // Get window title for logging
    WCHAR title[256] = {0};
    if (self->hwnd) {
        GetWindowTextW(self->hwnd, title, 256);
        LogWrite("MyRenderContent: window title='%ls'", title);
               if (ctx) {
                       // Draw our test text AFTER rendering so it's at the top
                       LogWrite("MyRenderContent: calling DrawTestText");
                       DrawTestText(ctx, self);
                       LogWrite("MyRenderContent: DrawTestText returned");
               }
    }

    return hr;
}

// Install hook
static BOOL InstallHook(void)
{
    LogWrite("InstallHook: starting");

    HMODULE base = GetModuleHandleW(L"dwmcore.dll");
    if (!base) {
        LogWrite("InstallHook: GetModuleHandleW(dwmcore.dll) failed");
        return FALSE;
    }
    LogWrite("InstallHook: dwmcore.dll base = %p", base);

    BYTE* target = (BYTE*)base + RENDER_CONTENT_RVA;
    LogWrite("InstallHook: target = %p", target);

    // Get __security_cookie address for RIP fixup
    BYTE* securityCookieAddr = (BYTE*)base + 0x344648;
    LogWrite("InstallHook: __security_cookie = %p", securityCookieAddr);

    // Allocate trampoline NEAR target
    SIZE_T trampSize = HOOK_LEN + 12;
    BYTE* tramp = AllocateNear(target, trampSize);
    if (!tramp) {
        LogWrite("InstallHook: AllocateNear failed");
        return FALSE;
    }
    LogWrite("InstallHook: trampoline = %p (distance=%lld)", tramp, (INT64)tramp - (INT64)target);

    memcpy(tramp, target, HOOK_LEN);
    memcpy(g_OriginalBytes, target, HOOK_LEN);
    g_Target = target;

    // Fix up RIP-relative instruction at offset 23: mov rax, [rip+0x2d0eba]
    // Original: 48 8b 05 ba 0e 2d 00 (at target+23)
    // At original: RIP = target+23+7 = target+30, target = target+30+0x2d0eba = base+0x344648
    // At trampoline: RIP = tramp+30, need offset = securityCookieAddr - (tramp+30)
    INT64 newOffset = (INT64)securityCookieAddr - (INT64)(tramp + 30);
    *(INT32*)(tramp + 23 + 3) = (INT32)newOffset;
    LogWrite("InstallHook: fixed RIP-relative offset to %lld", newOffset);

    // Write 64-bit absolute jump back to target+JUMP_BACK_OFFSET (first body instruction)
    WriteAbsoluteJmp(tramp + HOOK_LEN, target + JUMP_BACK_OFFSET);
    g_OriginalRenderContent = (RenderContentFn)tramp;
    LogWrite("InstallHook: trampoline function = %p", g_OriginalRenderContent);

    // Patch target: 64-bit absolute jump to MyRenderContent
    DWORD oldProt = 0;
    if (!VirtualProtect(target, HOOK_LEN, PAGE_EXECUTE_READWRITE, &oldProt)) {
        LogWrite("InstallHook: VirtualProtect failed: %lu", GetLastError());
        VirtualFree(tramp, 0, MEM_RELEASE);
        return FALSE;
    }
    LogWrite("InstallHook: VirtualProtect succeeded");

    WriteAbsoluteJmp(target, MyRenderContent);
    for (SIZE_T i = 12; i < HOOK_LEN; i++) target[i] = 0x90;

    FlushInstructionCache(GetCurrentProcess(), target, HOOK_LEN);
    VirtualProtect(target, HOOK_LEN, oldProt, &oldProt);

    g_Hooked = TRUE;
    LogWrite("InstallHook: SUCCESS");
    return TRUE;
}

static void Unhook(void)
{
    LogWrite("Unhook: starting");
    if (!g_Hooked || !g_Target) {
        LogWrite("Unhook: not hooked");
        return;
    }

    DWORD oldProt = 0;
    if (VirtualProtect(g_Target, HOOK_LEN, PAGE_EXECUTE_READWRITE, &oldProt)) {
        memcpy(g_Target, g_OriginalBytes, HOOK_LEN);
        FlushInstructionCache(GetCurrentProcess(), g_Target, HOOK_LEN);
        VirtualProtect(g_Target, HOOK_LEN, oldProt, &oldProt);
        LogWrite("Unhook: restored original bytes");
    } else {
        LogWrite("Unhook: VirtualProtect failed: %lu", GetLastError());
    }
    g_Hooked = FALSE;

    if (g_TextFormat) {
        g_TextFormat->Release();
        g_TextFormat = NULL;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        if (!g_LogInitialized) {
            LogInit();
            g_LogInitialized = TRUE;
        }
        LogWrite("DllMain: DLL_PROCESS_ATTACH");
        DisableThreadLibraryCalls(hinst);
        LogWrite("DllMain: calling InstallHook");
        BOOL result = InstallHook();
        LogWrite("DllMain: InstallHook returned %d", result);
    } else if (reason == DLL_PROCESS_DETACH) {
        LogWrite("DllMain: DLL_PROCESS_DETACH");
        Unhook();
        if (g_LogInitialized) {
            LogCleanup();
            g_LogInitialized = FALSE;
        }
    }
    return TRUE;
}
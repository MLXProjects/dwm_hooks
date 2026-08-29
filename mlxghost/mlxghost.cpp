// mlxghost.cpp  -- inline-hooks CGhostWindow::PaintGhost inside dwmghost.dll
//
// Build (x64, native tools command prompt):
//   (see mlxghost.vcxproj / `MSBuild ghost.sln /p:Platform=x64 /p:Configuration=Release`)
//
// /GUARD:CF matches DWM's Control Flow Guard so any indirect call into our code validates.
// CIG is OFF (verified) so LoadLibrary injection is allowed; no driver / manual mapping needed.
//
// ---------------------------------------------------------------------------
// !! BUILD-SPECIFIC VALUES -- re-derive if dwmghost.dll changes (Windows update) !!
//   * PAINTGHOST_RVA : from IDA, PaintGhost entry 0x1800057d8 - imagebase 0x180000000
//   * class field offsets below come from the decompiled CGhostWindow layout
// ---------------------------------------------------------------------------

#include <windows.h>
#include <dwmapi.h>

// ---- mirrors CGhostWindow field layout (offsets are in BYTE units) ----------
#pragma pack(push, 1)
typedef struct _CGhostWindow {
    BYTE     _pad0[0x30];        // 0x00
    HWND     hWnd;               // 0x30  (this+6 qword)  target window
    BYTE     _pad1[0x88 - 0x38]; // 0x38
    HBITMAP  hBmp;               // 0x88  (this+17 qword) captured window content bitmap
    HANDLE   hThumb;             // 0x90  (this+18 qword) DWM thumbnail handle (NULL on classic path)
    BYTE     _pad2[0xa0 - 0x98]; // 0x98
    UINT_PTR timerId;            // 0xa0  (this+20 qword) SetTimer id
    BYTE     _pad3[0xac - 0xa8]; // 0xa8
    UINT     width;              // 0xac  (this+43 dword) window width  in px
    UINT     height;             // 0xb0  (this+44 dword) window height in px
    BYTE     _pad4[0x144 - 0xb4];// 0xb4
    DWORD    f51;                // 0x144 (this+51 dword) guard flag
    DWORD    f52;                // 0x148 (this+52 dword) guard flag
    DWORD    f53;                // 0x14c (this+53 dword) guard flag "frosting in progress"
} CGhostWindow;
#pragma pack(pop)

// RVA of ?PaintGhost@CGhostWindow@@AEAAXPEAUHDC__@@PEBUtagRECT@@@Z relative to dwmghost.dll base
static const SIZE_T PAINTGHOST_RVA = 0x57d8;
// number of prologue bytes we relocate into the trampoline (clean instruction boundary at +0x13)
static const SIZE_T HOOK_LEN = 19;

typedef void (WINAPI* PaintGhostFn)(CGhostWindow*, HDC, const RECT*);
static PaintGhostFn g_OriginalPaintGhost = NULL;

// State needed to restore the original code on unload (so FreeLibrary doesn't
// leave PaintGhost jumping into freed memory).
static BYTE*  g_Target        = NULL;          // PaintGhost entry (in dwmghost.dll)
static BYTE   g_OriginalBytes[HOOK_LEN] = { 0 }; // saved prologue
static BOOL   g_Hooked        = FALSE;

// Our replacement for CGhostWindow::PaintGhost.
// This is what actually paints the visible ghost surface (called from WM_PAINT).
static void WINAPI MyPaintGhost(CGhostWindow* self, HDC hdc, const RECT* prc)
{
    // Paint a solid red ghost window on the ghost window's own GDI surface (layer A).
    // We do NOT hide the DWM thumbnail (layer B = the live hung window): DWM's built-in
    // ghost/fade animation ramps that thumbnail's opacity, so it fades from the live
    // content to reveal our red fill underneath. Hiding the thumbnail would skip that
    // nice fade and just show solid red immediately.

    // IMPORTANT: do NOT use self->width/self->height here -- on the thumbnail
    // (composited) path those fields are 0, so the rect would be degenerate and
    // FillRect would paint nothing, leaving the black WM_ERASEBKGND showing.
    // Always paint the rect that WM_PAINT handed us (PAINTSTRUCT.rcPaint), which
    // is guaranteed valid.

    RECT rc;
    if (prc && (prc->right > prc->left || prc->bottom > prc->top)) {
        rc = *prc;
    } else if (self->hWnd) {
        GetClientRect(self->hWnd, &rc);
    } else {
        SetRect(&rc, 0, 0, 320, 240);
    }
    HBRUSH red = CreateSolidBrush(RGB(255, 0, 0));
    FillRect(hdc, &rc, red);
    DeleteObject(red);

    // NOTE: we intentionally do NOT call the original PaintGhost, so the built-in
    // white fade is gone. To preserve the original frozen content under a tint,
    // call g_OriginalPaintGhost(self, hdc, prc) first, then overlay a semi-
    // transparent red brush (e.g. with a 32bpp DIB + GdiAlphaBlend) on top.
}

// Install a HOOK_LEN-byte prologue detour + trampoline.
static BOOL InstallHook(void)
{
    HMODULE base = GetModuleHandleW(L"dwmghost.dll");
    if (!base) return FALSE;                       // not loaded yet
    BYTE* target = (BYTE*)base + PAINTGHOST_RVA;

    // trampoline = stolen bytes + relative jmp back to target+HOOK_LEN
    BYTE* tramp = (BYTE*)VirtualAlloc(NULL, HOOK_LEN + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return FALSE;
    memcpy(tramp, target, HOOK_LEN);
    memcpy(g_OriginalBytes, target, HOOK_LEN);   // keep a clean copy to restore later
    g_Target = target;

    DWORD relBack = (DWORD)((INT_PTR)(target + HOOK_LEN) - (INT_PTR)(tramp + HOOK_LEN));
    tramp[HOOK_LEN] = 0xE9;
    *(DWORD*)(tramp + HOOK_LEN + 1) = relBack;
    g_OriginalPaintGhost = (PaintGhostFn)tramp;

    // patch target: E9 rel32 -> MyPaintGhost, rest nop'd
    DWORD oldProt = 0;
    if (!VirtualProtect(target, HOOK_LEN, PAGE_EXECUTE_READWRITE, &oldProt)) return FALSE;
    DWORD relFwd = (DWORD)((INT_PTR)MyPaintGhost - (INT_PTR)(target + 5));
    target[0] = 0xE9;
    *(DWORD*)(target + 1) = relFwd;
    for (SIZE_T i = 5; i < HOOK_LEN; i++) target[i] = 0x90;
    FlushInstructionCache(GetCurrentProcess(), target, HOOK_LEN);
    VirtualProtect(target, HOOK_LEN, oldProt, &oldProt);
    g_Hooked = TRUE;
    return TRUE;
}

// Restore the original prologue so the entry point is valid even after we unload.
static void Unhook(void)
{
    if (!g_Hooked || !g_Target) return;
    DWORD oldProt = 0;
    if (VirtualProtect(g_Target, HOOK_LEN, PAGE_EXECUTE_READWRITE, &oldProt)) {
        memcpy(g_Target, g_OriginalBytes, HOOK_LEN);
        FlushInstructionCache(GetCurrentProcess(), g_Target, HOOK_LEN);
        VirtualProtect(g_Target, HOOK_LEN, oldProt, &oldProt);
    }
    g_Hooked = FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        // NOTE: doing the hook directly in DllMain is fine here because we only
        // touch our own allocations / VirtualProtect / GDI; no loader-lock-sensitive calls.
        DisableThreadLibraryCalls(hinst);
        InstallHook();
    } else if (reason == DLL_PROCESS_DETACH) {
        // Restore PaintGhost's original bytes BEFORE the image is unmapped, so a
        // later call into it lands on valid code instead of freed memory.
        Unhook();
    }
    return TRUE;
}

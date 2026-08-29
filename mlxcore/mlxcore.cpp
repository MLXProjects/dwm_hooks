// mlxcore.cpp  -- placeholder hook DLL for mlxcore.dll
//
// Build (x64, native tools command prompt):
//   (see mlxcore.vcxproj / `MSBuild mlxghost.sln /p:Platform=x64 /p:Configuration=Release`)
//
// /GUARD:CF is OFF (GuardCfOff) to match DWM's Control Flow Guard so any
// indirect call into our code validates, and because CIG is OFF (verified) so
// LoadLibrary injection is allowed (no driver / manual mapping needed).

#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        // No hook installed yet. When the target is finalized, install it here
        // (and restore on DLL_PROCESS_DETACH so FreeLibrary leaves valid code).
        DisableThreadLibraryCalls(hinst);
    } else if (reason == DLL_PROCESS_DETACH) {
        // Restore any patched bytes here before the image is unmapped.
    }
    return TRUE;
}

// htest.c  -- Win32 test harness to exercise DWM mlxghosting.
//
// Build (x64 Native Tools command prompt):
//   cl /O2 /GUARD:CF htest.c /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib /OUT:htest.exe
//   (or: MSBuild mlxghost.sln /p:Platform=x64 /p:Configuration=Release)
//
// Buttons:
//   "Spawn child window"  -> creates a separate top-level window on its own thread
//   "Hang child window"   -> toggles: blocks that window's message loop so DWM
//                             flags it as hung and draws the mlxghost overlay (~5s);
//                             click again to "Restore" and make it responsive.

#include <windows.h>

#define WM_HTEST_TRIGGER_HANG  (WM_APP + 1)

#define ID_BTN_SPAWN  101
#define ID_BTN_HANG   102

static const wchar_t* MAIN_CLASS  = L"HTEST_MAIN";
static const wchar_t* CHILD_CLASS = L"HTEST_CHILD";

static HANDLE g_hChildThread  = NULL;
static HWND   g_hChildWnd     = NULL;
static HWND   g_hMainWnd      = NULL;
static volatile BOOL g_Hung   = FALSE;
static HANDLE g_hResumeEvent  = NULL;

// ---- child window (own thread + own message loop) ----------------------------
static LRESULT CALLBACK ChildWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    // When flagged, block this thread inside the WndProc -> window stops pumping
    // messages -> DWM considers it hung and shows the mlxghost window.
    if (g_Hung)
        WaitForSingleObject(g_hResumeEvent, INFINITE);

    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT r; GetClientRect(hwnd, &r);
        DrawTextW(hdc, L"Child window\n(hang me to see the mlxghost)", -1, &r,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        g_hChildWnd = NULL;
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

static DWORD WINAPI ChildThread(LPVOID lp)
{
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = ChildWndProc;
    wc.hInstance    = GetModuleHandleW(NULL);
    wc.lpszClassName = CHILD_CLASS;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);

    g_hChildWnd = CreateWindowExW(0, CHILD_CLASS, L"htest - child",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 380, 200,
        NULL, NULL, GetModuleHandleW(NULL), NULL);
    ShowWindow(g_hChildWnd, SW_SHOW);
    UpdateWindow(g_hChildWnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    g_hChildThread = NULL;
    return 0;
}

// ---- main window -------------------------------------------------------------
static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    static HWND hBtnSpawn, hBtnHang;

    switch (msg) {
    case WM_CREATE:
        hBtnSpawn = CreateWindowExW(0, L"BUTTON", L"Spawn child window",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 20, 20, 220, 32, hwnd,
            (HMENU)ID_BTN_SPAWN, GetModuleHandleW(NULL), NULL);
        hBtnHang = CreateWindowExW(0, L"BUTTON", L"Hang child window",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 20, 64, 220, 32, hwnd,
            (HMENU)ID_BTN_HANG, GetModuleHandleW(NULL), NULL);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wp) == ID_BTN_SPAWN) {
            if (!g_hChildThread) {
                g_Hung = FALSE;
                g_hChildThread = CreateThread(NULL, 0, ChildThread, NULL, 0, NULL);
            }
        } else if (LOWORD(wp) == ID_BTN_HANG) {
            if (g_hChildWnd) {
                if (!g_Hung) {
                    g_Hung = TRUE;
                    // poke the child so its WndProc enters the blocking wait
                    PostMessageW(g_hChildWnd, WM_HTEST_TRIGGER_HANG, 0, 0);
                    SetWindowTextW(hBtnHang, L"Restore child window");
                } else {
                    g_Hung = FALSE;
                    SetEvent(g_hResumeEvent);   // release the blocked WndProc
                    SetWindowTextW(hBtnHang, L"Hang child window");
                }
            }
        }
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nCmdShow)
{
    g_hResumeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance    = hInst;
    wc.lpszClassName = MAIN_CLASS;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);

    g_hMainWnd = CreateWindowExW(0, MAIN_CLASS, L"htest",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 280, 150,
        NULL, NULL, hInst, NULL);
    ShowWindow(g_hMainWnd, SW_SHOW);
    UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

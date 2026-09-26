#include "session.hpp"

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <d3d11.h>
#include <filesystem>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <string>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM,
                                                             LPARAM);

namespace {

ID3D11Device *device = nullptr;
ID3D11DeviceContext *context = nullptr;
IDXGISwapChain *swapChain = nullptr;
ID3D11RenderTargetView *renderTarget = nullptr;

void CreateRenderTarget() {
    ID3D11Texture2D *backBuffer = nullptr;

    if ( SUCCEEDED(swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer))) ) {
        device->CreateRenderTargetView(backBuffer, nullptr, &renderTarget);
        backBuffer->Release();
    }
}

void CleanupRenderTarget() {
    if ( renderTarget ) {
        renderTarget->Release();
        renderTarget = nullptr;
    }
}

bool CreateDevice(const HWND window) {
    DXGI_SWAP_CHAIN_DESC description{};
    description.BufferCount = 2;
    description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    description.OutputWindow = window;
    description.SampleDesc.Count = 1;
    description.Windowed = TRUE;
    description.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    constexpr D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0,
                                            D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL selected{};
    HRESULT result = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2,
        D3D11_SDK_VERSION, &description, &swapChain, &device, &selected,
        &context);
    if ( FAILED(result) )
        result = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2,
            D3D11_SDK_VERSION, &description, &swapChain, &device, &selected,
            &context);
    if ( FAILED(result) )
        return false;
    CreateRenderTarget();
    return renderTarget != nullptr;
}

void CleanupDevice() {
    CleanupRenderTarget();

    if ( swapChain ) {
        swapChain->Release();
        swapChain = nullptr;
    }

    if ( context ) {
        context->Release();
        context = nullptr;
    }

    if ( device ) {
        device->Release();
        device = nullptr;
    }
}

LRESULT WINAPI WindowProcedure(HWND window, UINT message, WPARAM wparam,
                               LPARAM lparam) {
    if ( ImGui::GetCurrentContext() &&
         ImGui_ImplWin32_WndProcHandler(window, message, wparam, lparam) )
        return 1;

    if ( message == WM_SIZE && swapChain && wparam != SIZE_MINIMIZED ) {
        CleanupRenderTarget();
        swapChain->ResizeBuffers(0, LOWORD(lparam), HIWORD(lparam),
                                 DXGI_FORMAT_UNKNOWN, 0);
        CreateRenderTarget();
        return 0;
    }

    if ( message == WM_DESTROY ) {
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(window, message, wparam, lparam);
}

std::string PickPath(HWND window, bool folder) {
    IFileOpenDialog *dialog = nullptr;
    if ( FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr,
                                 CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog))) )
        return {};

    if ( folder ) {
        FILEOPENDIALOGOPTIONS options{};
        if ( SUCCEEDED(dialog->GetOptions(&options)) )
            dialog->SetOptions(options | FOS_PICKFOLDERS);
    } else {
        COMDLG_FILTERSPEC filter[] = {{L"Applications", L"*.exe"},
                                      {L"All files", L"*.*"}};
        dialog->SetFileTypes(2, filter);
    }

    std::string result;

    if ( SUCCEEDED(dialog->Show(window)) ) {
        IShellItem *item = nullptr;

        if ( SUCCEEDED(dialog->GetResult(&item)) ) {
            PWSTR path = nullptr;

            if ( SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) ) {
                result = janus::gui::ToUtf8(path);
                CoTaskMemFree(path);
            }

            item->Release();
        }
    }

    dialog->Release();
    return result;
}

void CopyToField(char *field, size_t capacity, const std::string &text) {
    strncpy_s(field, capacity, text.c_str(), _TRUNCATE);
}

std::string Status(const janus::gui::Session &session,
                   const janus::gui::SessionManager &manager) {
    if ( manager.IsRunning(session.directory) )
        return "Recording";
    if ( session.storageFailed )
        return "Storage error";
    if ( session.hasExitCode )
        return session.exitCode ? "Exited " + std::to_string(session.exitCode)
                                : "Complete";
    if ( std::filesystem::exists(session.directory /
                                 "instrumentation-performance.json") )
        return "Complete";
    return "Unconfirmed";
}

void DrawUi(HWND window, janus::gui::SessionManager &manager) {
    static char target[4096]{};
    static char arguments[4096]{};
    static char folder[4096]{};
    static bool folderInitialized = false;
    static int scope = 0;
    static int memoryBytes = 64;
    static bool followChildren = true;
    static std::filesystem::path selected;
    static std::filesystem::path pendingDelete;

    if ( !folderInitialized ) {
        CopyToField(folder, sizeof(folder), manager.Root().u8string());
        folderInitialized = true;
    }

    const ImGuiViewport *viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::Begin("Janus Key", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoSavedSettings |
                     ImGuiWindowFlags_NoBringToFrontOnFocus);

    ImGui::TextUnformatted("JANUS KEY");
    ImGui::Separator();
    ImGui::TextUnformatted("Application");
    ImGui::SetNextItemWidth(-95);
    ImGui::InputText("##application", target, sizeof(target));
    ImGui::SameLine();

    if ( ImGui::Button("Browse##application", ImVec2(86, 0)) ) {
        const auto picked = PickPath(window, false);
        if ( !picked.empty() )
            CopyToField(target, sizeof(target), picked);
    }

    ImGui::TextUnformatted("Arguments");
    ImGui::InputText("##arguments", arguments, sizeof(arguments));
    ImGui::TextUnformatted("Sessions folder");
    ImGui::SetNextItemWidth(-155);
    if ( ImGui::InputText("##folder", folder, sizeof(folder),
                          ImGuiInputTextFlags_EnterReturnsTrue) )
        manager.SetRoot(std::filesystem::u8path(folder));
    ImGui::SameLine();
    if ( ImGui::Button("Use", ImVec2(48, 0)) )
        manager.SetRoot(std::filesystem::u8path(folder));
    ImGui::SameLine();

    if ( ImGui::Button("Browse##folder", ImVec2(86, 0)) ) {
        const auto picked = PickPath(window, true);

        if ( !picked.empty() ) {
            CopyToField(folder, sizeof(folder), picked);
            manager.SetRoot(std::filesystem::u8path(folder));
        }
    }

    ImGui::SetNextItemWidth(125);
    ImGui::Combo("Scope", &scope, "All modules\0Main executable\0");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(90);
    ImGui::InputInt("Memory bytes/access", &memoryBytes, 0);
    memoryBytes = std::clamp(memoryBytes, 0, 4096);
    ImGui::SameLine();
    ImGui::Checkbox("Follow children", &followChildren);
    ImGui::BeginDisabled(manager.HasActiveCapture());

    if ( ImGui::Button("Start profiling", ImVec2(150, 30)) ) {
        janus::gui::LaunchOptions options;
        options.target = target;
        options.arguments = arguments;
        options.scope = scope == 0 ? "all" : "main";
        options.memoryBytes = static_cast<unsigned>(memoryBytes);
        options.followChildren = followChildren;
        if ( manager.Launch(options) && !manager.Sessions().empty() )
            selected = manager.Sessions().front().directory;
    }

    ImGui::EndDisabled();

    if ( !manager.Message().empty() ) {
        ImGui::SameLine();
        ImGui::TextWrapped("%s", manager.Message().c_str());
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Text("Sessions (%zu)", manager.Sessions().size());
    ImGui::SameLine();
    if ( ImGui::SmallButton("Refresh") )
        manager.Refresh();

    const float tableHeight =
        std::max(160.0f, ImGui::GetContentRegionAvail().y * 0.46f);

    if ( ImGui::BeginTable("sessions", 4,
                           ImGuiTableFlags_BordersInnerH |
                               ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                               ImGuiTableFlags_Resizable,
                           ImVec2(0, tableHeight)) ) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Session", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Application",
                                ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed,
                                110);
        ImGui::TableSetupColumn("Trace", ImGuiTableColumnFlags_WidthFixed, 95);
        ImGui::TableHeadersRow();

        for ( const auto &session : manager.Sessions() ) {
            ImGui::PushID(session.directory.u8string().c_str());
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if ( ImGui::Selectable(
                     session.directory.filename().u8string().c_str(),
                     selected == session.directory,
                     ImGuiSelectableFlags_SpanAllColumns) )
                selected = session.directory;
            ImGui::TableSetColumnIndex(1);
            const auto name = session.target.empty()
                                  ? std::string("-")
                                  : std::filesystem::u8path(session.target)
                                        .filename()
                                        .u8string();
            ImGui::TextUnformatted(name.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(Status(session, manager).c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(
                janus::gui::FormatBytes(session.traceBytes).c_str());
            ImGui::PopID();
        }

        ImGui::EndTable();
    }

    const janus::gui::Session *current = nullptr;
    for ( const auto &session : manager.Sessions() )

        if ( session.directory == selected ) {
            current = &session;
            break;
        }

    if ( current ) {
        ImGui::Spacing();
        ImGui::Text("Started: %s",
                    janus::gui::FormatTime(current->startedAt).c_str());
        ImGui::SameLine(300);
        if ( current->finishedAt > current->startedAt )
            ImGui::Text("Elapsed: %lld s",
                        static_cast<long long>(current->finishedAt -
                                               current->startedAt));
        ImGui::Text("Trace size: %s",
                    janus::gui::FormatBytes(current->traceBytes).c_str());

        if ( current->completedBlocks ) {
            ImGui::SameLine(300);
            ImGui::Text("Blocks: %llu", static_cast<unsigned long long>(
                                            current->completedBlocks));
        }

        ImGui::TextWrapped("%s", current->directory.u8string().c_str());
        if ( ImGui::Button("Open folder") )
            ShellExecuteW(window, L"open", current->directory.c_str(), nullptr,
                          nullptr, SW_SHOWNORMAL);
        ImGui::SameLine();

        if ( ImGui::Button("Delete session") &&
             !manager.IsRunning(current->directory) ) {
            pendingDelete = current->directory;
            ImGui::OpenPopup("Delete session?");
        }
    } else {
        ImGui::TextDisabled("Select a session to see its details.");
    }

    if ( ImGui::BeginPopupModal("Delete session?", nullptr,
                                ImGuiWindowFlags_AlwaysAutoResize) ) {
        ImGui::Text("Delete %s and its trace files?",
                    pendingDelete.filename().u8string().c_str());

        if ( ImGui::Button("Delete", ImVec2(90, 0)) ) {
            if ( manager.Delete(pendingDelete) )
                selected.clear();
            ImGui::CloseCurrentPopup();
        }

        ImGui::SameLine();
        if ( ImGui::Button("Cancel", ImVec2(90, 0)) )
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    ImGui::End();
}

} 
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    ImGui_ImplWin32_EnableDpiAwareness();
    WNDCLASSEXW windowClass{sizeof(windowClass),
                            CS_CLASSDC,
                            WindowProcedure,
                            0,
                            0,
                            instance,
                            nullptr,
                            nullptr,
                            nullptr,
                            nullptr,
                            L"JanusKeyProfiler",
                            nullptr};
    RegisterClassExW(&windowClass);
    HWND window =
        CreateWindowW(windowClass.lpszClassName, L"Janus Key",
                      WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1040,
                      720, nullptr, nullptr, instance, nullptr);

    if ( !window || !CreateDevice(window) ) {
        MessageBoxW(nullptr, L"Could not initialize the window", L"Janus Key",
                    MB_ICONERROR);
        CleanupDevice();
        if ( window )
            DestroyWindow(window);
        UnregisterClassW(windowClass.lpszClassName, instance);
        CoUninitialize();
        return 1;
    }

    ShowWindow(window, SW_SHOWDEFAULT);
    UpdateWindow(window);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGuiStyle &style = ImGui::GetStyle();
    style.WindowPadding = ImVec2(18, 16);
    style.FramePadding = ImVec2(7, 5);
    style.ItemSpacing = ImVec2(8, 7);
    style.WindowRounding = 0;
    ImGui_ImplWin32_Init(window);
    ImGui_ImplDX11_Init(device, context);

    wchar_t executablePath[32768]{};
    GetModuleFileNameW(nullptr, executablePath, 32768);
    janus::gui::SessionManager manager(
        std::filesystem::path(executablePath).parent_path());
    auto refreshed = std::chrono::steady_clock::now();
    bool done = false;

    while ( !done ) {
        MSG message{};

        while ( PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE) ) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
            if ( message.message == WM_QUIT )
                done = true;
        }

        if ( done )
            break;
        manager.Poll();

        if ( std::chrono::steady_clock::now() - refreshed >=
             std::chrono::seconds(2) ) {
            manager.Refresh();
            refreshed = std::chrono::steady_clock::now();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        DrawUi(window, manager);
        ImGui::Render();

        if ( renderTarget ) {
            constexpr float clear[] = {0.07f, 0.08f, 0.10f, 1.0f};
            context->OMSetRenderTargets(1, &renderTarget, nullptr);
            context->ClearRenderTargetView(renderTarget, clear);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
            swapChain->Present(1, 0);
        }
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDevice();
    DestroyWindow(window);
    UnregisterClassW(windowClass.lpszClassName, instance);
    CoUninitialize();
    return 0;
}

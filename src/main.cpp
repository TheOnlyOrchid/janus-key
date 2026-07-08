#include "pin.H"
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>

// the info about one specific call of a function.
struct FunCallInstanceInfo {
    // UNIX timestamp of when the function was called
    UINT32 timestamp;
    // address from within the exe (or associated DLL)
    ADDRINT calledFromAddr;

    // the return type associated with the return value, if possible.
    // void = "void"
    // unknown = "unknown"
    // too large = "too large"
    // everything else is self explanatory
    std::string returnType;
    // return data
    std::vector<char> returnValue;
};

// the info about all calls of a function.
struct FuncInfo {
    // the function name
    std::string name;
    // if the function is a system function, e.g. if its from kernel32.dll
    bool systemFunction;
    // the path to the module it was called from
    std::string module;
    // the address of the function within the module.
    ADDRINT addr;
    // how many times this function has been called
    UINT64 count;

    // contains details about each call of the function
    std::vector<FunCallInstanceInfo> callInfos;
};

std::unordered_map<ADDRINT, FuncInfo> funcs;
PIN_LOCK lock;

KNOB<std::string> KnobOutput(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "o",
    ".",
    "output directory"
);

static std::string JoinPath(const std::string& dir, const std::string& filename) {
    if (dir.empty() || dir == ".") return filename;

    char last = dir[dir.size() - 1];
    if (last == '\\' || last == '/') return dir + filename;

    return dir + "\\" + filename;
}

static std::string CsvEscape(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

VOID CountFunc(const ADDRINT funcAddr, const ADDRINT calledFromAddr) {
    PIN_GetLock(&lock, 1);

    auto it = funcs.find(funcAddr);
    if (it != funcs.end()) {
        FuncInfo& f = it->second;
        f.count++;

        FunCallInstanceInfo callInfo;
        callInfo.timestamp = static_cast<UINT32>(std::time(nullptr));
        callInfo.calledFromAddr = calledFromAddr;

        // placeholder
        callInfo.returnType = "unknown";
        callInfo.returnValue = {};

        f.callInfos.push_back(callInfo);
    }

    PIN_ReleaseLock(&lock);
}

VOID ImageLoad(const IMG img, VOID* v) {
    const std::string module = IMG_Name(img);
    bool systemFunction = !IMG_IsMainExecutable(img);

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            ADDRINT addr = RTN_Address(rtn);
            const std::string name = RTN_Name(rtn);

            funcs.emplace(addr, FuncInfo{
                name,
                systemFunction,
                module,
                addr,
                0,
                {}
            });

            RTN_Open(rtn);

            RTN_InsertCall(
                rtn,
                IPOINT_BEFORE,
                (AFUNPTR)CountFunc,
                IARG_ADDRINT, addr,
                IARG_RETURN_IP,
                IARG_END
            );

            RTN_Close(rtn);
        }
    }
}

VOID Fini(INT32 code, VOID* v) {
    std::cout << "Writing CSV\n";

    const std::string outputDir = KnobOutput.Value();
    const std::string summaryPath = JoinPath(outputDir, "func_counts.csv");
    const std::string callsPath = JoinPath(outputDir, "func_call_instances.csv");

    std::ofstream summaryOut(summaryPath);
    if (!summaryOut.is_open()) {
        std::cerr << "Failed to open summary CSV: " << summaryPath << "\n";
        return;
    }

    summaryOut << "module,function,address,systemFunction,count\n";

    for (const auto& kv : funcs) {
        const FuncInfo& f = kv.second;
        if (f.count == 0) continue;

        summaryOut
            << CsvEscape(f.module) << ","
            << CsvEscape(f.name) << ","
            << "0x" << std::hex << f.addr << std::dec << ","
            << (f.systemFunction ? "true" : "false") << ","
            << f.count << "\n";
    }

    summaryOut.close();

    std::ofstream callsOut(callsPath);
    if (!callsOut.is_open()) {
        std::cerr << "Failed to open call instances CSV: " << callsPath << "\n";
        return;
    }

    callsOut << "module,function,address,timestamp,calledFromAddr,returnType,returnValueSize\n";

    for (const auto& kv : funcs) {
        const FuncInfo& f = kv.second;
        if (f.count == 0) continue;

        for (const FunCallInstanceInfo& call : f.callInfos) {
            callsOut
                << CsvEscape(f.module) << ","
                << CsvEscape(f.name) << ","
                << "0x" << std::hex << f.addr << std::dec << ","
                << call.timestamp << ","
                << "0x" << std::hex << call.calledFromAddr << std::dec << ","
                << CsvEscape(call.returnType) << ","
                << call.returnValue.size() << "\n";
        }
    }

    callsOut.close();
}

int main(int argc, char* argv[]) {
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        std::cout << "Usage:\n";
        std::cout << "  pin -t janus_key_pintool.dll -o output_dir -- target.exe\n";
        std::cerr << "Incorrect usage.\n";
        return 1;
    }

    PIN_InitLock(&lock);

    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);

    PIN_StartProgram();
    return 0;
}

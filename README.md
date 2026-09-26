# Janus Key

Janus key is an Intel Pin based profiler that produces extremely high-fidelity traces.
It's default compact binary output records process trees, module identities, instruction
encodings, executed instructions, repeated memory accesses, register states, calls, returns,
branches, syscalls, context transition, memory lifecycles and thread lifetimes. A CSV backend 
remains available for diagnostics - though note that it is not the intended output format, 
merely left in because I saw no reason to remove something I already had for a legacy version.

The actual profiler itself is independent of consumers - but it is designed with consumers in mind.

The accompanying Ghidra extension turns the traces into value hovers, writer history, observed
function args / return values, timeline stepping, execution hotspots and comparisons across runs.

## Ghidra analysis

```powershell
python ghidra/build.py --ghidra E:/coding/ghidra_11.4.2_PUBLIC
```

Install the generated extension ZIP from `ghidra/JanusKey/dist` through Ghidra's **File -> Install
Extensions**, restart, and enable **JanusKeyPlugin** in the plugin config page. Import a
run with **File -> Import Janus Key Run**, select the corresponding module, and enjoy.
The extension checks PE identity before rebasing observations and instruction 
bytes before navigation. It saves reusable disk indexes (this may eat a bit of storage)
and keeps each run's state separate.

## Build and test

Intel Pin's Windows kit requires MSVC-compatible object files. Use Visual C++ or `clang-cl`,
then use the three CMake targets: `janus_key_pintool` builds the DLL,
`janus_key_gui` builds the DLL and GUI,
`run_tests` builds the DLL and the test runner. It's named `run_tests` rather than `build_test_runner`
due to it being designed to use in an IDE that would run it on build.
```powershell
cmake -S . -B build
cmake --build build --target run_tests
ctest --test-dir build --output-on-failure
```

## Code formatting

I have a script that combines both clang-tidy and a custom spacer to format code to my preference.

```powershell
.\format_code.ps1
```

## Run

### Desktop GUI

Build the project, then launch `janus_key_gui.exe`. This will launch the ImGUI GUI. It uses the
same terminology as the CLI, so refer to below if you are confused about a specific option.

### Command line

Create the output directory before launching the target:

```powershell
mkdir trace
third_party\pin\pin.exe -follow_execv -t path\to\janus_key_pintool.dll -o trace -format binary -compression xpress -buffer_kb 1024 -max_memory_bytes 64 -call_stack_bytes 64 -registers 1 -scope all -follow_children 1 -- C:\Windows\System32\notepad.exe
```

`max_memory_bytes` The maximum size to record from a memory operation.
A value of `0` captures access metadata without copying values.
`scope` defaults to `all`; use `main` for a smaller trace containing only instructions in the main
executable.
`-registers 0` records neither register input values nor before/after register write values.
`call_stack_bytes` bounds the raw caller-stack snapshot stored with every call instance.
`format` defaults to `binary`, `csv` is also available. which writes `trace.jkt`
`-compression xpress` is the default compression codec, `none` is also available.;
Use `-follow_children 0` to not inject the profiler into children.

## DISCLAIMERS

In the current state - this project isn't exactly user friendly or practical. Per-instruction orchestration involves a significant
performance overhead - even running simple applications, such as notepad, can suffer. GUI applications do suffer more
than CLI applications though. The storage concerns are also non-trivial, a 10s~ capture of notepad where all i do is
type `hello` and then replace it with `world` takes about 150mb~. This project is not really intended for serious
real-world use yet. It is more of a personal proof of concept.
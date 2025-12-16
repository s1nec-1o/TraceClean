# TraceClean

[English](README.md) | [中文](README_zh.md)

**TraceClean** is an IDA Pro plugin designed to clean up obfuscated code (specifically OLLVM) by removing "dead code" based on runtime execution traces.

It reads an execution trace log (e.g., from Unidbg, Frida, or Qiling) and NOPs out instructions that were **not** executed. This is extremely effective against **OLLVM Bogus Control Flow**, making the control flow graph (CFG) readable again.

## 🚀 Features

- **Trace-Based Cleaning**: Only keeps code that actually runs; everything else is replaced with NOPs.
- **Multi-Architecture Support**:
  - x86 / x64 (`0x90`)
  - ARM32 (`0x00 0xF0 0x20 0xE3` or Thumb `0x00 0xBF`)
  - ARM64 (`0x1F 0x20 0x03 0xD5`)
- **IDA 9.x Compatible**: Uses the latest `ida_ida` and `ida_kernwin` APIs.
- **Safe Mode**: Asks for confirmation before patching and creates a selection range check.

## 📦 Installation

1. Copy the python script (`TraceClean.py`) into your IDA plugins folder:
   - `IDA_DIR/plugins/`
2. Restart IDA Pro.

## 📖 Usage Logic

The core logic of this plugin is simple: **"If it didn't run, it's dead code."**

### Step 1: Generate Trace Log (Unidbg Example)

You need a text file containing the execution addresses. The format should be one hexadecimal address per line (e.g., `0x1A2B`).

Add the following hook to your **Unidbg** script to generate the trace. **Note:** Ensure the address logged matches the base address in IDA. If IDA shows offsets (0x0 based), log offsets. If IDA shows memory addresses, log memory addresses.

```Java
// Define the range you want to trace (to avoid huge logs)
long startAddress = module.base + 0x1E31C; // Example Start
long endAddress   = module.base + 0x1E5B4; // Example End

System.out.println("Trace Range: " + Long.toHexString(startAddress) + " -> " + Long.toHexString(endAddress));

// Hook the code execution
emulator.getBackend().hook_add_new(new CodeHook() {
    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        // [IMPORTANT] Adjust the address calculation to match IDA
        // If your IDA shows offsets (Image Base = 0), subtract the module base.
        // Assuming module base is 0x40000000 in Unidbg:
        long offset = address - 0x40000000L; 
        
        // Print the offset to stdout or save to file
        System.out.println(String.format("0x%x", offset));
    }

    @Override
    public void onAttach(UnHook unHook) {}

    @Override
    public void detach() {}
}, startAddress, endAddress, null);
```

*Save the output output to a file named `trace.log`.*

### Step 2: Load into IDA

1. Open your target binary in IDA Pro.
2. Navigate to the function you traced.
3. Highlight the range of code you want to clean (or position the cursor inside the function).
4. Press the Hotkey: **`Ctrl-Alt-N`**.

### Step 3: Patching

1. A file dialog will appear. Select your `trace.log`.
2. The plugin will calculate the range. Confirm the Start and End addresses.
3. Click **Yes**.
4. The plugin will iterate through every instruction in the selected range. If an instruction's address is **NOT** found in your trace log, it will be replaced with NOPs.

## ⚙️ Configuration

Open the script file to adjust settings if needed:

```Python
# ================= Configuration =================
PLUGIN_NAME = "Trace Dead Code NOP (Safe)"
PLUGIN_HOTKEY = "Ctrl-Alt-N"

# Set this to match your trace log format.
# If your log contains Offsets (e.g. 0x1000), set IDA_BASE = 0
# If your log contains Absolute Addresses (e.g. 0x40001000) and IDA is not rebased, adjust this.
IDA_BASE = 0 
# ===============================================
```

## ⚠️ Disclaimer

- **Backup your IDB/I64 file** before running this. NOPing code is destructive.
- This approach relies on **code coverage**. If a valid path simply wasn't taken during your specific trace run (e.g., an error handling branch), it will be deleted. Ensure your trace covers the logic you care about.

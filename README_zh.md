# TraceClean

**TraceClean** 是一款 IDA Pro 插件，旨在通过运行时执行轨迹（Trace）来清除混淆代码（特别是 OLLVM）。

它读取执行日志（例如来自 Unidbg、Frida 或 Qiling 的 Log），并将**未执行**的指令全部替换为 NOP。这对于对抗 **OLLVM 虚假控制流（Bogus Control Flow）** 极其有效，能够让控制流图（CFG）重新恢复可读性，显著降低逆向分析难度。

## 🚀 功能特性

- **基于 Trace 的清理**：仅保留实际运行过的代码，未命中的代码一律被视为死代码并 NOP 掉。
- **多架构支持**：
  - x86 / x64 (`0x90`)
  - ARM32 (`0x00 0xF0 0x20 0xE3` 或 Thumb 模式 `0x00 0xBF`)
  - ARM64 (`0x1F 0x20 0x03 0xD5`)
- **适配 IDA 9.x**：使用最新的 `ida_ida` 和 `ida_kernwin` API 编写。
- **安全模式**：Patch 前会弹出确认框，自动校验选区范围，防止误操作。

## 📦 安装方法

1. 将 Python 脚本 (`TraceClean.py`) 复制到您的 IDA 插件目录中：
   - 路径通常为：`IDA安装目录/plugins/`
2. 重启 IDA Pro。

## 📖 使用逻辑

本插件的核心逻辑非常简单粗暴：**“没运行到的，就是死代码。”**

### 步骤 1: 生成 Trace Log (以 Unidbg 为例)

您需要准备一个包含执行地址的文本文件。格式要求为每行一个十六进制地址（例如 `0x1A2B`）。

请将以下 Hook 代码添加到您的 **Unidbg** 脚本中以生成 Trace。 **注意**：请确保记录的地址与 IDA 中的地址一致。如果 IDA 显示的是偏移量（基址为 0），请记录偏移量；如果 IDA 显示的是绝对内存地址，请记录绝对地址。

```Java
// 定义您想要 Trace 的范围（避免日志过大）
long startAddress = module.base + 0x1E31C; // 示例：起始地址
long endAddress   = module.base + 0x1E5B4; // 示例：结束地址

System.out.println("Trace Range: " + Long.toHexString(startAddress) + " -> " + Long.toHexString(endAddress));

// Hook 代码执行
emulator.getBackend().hook_add_new(new CodeHook() {
    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        // [重要] 调整地址计算以匹配 IDA 的视图
        // 如果您的 IDA 显示的是文件偏移（Image Base = 0），这里需要减去模块基址。
        // 假设 Unidbg 加载的模块基址是 0x40000000：
        long offset = address - 0x40000000L; 
        
        // 将计算出的偏移量打印到控制台或保存到文件
        // 输出格式示例: 0x1e320
        System.out.println(String.format("0x%x", offset));
    }

    @Override
    public void onAttach(UnHook unHook) {}

    @Override
    public void detach() {}
}, startAddress, endAddress, null);
```

*请将控制台输出保存为名为 `trace.log` 的文件。*

### 步骤 2: 在 IDA 中加载

1. 在 IDA Pro 中打开目标二进制文件。
2. 跳转到您刚刚 Trace 过的函数。
3. **选中**您想要清理的代码范围（或者直接将光标停留在函数内部，插件会自动识别函数范围）。
4. 按下热键：**`Ctrl-Alt-N`**。

### 步骤 3: 执行 Patch

1. 弹出文件选择框，选择您的 `trace.log` 文件。
2. 插件会计算并显示将要处理的地址范围。确认起始和结束地址无误。
3. 点击 **Yes**。
4. 插件将遍历选区内的每一条指令。如果某条指令的地址**没有**出现在 Trace Log 中，它将被替换为 NOP 指令。

## ⚙️ 配置说明

如有需要，您可以打开脚本文件修改顶部配置：

```Python
# ================= 配置区域 =================
PLUGIN_NAME = "Trace Dead Code NOP (Safe)"
PLUGIN_HOTKEY = "Ctrl-Alt-N"

# 设置此项以匹配您的 Trace Log 格式
# 如果您的 Log 包含的是偏移量 (如 0x1000)，请设置 IDA_BASE = 0
# 如果您的 Log 包含的是绝对地址 (如 0x40001000) 且 IDA 未进行 Rebase，请调整此值。
IDA_BASE = 0 
# ===========================================
```

## ⚠️ 免责声明

- **请务必先备份您的 IDB/I64 文件**。NOP 操作是破坏性的，不可逆。
- 此方法完全依赖于 **代码覆盖率 (Code Coverage)**。如果某条合法的逻辑路径（例如异常处理分支、错误提示分支）在您 Trace 的那次运行中没有被执行到，它也会被误认为是死代码并被删除。
- **请确保您的 Trace 样本覆盖了您关心的核心逻辑。**

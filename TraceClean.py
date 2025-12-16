import idaapi
import idc
import idautils
import ida_kernwin
import ida_bytes
import ida_funcs
import ida_ida
import os

# ================= 配置区域 =================
PLUGIN_NAME = "Trace Dead Code NOP (Safe)"
PLUGIN_HOTKEY = "Ctrl-Alt-N"
IDA_BASE = 0 
# ===========================================

class TraceNoperPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Nops out instructions not present in the trace file"
    help = "Trace Dead Code Remover"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        print(f"[-] {PLUGIN_NAME} loaded. Hotkey: {PLUGIN_HOTKEY}")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.main_logic()

    def term(self):
        pass

    def get_nop_opcode(self, ea, size):

        # 使用 ida_ida.inf_get_procname() 替代旧的 get_inf_structure().proc_name
        proc_name = ida_ida.inf_get_procname().lower()
        
        # --- x86 / x64 ---
        if "metapc" in proc_name or "8086" in proc_name:
            return b'\x90' * size 

        # --- ARM ---
        elif "arm" in proc_name:
            # 使用 ida_ida.inf_is_64bit() 替代旧的 get_inf_structure().is_64bit()
            if ida_ida.inf_is_64bit():
                # ARM64 (AArch64) NOP: 0xD503201F
                return b'\x1F\x20\x03\xD5' * (size // 4)
            else:
                # ARM32 / Thumb
                is_thumb = idc.get_sreg(ea, "T") == 1
                if is_thumb:
                    # Thumb NOP: 0xBF00
                    return b'\x00\xBF' * (size // 2)
                else:
                    # ARM Mode NOP: 0xE320F000 (nop) or 0xE1A00000 (mov r0,r0)
                    return b'\x00\xF0\x20\xE3' * (size // 4)

        # 默认回退
        return b'\x90' * size

    def main_logic(self):
        file_path = ida_kernwin.ask_file(0, "*.txt;*.log", "Select Trace Log (Addresses)")
        if not file_path or not os.path.exists(file_path):
            return

        sel_start, sel_end = idc.read_selection_start(), idc.read_selection_end()
        
        # 自动获取当前函数范围
        if sel_start == idc.BADADDR:
            func = idaapi.get_func(idc.get_screen_ea())
            if func:
                sel_start = func.start_ea
                sel_end = func.end_ea
            else:
                sel_start = ida_kernwin.ask_addr(0, "Enter Start Address:")
                sel_end = ida_kernwin.ask_addr(0, "Enter End Address (Exclusive):")

        if sel_start is None or sel_end is None or sel_start == idc.BADADDR:
            print("[!] Invalid address range.")
            return

        # --- 计算实际最后一条指令的地址，用于显示给用户 ---
        last_instruction_addr = idc.prev_head(sel_end)
        
        # 确认弹窗
        msg = (f"Range Start: {hex(sel_start)}\n"
               f"Range End  : {hex(sel_end)} (Exclusive)\n"
               f"Last Instr : {hex(last_instruction_addr)} (Inclusive)\n\n"
               f"Ready to NOP untraced code in this range?")
        
        if ida_kernwin.ask_yn(0, msg) != 1:
            return

        # 加载 Trace
        trace_set = set()
        print("[-] Loading trace...")
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    token = line.split()[0]
                    if token.startswith("0x"):
                        try:
                            addr = int(token, 16) + IDA_BASE
                            trace_set.add(addr)
                        except ValueError:
                            pass
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            return
        
        print(f"[-] Loaded {len(trace_set)} trace points.")

        # 开始 Patch
        curr = sel_start
        nop_count = 0
        patched_bytes_count = 0

        while curr < sel_end:
            # 安全检查：确保是代码
            if not idc.is_code(ida_bytes.get_flags(curr)):
                curr = idc.next_head(curr, sel_end)
                continue

            insn_len = idc.get_item_size(curr)
            if insn_len == 0: 
                curr += 1 
                continue

            # 核心逻辑
            if curr not in trace_set:
                nop_bytes = self.get_nop_opcode(curr, insn_len)
                ida_bytes.patch_bytes(curr, nop_bytes)
                nop_count += 1
                patched_bytes_count += insn_len
            
            curr += insn_len

        print(f"[+] Finished! NOPed {nop_count} instructions.")
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)

def PLUGIN_ENTRY():
    return TraceNoperPlugin()

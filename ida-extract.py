# LemonHaze - 2025

import idautils
import idaapi
import idc
import ida_hexrays
import json
import os
import subprocess
import re
import requests
import ollama

# Project Config
name="replace_me"

# Modes
gen_hooks = False                # generates a hooks.json to be used with gen_hooks.py
extract_selected = False        # extract the currently selected function        
rename_funcs = False            # reanames funcs that contain :: and replaces for NS_<namespace>_n_<func_name>
rename_vars = False             # renames vars that contain :: and replaces for NS_<namespace>_n_<var_name>
compile_all = False             # compile all funcs
compile_remaining = True        # only compile funcs not in passing list

# Settings
gen_hook_prefixes=[""]           # when generating hooks, only gen hooks for funcs with these prefixes
show_build_log = False           # show the compiler output when func fails to compile
only_named = False               # skip any funcs starting with sub_
single_extract = True            # just extract a single function at a time when `compile_remaining`
ask_llm_to_fix_on_fail=False     # asks below configured LLM to fix funcs that fail to compile
max_attempts = 1                 # max attempts when above is enabled
only_specifics=False             # only attempt funcs with prefixes defined below
specific_func_prefixes=[""]
exclude_prefixes = ["j_"]        # exclude funcs with these prefixes
exclude_funcs = ["free", "memcmp", "memcpy", "memset"]  # exclude these funcs

# Configuration
base_offset = 0x140000000
base_dir=f"C:\\dev\\{name}\\"
compiler = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin\\msbuild.exe"
msvc_sln_file=f"{base_dir}{name}.sln"
compiler_args = f"{msvc_sln_file}"
temp_c_filename = "autotest.cc"
ml_model = "Qwen2.5-Coder:32b" #"DeepSeek-Coder:6.7b"
prompt="Your task is to fix the code provided: "

# Internal variables
pass_func_file = f"{base_dir}passing_functions.json"
temp_c_file = f"{base_dir}{temp_c_filename}"
passing_funcs_c_file =f"{base_dir}autoconfirmed.cc"

def should_compile(name):
    if only_specifics == True:
        if any(name.startswith(prefix) for prefix in specific_func_prefixes):
            return True
        else:
            return False
    if name in exclude_funcs:
        return False
    if any(name.startswith(prefix) for prefix in exclude_prefixes):
        return False
    if only_named and name.startswith("sub_"):
        return False        
    return True

def get_num_compiled_funcs():
    passing_functions = load_passing_functions()
    return len (passing_functions)
        
def get_num_total_funcs():
    passing_functions = load_passing_functions()
    total = 0
    for func_ea in idautils.Functions():
        func_name = ida_name.get_name(func_ea)
        if func_name in passing_functions or any(name.startswith(prefix) for prefix in gen_hook_prefixes):
            continue
        total = total + 1
    return total

def get_remaining_work():
    return get_num_total_funcs() - get_num_compiled_funcs()
    
def load_passing_functions():
    if os.path.exists(pass_func_file):
        with open(pass_func_file, "r") as f:
            return json.load(f)
    return {}

def generate_hooks():
    passing_functions = load_passing_functions()
    hooks = {}
    for func_name in passing_functions.keys():
        addr = idc.get_name_ea_simple(func_name)
        if addr != idc.BADADDR:
            hooks[func_name] = hex(addr - base_offset)
    return hooks

def write_hooks():
    with open(f"{base_dir}hooks.json", "w") as f:
        json.dump(generate_hooks(), f, indent=4)

def save_passing_functions(passing_functions):
    with open(pass_func_file, "w") as f:
        json.dump(passing_functions, f, indent=4)

def get_pseudocode(ea):
    if not ida_hexrays.init_hexrays_plugin():
        print("[ERROR] Hex-Rays decompiler not available")
        return None
    
    pseudocode = ida_hexrays.decompile(ea)
    if not pseudocode:
        print(f"[ERROR] Failed to decompile function at {hex(ea)}")
        return None    
    return str(pseudocode)

def get_called_functions(func_ea):
    calls = set()
    
    for head in idautils.FuncItems(func_ea):
        if idc.print_insn_mnem(head) in ["call"]:
            callee = idc.get_operand_value(head, 0)
            if idaapi.get_func(callee):
                calls.add(callee)
    return calls

def write_c_file(functions):
    with open(temp_c_file, "w") as f:
        for func in functions:
            f.write(func + "\n\n")

def compile_c_file():
    try:
        result = subprocess.run([compiler, compiler_args, ""], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stdout
    except Exception as e:
        return False, str(e)

def ask_for_fix(error_msg, c_code):
    prompt = f"""{prompt}
    {c_code}

    compiler output log:
    {error_msg}
    """
    response = ollama.chat(model=ml_model, messages=[{'role': 'user','content': prompt}])
    return response['message']['content']
    
def extract_and_compile(function_ea):
    passing_functions = load_passing_functions()
    called_functions = get_called_functions(function_ea)
    extracted_functions = []
    
    for func_ea in called_functions:
        func_name = idc.get_func_name(func_ea)
        if func_name in passing_functions:
            continue
        
        pseudocode = get_pseudocode(func_ea)
        if not pseudocode:
            continue
        extracted_functions.append(pseudocode)
    
    extracted_functions.append(get_pseudocode(function_ea))
    
    if not extracted_functions:
        print("[INFO] No functions extracted.")
        return
    
    write_c_file(extracted_functions)
    
    attempts = 0
    while attempts < max_attempts:
        success, error_msg = compile_c_file()
        if success:
            print("[SUCCESS] Compilation passed.")
            for func_ea in called_functions:
                passing_functions[idc.get_func_name(func_ea)] = True
            passing_functions.append(idc.get_func_name(function_ea))
            save_passing_functions(passing_functions)
            return
        
        print(f"[ERROR] Compilation failed (Attempt {attempts + 1}/{max_attempts}):\n{error_msg}")
        if not ask_llm_to_fix_on_fail:
            return
        else:
            fixed_code = ask_for_fix(error_msg, "\n\n".join(extracted_functions))
            if not fixed_code:
                print("[ERROR] Ollama did not provide a fix.")
                return
        
            write_c_file([fixed_code])
            attempts += 1
        print("[FAIL] Maximum attempts reached. Could not fix compilation.")
        

def rename_functions():
    for func_ea in idautils.Functions():
        func_name = ida_name.get_name(func_ea)
        if "::" in func_name:
            new_name = "NS_" + func_name.replace("::", "_n_")
            if ida_name.set_name(func_ea, new_name, ida_name.SN_NOWARN):
                print(f"Renamed: {func_name} -> {new_name}")
            else:
                print(f"Failed to rename: {func_name}")

def rename_variables():
    for gvar_ea in idautils.Segments():
        seg_start = idc.get_segm_start(gvar_ea)
        seg_end = idc.get_segm_end(gvar_ea)

        for ea in idautils.Heads(seg_start, seg_end):
            if not ida_bytes.is_data(ida_bytes.get_full_flags(ea)):
                continue

            var_name = ida_name.get_name(ea)
            if not var_name:
                continue

            if "::" in var_name:
                new_name = "NS_" + var_name.replace("::", "_n_")
                if ida_name.set_name(ea, new_name, ida_name.SN_NOWARN):
                    print(f"Renamed: {var_name} -> {new_name}")
                else:
                    print(f"Failed to rename: {var_name}")

def get_function_call_counts():
    func_usage = {}
    passing_functions = load_passing_functions()
    
    for func_ea in idautils.Functions():
        func_name = ida_name.get_name(func_ea)
        if func_name in passing_functions:
            continue
                    
        func_usage[func_name] = 0
        refs = ida_xref.get_first_cref_to(func_ea)
        while refs != ida_idaapi.BADADDR:
            func_usage[func_name] += 1
            refs = ida_xref.get_next_cref_to(func_ea, refs)

    sorted_funcs = sorted(func_usage.items(), key=lambda x: x[1], reverse=True)
    return sorted_funcs

def attempt_compile(func_ea):
    func_name = idc.get_func_name(func_ea)
    passing_functions = load_passing_functions()
    if func_name in passing_functions:
        return
    if not should_compile(func_name):
        return
    
    extracted_functions = []
    called_functions = get_called_functions(func_ea)    
    if single_extract:        
        pseudocode = get_pseudocode(func_ea)
        if not pseudocode:
            return
        extracted_functions.append(pseudocode)
    else:
        for call_func_ea in called_functions:
            call_func_name = idc.get_func_name(call_func_ea)
            if call_func_name in passing_functions:
                continue
            if not should_compile(call_func_name):
                continue
        
            pseudocode = get_pseudocode(call_func_ea)
            if not pseudocode:
                continue
            extracted_functions.append(pseudocode)

        # add this function to the end    
        extracted_functions.append(get_pseudocode(func_ea))
        

    with open(temp_c_file, "w", encoding="utf-8", errors="ignore") as file:
        for func in extracted_functions:
            file.write("\n" + func + "\n\n")
            
    success, error_msg = compile_c_file()
    if success:
        with open(passing_funcs_c_file, "a", encoding="utf-8", errors="ignore") as file:
            for func in extracted_functions:
                file.write("\n" + func + "\n\n")
            
            # mark this func
            passing_functions[func_name] = True
            
            # mark all called funcs
            for call_func in called_functions:
                call_fn_name = idc.get_func_name(call_func)
                passing_functions[call_fn_name] = True
            
            save_passing_functions(passing_functions)
            print(f"{func_name} compiled.")
    else:
        print(f"{func_name} failed to compile.")
        if show_build_log:
            print(f"Log: {error_msg}")

def attempt_compile_all(start_addr=None):    
    if True:
        functions = list(idautils.Functions())
        if start_addr:
            functions = [ea for ea in functions if ea >= start_addr]
        
        for func_ea in functions:
            attempt_compile(func_ea)

def attempt_compile_all_sorted_most_used():
    sorted_funcs = get_function_call_counts()
    num = 0
    for func in sorted_funcs:
        func_ea = idc.get_name_ea_simple(func[0])
        attempt_compile(func_ea)
        num = num + 1
        #print(f"Processed func {num-1}")


def has_no_xrefs(func_ea):
    for head in idautils.Heads(func_ea, idc.get_func_attr(func_ea, idc.FUNCATTR_END)):
        for xref in idautils.XrefsFrom(head):
            if idc.get_func_name(xref.to) and xref.to != func_ea:
                return False
    return True

def get_functions_without_xrefs():
    no_xrefs_funcs = []
    passing_functions = load_passing_functions()
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        if has_no_xrefs(func_ea) and not func_name in passing_functions:
            no_xrefs_funcs.append(idc.get_func_name(func_ea))
    return no_xrefs_funcs

def main():
    try:
        print(f"Progress: {get_num_compiled_funcs()}/{get_num_total_funcs()} Incomplete: {get_remaining_work()}")

        ida_hexrays.clear_cached_cfuncs()
    
        if extract_selected:
            func_ea = idc.here()
            if not idaapi.get_func(func_ea):
                print("[ERROR] Please place the cursor inside a function.")
            else:
                extract_and_compile(func_ea)
    
        if rename_funcs:    
            rename_functions()
        
        if rename_vars:
            rename_variables()
    
        if compile_all:
            attempt_compile_all()
    
        if compile_remaining:
            if get_remaining_work() != 0:
                attempt_compile_all_sorted_most_used()
            
        if gen_hooks:
            write_hooks()
    except Exception as e:
        return
                    
if __name__ == "__main__":
    main()

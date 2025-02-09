# LemonHaze - 2020
import idc
import idautils
import idaapi


rename_funcs = True
func_prefix="Event_"
func_suffix=""
name_insns = []
name_regs = [] 
relevant_operands = []
exclude_func_substrings = []
unwanted_chars = ["[", ">"]

queue_func_size_threshold = 300
min_func_name = 5

def analyse_calls(target_function_name):
    target_func_ea = idc.get_name_ea_simple(target_function_name)
    if target_func_ea == idc.BADADDR:
        print(f"Target function {target_function_name} not found.")
        return        
        
    check_names(target_func_ea)
    check_queues(target_func_ea)

def check_queues(target_func_ea):
    for xref in idautils.XrefsTo(target_func_ea):
        call_addr = xref.frm
        
        lea_name, lea_ea = find_func(call_addr)
        callback_name = find_func_name(call_addr)
        if "nullsub" in callback_name:
            continue

        func_name = extract_and_flatten(callback_name)
        if len(func_name) > min_func_name and check_exclusions(unwanted_chars, func_name):
            func = idaapi.get_func(call_addr)
            caller_name = idaapi.get_func_name(call_addr)
            if func:
                func_size = func.end_ea - func.start_ea
                new_name = construct_new_func_name(func_name, "Queue_", "")
                if func_size < queue_func_size_threshold and (new_name != caller_name and check_exclusions(exclude_func_substrings, caller_name)):
                    print(f"INFO: Offset: {func.start_ea:X} Size: {func_size} | {caller_name} should be named {new_name}")
                    if rename_funcs == True:
                        rename_func(func.start_ea, new_name)

def check_names(target_func_ea):    
    for xref in idautils.XrefsTo(target_func_ea):
        call_addr = xref.frm
        
        lea_name, lea_ea = find_func(call_addr)
        if not idaapi.get_func(lea_ea):
            continue
            
        callback_name = find_func_name(call_addr)
        if "nullsub" in callback_name:
            continue

        func_name = extract_and_flatten(callback_name)
        new_name= construct_new_func_name(func_name, func_prefix, func_suffix)
        
        if idaapi.get_func(lea_ea) and lea_name != "nullsub" and (rename_funcs and lea_name != new_name):
            print(f"DBG: {lea_name} (0x{lea_ea:X}) is not named {new_name}")
            if rename_funcs == True:
                rename_func(lea_ea, new_name)            

def extract_and_flatten(input_str):
    match = re.search(r"\)\s*(.*)", input_str)
    if match:
        extracted = match.group(1)
    else:
        extracted = input_str
    flattened = re.sub(r"[()]", "_", extracted)
    return flattened    
    

def find_func(call_addr):
    instr_addr = idc.prev_head(call_addr)
    while instr_addr != idaapi.BADADDR:
        insn = idautils.DecodeInstruction(instr_addr)
        if insn and (insn.get_canon_mnem() in name_insns):
            if idc.print_operand(instr_addr, 0) in relevant_operands:
                operand = idc.print_operand(instr_addr, 1)
                resolved_address = resolve_operand(instr_addr, operand)
                if resolved_address:
                    if "(" in resolved_address:
                        name, addr = resolved_address.split("(")
                        return name.strip(), int(addr.strip(")"), 16)
                    else:
                        return resolved_address, None
        instr_addr = idc.prev_head(instr_addr)
    return None, None
     
def find_func_name(call_addr):
    instr_addr = idc.prev_head(call_addr)
    while instr_addr != idaapi.BADADDR:
        insn = idautils.DecodeInstruction(instr_addr)
        if insn and (insn.get_canon_mnem() in name_insns):
            if idc.print_operand(instr_addr, 0) in name_regs:
                operand = idc.print_operand(instr_addr, 1)
                resolved_address = resolve_operand(instr_addr, operand)
                
                if resolved_address:
                    string_value = get_string_from_address(resolved_address)
                    if string_value:
                        return string_value
        instr_addr = idc.prev_head(instr_addr)
    return None

def get_string_from_address(resolved_address):
    try:
        if "(" in resolved_address:
            addr = int(resolved_address.split("(")[1].strip(")"), 16)
        else:
            addr = int(resolved_address, 16)
        string_data = idc.get_strlit_contents(addr, -1, idc.STRTYPE_C)
        if string_data:
            return string_data.decode('utf-8')
    except Exception as e:
        print(f"ERR: Error reading string at address {resolved_address}: {e}")
    return None

def resolve_operand(instr_addr, operand):
    if operand.isidentifier():
        ea = idc.get_name_ea_simple(operand)
        if ea != idc.BADADDR:
            return f"{operand} (0x{ea:X})"
    
    if operand.startswith("0x") or operand.isdigit():
        try:
            addr = int(operand, 16) if operand.startswith("0x") else int(operand)
            if idc.get_segm_name(addr):
                return f"0x{addr:X}"
        except ValueError:
            pass
    
    operand_ea = idc.get_operand_value(instr_addr, 1)
    if operand_ea and idc.get_segm_name(operand_ea):
        symbolic_name = idc.get_name(operand_ea, idaapi.GN_VISIBLE)
        if symbolic_name:
            return f"{symbolic_name} (0x{operand_ea:X})"
        return f"0x{operand_ea:X}"
    return None

def rename_func(ea, name):
    desired_name = name
    attempt = 0
    while not idc.set_name(ea, desired_name, idc.SN_AUTO | idc.SN_NOWARN):
        attempt += 1
        desired_name = f"{name}_{attempt}"
        if attempt > 100:
            return False
    print(f"INFO: Renamed {ea:X} to {desired_name}")
    return True

def check_exclusions(tbl, n):
    return not any(sub in n for sub in tbl)

def construct_new_func_name(name, prefix, suffix):
    return f"{prefix}{name}{suffix}"

def rename_functions_with_prefix(prefix):
    renamed_count = 0
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        if func_name.startswith(prefix):
            new_name = func_name[len(prefix):]
            if rename_func(func_ea, new_name):
                print(f"INFO: Renamed function at 0x{func_ea:X} from {func_name} to {new_name}")
                renamed_count += 1
            else:
                print(f"ERR: Failed to rename function at 0x{func_ea:X} from {func_name} to {new_name}")
    
    print(f"INFO: Total functions renamed: {renamed_count}")


analyse_calls("REPLACE_ME")


# LemonHaze - 2025
from .config import *
from .tracking import *
import idautils
import ida_funcs
import idaapi
import idc
import ida_name
import ida_kernwin
import ida_hexrays

ACTION_RECURSIVE_EXTRACT = "lemonutils:recursive_extract"

def recursive_extract():
    start_ea = idc.here()

    if not ida_funcs.get_func(start_ea):
        print(f"Address {hex(start_ea)} is not within a function.")
        return
        
    skip = ida_kernwin.ask_yn(0, "Skip already processed functions?")
        
    ft = FunctionTracker()
    metadata = []
    to_remove = []
    
    
    # Collect all funcs and generate metadata
    all_called_funcs = collect_recursive_calls(start_ea, reex_skip_imports, reex_skip_thunks)
    for func in all_called_funcs:
        hash_value = ft.process_func(func)
        curr_hash = ft.get_hash(func)
        
        if skip == True and curr_hash == hash_value and curr_hash:
            to_remove.append(func)
        else:
            metadata.append(ft.generate_metadata_cmt(func, True))

    for rm in to_remove:
        print(f"Skipping 0x{rm:X}")
        all_called_funcs.remove(rm)

    print(f"Collected funcs {hex(start_ea)} (imports {'skipped' if reex_skip_imports else 'included'}, thunks {'skipped' if reex_skip_thunks else 'included'}):")
    for func in sorted(all_called_funcs):
        print(f" - {get_demangled_name(func)} at {hex(func)}")

    output_file = ida_kernwin.ask_file(1, "*.c", "Select Output File")
    if not output_file:
        return
    ida_hexrays.decompile_many(output_file, list(all_called_funcs), 0)
    
    # Write out metadata
    with open(output_file, "a") as f:
        for data in metadata:
            f.write(data + "\n")


#####################################

class RecursiveExtractFuncsHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        recursive_extract()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def register_recursive_extract():
    idaapi.register_action(
        idaapi.action_desc_t(
            ACTION_RECURSIVE_EXTRACT,
            "Recursively extract functions",
            RecursiveExtractFuncsHandler(),
            None
        )
    )
    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/Export/",
        ACTION_RECURSIVE_EXTRACT,
        ida_kernwin.SETMENU_APP
    )

def unregister_recursive_extract():
    ida_kernwin.unregister_action(ACTION_RECURSIVE_EXTRACT)
# LemonHaze - 2025
from .config import *
from .tracking import *
import idautils
import ida_funcs
import idaapi
import idc
import ida_name
import ida_kernwin

ACTION_RECURSIVE_EXTRACT = "lemonutils:recursive_extract"

def recursive_extract():
    start_ea = idc.here()

    if not ida_funcs.get_func(start_ea):
        print(f"Address {hex(start_ea)} is not within a function.")
        return

    all_called_funcs = collect_recursive_calls(start_ea, reex_skip_imports, reex_skip_thunks)

    print(f"Collected funcs {hex(start_ea)} (imports {'skipped' if reex_skip_imports else 'included'}, thunks {'skipped' if reex_skip_thunks else 'included'}):")
    for func in sorted(all_called_funcs):
        print(f" - {get_demangled_name(func)} at {hex(func)}")

    output_file = ida_kernwin.ask_file(1, "*.c", "Select Output File")
    if not output_file:
        return
    idaapi.decompile_many(output_file, list(all_called_funcs), 0)


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
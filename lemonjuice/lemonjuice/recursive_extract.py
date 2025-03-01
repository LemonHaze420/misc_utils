# LemonHaze - 2025
from .config import *
import idautils
import ida_funcs
import idaapi
import idc
import ida_name
import ida_kernwin

ACTION_RECURSIVE_EXTRACT = "lemonutils:recursive_extract"

def is_imported_function(ea):
    name = idc.get_name(ea)
    if not name:
        return False
    flags = idc.get_segm_attr(ea, idc.SEGATTR_TYPE)
    return flags == idc.SEG_XTRN

def is_thunk_function(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        return False
    return func.flags & ida_funcs.FUNC_THUNK != 0

def get_called_functions(func_ea, reex_skip_imports=False, reex_skip_thunks=False):
    called_funcs = set()
    for head in idautils.FuncItems(func_ea):
        if idc.print_insn_mnem(head) in {"call"}:
            target = idc.get_operand_value(head, 0)
            if ida_funcs.get_func(target):
                if reex_skip_imports and is_imported_function(target):
                    continue
                if reex_skip_thunks and is_thunk_function(target):
                    continue
                called_funcs.add(target)
    return called_funcs

def collect_recursive_calls(func_ea, visited=None, reex_skip_imports=False, reex_skip_thunks=False):
    if visited is None:
        visited = set()
    if func_ea in visited:
        return set()
    visited.add(func_ea)
    called_funcs = get_called_functions(func_ea, reex_skip_imports, reex_skip_thunks)
    all_called_funcs = set(called_funcs)
    for called_func in called_funcs:
        all_called_funcs.update(collect_recursive_calls(called_func, visited, reex_skip_imports, reex_skip_thunks))

    return all_called_funcs

def get_demangled_name(ea):
    name = idc.get_name(ea)
    if not name:
        return "<no_name>"

    demangled = ida_name.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    return demangled if demangled else name

def recursive_extract():
    start_ea = idc.here()

    if not ida_funcs.get_func(start_ea):
        print(f"Address {hex(start_ea)} is not within a function.")
        return

    all_called_funcs = collect_recursive_calls(start_ea, reex_skip_imports=reex_skip_imports, reex_skip_thunks=reex_skip_thunks)

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
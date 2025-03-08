from .config import *
from .tracking import *
import idaapi
import ida_kernwin
import idc
import idautils
import os
import re
from tkinter import Tk
from tkinter.filedialog import askdirectory

ACTION_EXPORT_NAMESPACE_FUNCTIONS = "lemonutils:export_namespace_functions"


def write_functions_to_directory():
    name = ida_kernwin.ask_str("std", ida_kernwin.HIST_IDENT, "Enter function name prefix:")
    if not name:
        return
    
    Tk().withdraw()
    output_dir = askdirectory(title="Select Output Directory")
    if not output_dir:
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    ft = FunctionTracker()
    
    header_filename = f"{name}.h"
    source_filepath = os.path.join(output_dir, f"{name}.c")
    header_filepath = os.path.join(output_dir, header_filename)
    
    with open(source_filepath, "w") as source_file, open(header_filepath, "w") as header_file:
        source_file.write(f"#include \"{header_filename}\"\n\n")
    
        mname=f"_{name.upper()}_H_"
        header_file.write(f"#ifndef {mname}\n")
        header_file.write(f"#define {mname}\n\n")
        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)
            if not func_name.startswith(name):
                continue
            
            hash_value = ft.process_func(func_ea)
            pseudocode = idaapi.decompile(func_ea)
            if not pseudocode:
                pseudocode = f"// Failed to decompile {func_name}"
            
            source_file.write(f"// @{ft.get_flag(func_ea, 'status')} - {hash_value}\n")
            source_file.write(f"{str(pseudocode)}\n\n")
            
            func_decl = get_func_decl(func_ea)
            if func_decl:
                header_file.write(f"{func_decl} \n")
        header_file.write(f"\n#endif")
        
    print(f"Functions written to {output_dir}")

class ExportNamespaceFunctionsHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        write_functions_to_directory()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def register_export_namespace_functions():
    idaapi.register_action(
        idaapi.action_desc_t(
            ACTION_EXPORT_NAMESPACE_FUNCTIONS,
            "Export Namespace Functions",
            ExportNamespaceFunctionsHandler(),
            None
        )
    )
    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/Export/",
        ACTION_EXPORT_NAMESPACE_FUNCTIONS,
        ida_kernwin.SETMENU_APP
    )


def unregister_export_namespace_functions():
    ida_kernwin.unregister_action(ACTION_EXPORT_NAMESPACE_FUNCTIONS)

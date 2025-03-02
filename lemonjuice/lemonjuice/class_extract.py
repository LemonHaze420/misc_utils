# LemonHaze - 2025
from .config import *
import os
import idc
import idaapi
import idautils
import ida_struct
import ida_typeinf
import ida_hexrays
import ida_kernwin
import datetime

ACTION_CLASS_EXTRACT = "lemonutils:class_extract"

def get_struct_def(name):
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, name):
        flags = ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_SEMI
        flags |= ida_typeinf.PRTYPE_METHODS                  
        flags |= ida_typeinf.PRTYPE_CPP
        return tif._print(tif.get_type_name(), flags)
    return None

def collect_dependencies_recursive(struct_name, collected=None):
    if collected is None:
        collected = set()
    sid = idc.get_struc_id(struct_name)
    if sid == idaapi.BADADDR:
        raise ValueError(f"Struct '{struct_name}' not found")
        
    if struct_name in collected:
        return collected

    collected.add(struct_name)
    s = ida_struct.get_struc(sid)

    offset = 0
    while offset < ida_struct.get_struc_size(s):
        member = ida_struct.get_member(s, offset)
        if not member:
            offset += 1
            continue

        mti = ida_typeinf.tinfo_t()
        if ida_struct.get_member_tinfo(mti, member):
            if mti.is_ptr():
                mti = mti.get_pointed_object()
            if mti.is_struct():
                nested_name = mti.get_type_name()
                if nested_name and nested_name not in collected:
                    collect_dependencies_recursive(nested_name, collected)

        offset += ida_struct.get_member_size(member)
    return collected

def generate_struct_header(struct_name, output_dir):
    sid = idc.get_struc_id(struct_name)
    if sid == idaapi.BADADDR:
        return

    san_name = struct_name.replace(':', '_')            # sanitise the name
    path = os.path.join(output_dir, f"{san_name}.h")
    with open(path, "w") as f:
        f.write(f"#pragma once\n\n")
        s = ida_struct.get_struc(sid)
        f.write(f"\n{get_struct_def(struct_name)}\n")
    print(f"Written {path}")

def collect_methods_for_struct(struct_name):
    methods = []
    prefix = f"{struct_name}::"
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if name.startswith(prefix):
            methods.append((ea, name))
    return methods

def decompile_function(ea):
    cfunc = ida_hexrays.decompile(ea)
    if not cfunc:
        return None
    return str(cfunc)

def generate_struct_cpp(struct_name, methods, output_dir):
    path = os.path.join(output_dir, f"{struct_name}.cpp")
    with open(path, "w") as f:
        f.write(f'#include "{struct_name}.h"\n\n')
        for ea, name in methods:
            try:
                decompiled = decompile_function(ea)
                if decompiled:
                    f.write(f"// @exported {name} - {datetime.datetime.now()}\n")
                    f.write(decompiled)
                    f.write("\n\n")
                else:
                    f.write(f"// Failed to decompile {name}\n")
            except Exception as ex:
                f.write(f"// Exception while decompiling {name}\n")

    print(f"Written {path}")

def ask_user():
    output_dir = ida_kernwin.ask_str("", 0, "Select output directory")
    if not output_dir:
        return None, None

    struct_name = ida_kernwin.ask_str("", 0, "Struct name:")
    if not struct_name:
        return None, None
    
    return output_dir, struct_name, ida_kernwin.ask_yn(0, "Recursive struct export?")

def extract_class():
    output_dir, struct_name, recursive = ask_user()
    if not output_dir or not struct_name:
        return

    os.makedirs(output_dir, exist_ok=True)

    if recursive == ida_kernwin.ASKBTN_YES:
        dependencies = collect_dependencies_recursive(struct_name)
        for dep in dependencies:
            generate_struct_header(dep, output_dir)

    generate_struct_header(struct_name, output_dir)
    methods = collect_methods_for_struct(struct_name)
    if methods:
        generate_struct_cpp(struct_name, methods, output_dir)

    print(f"Exported '{struct_name}'")


#####################################

class ExtractClassHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        extract_class()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def register_class_extract():
    idaapi.register_action(
        idaapi.action_desc_t(
            ACTION_CLASS_EXTRACT,
            "Extract class",
            ExtractClassHandler(),
            None
        )
    )
    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/Export/",
        ACTION_CLASS_EXTRACT,
        ida_kernwin.SETMENU_APP
    )

def unregister_class_extract():
    ida_kernwin.unregister_action(ACTION_CLASS_EXTRACT)
# LemonHaze - 2025
from .config import *
import os
import idc
import idaapi
import idautils
import ida_typeinf
import ida_hexrays
import ida_kernwin
import ida_funcs
import idautils

import datetime

ACTION_MISC_UTILS = "lemonutils:misc_utils"

def get_calling_functions(target_ea):
    callers = set()
    for xref in idautils.CodeRefsTo(target_ea, 0):
        func = idaapi.get_func(xref)
        if func:
            callers.add(func.start_ea)
    return list(callers)

class decompile_callers_of_selected_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        out_path = ida_kernwin.ask_file(
            True,
            None,
            "Please specify the output file name"
        )
        if not out_path:
            return 0

        eas = []
        for pfn_idx in ctx.chooser_selection:
            pfn = ida_funcs.getn_func(pfn_idx)
            if not pfn:
                continue
            callers = get_calling_functions(pfn.start_ea)
            eas.extend(callers)

        if not eas:
            ida_kernwin.info("No calling functions found.")
            return 0

        eas = list(set(eas))

        ida_kernwin.msg(f"Decompiling {len(eas)} functions...\n")
        ida_hexrays.decompile_many(out_path, eas, 0)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_FUNCS:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class popup_hooks_t(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, w, popup):
        if ida_kernwin.get_widget_type(w) == ida_kernwin.BWN_FUNCS:
            ida_kernwin.attach_action_to_popup(w, popup, ACTION_MISC_UTILS, None)

hooks = popup_hooks_t()
hooks.hook()

#####################################

def register_misc_utils():
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_MISC_UTILS,
            "Decompile all callers of selected function",
            decompile_callers_of_selected_t(),
            "Ctrl+Alt+F5"
        )
    )
    

def unregister_misc_utils():
    ida_kernwin.unregister_action(ACTION_MISC_UTILS)

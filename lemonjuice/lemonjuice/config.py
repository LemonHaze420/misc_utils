import ida_funcs
import ida_typeinf
import idc
import idaapi
import idautils

############################################################
# Global Configuration

# tracker config
func_tracker_file = "processed_functions.json"

# llm_index_and_query options
embed_model_name = "mxbai-embed-large"
reasoning_model_name = "DeepSeek-Coder:6.7b"
llm_util_include_pseudo = False


# recursive extract options
reex_skip_imports = True
reex_skip_thunks = True





############################################################
# General Helpers

def get_func_decl(ea, flags=idaapi.PRTYPE_1LINE|idaapi.PRTYPE_SEMI|idaapi.PRTYPE_CPP):
    tinfo_tuple = idc.get_tinfo(ea)
    if not tinfo_tuple or not isinstance(tinfo_tuple, tuple) or not tinfo_tuple[0]:
        return None

    tif = tinfo_tuple[0]
    decl = ida_typeinf.print_type(ea, flags)
    return decl

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

def get_called_functions(func_ea, skip_imports=False, skip_thunks=False):
    called_funcs = set()
    for head in idautils.FuncItems(func_ea):
        if idc.print_insn_mnem(head) in {"call"}:
            target = idc.get_operand_value(head, 0)
            if ida_funcs.get_func(target):
                if skip_imports and is_imported_function(target):
                    continue
                if skip_thunks and is_thunk_function(target):
                    continue
                called_funcs.add(target)
    return called_funcs

def get_demangled_name(ea):
    name = idc.get_name(ea)
    if not name:
        return "<no_name>"

    demangled = ida_name.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    return demangled if demangled else name
    
    
    

def collect_recursive_calls(func_ea, visited=None, skip_imports=False, skip_thunks=False):
    if visited is None:
        visited = set()
    if func_ea in visited:
        return set()
    visited.add(func_ea)
    called_funcs = get_called_functions(func_ea, skip_imports, skip_thunks)
    all_called_funcs = set(called_funcs)
    for called_func in called_funcs:
        all_called_funcs.update(collect_recursive_calls(called_func, visited, skip_imports, skip_thunks))

    return all_called_funcs
    

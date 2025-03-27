# LemonHaze - 2025

import idaapi

relevant_funcs = [""]                   # replaceme
helper_name = ""                        # replaceme
const_val_type = idaapi.BTMT_SIGNED     # replaceme


class ExpressionHelper(idaapi.ctree_visitor_t):
    def __init__(self):
        super().__init__(idaapi.CV_FAST)

    def visit_expr(self, expr):
        if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_obj:
            func_name = idaapi.get_name(expr.x.obj_ea)
            if func_name in relevant_funcs and len(expr.a) == 1:
                carg = expr.a[0]
                arg = carg.cexpr
                if arg.op == idaapi.cot_num:
                    const_val = arg.numval()
                    
                    
                    new_value = 1337 # replaceme
                    
                    print(f"[+] Rewriting {func_name}({const_val}) -> {func_name}({helper_name}({new_value}))")

                    new_expr = idaapi.cexpr_t()
                    new_expr.op = idaapi.cot_num
                    new_expr.n = idaapi.cnumber_t()
                    new_expr.n._value = new_value
                    new_expr.n.size = 2
                    
                    new_expr.type = idaapi.tinfo_t()
                    new_expr.type.create_simple_type(const_val_type)

                    expr.a.clear()
                    expr.a.push_back()
                    
                    to_orig_func = idaapi.cexpr_t()
                    to_orig_func.op = idaapi.cot_helper
                    to_orig_func.helper = helper_name

                    to_helper_call = idaapi.cexpr_t()
                    to_helper_call.op = idaapi.cot_call
                    to_helper_call.x = to_orig_func
                    to_helper_call.a = idaapi.carglist_t()
                    to_helper_call.a.push_back(idaapi.carg_t())
                    to_helper_call.a[0].replace_by(new_expr)

                    expr.a[0].replace_by(to_helper_call)
                    idaapi.set_cmt(expr.ea, f"{helper_name}({new_value}) from {const_val}", False)
                    return 1
        return 0

class ExpressionVisitorHook(idaapi.Hexrays_Hooks):
    def func_printed(self, cfunc):
        visitor = ExpressionHelper()
        if visitor.apply_to(cfunc.body, None):
            cfunc.save_user_labels()
            cfunc.refresh_func_ctext()
            return 1
        return 0

try:
    hook.unhook()
except:
    pass

hook = ExpressionVisitorHook()
hook.hook()

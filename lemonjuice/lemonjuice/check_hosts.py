# LemonHaze - 2025
from .config import *

import re
import requests
from urllib.parse import urlparse

import idaapi
import idautils
import idc
import ida_kernwin

import ida_funcs
import ida_name
import ida_kernwin
import ida_hexrays


ACTION_CHECK_HOSTS = "lemonutils:check_hosts"

# Configure
TARGET_FUNCS = [
    "curl_easy_setopt",
    "connect",
    "inet_addr",
    "getaddrinfo",
    "curl_easy_perform",
]

def extract_domain(value):
    try:
        parsed = urlparse(value)
        if parsed.hostname:
            return parsed.hostname
        return value.strip()
    except Exception:
        return value.strip()

def urlscan_query(domain):
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if not results:
                return "No known scans"
            for r in results[:1]:
                verdicts = r.get("verdicts", {})
                if verdicts:
                    malicious = verdicts.get("overall", {}).get("malicious", False)
                    score = "MALICIOUS" if malicious else "No verdict"
                    return f"{score} — {r.get('page', {}).get('url', '')}"
            return "No verdicts found"
        else:
            return f"Error: {resp.status_code}"
    except Exception as e:
        return f"Failed to query urlscan.io: {e}"

def handle_result(result):
    func_name, value, call_ea, func_start = result
#    print(f"\n[Handler] Function: {func_name}")
#    print(f"          String: \"{value}\"")
#    print(f"          Call EA: 0x{call_ea:X}")
#    print(f"          Function EA: 0x{func_start:X}")
    domain = extract_domain(value)
    if not domain:
        print("Potentially malformed URL")
        return
    verdict = urlscan_query(domain)
    print(f"URLScan verdict: {verdict}")


#####################################################################
CURLOPT_URL = 10002
def looks_like_network_target(s):
    if not s:
        return False
    return bool(re.search(r"https?://|ftp://|[\w\.-]+\.\w+|(?:\d{1,3}\.){3}\d{1,3}", s))

def is_hexrays_available():
    try:
        return idaapi.init_hexrays_plugin()
    except Exception:
        return False
        
def get_indirect_string(ptr_addr):
    if not idc.is_loaded(ptr_addr):
        return None
    ptr = idc.get_qword(ptr_addr) if idaapi.get_inf_structure().is_64bit() else idc.get_wide_dword(ptr_addr)
    if not idc.is_loaded(ptr):
        return None
    s = idc.get_strlit_contents(ptr, -1, idc.STRTYPE_C)
    return s.decode() if s else None
    
# @todo: folded strings?
def resolve_to_string(expr, cfunc, depth=0):
    if expr is None or depth > 5:
        return None

    if expr.op == idaapi.cot_obj:
        ea = expr.obj_ea

        s = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
        if s:
            return s.decode()
        s = get_indirect_string(ea)
        if s:
            return s
    elif expr.op in (idaapi.cot_ref, idaapi.cot_cast):
        return resolve_to_string(expr.x, cfunc, depth + 1)
    elif expr.op == idaapi.cot_var:
        v_idx = expr.v.idx
        for stmt in cfunc.body.cblock:
            if stmt.op == idaapi.cit_expr and stmt.e.op == idaapi.cot_asg:
                lhs = stmt.e.x
                rhs = stmt.e.y
                if lhs.op == idaapi.cot_var and lhs.v.idx == v_idx:
                    return resolve_to_string(rhs, cfunc, depth + 1)

    return None
def visit_expr(expr, cfunc):
    if expr.op != idaapi.cot_call:
        return None
    called = expr.x
    func_name = None
    if called.op == idaapi.cot_obj:
        func_name = idaapi.get_func_name(called.obj_ea)
    elif called.op == idaapi.cot_helper:
        func_name = called.helper
    if not func_name or func_name not in TARGET_FUNCS:
        return None
    args = expr.a
    if not args:
        return None
    if func_name == "curl_easy_setopt":
        if len(args) >= 3:
            opt_arg = args[1]
            if opt_arg.op == idaapi.cot_num and opt_arg.numval() == CURLOPT_URL:
                url = resolve_to_string(args[2], cfunc)
                if url and looks_like_network_target(url):
                    return (func_name, url, expr.ea, cfunc.entry_ea)
    else:
        for arg in args:
            s = resolve_to_string(arg, cfunc)
            if s and looks_like_network_target(s):
                return (func_name, s, expr.ea, cfunc.entry_ea)
    return None

def analyse_caller_function(func_ea):
    try:
        cfunc = idaapi.decompile(func_ea)
    except Exception:
        return []
    class NetworkCallVisitor(idaapi.ctree_visitor_t):
        def __init__(self, cfunc):
            super().__init__(idaapi.CV_FAST)
            self.cfunc = cfunc
            self.matches = []
        def visit_expr(self, expr):
            result = visit_expr(expr, self.cfunc)
            if result:
                self.matches.append(result)
            return 0
    visitor = NetworkCallVisitor(cfunc)
    visitor.apply_to(cfunc.body, None)
    return visitor.matches

def get_func_eas_by_name():
    eas = []
    for name in TARGET_FUNCS:
        ea = idc.get_name_ea_simple(name)
        if ea != idc.BADADDR:
            eas.append((name, ea))
    return eas


def prompt_user_and_handle(results):
    for r in results:
        func_name, value, call_ea, _ = r
        prompt = f"\nHandle this result?\n  Function: {func_name}\n  Value: \"{value}\"\n  Address: 0x{call_ea:X}\n[Y/n] "
        resp = ida_kernwin.ask_str("y", 0, prompt)
        if resp and resp.strip().lower().startswith("y"):
            handle_result(r)

def check_hosts():
    if not is_hexrays_available():
        return
    func_eas = get_func_eas_by_name()
    if not func_eas:
        print("No target functions found.")
        return
    all_results = []
    seen_funcs = set()
    for fname, ea in func_eas:
        for xref in idautils.CodeRefsTo(ea, 0):
            func = idaapi.get_func(xref)
            if func and func.start_ea not in seen_funcs:
                seen_funcs.add(func.start_ea)
                matches = analyse_caller_function(func.start_ea)
                all_results.extend(matches)
    if not all_results:
        print("No results found.")
        return


    for i, (fname, value, call_ea, func_ea) in enumerate(all_results):
        print(f"[{i+1}] {fname} -> \"{value}\" at 0x{call_ea:X} (in function 0x{func_ea:X})")

    prompt_user_and_handle(all_results)


#####################################

class CheckHostsHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        check_hosts()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def register_check_hosts():
    idaapi.register_action(
        idaapi.action_desc_t(
            ACTION_CHECK_HOSTS,
            "Check Hosts",
            CheckHostsHandler(),
            None
        )
    )
    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/Misc/",
        ACTION_CHECK_HOSTS,
        ida_kernwin.SETMENU_APP
    )
def unregister_check_hosts():
    ida_kernwin.unregister_action(ACTION_CHECK_HOSTS)
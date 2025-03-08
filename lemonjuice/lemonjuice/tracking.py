# LemonHaze - 2025
from .config import *
import idaapi
import idautils
import idc
import json
import hashlib
import os

TRACKING_FILE = os.path.join(os.path.dirname(idaapi.get_path(idaapi.PATH_TYPE_IDB)), func_tracker_file)

class FunctionTracker:
    def __init__(self):
        self.tracking_file = TRACKING_FILE
        self._load_tracking_data()

    def _load_tracking_data(self):
        if os.path.exists(self.tracking_file):
            with open(self.tracking_file, "r") as f:
                try:
                    self.tracking_data = json.load(f)
                except json.JSONDecodeError:
                    self.tracking_data = {}
        else:
            self.tracking_data = {}

    def _save_tracking_data(self):
        with open(self.tracking_file, "w") as f:
            json.dump(self.tracking_data, f, indent=4)

    def _get_function_pseudocode_hash(self, ea):
        if not idaapi.init_hexrays_plugin():
            return None
        try:
            cfunc = idaapi.decompile(ea)
            if cfunc:
                pseudocode = "\n".join([line.line for line in cfunc.get_pseudocode()])
                return hashlib.sha256(pseudocode.encode()).hexdigest()
        except idaapi.DecompilationFailure:
            return None
        return None

    def process_func(self, func):
        if isinstance(func, str):
            ea = idc.get_name_ea_simple(func)
        else:
            ea = func

        if ea == idc.BADADDR or ea == 0:
            return None

        func_hash = self._get_function_pseudocode_hash(ea)
        if not func_hash:
            return None

        if hex(ea) not in self.tracking_data:
            self.tracking_data[hex(ea)] = {"hash": func_hash, "flags": {"status": "todo"}}
        else:
            self.tracking_data[hex(ea)]["hash"] = func_hash
        self._save_tracking_data()
        return func_hash

    def get_hash(self, func):
        if isinstance(func, str):
            ea = idc.get_name_ea_simple(func)
        else:
            ea = func

        if ea == idc.BADADDR or ea == 0:
            return None

        return self.tracking_data.get(hex(ea), {}).get("hash")

    def get_processed(self):
        return [int(ea, 16) for ea in self.tracking_data.keys()]

    def get_unprocessed(self):
        all_funcs = set(idautils.Functions())
        processed_funcs = set(self.get_processed())
        return list(all_funcs - processed_funcs)

    def set_flag(self, func, flag_name, flag_value):
        if isinstance(func, str):
            ea = idc.get_name_ea_simple(func)
        else:
            ea = func

        if ea == idc.BADADDR or ea == 0:
            return False

        entry = self.tracking_data.get(hex(ea), {})
        if "flags" not in entry:
            entry["flags"] = {}
        entry["flags"][flag_name] = flag_value
        self.tracking_data[hex(ea)] = entry
        self._save_tracking_data()
        return True

    def get_flag(self, func, flag_name):
        if isinstance(func, str):
            ea = idc.get_name_ea_simple(func)
        else:
            ea = func

        if ea == idc.BADADDR or ea == 0:
            return None

        return self.tracking_data.get(hex(ea), {}).get("flags", {}).get(flag_name)

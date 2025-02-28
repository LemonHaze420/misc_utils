# LemonHaze - 2025
import os
import subprocess
import idc
import ida_funcs
import ida_kernwin
import ida_netnode
import idaapi
import idautils
import ida_hexrays
from lemonjuice.config import *
from lemonjuice.llm_index_and_query import register_llm_util, unregister_llm_util
from lemonjuice.ns_extract import register_export_namespace_functions, unregister_export_namespace_functions
from PyQt5.QtWidgets import QDialog, QPushButton, QCheckBox, QTextEdit, QVBoxLayout, QWidget
from PyQt5.QtCore import QThread, pyqtSignal

NODE_NAME = "$lemonutils_settings"
NN_COMPILER_PATH = 0
NN_PROJECT_PATH = 1
NN_COMPILER_ARGS = 2

ACTION_NEW_COMPILER = "lemonutils:select_compiler"
ACTION_NEW_PROJECT = "lemonutils:select_project"
ACTION_NEW_COMPILER_ARGS = "lemonutils:select_compiler_args"
ACTION_SHOW_WINDOW = "lemonutils:show_window"
ACTION_SETTINGS = "lemonutils:show_settings"

temp_c_file="main.c"            # @todo: should be an option in settings
including_called_funcs=True     # @todo: should be an option in settings
append=False                    # @todo: will be swapped for when compilations are successful

disassembler="replace-me"
disassembler_args="/DISASM "
compiled_binary_name="replace-me"

#@todo: this needs fixing so we don't specify insns
def get_called_functions(func_ea):
    calls = set()
    for head in idautils.FuncItems(func_ea):
        if idc.print_insn_mnem(head) in ["call"]:
            callee = idc.get_operand_value(head, 0)
            if idaapi.get_func(callee):
                calls.add(callee)
    return calls

def write_c_file(path, functions):
    with open(f"{path}\\{temp_c_file}", "a" if append else "w") as f:
        for func in functions:
            f.write(func + "\n\n")

def compile_c_file(compiler, compiler_args):
    try:
        result = subprocess.run([compiler, compiler_args, ""], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stdout
    except Exception as e:
        return False, str(e)
        
def disassemble_compiled_func(func, disassembler):
    try:
        result = subprocess.run([disassembler, disassembler_args, compiled_binary_name], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode == 0:
            return True, extract_disassembly(result.stdout, func)
        else:
            return False, result.stdout
    except Exception as e:
        return False, str(e)
        
def extract_disassembly(disasm_output: str, function_name: str) -> str:
    function_labels = [f"{function_name}:", f"?{function_name}"]
    found = False
    extracted_lines = []
    for line in disasm_output.splitlines():
        line = line.rstrip()
        if line.startswith(tuple( function_labels)):
            found = True
            extracted_lines.append(line)
            continue
        if found:
            if line.startswith(" "):
                extracted_lines.append(line)
            else:
                break
    return "\n".join(extracted_lines)
    
    
    
def get_pseudocode(ea):    
    pseudocode = ida_hexrays.decompile(ea)
    if not pseudocode:
        print(f"[ERROR] Failed to decompile function at {hex(ea)}")
        return None    
    return str(pseudocode)

def get_current_function_ea():
    ea = idc.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if func:
        return func.start_ea
    else:
        return None

def compile_funcs(functions, path, compiler, compiler_args):    
    write_c_file(path, functions)
    success, error_msg = compile_c_file(compiler, compiler_args)
    return success, error_msg
    
def extract_funcs(function_ea):
    extracted_functions = []
    if including_called_funcs:
        called_functions = get_called_functions(function_ea)    
        for func_ea in called_functions:
            func_name = idc.get_func_name(func_ea)
            pseudocode = get_pseudocode(func_ea)
            if not pseudocode:
                continue
            extracted_functions.append(pseudocode)

    extracted_functions.append(get_pseudocode(function_ea))     
    if not extracted_functions:
        print("[INFO] No functions extracted.")
        return
    return extracted_functions


def get_project_path():
    node = ida_netnode.netnode(NODE_NAME)
    stored_path = node.supval(NN_PROJECT_PATH)
    if stored_path:
        return stored_path.decode("utf-8") if isinstance(stored_path, bytes) else stored_path
    return None
    
def get_compiler_args():
    node = ida_netnode.netnode(NODE_NAME)
    stored_path = node.supval(NN_COMPILER_ARGS)
    if stored_path:
        return stored_path.decode("utf-8") if isinstance(stored_path, bytes) else stored_path
    return ""

def save_compiler_args(path):
    node = ida_netnode.netnode(NODE_NAME, 0, True)
    node.supset(NN_COMPILER_ARGS, path)
    
def ask_for_compiler_args():
    default=""
    temp_stored = get_compiler_args()
    if temp_stored:
        default = temp_stored
    path = ida_kernwin.ask_str(default, 1, "Enter new compiler args:")
    if path:
        save_compiler_args(path)
        ida_kernwin.info(f"Compiler args set to: {path}")
            
def save_project_path(path):
    node = ida_netnode.netnode(NODE_NAME, 0, True)
    node.supset(NN_PROJECT_PATH, path)
    
def ask_for_project_path():
    default=""
    temp_stored = get_project_path()
    if temp_stored:
        default = temp_stored
    path = ida_kernwin.ask_str(default, 1, "Select project path:")
    if path and os.path.isdir(path):
        save_project_path(path)
        ida_kernwin.info(f"Project path set to: {path}")
    else:
        ida_kernwin.warning("Invalid path selected.")
        
def demand_project_path():
    stored_path = get_project_path()
    if stored_path and os.path.isdir(stored_path):
        return stored_path
    else:
        return ask_for_project_path()
        
def get_compiler_path():
    node = ida_netnode.netnode(NODE_NAME)
    stored_path = node.supval(NN_COMPILER_PATH)
    if stored_path:
        return stored_path.decode("utf-8") if isinstance(stored_path, bytes) else stored_path
    return None

def save_compiler_path(path):
    node = ida_netnode.netnode(NODE_NAME, 0, True)
    node.supset(NN_COMPILER_PATH, path)

def ask_for_compiler_path():
    default=""
    temp_stored = get_compiler_path()
    if temp_stored:
        default = temp_stored
    path = ida_kernwin.ask_str(default, 1, "Select compiler path:")
    if path and os.path.isfile(path):
        save_compiler_path(path)
        ida_kernwin.info(f"Compiler path set to: {path}")
    else:
        ida_kernwin.warning("Invalid path selected.")

def demand_compiler_path():
    stored_path = get_compiler_path()
    if stored_path and os.path.isfile(stored_path):
        return stored_path
    else:
        return ask_for_compiler_path()
        
class CompilationWorker(QThread):
    output_signal = pyqtSignal(str)
    
    def __init__(self, compiler_path, compiler_args, project_path, funcs, func_name):
        super().__init__()
        self.compiler_path = compiler_path
        self.compiler_args = compiler_args
        self.project_path = project_path
        self.funcs = funcs
        self.func_name = func_name
        self.compiled=False

    def run(self):
        if self.funcs and not self.compiled:
            success, output = compile_funcs(self.funcs, self.project_path, self.compiler_path, self.compiler_args)
            self.output_signal.emit(output)
            self.compiled = True
        else:
            self.output_signal.emit("No function detected")
            
        if self.compiled:
            success, output = disassemble_compiled_func(self.func_name, disassembler)
            self.output_signal.emit(output)

class CompilerOutputWindow(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.populate()

    def populate(self):
        layout = QVBoxLayout()

        self.textbox = QTextEdit()
        self.textbox.setReadOnly(True)

        compiler_path = demand_compiler_path()
        if not compiler_path:
            self.textbox.setText("No valid compiler path")
        else:
            project_path = demand_project_path()
            if not project_path:
                self.textbox.setText("Project path not valid")
            else:
                func = get_current_function_ea()
                funcs = extract_funcs(func)
                #eas = [func]
                # pseudocode = ida_hexrays.decompile(  )
                if funcs:
                    self.worker = CompilationWorker(compiler_path, get_compiler_args(), project_path, funcs, ida_funcs.get_func_name(func))
                    self.worker.output_signal.connect(self.update_text)
                    self.worker.start()
                    self.textbox.setText("Compiling...")

        layout.addWidget(self.textbox)
        widget = QWidget()
        widget.setLayout(layout)
        self.parent.setLayout(layout)

    def update_text(self, output):
        self.textbox.setText(output)

    def Show(self):
        return ida_kernwin.PluginForm.Show(
            self,
            "Compiler Output",
            options=ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WOPN_DP_RIGHT
        )
class SelectCompilerArgsActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ask_for_compiler_args()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class SelectCompilerActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ask_for_compiler_path()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class SelectProjectActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ask_for_project_path()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ShowCompilerOutputActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        compilerOutputWindow = CompilerOutputWindow()
        compilerOutputWindow.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
        
class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super(SettingsDialog, self).__init__(parent)
        self.setWindowTitle("Plugin Settings")

        layout = QVBoxLayout(self)        
        self.checkbox1 = QCheckBox("WIP")
        layout.addWidget(self.checkbox1)
"""
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_settings)
        layout.addWidget(self.save_button)
    def save_settings(self):
        self.accept()
"""
class SettingsActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        dlg = SettingsDialog()
        dlg.exec_()
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

def register_actions():
    action_desc1 = ida_kernwin.action_desc_t(
        ACTION_NEW_COMPILER,  
        "Select Compiler Path",
        SelectCompilerActionHandler(), 
        "",
        "Change the compiler path",  
        198  
    )

    action_desc2 = ida_kernwin.action_desc_t(
        ACTION_NEW_COMPILER_ARGS,  
        "Select Compiler Args",  
        SelectCompilerArgsActionHandler(), 
        "",
        "Change Compiler Args",  
        198  
    )    
    action_desc3 = ida_kernwin.action_desc_t(
        ACTION_NEW_PROJECT,  
        "Select Project Path",  
        SelectProjectActionHandler(), 
        "",
        "Change project path",  
        198  
    )

    action_desc5 = ida_kernwin.action_desc_t(
        ACTION_SETTINGS,
        "Settings",
        SettingsActionHandler(),
        "",
        "Configure plugin settings",
        198
    )  
    action_desc4 = ida_kernwin.action_desc_t(
        ACTION_SHOW_WINDOW,  
        "Compile current function",  
        ShowCompilerOutputActionHandler(), 
        "Ctrl+Alt+W",
        "Compiles the current function with the selected options",  
        199  
    )
    ida_kernwin.register_action(action_desc1)
    ida_kernwin.register_action(action_desc2)
    ida_kernwin.register_action(action_desc3)
    ida_kernwin.register_action(action_desc4)
    ida_kernwin.register_action(action_desc5)
    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/Compiler Utility/",
        ACTION_NEW_COMPILER,  
        ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/Compiler Utility/",
        ACTION_NEW_COMPILER_ARGS,  
        ida_kernwin.SETMENU_APP
    )      
    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/Compiler Utility/",
        ACTION_NEW_PROJECT,  
        ida_kernwin.SETMENU_APP
    )   
    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/Compiler Utility/",  
        ACTION_SETTINGS,  
        ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/Compiler Utility/",  
        ACTION_SHOW_WINDOW,  
        ida_kernwin.SETMENU_APP
    )
    
def unregister_actions():
    ida_kernwin.unregister_action(ACTION_NEW_COMPILER)
    ida_kernwin.unregister_action(ACTION_NEW_COMPILER_ARGS)
    ida_kernwin.unregister_action(ACTION_NEW_PROJECT)
    ida_kernwin.unregister_action(ACTION_SETTINGS)    
    ida_kernwin.unregister_action(ACTION_SHOW_WINDOW)

def init_plugin():
    unregister_llm_util()
    register_llm_util()
    
    unregister_actions()
    register_actions()
    
    unregister_export_namespace_functions()
    register_export_namespace_functions()


class lemonjuice(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "LemonJuice Plugin"
    help = "A set of utilities for IDA"
    wanted_name = "LemonJuice"
    wanted_hotkey = ""

    def init(self):
        init_plugin()
        return idaapi.PLUGIN_KEEP
    def run(self, arg):
        init_plugin()
        return idaapi.PLUGIN_OK()
        
def PLUGIN_ENTRY():
    return lemonjuice()

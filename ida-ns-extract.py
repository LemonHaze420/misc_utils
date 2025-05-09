# LemonHaze - 2024

import idaapi
import idautils
import idc
from tkinter import Tk
from tkinter.filedialog import askdirectory
import os
import re
import string


def write_functions_to_directory():
    Tk().withdraw()
    output_dir = askdirectory(title="Select Output Directory")
    
    if not output_dir:
        print("No directory selected. Operation canceled.")
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    special_mappings = {
        "Prefix_": "Prefix.c"
    }

    function_files = {}

    # match "e<4 uppercase letters>" pattern
    e_uppercase_pattern = re.compile(r"^e[A-Z]{4}")
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        if func_name.startswith("sub_"):
            continue
          
        output_file = None
        for prefix, filename in special_mappings.items():
            if func_name.startswith(prefix):
                output_file = os.path.join(output_dir, filename)
                break

        if output_file is None:
            if e_uppercase_pattern.match(func_name):
                prefix = func_name[:5]
                output_file = os.path.join(output_dir, f"{prefix}.c")
            elif not func_name[0].isalpha() or func_name.startswith("::"):
                output_file = os.path.join(output_dir, "functions.c")
            else:
                output_file = os.path.join(output_dir, "functions.c")

        if output_file not in function_files:
            function_files[output_file] = []

        function_files[output_file].append(func_ea)

    for output_file, functions in function_files.items():
        with open(output_file, "w", encoding="utf-8") as file:
            for func_ea in functions:
                func_name = idc.get_func_name(func_ea)
                try:
                    func_decompiled = idaapi.decompile(func_ea)
                    if func_decompiled:
                        file.write(f"{func_decompiled}\n")
                except Exception as e:
                    file.write(f"// Unable to include {func_name}\n")

    print(f"Functions written to {output_dir}")


write_functions_to_directory()

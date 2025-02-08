# LemonHaze - 2024
import json

with open("hooks.json", "r") as f:
    hooks = json.load(f)

with open("gen_hooks.h", "w") as f:
    f.write("#pragma once\n")
    f.write("#include <MinHook.h>\n\n")
    f.write("typedef struct {\n")
    f.write("    const char* name;\n")
    f.write("    uintptr_t address;\n")
    f.write("    void* hook;\n")
    f.write("    void* original;\n")
    f.write("} Hook;\n\n")
    #f.write("extern void* " + ";\nextern void* ".join(hooks.keys()) + ";\n\n")
    f.write("static Hook hooks[] = {\n")
    for func_name, addr in hooks.items():
        f.write(f'    {{ "{func_name}", {addr}, (void*)&{func_name}, NULL }},\n')
    f.write("};\n\n")
    f.write("#define HOOK_COUNT (sizeof(hooks) / sizeof(hooks[0]))\n")

print("gen_hooks.h generated.")

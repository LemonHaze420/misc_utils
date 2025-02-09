# LemonHaze - 2023

import idc
import idaapi
import idautils

target_ea = 0x0
relevant_insns=["call"]
max_num_args=4

def get_function_calls_via_pointer(func_ea):
    print(f"[ptr_analyse] Analyzing calls to func {hex(func_ea)}")

    # @todo: using a specific range and searching xrefs are useful
    for seg_ea in idautils.Segments():
        for head_ea in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
            if idc.print_insn_mnem(head_ea) in relevant_insns:
                insn = idautils.DecodeInstruction(head_ea)
                if not insn:
                    continue

                if insn.Op1.type == idaapi.o_mem or insn.Op1.type == idaapi.o_reg:
                    target = idc.get_operand_value(head_ea, 0)

                    if target == func_ea:
                        print(f"[ptr_analyse] Indirect call to {hex(func_ea)} found at {hex(head_ea)}")

                        print(f"[ptr_analyse]   Disassembly: {idc.generate_disasm_line(head_ea, 0)}")
                        args = []

                        func_type = idaapi.get_func_type(func_ea)
                        if func_type:
                            print(f"[ptr_analyse]   Function type: {func_type}")

                        for i in range(max_num_args):
                            arg = idc.get_arg_value(i)
                            if arg is not None:
                                args.append(arg)

                        print(f"[ptr_analyse]   Arguments: {args}")
                        print("[ptr_analyse] -" * 40)


get_function_calls_via_pointer(target_ea)

import idaapi
import idc
import idautils
import ida_kernwin
import ida_typeinf

class GapModifierHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        declaration = ida_kernwin.ask_str("", 0, "Enter member declaration (e.g., 'float the_member;')")
        if not declaration:
            return 1

        # Parse
        tinfo = idaapi.tinfo_t()
        name = idaapi.decl_t()
        if not ida_typeinf.parse_decl(tinfo, name, declaration, idaapi.PT_TYP):
            idaapi.warning("Invalid declaration!")
            return 1

        member_name = name.name
        member_size = tinfo.get_size()

        # Extract the struct name and offset from the clicked line
        line = idaapi.get_custom_viewer_curline(ctx.widget, True)
        if not line:
            return 1
        line = idaapi.tag_remove(line)
        if "*(" in line and "*)&" in line:
            parts = line.split('*)&')
            if len(parts) != 2:
                return 1
            _, struct_var_offset = parts
            parts = struct_var_offset.split('->')
            if len(parts) != 2:
                return 1
            struct_var, offset_str = parts
            offset = int(offset_str.split('[')[1].split(']')[0], 16)
        else:
            return 1

        # Determine the struct type from the variable
        struct_type = idaapi.get_type(idaapi.get_name_ea_simple(struct_var))
        if not struct_type:
            idaapi.warning("Cannot determine struct type from variable!")
            return 1

        sid = idaapi.get_struc_id(struct_type)
        if sid != idaapi.BADADDR:
            sptr = idaapi.get_struc(sid)
            member = idaapi.get_member(sptr, offset)
            if member:
                # Adjust the size of the gap
                gap_size = idaapi.get_member_size(member) - member_size
                idaapi.del_struc_member(sptr, offset)
                if gap_size > 0:
                    idaapi.add_struc_member(sptr, "gap{}".format(hex(offset + member_size)), offset + member_size, idaapi.FF_BYTE, None, gap_size)
                idaapi.add_struc_member(sptr, member_name, offset, tinfo, None, member_size)

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def add_menu_item():
    menu_item = "GapModifier:InsertMember"
    if idaapi.unregister_action(menu_item):
        idaapi.register_action(idaapi.action_desc_t(
            menu_item, 
            "Insert Struct Member", 
            GapModifierHandler(), 
            "", 
            "Inserts a member in the struct", 
            -1))
        idaapi.attach_action_to_popup(ctx.widget, None, menu_item)

idaapi.register_timer(1000, add_menu_item)  # Register after IDA starts up

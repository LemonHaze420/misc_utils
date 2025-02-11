'''
IDA 7.4+ Python 3 IDA Plugin for hexrays struct fixer uppering
Dedicated to Lemon Haze
SocraticBliss (R) + LemonHaze (c) >:(
'''
import re
import idaapi

from idaapi import stroff_flag, off_flag

class lemonyfresh_t(idaapi.plugin_t):
    flags         = idaapi.PLUGIN_PROC
    comment       = "Hexrays struct fixer upper"
    help          = "When life gives you lemons, don't make lemonade! Make life take the lemons back! Get mad! I don't want your damn lemons!"
    wanted_name   = "Lemonyfresh"
    wanted_hotkey = "Alt-F12"
    
    def init(self):
        # We only want to load the plugin if hexrays is available
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        else:
            '''
            # Register an action for right click events
            idaapi.install_hexrays_callback(right_click)
            desc = idaapi.action_desc_t()
            desc.name     = "lhz:InsertNewField"
            desc.label    = "Insert new field..."
            desc.owner    = self
            idaapi.register_action(desc)
            '''
            print("Hex-rays %s has been detected, %s is ready to use" % (idaapi.get_hexrays_version(), self.wanted_name))
            return idaapi.PLUGIN_KEEP
        
    
    def run(self, arg):
        view    = idaapi.get_current_viewer()
        psuedo  = idaapi.get_widget_vdui(view)
        
        # Continue if we are currently in a psuedocode window
        if psuedo:
            # Grab the current highlighted item in the window
            psuedo.get_current_item(idaapi.USE_KEYBOARD)
            
            # TODO: Local variable handling I guess?
            '''
            # Get our local variable
            local   = psuedo.item.get_lvar()
            if local:
                print("local var = %s" % local.name)
                
                # Get our existing struct
                if not local.tif.is_ptr():
                    print("datatype = %s" % local.tif)
                    sptr    = idaapi.get_struc(idaapi.get_struc_id("%s" % local.tif))
                else:
                    print("datatype = %s" % local.tif.get_ptrarr_object())
                    sptr    = idaapi.get_struc(idaapi.get_struc_id("%s" % local.tif.get_ptrarr_object()))
            '''
            
            # Get our existing struct member
            mptr    = psuedo.item.get_memptr()
            if mptr:
                
                #print (mptr)
                fname = idaapi.get_member_fullname(mptr.id)
                #print(fname)
                
                sname = fname.split('.')[0]
                sptr  = idaapi.get_struc(idaapi.get_struc_id(sname))
                
                if sptr:
                    sname = idaapi.get_struc_name(sptr.id, -1)
                    #print('structure = %s' % sname)
                    
                    # Ask the user for the member declaration
                    decl = idaapi.ask_str("", 0, "Enter member declaration (e.g., 'float the_member;')")
                    if decl:
                        # Parse input declaration
                        tinfo = idaapi.tinfo_t()
                        idaapi.parse_decl(tinfo, idaapi.cvar.idati, decl, idaapi.PT_TYP)
                        tsize = tinfo.get_size()
                        
                        match = re.match(r"\s*(\w+[\w\s\*]*?)\s+(\w+(?:\s*\[\s*\d*\s*\])*)\s*;", decl)
                        if match:
                            tname = match.group(1)
                            varname = match.group(2)
                            print('Parsed type: %s, variable name: %s' % (tname, varname))
                        else:
                            print("Failed to parse the declaration.")
                            tname = varname = None

                        print('rawdecl = %s' % decl)
                                                
                        line = idaapi.tag_remove(idaapi.get_custom_viewer_curline(view, None))
                        match = re.search(r"\[(\d+)\]", line)
                        if match:
                            psize = int(match.group(1))
                        else:
                            psize = 0
                        
                        # Mind the gap
                        gname = idaapi.get_member_name(mptr.id)
                        gsize = mptr.get_size() - tsize - psize
                        moff  = mptr.soff
                        
                        #if "gap" in gname:
                        #    gname = "gap%x" % (psize + tsize)
                        
                        # Delete existing member
                        idaapi.del_struc_member(sptr, moff)
                        
                        # Add a pre gap member if needed
                        #if psize > 0:
                        #    idaapi.add_struc_member(sptr, "gap0", moff, idaapi.FF_BYTE, None, psize)
                            
                        flags = idaapi.FF_DATA  # Basic flag for a data member
                        if tinfo.is_ptr():
                            flags |= off_flag()|idaapi.FF_DATA|idaapi.FF_DWORD  # Add the pointer flag if it's a pointer type
                            print('pointer')

                        # Create the new member
                        idaapi.add_struc_member(sptr, varname, moff + psize, flags, None, tsize)
                        
                        # Add a post gap member if needed
                        if gsize > 0:
                            idaapi.add_struc_member(sptr, gname, moff + psize + tsize, idaapi.FF_BYTE, None, gsize)
                        
                        # Refresh the psuedocode window
                        psuedo.refresh_view(view)
                    
    def term(self):
        pass
    

def PLUGIN_ENTRY():
    return lemonyfresh_t()

import ida_hexrays
import ida_typeinf
import ida_kernwin
import ida_funcs
import idc

"""
Made by Veni
"""

HOTKEY = "Shift-A"

def log(m):
    print(f"[autostruct] {m}")

def strip_casts(e):
    while e.op == ida_hexrays.cot_cast:
        e = e.x
    return e

def get_safe_size(t):
    if t is None or t.empty():
        return 1
    sz = t.get_size()
    if sz == ida_typeinf.BADSIZE or sz <= 0 or sz > 0x10000:
        return 1
    return sz

def get_add_offset(a1, a2):
    sz = a1.type.get_ptrarr_objsize()
    if sz == ida_typeinf.BADSIZE or sz <= 0:
        sz = 1
    val = a2.n._value
    if val > 0x7FFFFFFFFFFFFFFF:
        val -= 0x10000000000000000
    return val * sz

class DisjointSet:
    def __init__(self):
        self.p = {}
        
    def find(self, i):
        if i not in self.p:
            self.p[i] = i
        if self.p[i] == i:
            return i
        self.p[i] = self.find(self.p[i])
        return self.p[i]
        
    def union(self, i, j):
        ri = self.find(i)
        rj = self.find(j)
        if ri != rj:
            self.p[ri] = rj

class ASTScanner(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super(ASTScanner, self).__init__(ida_hexrays.CV_FAST)
        self.uf = DisjointSet()
        self.inline_rels = []
        self.ptr_rels = []
        self.scalars = []

    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_asg:
            lhs = strip_casts(e.x)
            rhs = strip_casts(e.y)
            
            if lhs.op == ida_hexrays.cot_var:
                v_dst = lhs.v.idx
                
                if rhs.op == ida_hexrays.cot_var:
                    self.uf.union(v_dst, rhs.v.idx)
                    
                elif rhs.op == ida_hexrays.cot_add:
                    a1 = strip_casts(rhs.x)
                    a2 = strip_casts(rhs.y)
                    if a1.op == ida_hexrays.cot_var and a2.op == ida_hexrays.cot_num:
                        self.inline_rels.append((v_dst, a1.v.idx, get_add_offset(a1, a2)))
                        
                elif rhs.op == ida_hexrays.cot_ref:
                    obj = strip_casts(rhs.x)
                    if obj.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                        base = strip_casts(obj.x)
                        if base.op == ida_hexrays.cot_var:
                            self.inline_rels.append((v_dst, base.v.idx, obj.m))
                            
                elif rhs.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                    base = strip_casts(rhs.x)
                    if base.op == ida_hexrays.cot_var:
                        self.ptr_rels.append((v_dst, base.v.idx, rhs.m))
                        
                elif rhs.op == ida_hexrays.cot_ptr:
                    obj = strip_casts(rhs.x)
                    if obj.op == ida_hexrays.cot_add:
                        a1 = strip_casts(obj.x)
                        a2 = strip_casts(obj.y)
                        if a1.op == ida_hexrays.cot_var and a2.op == ida_hexrays.cot_num:
                            self.ptr_rels.append((v_dst, a1.v.idx, get_add_offset(a1, a2)))
                    elif obj.op == ida_hexrays.cot_var:
                        self.ptr_rels.append((v_dst, obj.v.idx, 0))

                elif rhs.op == ida_hexrays.cot_idx:
                    a1 = strip_casts(rhs.x)
                    a2 = strip_casts(rhs.y)
                    if a1.op == ida_hexrays.cot_var and a2.op == ida_hexrays.cot_num:
                        self.ptr_rels.append((v_dst, a1.v.idx, get_add_offset(a1, a2)))

        if e.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
            obj = strip_casts(e.x)
            if obj.op == ida_hexrays.cot_var:
                self.scalars.append((obj.v.idx, e.m, get_safe_size(e.type)))
                
        elif e.op == ida_hexrays.cot_ptr:
            obj = strip_casts(e.x)
            if obj.op == ida_hexrays.cot_add:
                a1 = strip_casts(obj.x)
                a2 = strip_casts(obj.y)
                if a1.op == ida_hexrays.cot_var and a2.op == ida_hexrays.cot_num:
                    self.scalars.append((a1.v.idx, get_add_offset(a1, a2), get_safe_size(e.type)))
            elif obj.op == ida_hexrays.cot_var:
                self.scalars.append((obj.v.idx, 0, get_safe_size(e.type)))
                
        elif e.op == ida_hexrays.cot_idx:
            a1 = strip_casts(e.x)
            a2 = strip_casts(e.y)
            if a1.op == ida_hexrays.cot_var and a2.op == ida_hexrays.cot_num:
                self.scalars.append((a1.v.idx, get_add_offset(a1, a2), get_safe_size(e.type)))

        return 0

def process_cfunc(cfunc):
    scanner = ASTScanner()
    scanner.apply_to(cfunc.body, None)
    
    p_inline = {}
    p_ptr = {}
    
    for c, p, off in scanner.inline_rels:
        if off < 0 or off > 0x10000:
            continue
        cr = scanner.uf.find(c)
        pr = scanner.uf.find(p)
        key = (pr, off)
        if key in p_inline:
            scanner.uf.union(cr, p_inline[key])
        else:
            p_inline[key] = cr
            
    for c, p, off in scanner.ptr_rels:
        if off < 0 or off > 0x10000:
            continue
        cr = scanner.uf.find(c)
        pr = scanner.uf.find(p)
        key = (pr, off)
        if key in p_ptr:
            scanner.uf.union(cr, p_ptr[key])
        else:
            p_ptr[key] = cr
            
    f_inline = {}
    for c, p, off in scanner.inline_rels:
        if 0 <= off <= 0x10000:
            f_inline[(scanner.uf.find(p), off)] = scanner.uf.find(c)
        
    f_ptr = {}
    for c, p, off in scanner.ptr_rels:
        if 0 <= off <= 0x10000:
            f_ptr[(scanner.uf.find(p), off)] = scanner.uf.find(c)
        
    ledgers = {}
    for v, off, size in scanner.scalars:
        if off < 0 or off > 0x10000 or size <= 0 or size > 0x10000:
            continue
        r = scanner.uf.find(v)
        if r not in ledgers:
            ledgers[r] = set()
        if size in (1, 2, 4, 8):
            off = off & ~(size - 1)
        ledgers[r].add((off, size))
        
    lvars = cfunc.get_lvars()
    all_roots = set()
    for (p, o), c in f_inline.items():
        all_roots.add(p)
        all_roots.add(c)
    for (p, o), c in f_ptr.items():
        all_roots.add(p)
        all_roots.add(c)
    for r in ledgers.keys():
        all_roots.add(r)
        
    struct_names = { r: f"auto_struc_{lvars[r].name}" for r in all_roots }
    
    visited = set()
    order = []
    
    def dfs(node):
        if node in visited:
            return
        visited.add(node)
        for (p, o), c in f_inline.items():
            if p == node: dfs(c)
        for (p, o), c in f_ptr.items():
            if p == node: dfs(c)
        order.append(node)
        
    for r in all_roots:
        dfs(r)
        
    built = set()
    for root in order:
        fields = []
        for (p, off), c in f_inline.items():
            if p == root:
                tif = ida_typeinf.tinfo_t()
                tif.get_named_type(ida_typeinf.get_idati(), struct_names[c])
                sz = get_safe_size(tif)
                fields.append((off, sz, tif, f"inline_{struct_names[c]}_{off:X}"))
                
        for (p, off), c in f_ptr.items():
            if p == root:
                tif = ida_typeinf.tinfo_t()
                tif.get_named_type(ida_typeinf.get_idati(), struct_names[c])
                ptif = ida_typeinf.tinfo_t()
                if not tif.empty():
                    ptif.create_ptr(tif)
                else:
                    ptif.create_ptr(ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID))
                fields.append((off, 8, ptif, f"ptr_{struct_names[c]}_{off:X}"))
                
        if root in ledgers:
            for off, sz in ledgers[root]:
                overlap = False
                for c_off, c_sz, _, _ in fields:
                    if not (off + sz <= c_off or off >= c_off + c_sz):
                        overlap = True
                        break
                if not overlap:
                    if sz == 1: mt = ida_typeinf.BTF_BYTE
                    elif sz == 2: mt = ida_typeinf.BTF_INT16
                    elif sz == 4: mt = ida_typeinf.BTF_UINT32
                    elif sz == 8: mt = ida_typeinf.BTF_UINT64
                    else: mt = ida_typeinf.BTF_BYTE
                    fields.append((off, sz, ida_typeinf.tinfo_t(mt), f"field_{off:X}"))
                    
        if not fields:
            fields.append((0, 1, ida_typeinf.tinfo_t(ida_typeinf.BTF_BYTE), "dummy"))
            
        fields.sort(key=lambda x: x[0])
        
        udt = ida_typeinf.udt_type_data_t()
        cur_off = 0
        
        for off, sz, tif, name in fields:
            off = int(off)
            sz = int(sz)
            
            if off < cur_off:
                continue
                
            if off > cur_off:
                pad_sz = int(off - cur_off)
                pad_tif = ida_typeinf.tinfo_t()
                pad_tif.create_array(ida_typeinf.tinfo_t(ida_typeinf.BTF_BYTE), pad_sz)
                
                udm = ida_typeinf.udm_t()
                udm.name = f"pad_{cur_off:X}"
                udm.type = pad_tif
                udt.push_back(udm)
            
            udm = ida_typeinf.udm_t()
            udm.name = name
            udm.type = tif
            udt.push_back(udm)
            
            cur_off = off + sz
            
        ftif = ida_typeinf.tinfo_t()
        if ftif.create_udt(udt, ida_typeinf.BTF_STRUCT):
            ftif.set_named_type(None, struct_names[root])
            built.add(root)
            
    lv_vec = ida_hexrays.lvar_uservec_t()
    inner_list = lv_vec.lvvec
    queued = 0

    for v_idx in range(len(lvars)):
        root = scanner.uf.find(v_idx)
        if root in built:
            var = lvars[v_idx]
            stif = ida_typeinf.tinfo_t()
            stif.get_named_type(ida_typeinf.get_idati(), struct_names[root])
            ptif = ida_typeinf.tinfo_t()
            ptif.create_ptr(stif)
            
            m = ida_hexrays.lvar_saved_info_t()
            m.ll = var
            m.name = var.name
            m.type = ptif
            inner_list.push_back(m)
            queued += 1

    if queued > 0:
        ida_hexrays.save_user_lvar_settings(cfunc.entry_ea, lv_vec)
        log(f"Applied AutoStructs to {queued} variables.")

def logic():
    ea = idc.here()
    try:
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return
        process_cfunc(cfunc)
        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
        if vdui:
            vdui.refresh_view(True)
    except Exception as e:
        log(f"Error: {e}")

class AutoStructAction(ida_kernwin.action_handler_t):
    def __init__(self):
        super(AutoStructAction, self).__init__()

    def activate(self, ctx):
        logic()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
               ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
               ida_kernwin.AST_DISABLE_FOR_WIDGET

def register():
    action_name = "my:autostruct"
    desc = ida_kernwin.action_desc_t(action_name, "AutoStruct", AutoStructAction(), HOTKEY, "", -1)
    ida_kernwin.register_action(desc)
    log(f"Loaded. Use {HOTKEY} in Pseudocode")

if __name__ == "__main__":
    if ida_hexrays.init_hexrays_plugin():
        register()

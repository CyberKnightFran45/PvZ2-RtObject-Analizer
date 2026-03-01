# PvZ 2 Library Analizer by FranZ for Chinese Version (1.6.3 debug)

import ida_bytes, idc, idaapi, ida_funcs
import json, os, re

def r32(ea): return ida_bytes.get_wide_dword(ea)

def read_str(ea):
    if not ida_bytes.is_loaded(ea): return None
    s = b""
    for i in range(200):
        b = ida_bytes.get_byte(ea + i)
        if b == 0: break
        if b < 0x20 or b > 0x7e: return None
        s += bytes([b])
    return s.decode('ascii') if s else None

def get_ldr_add_string(ldr_ea):
    for op_idx in range(3):
        if idc.get_operand_type(ldr_ea, op_idx) != 2: continue
        pool_addr = idc.get_operand_value(ldr_ea, op_idx)
        if not ida_bytes.is_loaded(pool_addr): continue
        raw_val = r32(pool_addr)
        add_ea = ldr_ea + idc.get_item_size(ldr_ea)
        if idc.print_insn_mnem(add_ea) == 'ADD' and idc.print_operand(add_ea, 1) == 'PC':
            s = read_str((add_ea + 8) + raw_val)
            if s and 1 < len(s) < 100:
                return s, add_ea
    return None, None

def get_class_name_from_singleton(singleton_ea):
    fn = ida_funcs.get_func(singleton_ea)
    if not fn: return None
    ea = fn.start_ea
    while ea < fn.end_ea:
        sz = idc.get_item_size(ea)
        if sz <= 0: sz = 4
        if idc.print_insn_mnem(ea) == 'LDR' and idc.get_operand_type(ea, 1) == 2:
            s, _ = get_ldr_add_string(ea)
            if s:
                ea2 = ea
                for _ in range(10):
                    sz2 = idc.get_item_size(ea2)
                    if sz2 <= 0: sz2 = 4
                    if idc.print_insn_mnem(ea2) == 'BLX' and idc.print_operand(ea2, 0) == 'R4':
                        return s
                    ea2 += sz2
        ea += sz
    return None

def get_singleton_from_registrar(registrar_ea):
    fn = ida_funcs.get_func(registrar_ea)
    if not fn: return None
    ea = fn.start_ea
    while ea < fn.end_ea:
        sz = idc.get_item_size(ea)
        if sz <= 0: sz = 4
        mnem = idc.print_insn_mnem(ea)
        if mnem == 'BL':
            return idc.get_operand_value(ea, 0)
        elif mnem == 'BLX':
            break
        ea += sz
    return None

def parse_registrar(registrar_ea):
    fn = ida_funcs.get_func(registrar_ea)
    if not fn: return None, []
    strings = []
    last_offset = None
    blxR4_count = 0
    skip_until = 0
    parent = None
    fields = []
    ea = fn.start_ea
    while ea < fn.end_ea:
        sz = idc.get_item_size(ea)
        if sz <= 0: sz = 4
        mnem = idc.print_insn_mnem(ea)
        if ea < skip_until:
            ea += sz; continue
        if mnem == 'LDR' and idc.get_operand_type(ea, 1) == 2:
            s, add_ea = get_ldr_add_string(ea)
            if s:
                strings.append(s)
                if len(strings) > 4: strings.pop(0)
                skip_until = add_ea + idc.get_item_size(add_ea)
        elif mnem == 'MOV' and idc.print_operand(ea, 0) == 'R3' and idc.get_operand_type(ea, 1) == 5:
            v = idc.get_operand_value(ea, 1)
            if 0 < v < 0x10000:
                last_offset = v
        elif mnem == 'BLX' and idc.print_operand(ea, 0) == 'R4':
            blxR4_count += 1
            if blxR4_count == 1:
                parent = strings[-1] if strings else None
                strings = []; last_offset = None
            else:
                if len(strings) >= 2 and last_offset is not None:
                    fields.append({'field': strings[-2], 'type': strings[-1], 'offset': hex(last_offset)})
                elif len(strings) == 1 and last_offset is not None:
                    fields.append({'field': strings[-1], 'type': None, 'offset': hex(last_offset)})
                strings = []; last_offset = None
        ea += sz
    return parent, fields

# Register Lookup for Classes

pat = ida_bytes.compiled_binpat_vec_t()
ida_bytes.parse_binpat_str(pat, 0, "2C 30 83 E2", 16, 0)
registrar_fns = set()
ea = 0x8000
while True:
    res = ida_bytes.bin_search(ea, 0x5800000, pat, ida_bytes.BIN_SEARCH_FORWARD)
    hit = res[0] if isinstance(res, tuple) else res
    if hit == idaapi.BADADDR: break
    fn = ida_funcs.get_func(hit)
    if fn: registrar_fns.add(fn.start_ea)
    ea = hit + 4

print(f"Candidates: {len(registrar_fns)}")

# Parse all

raw_classes = {}
for fn_ea in sorted(registrar_fns):
    singleton = get_singleton_from_registrar(fn_ea)
    if not singleton: continue
    class_name = get_class_name_from_singleton(singleton)
    if not class_name: continue
    parent, fields = parse_registrar(fn_ea)
    if class_name not in raw_classes or len(fields) > len(raw_classes[class_name]['own_fields']):
        raw_classes[class_name] = {'parent': parent, 'own_fields': fields}

print(f"Classes found: {len(raw_classes)}")

# Solve inheritence

def resolve_fields(class_name, visited=None):
    if visited is None: visited = set()
    if class_name in visited or class_name not in raw_classes: return []
    visited.add(class_name)
    entry = raw_classes[class_name]
    parent_fields = resolve_fields(entry['parent'], visited) if entry['parent'] else []
    seen = {f['offset'] for f in parent_fields}
    own = [f for f in entry['own_fields'] if f['offset'] not in seen]
    return parent_fields + own

# Export JSONs

OUT_DIR = r"RtObject scan"
os.makedirs(OUT_DIR, exist_ok=True)

# Clear folder

for f in os.listdir(OUT_DIR):
    if f.endswith('.json'):
        os.remove(os.path.join(OUT_DIR, f))

def safe_name(n): return re.sub(r'[<>:"/\\|?*]', '_', n)

for class_name, entry in raw_classes.items():
    data = {
        'class':  class_name,
        'parent': entry['parent'],
        'fields': resolve_fields(class_name)
    }
    fpath = os.path.join(OUT_DIR, safe_name(class_name) + '.json')
    with open(fpath, 'w', encoding='utf-8') as fp:
        json.dump(data, fp, indent=2, ensure_ascii=False)

print(f"Classes exported: {len(raw_classes)}")

# Validate

for name in ['GridItemArmrack', 'Plant', 'Zombie', 'GameObject']:
    if name in raw_classes:
        fields = resolve_fields(name)
        print(f"\n{name} (parent: {raw_classes[name]['parent']}) {len(fields)} fields:")
        for f in fields[:6]:
            print(f"  [{f['offset']}] {f['field']} : {f['type']}")
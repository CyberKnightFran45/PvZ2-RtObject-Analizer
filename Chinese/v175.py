import ida_bytes, idc, idaapi, ida_funcs
import json, os

PLAYERINFO_MONO_REGISTRAR = 0x72b1f4
PLAYERINFO_OWN_REGISTRAR  = 0x7306DC
PLAYERINFO_TOTAL_SIZE     = 0x7C0

# ── Helpers ───────────────────────────────────────────────────────────────────

def read_str(ea):
    if not ida_bytes.is_loaded(ea):
        return None
    s = b""
    for i in range(256):
        b = ida_bytes.get_byte(ea + i)
        if b == 0:
            break
        if b < 0x20 or b > 0x7E:
            return None
        s += bytes([b])
    return s.decode("ascii") if s else None

def signed32(v):
    return v if v <= 0x7fffffff else v - 0x100000000

def find_add_pc(ldr_ea, reg, max_scan=16):
    ea = ldr_ea + (idc.get_item_size(ldr_ea) or 4)
    for _ in range(max_scan):
        if (idc.print_insn_mnem(ea) == "ADD" and
                idc.print_operand(ea, 0) == reg and
                idc.print_operand(ea, 1) == "PC"):
            return ea
        ea = idc.next_head(ea)
    return None

def resolve_ldr_pc_string(ldr_ea):
    if idc.get_operand_type(ldr_ea, 1) != 2:
        return None, None
    reg     = idc.print_operand(ldr_ea, 0)
    pool_ea = idc.get_operand_value(ldr_ea, 1)
    if not ida_bytes.is_loaded(pool_ea):
        return None, None
    delta   = signed32(ida_bytes.get_wide_dword(pool_ea))
    add_ea  = find_add_pc(ldr_ea, reg)
    if add_ea is None:
        return None, None
    str_ea  = (add_ea + 8) + delta
    s       = read_str(str_ea)
    if s and 1 < len(s) < 128:
        return s, add_ea
    return None, None

def resolve_ldr_pc_addr(ldr_ea):
    if idc.get_operand_type(ldr_ea, 1) != 2:
        return None, None
    reg     = idc.print_operand(ldr_ea, 0)
    pool_ea = idc.get_operand_value(ldr_ea, 1)
    if not ida_bytes.is_loaded(pool_ea):
        return None, None
    delta   = signed32(ida_bytes.get_wide_dword(pool_ea))
    add_ea  = find_add_pc(ldr_ea, reg)
    if add_ea is None:
        return None, None
    return (add_ea + 8) + delta, add_ea

# ── Parse monolithic registrar ─────────────────────────────────────────────────

def parse_mono_registrar(fn_ea):
    fn = ida_funcs.get_func(fn_ea)
    if not fn:
        return []

    fields       = []
    pending_name = None
    pending_sub  = None
    seen_add     = set()

    ea = fn.start_ea
    while ea < fn.end_ea:
        mnem = idc.print_insn_mnem(ea)

        if mnem == "LDR" and idc.get_operand_type(ea, 1) == 2:
            reg = idc.print_operand(ea, 0)

            if reg == "R1":
                s, add_ea = resolve_ldr_pc_string(ea)
                if s and add_ea not in seen_add:
                    seen_add.add(add_ea)
                    pending_name = s

            elif reg == "R2":
                addr, add_ea = resolve_ldr_pc_addr(ea)
                if addr and add_ea not in seen_add:
                    seen_add.add(add_ea)
                    pending_sub = addr

        elif (mnem == "MOV" and
              idc.print_operand(ea, 0) == "R3" and
              idc.get_operand_type(ea, 1) == 5):

            size_val = idc.get_operand_value(ea, 1)

            if pending_name and size_val > 0:
                fields.append({
                    "field":         pending_name,
                    "sub_registrar": hex(pending_sub) if pending_sub else None,
                    "size":          hex(size_val),
                })
                pending_name = None
                pending_sub  = None

        ea = idc.next_head(ea)

    return fields

# ── Robust sub-registrar parser ────────────────────────────────────────────────

def parse_sub_registrar(fn_ea):
    fn = ida_funcs.get_func(fn_ea)
    if not fn:
        return None, []

    instrs = []
    ea = fn.start_ea
    while ea < fn.end_ea:
        instrs.append((
            ea,
            idc.print_insn_mnem(ea),
            idc.print_operand(ea, 0),
            idc.print_operand(ea, 1),
            idc.get_operand_type(ea, 1),
            idc.get_operand_value(ea, 1)
        ))
        ea = idc.next_head(ea)

    # Detect preloaded type
    preloaded_type = None
    for ea, mnem, op0, op1, t1, v1 in instrs[:20]:
        if mnem == "LDR" and op0 in ("R8","R9","R10"):
            s, _ = resolve_ldr_pc_string(ea)
            if s:
                preloaded_type = s
                break

    fields = []
    string_buffer = []
    current_offset = None

    for ea, mnem, op0, op1, t1, v1 in instrs:
        # Capture strings
        if mnem == "LDR" and t1 == 2:
            s, _ = resolve_ldr_pc_string(ea)
            if s:
                string_buffer.append(s)

        # Capture offset
        elif mnem == "MOV" and op0 == "R3" and t1 == 5:
            current_offset = v1

        # Commit on BLX or MOV R3 with offset
        if current_offset is not None and string_buffer:
            # Assign first string as field, second (if exists) as type
            field_name = string_buffer[0]
            field_type = string_buffer[1] if len(string_buffer) > 1 else preloaded_type or field_name
            fields.append({
                "field": field_name,
                "type": field_type,
                "offset": hex(current_offset)
            })
            string_buffer = []
            current_offset = None

    # Catch leftover in buffer at end
    if string_buffer and current_offset is not None:
        field_name = string_buffer[0]
        field_type = string_buffer[1] if len(string_buffer) > 1 else preloaded_type or field_name
        fields.append({
            "field": field_name,
            "type": field_type,
            "offset": hex(current_offset)
        })

    return None, fields

# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    print("[*] Parsing PlayerInfo...")

    sub_fields = parse_mono_registrar(PLAYERINFO_MONO_REGISTRAR)

    schema = {
        "class": "PlayerInfo",
        "total_size": hex(PLAYERINFO_TOTAL_SIZE),
        "own_fields": [],
        "sub_fields": []
    }

    for sf in sub_fields:
        entry = {
            "name": sf["field"],
            "fields": []
        }

        if sf["sub_registrar"]:
            sub_ea = int(sf["sub_registrar"], 16)
            _, typed = parse_sub_registrar(sub_ea)
            entry["fields"] = typed

        schema["sub_fields"].append(entry)

    _, own_fields = parse_sub_registrar(PLAYERINFO_OWN_REGISTRAR)
    schema["own_fields"] = own_fields

    os.makedirs("RtObject_scan", exist_ok=True)

    with open("RtObject_scan/PlayerInfo_fixed.json", "w") as f:
        json.dump(schema, f, indent=2)

    print("[+] Done. Output in RtObject_scan/PlayerInfo_fixed.json")

main()
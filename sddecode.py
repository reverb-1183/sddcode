#!/usr/bin/env python3
"""
sddecode.py - Offline decoder for Windows security-descriptor blobs
(e.g. msDS-GroupMSAMembership / PrincipalsAllowedToRetrieveManagedPassword).

Constants live in sdconstants.py (same directory).

Usage:
    python3 sddecode.py "AQAEgEAAAA...=="
    python3 sddecode.py -f blob.b64
    python3 sddecode.py --hex 0100048040000000...
    echo "AQAEgE..." | python3 sddecode.py
"""
import argparse
import base64
import struct
import sys

from sdconstants import (
    ACCESS_MASK,
    ACE_FLAGS,
    ACE_INHERITED_OBJECT_TYPE_PRESENT,
    ACE_OBJECT_TYPE_PRESENT,
    ACE_TYPES,
    FULL_CONTROL,
    OBJECT_ACE_TYPES,
    SD_CONTROL,
    SE_DACL_PRESENT,
    SE_SACL_PRESENT,
    WELL_KNOWN_SIDS,
)


def decode_flags(value, table):
    return [name for bit, name in table if value & bit]


def sid_name(sid):
    return WELL_KNOWN_SIDS.get(sid, "")


def str_guid(b):
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    return "%08x-%04x-%04x-%s-%s" % (d1, d2, d3, b[8:10].hex(), b[10:16].hex())


def parse_sid(buf, off):
    revision = buf[off]
    count = buf[off + 1]
    ident_auth = int.from_bytes(buf[off + 2:off + 8], "big")
    subs = []
    p = off + 8
    for _ in range(count):
        subs.append(struct.unpack_from("<I", buf, p)[0])
        p += 4
    sid = "S-%d-%d%s" % (revision, ident_auth, "".join("-%d" % s for s in subs))
    return sid, p


def parse_acl(buf, off, label):
    acl_rev, _sbz1, acl_size, ace_count, _sbz2 = struct.unpack_from("<BBHHH", buf, off)
    print(f"\n{label}: revision={acl_rev} size={acl_size} ace_count={ace_count}")
    p = off + 8
    for i in range(ace_count):
        ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", buf, p)
        mask = struct.unpack_from("<I", buf, p + 4)[0]
        body = p + 8

        obj_guid = inh_guid = None
        if ace_type in OBJECT_ACE_TYPES:
            obj_flags = struct.unpack_from("<I", buf, body)[0]
            body += 4
            if obj_flags & ACE_OBJECT_TYPE_PRESENT:
                obj_guid = str_guid(buf[body:body + 16]); body += 16
            if obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
                inh_guid = str_guid(buf[body:body + 16]); body += 16

        sid, _ = parse_sid(buf, body)
        tname = ACE_TYPES.get(ace_type, "UNKNOWN(0x%02x)" % ace_type)
        name = sid_name(sid)
        rights = "FULL_CONTROL" if mask == FULL_CONTROL else ", ".join(decode_flags(mask, ACCESS_MASK))
        print(f"  ACE {i}:")
        print(f"    Type   : {tname}")
        print("    Flags  : 0x%02x %s" % (ace_flags, decode_flags(ace_flags, ACE_FLAGS) or ""))
        print("    Mask   : 0x%08x (%s)" % (mask, rights))
        if obj_guid:
            print(f"    Object GUID          : {obj_guid}")
        if inh_guid:
            print(f"    Inherited Object GUID: {inh_guid}")
        print(f"    Trustee: {sid}" + (f"  [{name}]" if name else ""))
        p += ace_size


def decode_sd(data):
    if len(data) < 20:
        raise ValueError("Too short to be a security descriptor")
    rev, _sbz1, control, o_owner, o_group, o_sacl, o_dacl = struct.unpack_from("<BBHIIII", data, 0)
    if rev != 1:
        print(f"Warning: unexpected SD revision {rev}")
    print("=== Security Descriptor ===")
    print("Total length :", len(data))
    print("Revision     :", rev)
    print("Control      : 0x%04x [%s]" % (control, ", ".join(decode_flags(control, SD_CONTROL))))

    if o_owner:
        sid, _ = parse_sid(data, o_owner)
        print("Owner        :", sid, (f"[{sid_name(sid)}]" if sid_name(sid) else ""))
    if o_group:
        sid, _ = parse_sid(data, o_group)
        print("Group        :", sid, (f"[{sid_name(sid)}]" if sid_name(sid) else ""))
    if control & SE_SACL_PRESENT and o_sacl:
        parse_acl(data, o_sacl, "SACL")
    if control & SE_DACL_PRESENT and o_dacl:
        parse_acl(data, o_dacl, "DACL")


def main():
    ap = argparse.ArgumentParser(description="Decode a base64/hex Windows security-descriptor blob (GMSA, etc.)")
    ap.add_argument("blob", nargs="?", help="base64 string")
    ap.add_argument("-f", "--file", help="read blob from file")
    ap.add_argument("--hex", action="store_true", help="input is hex instead of base64")
    args = ap.parse_args()

    if args.file:
        raw = open(args.file).read().strip()
    elif args.blob:
        raw = args.blob.strip()
    else:
        raw = sys.stdin.read().strip()

    data = bytes.fromhex(raw) if args.hex else base64.b64decode(raw)
    decode_sd(data)


if __name__ == "__main__":
    main()

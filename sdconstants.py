"""Constant tables for Windows security-descriptor decoding."""

# Well-known SIDs (extend as needed)
WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-3-0": "Creator Owner",
    "S-1-5-7": "Anonymous",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "Local System",
    "S-1-5-19": "Local Service",
    "S-1-5-20": "Network Service",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
}

# Security-descriptor control flags
SD_CONTROL = [
    (0x0001, "SE_OWNER_DEFAULTED"),
    (0x0002, "SE_GROUP_DEFAULTED"),
    (0x0004, "SE_DACL_PRESENT"),
    (0x0008, "SE_DACL_DEFAULTED"),
    (0x0010, "SE_SACL_PRESENT"),
    (0x0020, "SE_SACL_DEFAULTED"),
    (0x0100, "SE_DACL_AUTO_INHERIT_REQ"),
    (0x0200, "SE_SACL_AUTO_INHERIT_REQ"),
    (0x0400, "SE_DACL_AUTO_INHERITED"),
    (0x0800, "SE_SACL_AUTO_INHERITED"),
    (0x1000, "SE_DACL_PROTECTED"),
    (0x2000, "SE_SACL_PROTECTED"),
    (0x4000, "SE_RM_CONTROL_VALID"),
    (0x8000, "SE_SELF_RELATIVE"),
]

# Control bits used by the parser
SE_DACL_PRESENT = 0x0004
SE_SACL_PRESENT = 0x0010

# ACE types
ACE_TYPES = {
    0x00: "ACCESS_ALLOWED",
    0x01: "ACCESS_DENIED",
    0x02: "SYSTEM_AUDIT",
    0x05: "ACCESS_ALLOWED_OBJECT",
    0x06: "ACCESS_DENIED_OBJECT",
    0x07: "SYSTEM_AUDIT_OBJECT",
}
OBJECT_ACE_TYPES = {0x05, 0x06, 0x07}

# Object-ACE presence flags
ACE_OBJECT_TYPE_PRESENT = 0x1
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2

# ACE flags
ACE_FLAGS = [
    (0x01, "OBJECT_INHERIT"),
    (0x02, "CONTAINER_INHERIT"),
    (0x04, "NO_PROPAGATE_INHERIT"),
    (0x08, "INHERIT_ONLY"),
    (0x10, "INHERITED"),
    (0x40, "SUCCESSFUL_ACCESS"),
    (0x80, "FAILED_ACCESS"),
]

# Access-mask rights
ACCESS_MASK = [
    (0x00000001, "READ_DATA/LIST_DIRECTORY"),
    (0x00000002, "WRITE_DATA/ADD_FILE"),
    (0x00000004, "APPEND_DATA/ADD_SUBDIR"),
    (0x00000008, "READ_EA"),
    (0x00000010, "WRITE_EA"),
    (0x00000020, "EXECUTE/TRAVERSE"),
    (0x00000040, "DELETE_CHILD"),
    (0x00000080, "READ_ATTRIBUTES"),
    (0x00000100, "WRITE_ATTRIBUTES"),
    (0x00010000, "DELETE"),
    (0x00020000, "READ_CONTROL"),
    (0x00040000, "WRITE_DAC"),
    (0x00080000, "WRITE_OWNER"),
    (0x00100000, "SYNCHRONIZE"),
    (0x01000000, "ACCESS_SYSTEM_SECURITY"),
    (0x10000000, "GENERIC_ALL"),
    (0x20000000, "GENERIC_EXECUTE"),
    (0x40000000, "GENERIC_WRITE"),
    (0x80000000, "GENERIC_READ"),
]
FULL_CONTROL = 0x000F01FF

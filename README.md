# sddecode

*Warning : This was 100% vibe-coded by Claude - shout at it if this breaks :D*

Offline decoder for Windows **self-relative security descriptor** blobs, such as the
`msDS-GroupMSAMembership` attribute of a gMSA
(a.k.a. `PrincipalsAllowedToRetrieveManagedPassword`). No network, no AD, no dependencies.

## When to use it

Use this when you have a base64 (or hex) blob that **starts with `01 00 .. 80`**
(SD revision 1, `SE_SELF_RELATIVE`), typically obtained from:

- `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPasswordAccount`
- `ntSecurityDescriptor` or any other attribute holding a security descriptor
- an LDAP/BloodHound/export dump where you need to know **who owns it** and
  **which trustees (SIDs) have which rights**.

> Note: this does **not** decode the gMSA password itself. The actual password is in a
> different attribute, `msDS-ManagedPassword` (an `MSDS-MANAGEDPASSWORD_BLOB`), not a
> security descriptor.

## Files

- `sddecode.py`    - the decoder (CLI)
- `sdconstants.py` - all lookup tables (SIDs, control flags, ACE types, access mask)

## Usage

```bash
# base64 as an argument
python3 sddecode.py "AQAEgEAAAA...=="

# from a file
python3 sddecode.py -f blob.b64

# hex input instead of base64
python3 sddecode.py --hex 0100048040000000...

# from stdin
echo "AQAEgE..." | python3 sddecode.py
```

## Output

Prints the owner/group SIDs and every ACE in the DACL/SACL with its type, flags,
access mask (rights), object GUIDs if present, and trustee SID (resolving well-known
SIDs to names). Extend `WELL_KNOWN_SIDS` in `sdconstants.py` to label more SIDs.

Requires Python 3.6+ (standard library only).

"""Generate synthetic binary registry hive files for forensic testing.

Creates valid regf-format hive files containing known forensic artifacts
(services, Run keys) that python-registry and regipy can parse.

Registry hive binary format notes:
- REGF header: 4096 bytes
- HBIN blocks: each starts with 32-byte header, then cell data
- Cell offsets throughout the hive are relative to start of first HBIN block
- Cells in the data area start at HBIN offset 32 (after the hbin header)
"""

import struct
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent
HBIN_HEADER_SIZE = 32


def create_forensic_test_hive(filepath: str, hive_type: str = "SYSTEM") -> int:
    """Create a binary registry hive file with forensic test data."""

    cells = bytearray()

    def align8(n):
        return (n + 7) & ~7

    def add_cell(data: bytes) -> tuple[int, int]:
        """Add a cell. Returns (hbin_offset, cells_array_index)."""
        nonlocal cells
        array_idx = len(cells)
        hbin_offset = array_idx + HBIN_HEADER_SIZE
        size = align8(len(data) + 4)
        cell = struct.pack("<i", -size)  # negative = allocated
        cell += data
        cell += b"\x00" * (size - len(data) - 4)
        cells += cell
        return hbin_offset, array_idx

    def overwrite_cell(array_idx: int, data: bytes):
        """Overwrite an existing cell in the cells array."""
        size = align8(len(data) + 4)
        replacement = struct.pack("<i", -size) + data
        replacement += b"\x00" * (size - len(replacement))
        cells[array_idx : array_idx + size] = replacement

    def make_nk(
        name: bytes,
        flags: int = 0x0020,
        parent_offset: int = 0,
        num_subkeys: int = 0,
        subkeys_offset: int = 0xFFFFFFFF,
        num_values: int = 0,
        values_offset: int = 0xFFFFFFFF,
        timestamp: int = 133500000000000000,
    ) -> bytes:
        nk = bytearray(76 + len(name))
        nk[0:2] = b"nk"
        struct.pack_into("<H", nk, 2, flags)
        struct.pack_into("<Q", nk, 4, timestamp)
        struct.pack_into("<I", nk, 12, 0)  # access bits
        struct.pack_into("<I", nk, 16, parent_offset)
        struct.pack_into("<I", nk, 20, num_subkeys)  # stable subkeys
        struct.pack_into("<I", nk, 24, 0)  # volatile subkeys
        struct.pack_into("<I", nk, 28, subkeys_offset)  # stable subkeys list
        struct.pack_into("<I", nk, 32, 0xFFFFFFFF)  # volatile subkeys list
        struct.pack_into("<I", nk, 36, num_values)
        struct.pack_into("<I", nk, 40, values_offset)
        struct.pack_into("<I", nk, 44, 0xFFFFFFFF)  # security
        struct.pack_into("<I", nk, 48, 0xFFFFFFFF)  # class
        struct.pack_into("<I", nk, 52, 0)  # max subkey name len
        struct.pack_into("<I", nk, 56, 0)  # max class name len
        struct.pack_into("<I", nk, 60, 0)  # max value name len
        struct.pack_into("<I", nk, 64, 0)  # max value data size
        struct.pack_into("<I", nk, 68, 0)  # fingerprint
        struct.pack_into("<H", nk, 72, len(name))
        struct.pack_into("<H", nk, 74, 0)  # class name length
        nk[76 : 76 + len(name)] = name
        return bytes(nk)

    def make_vk(name: bytes, data: bytes, value_type: int = 1) -> bytes:
        """Build a VK record. For non-inline data, allocates a data cell first.

        VK flags at offset 16: 0x0001 = ASCII name (otherwise UTF-16LE).
        """
        data_size = len(data)
        # VK_FLAG_ASCII_NAME = 0x0001
        vk_flags = 0x0001  # names are always ASCII in our test hives

        if data_size <= 4 and value_type == 4:
            # Inline data
            vk = bytearray(20 + len(name))
            vk[0:2] = b"vk"
            struct.pack_into("<H", vk, 2, len(name))
            struct.pack_into("<I", vk, 4, data_size | 0x80000000)
            vk[8 : 8 + data_size] = data
            struct.pack_into("<I", vk, 12, value_type)
            struct.pack_into("<H", vk, 16, vk_flags)
            struct.pack_into("<H", vk, 18, 0)
            vk[20 : 20 + len(name)] = name
            return bytes(vk)
        else:
            data_hbin_offset, _ = add_cell(data)
            vk = bytearray(20 + len(name))
            vk[0:2] = b"vk"
            struct.pack_into("<H", vk, 2, len(name))
            struct.pack_into("<I", vk, 4, data_size)
            struct.pack_into("<I", vk, 8, data_hbin_offset)
            struct.pack_into("<I", vk, 12, value_type)
            struct.pack_into("<H", vk, 16, vk_flags)
            struct.pack_into("<H", vk, 18, 0)
            vk[20 : 20 + len(name)] = name
            return bytes(vk)

    def make_lf(entries: list) -> bytes:
        """Build an LF (fast leaf) subkey index.

        entries: list of (hbin_offset_of_key, first_4_chars_of_name)
        """
        lf = bytearray(4 + 8 * len(entries))
        lf[0:2] = b"lf"
        struct.pack_into("<H", lf, 2, len(entries))
        for i, (offset, hint) in enumerate(entries):
            struct.pack_into("<I", lf, 4 + i * 8, offset)
            padded_hint = hint[:4].ljust(4, b"\x00")
            lf[4 + i * 8 + 4 : 4 + i * 8 + 8] = padded_hint
        return bytes(lf)

    def encode_sz(s: str) -> bytes:
        """Encode a string as UTF-16LE with null terminator (REG_SZ)."""
        return (s + "\x00").encode("utf-16-le")

    # =====================================================================
    # Build hive content
    # =====================================================================

    if hive_type == "SYSTEM":
        # Reserve root cell slot (will be overwritten at the end)
        root_hbin_offset, root_array_idx = add_cell(b"\x00" * 120)

        services = [
            {
                "name": "Dhcp",
                "display_name": "DHCP Client",
                "image_path": "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                "start": 2,
            },
            {
                "name": "WinDefend",
                "display_name": "Windows Defender Antivirus Service",
                "image_path": '"C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.23110.3-0\\MsMpEng.exe"',
                "start": 2,
            },
            {
                "name": "WinUpdateHelper",
                "display_name": "Windows Update Helper",
                "image_path": "C:\\Users\\victim\\AppData\\Local\\Temp\\update.dll",
                "start": 2,
            },
        ]

        service_key_offsets = []
        for svc in services:
            ip_vk = make_vk(b"ImagePath", encode_sz(svc["image_path"]), value_type=2)
            ip_hbin, _ = add_cell(ip_vk)

            dn_vk = make_vk(b"DisplayName", encode_sz(svc["display_name"]), value_type=1)
            dn_hbin, _ = add_cell(dn_vk)

            start_vk = make_vk(b"Start", struct.pack("<I", svc["start"]), value_type=4)
            start_hbin, _ = add_cell(start_vk)

            values_list = struct.pack("<III", ip_hbin, dn_hbin, start_hbin)
            vl_hbin, _ = add_cell(values_list)

            timestamp = (
                133510800000000000
                if "Update" in svc["name"]
                else 133500000000000000
            )
            svc_nk = make_nk(
                name=svc["name"].encode("ascii"),
                flags=0x0020,
                num_values=3,
                values_offset=vl_hbin,
                timestamp=timestamp,
            )
            svc_hbin, _ = add_cell(svc_nk)
            service_key_offsets.append(
                (svc_hbin, svc["name"].encode("ascii")[:4])
            )

        services_lf = make_lf(service_key_offsets)
        services_lf_hbin, _ = add_cell(services_lf)

        services_nk = make_nk(
            name=b"Services",
            flags=0x0020,
            num_subkeys=len(services),
            subkeys_offset=services_lf_hbin,
        )
        services_hbin, _ = add_cell(services_nk)

        cs_lf = make_lf([(services_hbin, b"Serv")])
        cs_lf_hbin, _ = add_cell(cs_lf)
        cs_nk = make_nk(
            name=b"ControlSet001",
            flags=0x0020,
            num_subkeys=1,
            subkeys_offset=cs_lf_hbin,
        )
        cs_hbin, _ = add_cell(cs_nk)

        root_lf = make_lf([(cs_hbin, b"Cont")])
        root_lf_hbin, _ = add_cell(root_lf)
        root_nk = make_nk(
            name=b"CMI-CreateHive{SYSTEM}",
            flags=0x0024,
            num_subkeys=1,
            subkeys_offset=root_lf_hbin,
        )
        overwrite_cell(root_array_idx, root_nk)

    elif hive_type == "SOFTWARE":
        root_hbin_offset, root_array_idx = add_cell(b"\x00" * 120)

        run_entries = [
            ("SecurityHealth", "C:\\Windows\\System32\\SecurityHealthSystray.exe"),
            (
                "WindowsDefender",
                '"C:\\Program Files\\Windows Defender\\MSASCuiL.exe"',
            ),
            (
                "WindowsUpdateHelper",
                "rundll32.exe C:\\Users\\victim\\AppData\\Local\\Temp\\update.dll,DllRegisterServer",
            ),
        ]

        vk_hbin_offsets = []
        for name, data in run_entries:
            vk = make_vk(name.encode("ascii"), encode_sz(data), value_type=1)
            vk_hbin, _ = add_cell(vk)
            vk_hbin_offsets.append(vk_hbin)

        values_list = struct.pack(f"<{len(vk_hbin_offsets)}I", *vk_hbin_offsets)
        vl_hbin, _ = add_cell(values_list)

        run_nk = make_nk(
            b"Run",
            flags=0x0020,
            num_values=len(run_entries),
            values_offset=vl_hbin,
        )
        run_hbin, _ = add_cell(run_nk)

        cv_lf = make_lf([(run_hbin, b"Run\x00")])
        cv_lf_hbin, _ = add_cell(cv_lf)
        cv_nk = make_nk(
            b"CurrentVersion",
            flags=0x0020,
            num_subkeys=1,
            subkeys_offset=cv_lf_hbin,
        )
        cv_hbin, _ = add_cell(cv_nk)

        win_lf = make_lf([(cv_hbin, b"Curr")])
        win_lf_hbin, _ = add_cell(win_lf)
        win_nk = make_nk(
            b"Windows",
            flags=0x0020,
            num_subkeys=1,
            subkeys_offset=win_lf_hbin,
        )
        win_hbin, _ = add_cell(win_nk)

        ms_lf = make_lf([(win_hbin, b"Wind")])
        ms_lf_hbin, _ = add_cell(ms_lf)
        ms_nk = make_nk(
            b"Microsoft",
            flags=0x0020,
            num_subkeys=1,
            subkeys_offset=ms_lf_hbin,
        )
        ms_hbin, _ = add_cell(ms_nk)

        root_lf = make_lf([(ms_hbin, b"Micr")])
        root_lf_hbin, _ = add_cell(root_lf)
        root_nk = make_nk(
            name=b"CMI-CreateHive{SOFTWARE}",
            flags=0x0024,
            num_subkeys=1,
            subkeys_offset=root_lf_hbin,
        )
        overwrite_cell(root_array_idx, root_nk)

    # =====================================================================
    # Assemble hive file
    # =====================================================================

    hbin_total = max(4096, ((len(cells) + HBIN_HEADER_SIZE + 4095) // 4096) * 4096)

    hbin = bytearray(hbin_total)
    hbin[0:4] = b"hbin"
    struct.pack_into("<I", hbin, 4, 0)  # offset from start of hive
    struct.pack_into("<I", hbin, 8, hbin_total)  # size
    struct.pack_into("<Q", hbin, 0x0C, 0)  # reserved
    struct.pack_into("<I", hbin, 0x14, 0)  # spare
    hbin[HBIN_HEADER_SIZE : HBIN_HEADER_SIZE + len(cells)] = cells

    # Mark remaining space as a free cell
    free_start = HBIN_HEADER_SIZE + len(cells)
    free_size = hbin_total - free_start
    if free_size >= 8:
        struct.pack_into("<i", hbin, free_start, free_size)  # positive = free

    # REGF header
    regf = bytearray(4096)
    regf[0:4] = b"regf"
    struct.pack_into("<I", regf, 4, 1)  # primary seq
    struct.pack_into("<I", regf, 8, 1)  # secondary seq
    struct.pack_into("<Q", regf, 0x0C, 133500000000000000)  # timestamp
    struct.pack_into("<I", regf, 0x14, 1)  # major version
    struct.pack_into("<I", regf, 0x18, 5)  # minor version
    struct.pack_into("<I", regf, 0x1C, 0)  # type
    struct.pack_into("<I", regf, 0x20, 3)  # format
    struct.pack_into("<I", regf, 0x24, root_hbin_offset)  # root cell offset
    struct.pack_into("<I", regf, 0x28, hbin_total)  # hive bins data size
    struct.pack_into("<I", regf, 0x2C, 1)  # cluster

    hive_name = hive_type.encode("utf-16-le")
    regf[0x30 : 0x30 + len(hive_name)] = hive_name

    # Checksum (XOR of first 127 dwords)
    checksum = 0
    for i in range(0, 0x1FC, 4):
        checksum ^= struct.unpack_from("<I", regf, i)[0]
    struct.pack_into("<I", regf, 0x1FC, checksum)

    with open(filepath, "wb") as f:
        f.write(regf)
        f.write(hbin)

    return 4096 + hbin_total


if __name__ == "__main__":
    system_path = str(FIXTURES_DIR / "SYSTEM_test.dat")
    software_path = str(FIXTURES_DIR / "SOFTWARE_test.dat")

    s1 = create_forensic_test_hive(system_path, "SYSTEM")
    s2 = create_forensic_test_hive(software_path, "SOFTWARE")
    print(f"Created SYSTEM hive: {s1} bytes -> {system_path}")
    print(f"Created SOFTWARE hive: {s2} bytes -> {software_path}")

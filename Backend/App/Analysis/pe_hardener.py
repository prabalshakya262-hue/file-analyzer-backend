import pefile
import os
import struct
from ..config import settings
from ..utils.signing import sign_pe

class PEHardener:
    def __init__(self):
        self.output_dir = "/tmp/hardened_exes"

    def harden(self, exe_path):
        os.makedirs(self.output_dir, exist_ok=True)
        try:
            pe = pefile.PE(exe_path)
        except Exception as e:
            print(f"Failed to parse PE: {e}")
            return None

        current = pe.OPTIONAL_HEADER.DllCharacteristics
        current |= 0x0040  # ASLR
        current |= 0x0100  # DEP
        current |= 0x0400  # No SEH (SafeSEH)
        if pe.FILE_HEADER.Machine == 0x8664:
            current |= 0x0020  # High Entropy ASLR
        current |= 0x4000  # Control Flow Guard (if supported)
        pe.OPTIONAL_HEADER.DllCharacteristics = current

        base_name = os.path.basename(exe_path)
        out_path = os.path.join(self.output_dir, base_name + "_hardened.exe")
        pe.write(out_path)
        pe.close()

        signed_path = self._sign_pe(out_path)
        return signed_path

    def _sign_pe(self, pe_path):
        return sign_pe(pe_path)
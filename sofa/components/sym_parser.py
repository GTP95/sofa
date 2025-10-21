from elftools.elf.elffile import ELFFile
from io import BytesIO


class SymParser:
    """
    Responsible for parsing symbols from a target ELF file for use in emulation and analysis.

    Attributes:
        elf_path (str): Path to the ELF file being parsed.
    """

    def __init__(self, elf_path: str) -> None:
        """
        Initializes the SymParser with the given path to the ELF file.

        Args:
            elf_path (str): The file path to the ELF file that contains symbols for parsing.
        """
        with open(file=elf_path, mode="rb") as f:
            __elf_data: bytes = f.read()
        self.__elf = ELFFile(stream=BytesIO(initial_bytes=__elf_data))

    def get_symbol_by_name(self, name) -> int:
        """
        Retrieves the details of a specific symbol by its name.

        Args:
            name (str): The name of the symbol to retrieve.

        Returns:
            int: The address of the symbol.
        """
        symtab = self.__elf.get_section_by_name(".symtab")
        sym = symtab.get_symbol_by_name(name)
        if sym is None:
            raise ValueError(f"Error, function {name} not found in the .sym file")
        # Because of Thumb 1 is added to every instruction
        return sym[0]["st_value"] - 1

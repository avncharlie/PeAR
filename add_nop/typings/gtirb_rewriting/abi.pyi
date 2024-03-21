"""
This type stub file was generated by pyright.
"""

import dataclasses
import gtirb
from typing import Dict, List, Set, Tuple
from typing_extensions import Literal, Protocol
from .assembly import Register

class ABIDescriptor(Protocol):
    """
    An object that describes an ABI. This will typically be a GTIRB Module
    object.
    """
    file_format: gtirb.Module.FileFormat
    isa: gtirb.Module.ISA
    ...


@dataclasses.dataclass
class CallingConventionDesc:
    """
    Describes an ABI's calling convention.
    """
    registers: Tuple[str, ...]
    stack_alignment: int
    caller_cleanup: bool
    shadow_space: int = ...


@dataclasses.dataclass
class _PatchRegisterAllocation:
    """
    The register allocation for a patch.
    """
    clobbered_registers: List[Register]
    scratch_registers: List[Register]
    available_registers: List[Register]
    ...


class ABI:
    """
    Describes an application binary interface (ABI) and the instruction set
    architecture (ISA) beneath it.
    """
    def __init__(self) -> None:
        ...
    
    @classmethod
    def get(cls, format: ABIDescriptor) -> ABI:
        """
        Gets the appropriate ABI object for a module.
        """
        ...
    
    def get_register(self, name: str) -> Register:
        """
        Gets a Register object by its name (or the name of a subregister).
        """
        ...
    
    def all_registers(self) -> List[Register]:
        """
        Returns all general-purpose registers for the ISA.
        """
        ...
    
    def nop(self) -> bytes:
        """
        Returns the encoding of a no-op instruction.
        """
        ...
    
    def caller_saved_registers(self) -> Set[Register]:
        """
        Returns the registers that need to be saved by the caller if it wants
        the values preserved across the call.
        """
        ...
    
    def byteorder(self) -> Literal["little", "big"]:
        """
        The ABI's native endianness.
        """
        ...
    
    def pointer_size(self) -> int:
        """
        Returns the size of a pointer on the ISA (which is assumed to match
        the size of general purpose registers).
        """
        ...
    
    def red_zone_size(self) -> int:
        """
        Returns the number of bytes that leaf functions are allowed to use on
        the stack (without adjusting the stack pointer).
        """
        ...
    
    def calling_convention(self) -> CallingConventionDesc:
        """
        Returns a description of the ABI's default calling convention.
        """
        ...
    
    def stack_register(self) -> Register:
        """
        Returns the stack pointer register.
        """
        ...
    
    def temporary_label_prefix(self) -> str:
        """
        The prefix used to denote that a label is temporary.
        """
        ...
    


class _IA32(ABI):
    def all_registers(self) -> List[Register]:
        ...
    
    def nop(self) -> bytes:
        ...
    
    def pointer_size(self) -> int:
        ...
    
    def stack_register(self) -> Register:
        ...
    


class _IA32_PE(_IA32):
    def caller_saved_registers(self) -> Set[Register]:
        ...
    
    def calling_convention(self) -> CallingConventionDesc:
        ...
    
    def temporary_label_prefix(self) -> str:
        ...
    


class _X86_64(ABI):
    def all_registers(self) -> List[Register]:
        ...
    
    def nop(self) -> bytes:
        ...
    
    def pointer_size(self) -> int:
        ...
    
    def stack_register(self) -> Register:
        ...
    


class _X86_64_PE(_X86_64):
    def caller_saved_registers(self) -> Set[Register]:
        ...
    
    def calling_convention(self) -> CallingConventionDesc:
        ...
    
    def temporary_label_prefix(self) -> str:
        ...
    


class _X86_64_ELF(_X86_64):
    def caller_saved_registers(self) -> Set[Register]:
        ...
    
    def red_zone_size(self) -> int:
        ...
    
    def calling_convention(self) -> CallingConventionDesc:
        ...
    
    def temporary_label_prefix(self) -> str:
        ...
    


class _ARM64_ELF(ABI):
    def all_registers(self) -> List[Register]:
        ...
    
    def nop(self) -> bytes:
        ...
    
    def caller_saved_registers(self) -> Set[Register]:
        ...
    
    def pointer_size(self) -> int:
        ...
    
    def calling_convention(self) -> CallingConventionDesc:
        ...
    
    def stack_register(self) -> Register:
        ...
    
    def temporary_label_prefix(self) -> str:
        ...
    


_ABIS: Dict[Tuple[gtirb.Module.ISA, gtirb.Module.FileFormat], ABI] = ...

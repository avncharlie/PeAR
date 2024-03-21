"""
This type stub file was generated by pyright.
"""

import uuid
import gtirb
from typing import Callable, Dict, Generic, List, Optional, Tuple, Type, TypeVar, Union

DataT = TypeVar("DataT")
ContainerT = TypeVar("ContainerT", bound=gtirb.AuxDataContainer)
class TableDefinition(Generic[ContainerT, DataT]):
    """
    An aux data table definition that provides type-safe accessors to the
    data.
    """
    def __init__(self, container_type: Type[ContainerT], name: str, type_name: str, static_type: Type[DataT], table_hook: Optional[Callable[[gtirb.AuxData], None]] = ...) -> None:
        ...
    
    def exists(self, container: ContainerT) -> bool:
        """
        Checks if the aux data table exists in the container.
        """
        ...
    
    def get(self, container: ContainerT) -> Optional[DataT]:
        """
        Gets the aux data table's data, if it exists.
        """
        ...
    
    def get_or_insert(self, container: ContainerT) -> DataT:
        """
        Gets the aux data table's data, creating it if needed.
        """
        ...
    
    def remove(self, container: ContainerT) -> None:
        """
        Removes the aux data table form the container, if it exists.
        """
        ...
    


def define_table(container_type: Type[ContainerT], name: str, gt_type: str, py_type: Type[DataT]) -> TableDefinition[ContainerT, DataT]:
    """
    Defines an aux data table.

    :param container_type: The container type, Module or IR, that the aux data
                           table can be within.
    :param name: The name of the aux data table.
    :param gt_type: The GTIRB type encoding for the aux data table.
    :param py_type: The static Python type for the data in the aux data table.
    """
    ...

alignment = ...
comments = ...
function_entries = ...
function_blocks = ...
function_names = ...
padding = ...
symbol_forwarding = ...
types = ...
binary_type = ...
CFIDirectiveType = Tuple[str, List[int], Union[gtirb.Symbol, uuid.UUID]]
NULL_UUID = ...
cfi_directives = ...
elf_symbol_info = ...
elf_section_properties = ...
section_properties = ...
encodings = ...
libraries = ...
library_paths = ...
pe_import_entries = ...
pe_imported_symbols = ...
pe_resource = ...
symbolic_expression_sizes = ...
leaf_functions = ...
def compat_section_properties(module: gtirb.Module) -> Dict[gtirb.Section, Tuple[int, int]]:
    """
    Gets the sectionProperties (modern) or elfSectionProperties (older) aux
    data table, depending on which one is present. This is for backwards
    compatibility.
    """
    ...


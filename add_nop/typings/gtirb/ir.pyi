"""
This type stub file was generated by pyright.
"""

import os
import typing
from uuid import UUID
from .auxdata import AuxData, AuxDataContainer
from .block import ByteBlock, CfgNode, CodeBlock, DataBlock, ProxyBlock
from .byteinterval import ByteInterval, SymbolicExpressionElement
from .cfg import Edge
from .module import Module
from .node import Node
from .section import Section
from .symbol import Symbol
from .util import DictLike, ListWrapper

"""The IR is the core class for reading and writing GTIRB files.

    You can open a GTIRB Protobuf file and load it into an IR instance:

    >>> ir = IR.load_protobuf('filename.gtirb')

    And then you can write the IR instance as a Protobuf file:

    >>> ir.save_protobuf('filename.gtirb')
"""
GTIRB_MAGIC_CHARS = ...
class IR(AuxDataContainer):
    """A complete internal representation consisting of multiple Modules.

    :ivar ~.modules: A list of :class:`Module`\\s contained in the IR.
    :ivar ~.cfg: The IR's control flow graph.
    :ivar ~.version: The Protobuf version of this IR.
    """
    class _ModuleList(ListWrapper[Module]):
        def __init__(self, node: IR, *args: typing.Iterable[Module]) -> None:
            ...
        
    
    
    def __init__(self, *, modules: typing.Iterable[Module] = ..., aux_data: DictLike[str, AuxData] = ..., cfg: typing.Iterable[Edge] = ..., version: int = ..., uuid: typing.Optional[UUID] = ...) -> None:
        """
        :param modules: A list of Modules contained in the IR.
        :param cfg: A set of :class:`Edge`\\s representing the IR's control
            flow graph. Defaults to being empty.
        :param aux_data: The initial auxiliary data to be associated
            with the object, as a mapping from names to
            :class:`gtirb.AuxData`. Defaults to being empty.
        :param version: The Protobuf version of this IR.
        :param uuid: The UUID of this ``IR``,
            or None if a new UUID needs generated via :func:`uuid.uuid4`.
            Defaults to None.
        """
        ...
    
    def deep_eq(self, other: object) -> bool:
        ...
    
    @staticmethod
    def load_protobuf_file(protobuf_file: typing.BinaryIO) -> IR:
        """Load IR from a Protobuf object.

        Use this function when you have a Protobuf object already loaded,
        and you want to parse it as a GTIRB IR.
        If the Protobuf object is stored in a file,
        use :func:`gtirb.IR.load_protobuf` instead.

        :param protobuf_file: A byte stream encoding a GTIRB Protobuf message.
        :returns: An IR object representing the same
            information that is contained in ``protobuf_file``.
        """
        ...
    
    @staticmethod
    def load_protobuf(file_name: typing.Union[str, os.PathLike[str]]) -> IR:
        """Load IR from a Protobuf file at the specified path.

        :param file_name: The path to the Protobuf file.
        :returns: A Python GTIRB IR object.
        """
        ...
    
    def save_protobuf_file(self, protobuf_file: typing.BinaryIO) -> None:
        """Save ``self`` to a Protobuf object.

        :param protobuf_file: The byte stream to write the GTIRB Protobuf
            message to.
        """
        ...
    
    def save_protobuf(self, file_name: typing.Union[str, os.PathLike[str]]) -> None:
        """Save ``self`` to a Protobuf file at the specified path.

        :param file_name: The file path at which to
            save the Protobuf representation of ``self``.
        """
        ...
    
    def __repr__(self) -> str:
        ...
    
    @property
    def proxy_blocks(self) -> typing.Iterator[ProxyBlock]:
        """The :class:`ProxyBlock`\\s in this IR."""
        ...
    
    @property
    def sections(self) -> typing.Iterator[Section]:
        """The :class:`Section`\\s in this IR."""
        ...
    
    @property
    def symbols(self) -> typing.Iterator[Symbol]:
        """The :class:`Symbol`\\s in this IR."""
        ...
    
    @property
    def byte_intervals(self) -> typing.Iterator[ByteInterval]:
        """The :class:`ByteInterval`\\s in this IR."""
        ...
    
    @property
    def byte_blocks(self) -> typing.Iterator[ByteBlock]:
        """The :class:`ByteBlock`\\s in this IR."""
        ...
    
    @property
    def code_blocks(self) -> typing.Iterator[CodeBlock]:
        """The :class:`CodeBlock`\\s in this IR."""
        ...
    
    @property
    def data_blocks(self) -> typing.Iterator[DataBlock]:
        """The :class:`DataBlock`\\s in this IR."""
        ...
    
    @property
    def cfg_nodes(self) -> typing.Iterator[CfgNode]:
        """The :class:`CfgNode`\\s in this IR."""
        ...
    
    def modules_named(self, name: str) -> typing.Iterator[Module]:
        """Find all modules with a given name"""
        ...
    
    def sections_on(self, addrs: typing.Union[int, range]) -> typing.Iterable[Section]:
        """Finds all the sections that overlap an address or range of
        addresses.

        :param addrs: Either a ``range`` object or a single address.
        """
        ...
    
    def sections_at(self, addrs: typing.Union[int, range]) -> typing.Iterable[Section]:
        """Finds all the sections that begin at an address or range of
        addresses.

        :param addrs: Either a ``range`` object or a single address.
        """
        ...
    
    def byte_intervals_on(self, addrs: typing.Union[int, range]) -> typing.Iterable[ByteInterval]:
        """Finds all the byte intervals that overlap an address or range of
        addresses.

        :param addrs: Either a ``range`` object or a single address.
        """
        ...
    
    def byte_intervals_at(self, addrs: typing.Union[int, range]) -> typing.Iterable[ByteInterval]:
        """Finds all the byte intervals that begin at an address or range of
        addresses.

        :param addrs: Either a ``range`` object or a single address.
        """
        ...
    
    def byte_blocks_on(self, addrs: typing.Union[int, range]) -> typing.Iterable[ByteBlock]:
        """Finds all the byte blocks that overlap an address or range of
        addresses.

        :param addrs: Either a ``range`` object or a single address.
        """
        ...
    
    def byte_blocks_at(self, addrs: typing.Union[int, range]) -> typing.Iterable[ByteBlock]:
        """Finds all the byte blocks that begin at an address or range of
        addresses.

        :param addrs: Either a ``range`` object or a single address.
        """
        ...
    
    def code_blocks_on(self, addrs: typing.Union[int, range]) -> typing.Iterable[CodeBlock]:
        """Finds all the code blocks that overlap an address or range of
        addresses.

        :param addrs: Either a ``range`` object or a single address.
        """
        ...
    
    def code_blocks_at(self, addrs: typing.Union[int, range]) -> typing.Iterable[CodeBlock]:
        """Finds all the code blocks that begin at an address or range of
        addresses.

        :param addrs: Either a ``range`` object or a single address.
        """
        ...
    
    def data_blocks_on(self, addrs: typing.Union[int, range]) -> typing.Iterable[DataBlock]:
        """Finds all the data blocks that overlap an address or range of
        addresses.

        :param addrs: Either a ``range`` object or a single address.
        """
        ...
    
    def data_blocks_at(self, addrs: typing.Union[int, range]) -> typing.Iterable[DataBlock]:
        """Finds all the data blocks that begin at an address or range of
        addresses.

        :param addrs: Either a ``range`` object or a single address.
        """
        ...
    
    def symbolic_expressions_at(self, addrs: typing.Union[int, range]) -> typing.Iterable[SymbolicExpressionElement]:
        """Finds all the symbolic expressions that begin at an address or
        range of addresses.

        :param addrs: Either a ``range`` object or a single address.
        :returns: Yields ``(interval, offset, symexpr)`` tuples for every
            symbolic expression in the range.
        """
        ...
    
    def get_by_uuid(self, uuid: UUID) -> typing.Optional[Node]:
        """Look up a node by its UUID.

        This method will find any node currently attached to this IR.
        It will not find any nodes attached to other IRs, or not attached to
        any IR.

        :param uuid: The UUID to look up.
        :returns: The Node this UUID corresponds to, or None if no node exists
            with that UUID.
        """
        ...
    



"""
This type stub file was generated by pyright.
"""

import builtins
import collections.abc
import google.protobuf.descriptor
import google.protobuf.internal.containers
import google.protobuf.message
import gtirb.proto.CodeBlock_pb2
import gtirb.proto.DataBlock_pb2
import gtirb.proto.SymbolicExpression_pb2
import sys
import typing as typing_extensions

"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
===- ByteInterval.proto -------------------------------------*- Proto -*-===//

 Copyright (C) 2020 GrammaTech, Inc.

 This code is licensed under the MIT license. See the LICENSE file in the
 project root for license terms.

 This project is sponsored by the Office of Naval Research, One Liberty
 Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
 N68335-17-C-0700.  The content of the information does not necessarily
 reflect the position or policy of the Government and no official
 endorsement should be inferred.

===----------------------------------------------------------------------===//
"""
if sys.version_info >= (3, 8):
    ...
else:
    ...
DESCRIPTOR: google.protobuf.descriptor.FileDescriptor
class Block(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    OFFSET_FIELD_NUMBER: builtins.int
    CODE_FIELD_NUMBER: builtins.int
    DATA_FIELD_NUMBER: builtins.int
    offset: builtins.int
    @property
    def code(self) -> gtirb.proto.CodeBlock_pb2.CodeBlock:
        ...
    
    @property
    def data(self) -> gtirb.proto.DataBlock_pb2.DataBlock:
        ...
    
    def __init__(self, *, offset: builtins.int = ..., code: gtirb.proto.CodeBlock_pb2.CodeBlock | None = ..., data: gtirb.proto.DataBlock_pb2.DataBlock | None = ...) -> None:
        ...
    
    def HasField(self, field_name: typing_extensions.Literal["code", b"code", "data", b"data", "value", b"value"]) -> builtins.bool:
        ...
    
    def ClearField(self, field_name: typing_extensions.Literal["code", b"code", "data", b"data", "offset", b"offset", "value", b"value"]) -> None:
        ...
    
    def WhichOneof(self, oneof_group: typing_extensions.Literal["value", b"value"]) -> typing_extensions.Literal["code", "data"] | None:
        ...
    


global___Block = Block
class ByteInterval(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    class SymbolicExpressionsEntry(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor
        KEY_FIELD_NUMBER: builtins.int
        VALUE_FIELD_NUMBER: builtins.int
        key: builtins.int
        @property
        def value(self) -> gtirb.proto.SymbolicExpression_pb2.SymbolicExpression:
            ...
        
        def __init__(self, *, key: builtins.int = ..., value: gtirb.proto.SymbolicExpression_pb2.SymbolicExpression | None = ...) -> None:
            ...
        
        def HasField(self, field_name: typing_extensions.Literal["value", b"value"]) -> builtins.bool:
            ...
        
        def ClearField(self, field_name: typing_extensions.Literal["key", b"key", "value", b"value"]) -> None:
            ...
        
    
    
    UUID_FIELD_NUMBER: builtins.int
    BLOCKS_FIELD_NUMBER: builtins.int
    SYMBOLIC_EXPRESSIONS_FIELD_NUMBER: builtins.int
    HAS_ADDRESS_FIELD_NUMBER: builtins.int
    ADDRESS_FIELD_NUMBER: builtins.int
    SIZE_FIELD_NUMBER: builtins.int
    CONTENTS_FIELD_NUMBER: builtins.int
    uuid: builtins.bytes
    @property
    def blocks(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___Block]:
        ...
    
    @property
    def symbolic_expressions(self) -> google.protobuf.internal.containers.MessageMap[builtins.int, gtirb.proto.SymbolicExpression_pb2.SymbolicExpression]:
        ...
    
    has_address: builtins.bool
    address: builtins.int
    size: builtins.int
    contents: builtins.bytes
    def __init__(self, *, uuid: builtins.bytes = ..., blocks: collections.abc.Iterable[global___Block] | None = ..., symbolic_expressions: collections.abc.Mapping[builtins.int, gtirb.proto.SymbolicExpression_pb2.SymbolicExpression] | None = ..., has_address: builtins.bool = ..., address: builtins.int = ..., size: builtins.int = ..., contents: builtins.bytes = ...) -> None:
        ...
    
    def ClearField(self, field_name: typing_extensions.Literal["address", b"address", "blocks", b"blocks", "contents", b"contents", "has_address", b"has_address", "size", b"size", "symbolic_expressions", b"symbolic_expressions", "uuid", b"uuid"]) -> None:
        ...
    


global___ByteInterval = ByteInterval

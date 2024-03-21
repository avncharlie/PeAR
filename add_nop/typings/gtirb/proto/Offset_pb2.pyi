"""
This type stub file was generated by pyright.
"""

import builtins
import google.protobuf.descriptor
import google.protobuf.message
import sys
import typing as typing_extensions

"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
===- Offset.proto -------------------------------------------*- Proto -*-===//

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
class Offset(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    ELEMENT_ID_FIELD_NUMBER: builtins.int
    DISPLACEMENT_FIELD_NUMBER: builtins.int
    element_id: builtins.bytes
    displacement: builtins.int
    def __init__(self, *, element_id: builtins.bytes = ..., displacement: builtins.int = ...) -> None:
        ...
    
    def ClearField(self, field_name: typing_extensions.Literal["displacement", b"displacement", "element_id", b"element_id"]) -> None:
        ...
    


global___Offset = Offset

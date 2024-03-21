"""
This type stub file was generated by pyright.
"""

from enum import Enum
from typing import Iterable, Iterator, MutableSet, NamedTuple, Optional, TYPE_CHECKING
from networkx import MultiDiGraph
from .block import CfgNode

if TYPE_CHECKING:
    ...
class EdgeType(Enum):
    """The type of control flow transfer indicated by a
    :class:`gtirb.Edge`.
    """
    Branch = ...
    Call = ...
    Fallthrough = ...
    Return = ...
    Syscall = ...
    Sysret = ...


class EdgeLabel(NamedTuple):
    """Contains a more detailed description of a :class:`gtirb.Edge`
    in the CFG.

    :ivar ~.conditional: When this edge is part of a conditional branch,
        ``conditional`` is ``True`` when the edge represents the control
        flow taken when the branch's condition is met, and ``False``
        when it represents the control flow taken when the branch's
        condition is not met. Otherwise, it is always ``False``.
    :ivar ~.direct: ``True`` if the branch or call is direct,
            and ``False`` if it is indirect. If an edge is indirect,
            then all outgoing indirect edges represent the set of
            possible locations the edge may branch to. If there
            exists an indirect outgoing edge to a :class:`gtirb.ProxyBlock`
            without any :class:`gtirb.Symbol` objects referring to it,
            then the set of all possible branch locations is unknown.
    :ivar ~.type: The type of control flow the :class:`gtirb.Edge`
        represents.
    """
    type: EdgeType
    conditional: bool = ...
    direct: bool = ...
    def __repr__(self) -> str:
        ...
    


class Edge(NamedTuple("NamedTuple", (("source", CfgNode), ("target", CfgNode), ("label", Optional[EdgeLabel])))):
    """An edge in the CFG from ``source`` to ``target``, with optional
    control-flow details in ``label``.

    :ivar ~.source: The source CFG node.
    :ivar ~.target: The target CFG node.
    :ivar ~.label: An optional label containing more control flow information.
    """
    __slots__ = ...
    def __new__(cls, source: CfgNode, target: CfgNode, label: Optional[EdgeLabel] = ...) -> Edge:
        ...
    
    Type = EdgeType
    Label = EdgeLabel


class CFG(MutableSet[Edge]):
    """A control-flow graph for an :class:`IR`. Vertices are
    :class:`CfgNode`\\s, and edges may optionally contain
    :class:`Edge.Label`\\s.

    The graph may be viewed simply as a set of :class:`Edge`\\s. For
    convenience, the :meth:`out_edges` and :meth:`in_edges` methods provide
    access to the outgoing or incoming edges of individual nodes.

    For efficency, only vertices with edges are guaranteed to be stored in this
    graph. If you want to find all vertices possible (that is, all
    :class:`CfgNode`\\s), use :meth:`IR.cfg_nodes` instead.

    Internally, the graph is stored as a NetworkX instance, which can be
    accessed using :meth:`nx`. This allows NetworkX's large library of graph
    algorithms to be used on CFGs, if desired.
    """
    def __init__(self, edges: Optional[Iterable[Edge]] = ...) -> None:
        ...
    
    def __contains__(self, edge: object) -> bool:
        ...
    
    def __iter__(self) -> Iterator[Edge]:
        ...
    
    def __len__(self) -> int:
        ...
    
    def update(self, edges: Iterable[Edge]) -> None:
        ...
    
    def add(self, edge: Edge) -> None:
        ...
    
    def clear(self) -> None:
        ...
    
    def discard(self, edge: Edge) -> None:
        ...
    
    def out_edges(self, node: CfgNode) -> Iterator[Edge]:
        ...
    
    def in_edges(self, node: CfgNode) -> Iterator[Edge]:
        ...
    
    def nx(self) -> MultiDiGraph:
        ...
    
    def deep_eq(self, other: CFG) -> bool:
        ...
    
    def __repr__(self) -> str:
        ...
    



from binaryninja.function import InstructionTextToken, DisassemblyTextLine, Function
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.enums import InstructionTextTokenType, BranchType
from collections import defaultdict

class ProximityGraph(FlowGraph):
    def __init__(self, parent, edges):
        super(ProximityGraph, self).__init__()
        self.edges = edges
        self.func_nodes = {}
        self.parent = parent


    def populate_nodes(self):
        for edge_start in self.edges:
            for edge_end in self.edges[edge_start]:
                self.add_edge(edge_start, edge_end)


    def add_func_node(self, func):
        if func in self.func_nodes:
            print(f"{func} already in, returning existing...")
            return self.func_nodes[func]

        func_node = FlowGraphNode(self)
        line = DisassemblyTextLine([])
        line.tokens.append(InstructionTextToken(InstructionTextTokenType.CodeSymbolToken, func.name, value=func.start, address=func.start))
        func_node.lines = [line]
        self.append(func_node)
        self.func_nodes[func] = func_node
        return func_node


    def add_edge(self, origin, end):
        if origin in self.func_nodes and end in self.func_nodes:
            print(f"Edge 0x{origin.start:x} -> 0x{end.start:x} exists, skipping...")
            return

        origin_node = self.add_func_node(origin)
        end_node = self.add_func_node(end)
        origin_node.add_outgoing_edge(BranchType.IndirectBranch, end_node)


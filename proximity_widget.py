from collections import defaultdict

from binaryninjaui import FlowGraphWidget, ViewType
from binaryninja import Function
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.function import InstructionTextToken, DisassemblyTextLine, Function
from binaryninja.enums import InstructionTextTokenType, BranchType

from .proximity_graph import ProximityGraph

#TODO: add ability to find paths
#TODO: highlight nodes without children in red? (or add dummy "..." node to those that do)

class ProximityWidget(FlowGraphWidget):
    def __init__(self, parent, data):
        self.bv = data
        self.edges = defaultdict(set)
        self.graph = ProximityGraph(self, self.edges)
        super(ProximityWidget, self).__init__(parent, self.bv, self.graph)
        self.populate_initial()

    def update_graph(self):
        self.graph = ProximityGraph(self, self.edges)
        self.updateToGraph(self.graph)

    def populate_initial(self):
        self.add_proximity_layer(self.bv.entry_function)

    def navigateToFunction(self, func, addr):
        self.add_proximity_layer(func)
        return True

    def navigate(self, addr):
        func = self.bv.get_function_at(addr)
        if func is None:
            return False
        self.navigateToFunction(func, addr)
        return True

    def get_children_nodes(self, func):
        refs = self.bv.get_code_refs_from(func.lowest_address, func=func, length=func.highest_address-func.lowest_address)
        refs = set(refs) #TODO: fix api and remove this workaround
        return refs

    def get_parent_nodes(self, func):
        refs = self.bv.get_code_refs(func.start)
        return refs

    def add_proximity_layer(self, func):
        parents = self.get_parent_nodes(func)
        for r in parents:
            self.edges[r.function].add(func)

        children = self.get_children_nodes(func)
        for r in children:
            for f in self.bv.get_functions_containing(r):
                self.edges[func].add(f)

        
        #TODO: if a layer was expanded and a new node was added, check if it has a child that's in current graph. If it is, add an edge, else add '...' if it has other children

        #TODO: iterate over IL and add nodes and edge if there is a reference to a function
        #TODO: data vars
        self.update_graph()



class ProximityViewType(ViewType):
    def __init__(self):
        super(ProximityViewType, self).__init__("Proximity View", "Proximity")

    def getPriority(self, data, filename):
        if data.executable:
            # Use low priority so that this view is not picked by default
            return 1
        return 0

    def create(self, data, view_frame):
        return ProximityWidget(view_frame, data)
ViewType.registerViewType(ProximityViewType())

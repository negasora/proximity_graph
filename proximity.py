from binaryninja.function import InstructionTextToken, DisassemblyTextLine, Function
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninjaui import FlowGraphWidget, ViewType

class ProximityGraph(FlowGraph):
    def __init__(self, funcs, edges):
        super(ProximityGraph, self).__init__()
        self.prox = {}
        self.funcs = funcs
        
        for i in self.funcs:
            if type(i) != Function:
                print(type(i))
                return False

        self.edges = edges

        self.uses_block_highlights = True
        self.uses_instruction_highlights = False
        self.includes_user_comments = True
        self.allows_patching = False
    

    def populate_nodes(self):
        nodes = []
        for i in self.funcs:
            self.add_node(i)
            #print("Added node for: {}".format(i.name))

        for src_func in self.edges:
            for end_func in self.edges[src_func]:
                self.add_edge(src_func, end_func)
        
        for node in nodes:
            self.append(node)

    def add_node(self, func):
        func_node = FlowGraphNode(self)
        line = DisassemblyTextLine([])
        line.tokens.append(InstructionTextToken(InstructionTextTokenType.CodeSymbolToken, func.name, value=func.start, address=func.start))
        func_node.lines = [line]
        self.append(func_node)

    def find_func_node(self, func):
        for i in self.nodes:
            if i.lines[0].tokens[0].address == func.start:
                return i
        return None

    def add_edge(self, start_func, end_func):
        start_func_node = self.find_func_node(start_func)
        end_func_node = self.find_func_node(end_func)

        if not start_func_node:
            self.add_node(start_func)
            start_func_node = self.find_func_node(start_func)
        
        if not end_func_node:
            self.add_node(end_func)
            end_func_node = self.find_func_node(end_func)
        
        #TODO do nothing if edge already exists
        start_func_node.add_outgoing_edge(BranchType.UnconditionalBranch, end_func_node)
        #print("added edge: {} -> {}".format(start_func.name, end_func.name))

    def update(self):
        return ProximityGraph(self.funcs, self.edges)




class ProximityView(FlowGraphWidget):
    def __init__(self, parent, data):
        self.data = data
        self.function = data.entry_function
        self.graph = None
        self.proximity_map = {}
        # TODO: update proximity map when functions added/removed/updated

        # init every func proximity to empty
        for func in self.data.functions:
            self.proximity_map[func] = set()
        
        # populate func proximity
        for function in self.data.functions:
            for ref_func in self.get_functions_that_ref(function):
                self.proximity_map[ref_func].add(function)
        
        self.graph_funcs = [self.function]
        self.graph_edges = {self.function: self.proximity_map[self.function]}
        for i in self.proximity_map[self.function]:
            self.graph_funcs.append(i)

        if not self.function is None:
            self.graph = ProximityGraph(self.graph_funcs, self.graph_edges)
        super(ProximityView, self).__init__(parent, data, self.graph)


    def get_functions_that_ref(self, func):
        out = set()
        refs = self.data.get_code_refs(func.start)
        for ref in refs:
            funcs = self.data.get_functions_containing(ref.address)
            if not funcs:
                continue
            for ref_func in funcs:
                out.add(ref_func)
        return out

    def navigate(self, addr):
        func = self.data.get_function_at(addr)
        
        if func is None:
            # No function contains this address, fail navigation in this view
            return False

        return self.navigateToFunction(func, addr)

    def navigateToFunction(self, func, addr):
        # print("navigate")

        if func in self.graph_funcs:
            #print("func already in graph")
            self.showAddress(addr, True)
            if not func in self.graph_edges:
                prox_funcs = self.proximity_map[func]
                if len(prox_funcs) == 0:
                    return True
                for i in prox_funcs:
                    self.graph_funcs.append(i)
                self.graph_edges[func] = prox_funcs
                self.graph = ProximityGraph(self.graph_funcs, self.graph_edges)
                self.setGraph(self.graph, addr)
            return True

        #print("func not in graph")
        # Moving to new function, empty everything
        self.function = func
        self.graph_funcs = [func]
        for i in self.proximity_map[func]:
            self.graph_funcs.append(i)
        self.graph_edges = {func: self.proximity_map[func]}
        newgraph = ProximityGraph(self.graph_funcs, self.graph_edges)
        self.graph = newgraph
        self.setGraph(self.graph, addr)
        return True




class ProximityViewType(ViewType):
    def __init__(self):
        super(ProximityViewType, self).__init__("Proximity View", "Proximity")

    def getPriority(self, data, filename):
        if data.executable:
            # Use low priority so that this view is not picked by default
            return 1
        return 0

    def create(self, data, view_frame):
        return ProximityView(view_frame, data)


# Register the view type so that it can be chosen by the user
ViewType.registerViewType(ProximityViewType())


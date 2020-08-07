from binaryninja.function import InstructionTextToken, DisassemblyTextLine, Function
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninjaui import FlowGraphWidget, ViewType

#TODO: highlight red on update, change edges to red, 
#TODO: handle function updates
#TODO: handle data and imports
#TODO: first flowgraph always saved :/ opening a second bndb fails
#TODO: move to per-function proximity

class ProximityGraph(FlowGraph):
    def __init__(self, bv, prox_nodes={}, edges={}):
        super(ProximityGraph, self).__init__()
        self.prox_nodes = prox_nodes
        self.edges = edges

        self.bv = bv

        self.uses_block_highlights = True
        self.uses_instruction_highlights = False
        self.includes_user_comments = True
        self.allows_patching = False


    def populate_nodes(self):
        # TODO: configurable initial depth setting

        if self.prox_nodes != {}:
            for func in self.prox_nodes:
                node = self.prox_nodes[func]
                self.append(node)

            for edge_start in self.edges:
                for edge_end in self.edges[edge_start]:
                    self.add_edge(edge_start, edge_end)
            return

        # queue the ones that we have in prox_nodes but not as a key in edges
        queue = [self.bv.entry_function]
        while len(queue) != 0:
            print(len(queue))
            func = queue.pop(0)
            if func in self.edges:
                continue
            self.prox_for_func(func)
            queue += self.edges[func]


    def prox_for_func(self, f):
        if not f in self.edges:
            self.edges[f] = set()
        prox = set()
        for r in self.bv.get_code_refs_from(f.start, f, f.arch, f.highest_address - f.lowest_address):
            ref_func = self.bv.get_function_at(r)
            if ref_func is None:
                print(f"Not a real function: 0x{r:x}")
                continue
            self.add_edge(f, ref_func)
            prox.add(ref_func)
        return prox



    def add_node(self, func):
        func_node = FlowGraphNode(self)
        line = DisassemblyTextLine([])
        line.tokens.append(InstructionTextToken(InstructionTextTokenType.CodeSymbolToken, func.name, value=func.start, address=func.start))
        func_node.lines = [line]
        self.prox_nodes[func] = func_node
        self.append(func_node)
        return func_node


    def add_edge(self, start_func, end_func):
        start_node = self.prox_nodes.get(start_func)
        end_node = self.prox_nodes.get(end_func)

        if start_node is None:
            start_node = self.add_node(start_func)

        if end_node is None:
            end_node = self.add_node(end_func)

        if not start_func in self.edges:
            print("AAAAAAAAAAAAAAAAAAAAAA", start_func)
            self.edges[start_func] = set([end_func])
        else:
            # don't add duplicate edges
            if end_func in self.edges[start_func]:
                return
            self.edges[start_func].add(end_func)

        start_node.add_outgoing_edge(BranchType.UnconditionalBranch, end_node)
        print("added edge: {} -> {}".format(start_func.name, end_func.name))


    def update(self):
        return ProximityGraph(self.bv, self.prox_nodes, self.edges)


class ProximityView(FlowGraphWidget):
    def __init__(self, parent, bv):
        self.bv = bv
        # TODO: update proximity map when functions added/removed/updated

        self.graph = ProximityGraph(self.bv)
        super(ProximityView, self).__init__(parent, self.bv, self.graph)


    def navigate(self, addr):
        f = self.bv.get_function_at(addr)
        if f is None:
            return False
        return self.navigateToFunction(f, addr)

    def navigateToFunction(self, func, addr):
        print(func, addr)
        self.graph.prox_for_func(func)
        self.setGraph(self.graph.update(), func.start)
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

from binaryninjaui import DockContextHandler, DockHandler
from PySide2.QtCore import Qt
from PySide2.QtWebEngineWidgets import QWebEngineView
from PySide2.QtWidgets import QApplication, QGridLayout, QWidget

from .proximity_widget import ProximityWidget


class ProximityDockWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name, view):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)
        self.view = view
        self.graph_widget = ProximityWidget(self, view)
        self.layout = QGridLayout(self)
        self.layout.addWidget(self.graph_widget)

    """
    def notifyViewChanged(self, view_frame):
        view = view_frame.getCurrentViewInterface()
        if view is None:
            self.graph_widget = None
            return

        widget = ProximityWidget(self, view)
        if widget is None or self.graph_widget == widget:
            return

        #if self.graph_widget is not None:
        #    self.graph_widget.disconnect(self)

        self.graph_widget = widget
        #TODO: connect here?
    """


    @staticmethod
    def create_widget(name, parent, data=None):
        return ProximityDockWidget(parent, name, data)

def addDockWidget():
    if len(QApplication.allWidgets()) == 0:
        return
    w = QApplication.allWidgets()[0].window()
    w.findChild(DockHandler, '__DockHandler').addDockWidget("Proximity", ProximityDockWidget.create_widget)

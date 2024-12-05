import tkinter

def get_sources(path):
    tcl = tkinter.Tcl()

    tcl.call('set', 'ENTITY_BASE', '/Users/paprikadobi/Documents/vut/axe/kyber-opt')
    tcl.evalfile(path)

    return list(tcl.call('set', 'PACKAGES')) + list(tcl.call('set', 'MOD'))
import idaapi
import subprocess
import sys, os, re, struct
from idc import *
from idaapi import *
from PySide import QtGui, QtCore

import timeit

DBG = False

ADDRINT_SIZE = 4
TMPDIR = os.getenv('TMP')
INFILE_PATH = '%s\\classident.in' % TMPDIR
OUTFILE_PATH = '%s\\classident.out' % TMPDIR
# TOOL_PATH = 'C:\\pin\\source\\tools\\ManualExamples\\obj-ia32'
TOOL_PATH = '%s\\plugins\\ClassIdent' % GetIdaDirectory()
PIN_PATH = TOOL_PATH

RUN32 = '"%s\\ia32\\bin\\pin.exe" -t "%s\\classident.dll" -- "%s"' % \
        (PIN_PATH, TOOL_PATH, GetInputFilePath())
RUN64 = '"%s\\intel64\\bin\\pin.exe" -t "%s\\classident64.dll" -- "%s"' % \
        (PIN_PATH, TOOL_PATH, GetInputFilePath())

# import static analysis parts from subfolders
sys.path.insert(0, '%s\\' % TOOL_PATH)



# ===================================== SHOW RESULTS =================================
class ThisfForm_t(PluginForm):

    def onDoubleClickItem(self, item, column):
        if hasattr(item, 'pointer'):
            ea = item.pointer
            Jump(ea)

    def PopulateTree(self):
        self.tree.clear()
        for cname, funcs in nameFuncs.iteritems():
            root = QtGui.QTreeWidgetItem(self.tree)
            root.setText(0, cname)
            for fun in funcs:
                faddr = fun[0]
                fisconstr = fun[1]
                f = QtGui.QTreeWidgetItem(root)
                label = EAFORMAT % faddr
                demangleName = Demangle(GetFunctionName(faddr), INF_SHORT_DN)
                if demangleName:
                    label += ' - %s' % demangleName
                if fisconstr:
                    label += ' (CONSTRUCTOR)'
                f.setText(0, label)
                f.pointer = faddr


    def OnCreate(self, form):
        self.parent = self.FormToPySideWidget(form)
        self.tree = QtGui.QTreeWidget()
        self.tree.setHeaderLabels(("Classes",))
        self.tree.setColumnWidth(0, 100)
        self.tree.connect(self.tree, QtCore.SIGNAL("itemDoubleClicked(QTreeWidgetItem*, int)"), self.onDoubleClickItem)

        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.tree)

        self.PopulateTree()
        self.parent.setLayout(layout)


    def OnClose(self, form):
        print "Closed"


    def Show(self):
        return PluginForm.Show(self,
                               "[Class Identifier]")
#                               options=PluginForm.FORM_PERSIST)

# =================== PLUGIN WRAPPER =======================================
class ClassIdent(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "ClassIdent - IDAPython plugin for classes' functions identification using static and dynamic analysis"

    help = "This is help"
    wanted_name = "ClassIdent"
    wanted_hotkey = "Alt-F8"

    def init(self):
        idaapi.msg("ClassIdent init() called!\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg("ClassIdent run() called with %d!\n" % arg)
        main()

    def term(self):
        idaapi.msg("ClassIdent term() called!\n")


def PLUGIN_ENTRY():
    return ClassIdent()


# ===================================== ANALYSIS ====================================
def static():
    global rttiEnabled
    global img_base
    global virtualFunctions
    virtualFunctions = set()
    rttiEnabled = rtti.getRTTIData()
    thiscall.findThisFuncByCall()
    # funcs list
    funcs = thisfunc.findThisFuncs()
    funcs = funcs.union(thiscall.simpFuncs).union(thiscall.virtCalls)
    if rttiEnabled:
        for c in rtti.classVFuncDict:
            virtualFunctions = virtualFunctions.union(rtti.classVFuncDict[c])
    funcs = funcs.union(virtualFunctions)
    if len(funcs) == 0:
        msg("Error: nothing found")
        exit(2)

    img_base = get_imagebase()
    # write to input file for pintool
    with open(INFILE_PATH, 'wb') as f:
        for func in funcs:
            fmt = 'Q'
            if not __EA64__:
                fmt = 'L'
            f.write(struct.pack(fmt, func - img_base))

def init():
    global __EA64__
    global EAFORMAT
    info = get_inf_structure()
    if info.is_64bit():
        __EA64__ = True
    elif info.is_32bit():
        __EA64__ = False
    else:
        print "Error"
    EAFORMAT = "%X"
    #EAFORMAT = "%08X" if not __EA64__ else "%016X"

def analys():
    global nameFuncs

    # Load PIN output
    objectRecords = set()
    # Optimization
    blck_size = 4 * 3 if not __EA64__ else 8*3

    seg = get_segm_by_name('.rdata')
    rdataStart = seg.startEA
    rdataEnd = seg.endEA
    seg = get_segm_by_name('.data')
    dataStart = seg.startEA
    dataEnd = seg.endEA

    # Loading
    objConstr = {}
    constrFuncs = {}
    constrName = {}
    with open(OUTFILE_PATH, "rb") as f:
        while True:
            rec = f.read(blck_size)
            if len(rec) != blck_size:
                break
            if not __EA64__:
                rec = struct.unpack('LLL', rec)
            else:
                rec = struct.unpack('QQQ', rec)
            obj, vft, fun = rec
            vft += img_base
            fun += img_base

            fu = get_func(fun)
            if fu:
                if fu.startEA != fun:
                    continue

            if rttiEnabled:
                # check vftable
                if vft <= img_base or  not ((vft >= dataStart and vft < dataEnd) or (vft >= rdataStart and vft < rdataEnd)):
                        vft = 0
            # check function (VERY SLOW!!)
            # if fun not in virtualFunctions:
            #    if not thisfunc.isThisFunc(fun):
            #        continue
            #print '%x' % fun
            if not objConstr.has_key(obj):
                constr = fun
                objConstr[obj] = constr
                if vft != 0:
                    if not constrName.has_key(fun):
                        name = rtti.getPlainTypeNameByVft(vft)
                        constrName[constr] = (name, True) if name else (('Class_'+EAFORMAT) % constr, False)
                else:
                    constrName[constr] = (('Class_'+EAFORMAT) % constr, False)
                if not constrFuncs.has_key(constr):
                    constrFuncs[constr] = set([(constr, True)])
            else:
                constr = objConstr[obj]
                if rttiEnabled:
                    if not constrName[constr][1]:
                        name = rtti.getPlainTypeNameByVft(vft) if vft != 0 else None
                        if name:
                            constrName[constr] = (name, True)
                if (fun, True) not in constrFuncs[constr]:
                    constrFuncs[constr].add((fun, False))

    nameFuncs = {}
    for constr in constrName:
        name = constrName[constr][0]
        if constrName[constr][1]:
            if not nameFuncs.has_key(name):
                nameFuncs[name] = constrFuncs[constr]
            else:
                nameFuncs[name] = nameFuncs[name].union(constrFuncs[constr])
                constrs = set([f[0] for f in nameFuncs[name] if f[1]])
                notconstrs = set([f[0] for f in nameFuncs[name] if not f[1]])
                fakes = constrs.intersection(notconstrs)
                for f in fakes:
                    nameFuncs[name].remove((f, True))
        else:
            nameFuncs[name] = constrFuncs[constr]

    #if rttiEnabled:
    #    for name, funcs in rtti.classVFuncDict.iteritems():
    #        funcs = set([(f, False) for f in funcs])
    #        if not nameFuncs.has_key(name):
    #            nameFuncs[name] = funcs
    #        else:
    #            nameFuncs[name] = nameFuncs[name].union(funcs)


def main():
    global rtti
    global thisfunc
    global thiscall
    try:
        import rtti
        import thisfunc
        import thiscall
    except:
        msg("Wrong install. Lib files for ClassIdent was not found!")
    init()
    static()

    runcmd =  RUN32 if not __EA64__ else RUN64
    subprocess.check_call(runcmd)

    analys()
    try:
        del ThisfForm
    except:
        ThisfForm = ThisfForm_t()
        ThisfForm.Show()
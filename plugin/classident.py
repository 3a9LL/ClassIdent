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
        for c in constrFuncs:
            functions = constrFuncs[c]
            root = QtGui.QTreeWidgetItem(self.tree)
            className = constrName[c][0] if rttiEnabled else ('Class_'+EAFORMAT) % (c+img_base)
            root.setText(0, className)
            # print '0x%x'%funs[0]
            for fun in functions:
                f = QtGui.QTreeWidgetItem(root)
                fun += img_base
                label = EAFORMAT % fun
                demangleName = Demangle(GetFunctionName(fun), INF_SHORT_DN)
                if demangleName:
                    label += ' - %s' % demangleName
                elif c + img_base == fun:
                    label += ' - %s::%s()' % (className,className)
                f.setText(0, label)
                f.pointer = fun


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

    # name-vftable list
    # TODO

    img_base = get_imagebase()
    # write to input file for pintool
    with open(INFILE_PATH, 'wb') as f:
        for func in funcs:
            print '\t%s(0x%x)' % (Demangle(GetFunctionName(func), INF_SHORT_DN), func)
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
    global constrFuncs
    global constrName

    # Load PIN output
    objectRecords = set()
    # Optimization
    blck_size = 4 * 3 if not __EA64__ else 8*3

    seg = get_segm_by_name('.rdata')
    rdataStart = seg.startEA - img_base
    rdataEnd = seg.endEA - img_base
    seg = get_segm_by_name('.data')
    dataStart = seg.startEA - img_base
    dataEnd = seg.endEA - img_base

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

            if rttiEnabled:
                # check vftable
                if vft != 0:
                    if not ((vft >= dataStart and vft < dataEnd) or (vft >= rdataStart and vft < rdataEnd)):
                        vft = 0
            # check function (VERY SLOW!!)
            # if fun not in virtualFunctions:
            #    if not thisfunc.isThisFunc(fun):
            #        continue
            #print '%x' % fun
            if not objConstr.has_key(obj):
                objConstr[obj] = fun
                if rttiEnabled:
                    constrName[fun] = (('Class_'+EAFORMAT) % (fun + img_base), False)
                constrFuncs[fun] = set([fun])
            else:
                constr = objConstr[obj]
                if rttiEnabled:
                    if not constrName[constr][1]:
                        name = rtti.getPlainTypeNameByVft(vft + img_base) if vft != 0 else None
                        if name:
                            constrName[constr] = (name, True)
                constrFuncs[constr].add(fun)

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

    if not __EA64__:
        print RUN32
        subprocess.check_call(RUN32)
    else:
        print RUN64
        subprocess.check_call(RUN64)
    analys()
    try:
        del ThisfForm
    except:
        ThisfForm = ThisfForm_t()
        ThisfForm.Show()
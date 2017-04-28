from idc import *
from idaapi import *
from idautils import *

import subprocess
import re
from collections import namedtuple
from PySide import QtGui, QtCore

DBG = False

# Jump and call instruction checks
def isJump(cur):
    inst = DecodeInstruction(cur)
    mnem = inst.itype
    return mnem >= NN_ja and mnem <= NN_jmpshort
def isCall(cur):
    inst = DecodeInstruction(cur)
    mnem = inst.itype
    return mnem >= NN_call and mnem <= NN_callni

# Amnalysis states
class AS:
    START = 0
    PUSHED = 1

def isThisFunc(func):
    global DBG

    def isPush(cur):
        return GetMnem(cur)=='push' and GetOpnd(cur, 0).endswith('cx')
    def isToLocReg(cur):
        if GetMnem(cur) == 'mov' and GetOpnd(cur, 1).endswith('cx'):
            op1t = GetOpType(cur, 0)
            o1 = GetOpnd(cur, 0)
            if op1t == o_reg or \
                (op1t == o_displ and 'sp' in o1 or 'bp' in o1):
                return True
        return False
    def isEcxChange(cur):
        mnem = GetMnem(cur)
        return (GetOpnd(cur, 0) in ['cl', 'cx', 'ecx', 'rcx'] or \
            mnem.startswith("loop") or \
            mnem.startswith("rep")) and \
            mnem != 'push'
    def isEcxUse(cur):
        return  ("cx" in GetOpnd(cur, 0) and GetOpType(cur,0) == o_displ) or \
                ("cx" in GetOpnd(cur, 1) and GetOpType(cur, 1) == o_displ)

    flags = GetFunctionFlags(func)
    if flags & (FUNC_THUNK):
        return False
    state = AS.START
    for cur in FuncItems(func):
        if DBG: print GetDisasm(cur)
        if isJump(cur) or isCall(cur):
            break
        if state == AS.START:
            if isEcxChange(cur):
                break
            elif isToLocReg(cur):
                return True
            # push
            elif isPush(cur):
                state = AS.PUSHED
                pushLevel = 1
            # use cx
            elif isEcxUse(cur):
                return True
        elif state == AS.PUSHED:
            if GetMnem(cur) == 'push':
                pushLevel += 1
            elif GetMnem(cur) == 'pop':
                pushLevel -= 1
                if pushLevel==0:
                    if GetOpnd(cur,0) in ['ecx', 'rcx']:
                        state = AS.START
                    else:
                        break
            elif isToLocReg(cur):
                return True
            elif isEcxUse(cur):
                return True
    return False


def findByFunc():
    funcs = set()
    # by function
    for f in Functions():
        if isThisFunc(f):
            funcs.add(f)
    return funcs

def findThisFuncs():
    funcs = findByFunc()
    return set(funcs)
#    return funcs

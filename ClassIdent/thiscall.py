from idc import *
from idaapi import *
from idautils import *

CALL_OPTYPES = [o_displ, o_phrase, o_reg, 2]

def fixFunction(ea):
    flags = get_flags_novalue(ea)
    if not isCode(flags):
        create_insn(ea)
        add_func(ea, BADADDR)
    elif not isFunc(flags):
        add_func(ea, BADADDR)

def isCall(cur):
    inst = DecodeInstruction(cur)
    mnem = inst.itype
    return mnem >= NN_call and mnem <= NN_callni

def get_basic_block_begin_from_ea(ea):
    oldea = 0
    while get_first_fcref_to(ea) == BADADDR and get_first_fcref_from(
            get_first_cref_to(ea)) == BADADDR and ea != BADADDR:
        oldea = ea
        ea = get_first_cref_to(ea)
    if ea == BADADDR:
        return oldea
    return ea


def isThisCall(cur):
    if not isCode(GetFlags(cur)) or \
                    not isCall(cur) or not GetOpType(cur,0) in CALL_OPTYPES:
        return False

    global DBG
    blck_startEa = get_basic_block_begin_from_ea(cur)
    while cur > blck_startEa:
        prev = PrevHead(cur)
        #print 'cur=%08x blck_start=%08x %s'%(cur, blck_startEa, GetDisasm(prev))
        if not isCode(GetFlags(prev)):
            break
        if GetMnem(prev).startswith('rep') or GetMnem(prev).startswith('loop') or isCall(prev):
            break
        if GetOpnd(prev, 0) in ['ecx','rcx']:
            # change test cx
            if GetMnem(prev) not in ['lea', 'mov', 'add']:
                break
            # this -> cx
            #elif ((GetOpType(prev, 1) == o_displ or GetOpType(prev, 1) == o_reg) and GetMnem(prev) in ['lea', 'mov']):
            elif GetMnem(prev) in ['lea', 'mov']:
                return True
            elif not (GetOpType(prev, 1) == o_imm and GetMnem(prev) == 'add'):
                break
        cur = prev
    return False


simpFuncs = set([])
virtCalls = set([])
def findThisFuncByCall():
    global simpFuncs
    global virtCalls
    # by call
    for seg_ea in Segments():
       for head in Heads(seg_ea, SegEnd(seg_ea)):
            if isThisCall(head):
                if GetOpType(head, 0) in CALL_OPTYPES:
                    #print 'V %08x' % (head)
                    virtCalls.add(head)
                else:
                    #print "S %08x" % (head),
                    f = GetOperandValue(head, 0)
                    fixFunction(f)
                    flags = GetFunctionFlags(f)
                    if flags & FUNC_LIB:
                        #print 'LIB'
                        continue
                    if flags & FUNC_THUNK:
                        #print 'THUNK'
                        f = GetOperandValue(f, 0)
                        fixFunction(f)
                    simpFuncs.add(f)

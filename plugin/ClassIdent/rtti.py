from idaapi import *
from idautils import *
from idc import *
import ctypes

# =========== CONSTANTS =============
FORMAT_RTTI_VFTABLE = "??_7%s6B@"
FORMAT_RTTI_VFTABLE_PREFIX = "??_7"
FORMAT_RTTI_TYPE = "??_R0?%s@8"
FORMAT_RTTI_BCD = "??_R1%s%s%s%s%s8"
FORMAT_RTTI_BCA = "??_R2%s8"
FORMAT_RTTI_CHD = "??_R3%s8"
FORMAT_RTTI_COL = "??_R4%s6B@"
FORMAT_RTTI_COL_PREFIX = "??_R4"
TD_TAG = ".?Ax"
CHD_MULTINH = 0x01
CHD_VIRTINH = 0x02
CHD_AMBIGUOUS = 0x04
MNG_NODEFINIT = 0x00000008
MT_MSCOMP = 0x10000000

info = get_inf_structure()
__EA64__ = True if info.is_64bit() else False
EAFORMAT = "%X"
POINTER_SIZE = 4 if not __EA64__ else 8

# =========== GLOBALS ==========================
stringCache = {}
tdSet = set()
bcdSet = set()
chdSet = set()
colList = []
colMap = {}

classVFuncDict = {}
classVFtable = {}

# ============ STRUCTURES =============================
class PMD:
    def __init__(self):
        self.mdisp = None
        self.pdisp = None
        self.vdisp = None

class bcdInfo:
    def __init__(self):
        self.m_name = None
        self.m_attribute = None
        self.m_pmd = PMD()

"""
// std::TypeDescriptor class representation
    struct TypeDescriptor
	{
		ea_t vfptr;	       // TypeDescriptor class vftable
        ea_t _M_data;      // NULL until loaded at runtime
		char _M_d_name[1]; // Mangled name (prefix: .?AV=classes, .?AU=structs)

        static BOOL isValid(ea_t typeInfo);
        static BOOL isTypeName(ea_t name);
        static int  getName(ea_t typeInfo, __out LPSTR bufffer, int bufferSize);
        static void doStruct(ea_t typeInfo);
    };
"""

class TypeDescriptor(ctypes.Structure):
    """"std::TypeDescriptor class representation"""
    _fields_ = [('vfptr', ctypes.c_ulonglong if __EA64__ else ctypes.c_uint),
                ('_M_data', ctypes.c_ulonglong if __EA64__ else ctypes.c_uint),
                ('_M_d_name', ctypes.c_char)]


def TypeDescriptor_isValid(typeInfo):
    if typeInfo in tdSet:
        return True
    if isLoaded(typeInfo):
        ea = getEa(typeInfo+TypeDescriptor.vfptr.offset)
        if isLoaded(ea):
            _M_data = getVerifyEa(typeInfo+TypeDescriptor._M_data.offset)
            if _M_data == 0:
                return isTypeName(typeInfo+TypeDescriptor._M_d_name.offset)
    return False

"""
// "Complete Object Locator" location of the complete object from a specific vftable pointer
    struct _RTTICompleteObjectLocator
	{
		UINT signature;				// 00 32bit zero, 64bit one, until loaded
		UINT offset;				// 04 Offset of this vftable in the complete class
		UINT cdOffset;				// 08 Constructor displacement offset
        #ifndef __EA64__
        ea_t typeDescriptor;	    // 0C (TypeDescriptor *) of the complete class
        ea_t classDescriptor;       // 10 (_RTTIClassHierarchyDescriptor *) Describes inheritance hierarchy
        #else
        UINT typeDescriptor;	    // 0C (TypeDescriptor *) of the complete class  *X64 int32 offset
        UINT classDescriptor;       // 10 (_RTTIClassHierarchyDescriptor *) Describes inheritance hierarchy  *X64 int32 offset
        UINT objectBase;            // 14 Object base offset (base = ptr col - objectBase)
        #endif

        static BOOL isValid(ea_t col);
        #ifndef __EA64__
        static BOOL isValid2(ea_t col);
        #endif
        static void doStruct(ea_t col);
	};
"""
if __EA64__:
    class RTTICompleteObjectLocator(ctypes.Structure):
        """"Complete Object Locator" location of the complete object from a specific vftable pointer"""
        _fields_ = [('signature', ctypes.c_uint),
                    ('offset', ctypes.c_uint),
                    ('cdOffset', ctypes.c_uint),
                    ('typeDescriptor', ctypes.c_uint),
                    ('classDescriptor', ctypes.c_uint),
                    ('objectBase', ctypes.c_uint)]
else:
    class RTTICompleteObjectLocator(ctypes.Structure):
        """"Complete Object Locator" location of the complete object from a specific vftable pointer"""
        _fields_ = [('signature', ctypes.c_uint),
                    ('offset', ctypes.c_uint),
                    ('cdOffset', ctypes.c_uint),
                    ('typeDescriptor', ctypes.c_uint),
                    ('classDescriptor', ctypes.c_uint)]

def RTTICompleteObjectLocator_isValid(col):
    if isLoaded(col):
        signature = getVerify32(col+RTTICompleteObjectLocator.signature.offset)
        if signature == None:
            return False
        if not __EA64__:
            if signature == 0:
                typeInfo = getEa(col + RTTICompleteObjectLocator.typeDescriptor.offset)
                if TypeDescriptor_isValid(typeInfo):
                    classDescriptor = getEa(col + RTTICompleteObjectLocator.classDescriptor.offset)
                    if RTTIClassHierarchyDescriptor_isValid(classDescriptor):
                        return True
        else:
            if signature == 1:
                objectLocator = get_32bit(col + RTTICompleteObjectLocator.objectBase.offset)
                if objectLocator != 0:
                    tdOffset =  get_32bit(col + RTTICompleteObjectLocator.typeDescriptor.offset)
                    if tdOffset != 0:
                        cdOffset = get_32bit(col + RTTICompleteObjectLocator.classDescriptor.offset)
                        if cdOffset != 0:
                            colBase = (col - objectLocator)
                            typeInfo = colBase + tdOffset
                            if TypeDescriptor_isValid(typeInfo):
                                classDescriptor = colBase + cdOffset
                                if RTTIClassHierarchyDescriptor_isValid(classDescriptor, colBase):
                                    return True
    return False

def RTTICompleteObjectLocator_isValid2(col):
    signature = getVerify32(col+RTTICompleteObjectLocator.signature.offset)
    if signature == 0:
        # Verify CHD
        classDescriptor = getEa(col+RTTICompleteObjectLocator.classDescriptor.offset)
        if classDescriptor and classDescriptor!=BADADDR:
            return RTTIClassHierarchyDescriptor_isValid(classDescriptor)
    return False

"""
struct _RTTIClassHierarchyDescriptor
	{
		UINT signature;			// 00 Zero until loaded
		UINT attributes;		// 04 Flags
		UINT numBaseClasses;	// 08 Number of classes in the following 'baseClassArray'
        #ifndef __EA64__
        ea_t baseClassArray;    // 0C _RTTIBaseClassArray*
        #else
        UINT baseClassArray;    // 0C *X64 int32 offset to _RTTIBaseClassArray*
        #endif

        static BOOL isValid(ea_t chd, ea_t colBase64 = NULL);
        static void doStruct(ea_t chd, ea_t colBase64 = NULL);
	};
"""
class RTTIClassHierarchyDescriptor(ctypes.Structure):
    """"Class Hierarchy Descriptor" describes the inheritance hierarchy of a class; shared by all COLs for the class"""
    _fields_ = [('signature', ctypes.c_uint),
                ('attributes', ctypes.c_uint),
                ('numBaseClasses', ctypes.c_uint),
                ('baseClassArray', ctypes.c_uint)]

def RTTIClassHierarchyDescriptor_isValid(chd, colBase64 = 0):
    if chd in chdSet:
        return True
    if isLoaded(chd):
        signature = getVerify32(chd + RTTIClassHierarchyDescriptor.signature.offset)
        if signature==0:
            attributes = getVerify32(chd + RTTIClassHierarchyDescriptor.attributes.offset)
            if attributes!=None and attributes&0xFFFFFFF0==0:
                if getVerify32(chd+RTTIClassHierarchyDescriptor.numBaseClasses.offset)>=1:
                    if __EA64__:
                        baseClassArrayOffset = get_32bit(chd + RTTIClassHierarchyDescriptor.baseClassArray.offset)
                        baseClassArray = colBase64 + baseClassArrayOffset
                    else:
                        baseClassArray = getEa(chd + RTTIClassHierarchyDescriptor.baseClassArray.offset)
                    if isLoaded(baseClassArray):
                        if not __EA64__:
                            baseClassDescriptor = getEa(baseClassArray)
                            return RTTIBaseClassDescriptor_isValid(baseClassDescriptor)
                        else:
                            baseClassDescriptor = colBase64 + get_32bit(baseClassArray)
                            return RTTIBaseClassDescriptor_isValid(baseClassDescriptor, colBase64)
    return False

"""
struct _RTTIBaseClassDescriptor
	{
        #ifndef __EA64__
		ea_t typeDescriptor;        // 00 Type descriptor of the class
        #else
        UINT typeDescriptor;        // 00 Type descriptor of the class  *X64 int32 offset
        #endif
		UINT numContainedBases;		// 04 Number of nested classes following in the Base Class Array
		PMD  pmd;					// 08 Pointer-to-member displacement info
		UINT attributes;			// 14 Flags
        // 18 When attributes & BCD_HASPCHD
        //_RTTIClassHierarchyDescriptor *classDescriptor; *X64 int32 offset

        static BOOL isValid(ea_t bcd, ea_t colBase64 = NULL);
        static void doStruct(ea_t bcd, __out_bcount(MAXSTR) LPSTR baseClassName, ea_t colBase64 = NULL);
	};
"""
BCD_NOTVISIBLE          = 0x01
BCD_AMBIGUOUS           = 0x02
BCD_PRIVORPROTINCOMPOBJ = 0x04
BCD_PRIVORPROTBASE      = 0x08
BCD_VBOFCONTOBJ         = 0x10
BCD_NONPOLYMORPHIC      = 0x20
BCD_HASPCHD             = 0x40
class RTTIBaseClassDescriptor(ctypes.Structure):
    _fields_ = [('typeDescriptor', ctypes.c_uint),
                ('numContainedBases', ctypes.c_uint),
                ('pmd_mdisp', ctypes.c_uint),
                ('pmd_pdisp', ctypes.c_uint),
                ('pmd_vdisp', ctypes.c_uint),
                ('attributes', ctypes.c_uint),
                ('pClassDescriptor', ctypes.c_uint)]

def RTTIBaseClassDescriptor_isValid(bcd, colBase64 = 0):
    if bcd in bcdSet:
        return True
    if isLoaded(bcd):
        attributes = getVerify32(bcd + RTTIBaseClassDescriptor.attributes.offset)
        if attributes!=None and attributes&0xFFFFFF00==0:
            if not __EA64__:
                return TypeDescriptor_isValid(getEa(bcd + RTTIBaseClassDescriptor.typeDescriptor.offset))
            else:
                tdOffset = get_32bit(bcd + RTTIBaseClassDescriptor.typeDescriptor.offset)
                typeInfo = colBase64 + tdOffset
                return TypeDescriptor_isValid(typeInfo)
    return False

# vftable info container
class vtinfo:
    def __init__(self, start=None, end=None):
        self.start = start
        self.end = end
        self.methodCount = 0

# ============ FUNCTIONS =====================

# __unDName
import ctypes.wintypes

UNDNAME_COMPLETE = 0x0000 #Enables full undecoration.
UNDNAME_NO_LEADING_UNDERSCORES = 0x0001 #Removes leading underscores from Microsoft extended keywords.
UNDNAME_NO_MS_KEYWORDS = 0x0002 #Disables expansion of Microsoft extended keywords.
UNDNAME_NO_FUNCTION_RETURNS = 0x0004 #Disables expansion of return type for primary declaration.
UNDNAME_NO_ALLOCATION_MODEL = 0x0008 #Disables expansion of the declaration model.
UNDNAME_NO_ALLOCATION_LANGUAGE = 0x0010 #Disables expansion of the declaration language specifier.
UNDNAME_RESERVED1 = 0x0020 #RESERVED.
UNDNAME_RESERVED2 = 0x0040 #RESERVED.
UNDNAME_NO_THISTYPE = 0x0060 #Disables all modifiers on the this type.
UNDNAME_NO_ACCESS_SPECIFIERS = 0x0080 #Disables expansion of access specifiers for members.
UNDNAME_NO_THROW_SIGNATURES = 0x0100 #Disables expansion of "throw-signatures" for functions and pointers to functions.
UNDNAME_NO_MEMBER_TYPE = 0x0200 #Disables expansion of static or virtual members.
UNDNAME_NO_RETURN_UDT_MODEL = 0x0400 #Disables expansion of the Microsoft model for UDT returns.
UNDNAME_32_BIT_DECODE = 0x0800 #Undecorates 32-bit decorated names.
UNDNAME_NAME_ONLY = 0x1000 #Gets only the name for primary declaration; returns just [scope::]name. Expands template params.
UNDNAME_TYPE_ONLY = 0x2000 #Input is just a type encoding; composes an abstract declarator.
UNDNAME_HAVE_PARAMETERS = 0x4000 #The real template parameters are available.
UNDNAME_NO_ECSU = 0x8000 #Suppresses enum/class/struct/union.
UNDNAME_NO_IDENT_CHAR_CHECK = 0x10000 #Suppresses check for valid identifier characters.
UNDNAME_NO_PTR64 = 0x20000 #Does not include ptr64 in output.
UNDNAME_SCOPES_ONLY = UNDNAME_NO_LEADING_UNDERSCORES \
                          | UNDNAME_NO_MS_KEYWORDS \
                          | UNDNAME_NO_FUNCTION_RETURNS \
                          | UNDNAME_NO_ALLOCATION_MODEL \
                          | UNDNAME_NO_ALLOCATION_LANGUAGE \
                          | UNDNAME_NO_ACCESS_SPECIFIERS \
                          | UNDNAME_NO_THROW_SIGNATURES \
                          | UNDNAME_NO_MEMBER_TYPE \
                          | UNDNAME_NO_ECSU \
                          | UNDNAME_NO_IDENT_CHAR_CHECK
SHORT_UNIQUE_NAME = UNDNAME_NO_MS_KEYWORDS | UNDNAME_NO_ACCESS_SPECIFIERS | UNDNAME_NO_ECSU

def __unDName(name, options):
    __undname = ctypes.windll.dbghelp.UnDecorateSymbolName
    __undname.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]
    if options is None:
        options = SHORT_UNIQUE_NAME
    buffer = ctypes.create_string_buffer(1024 * 16)
    res = __undname(str(name), buffer, ctypes.sizeof(buffer), options)
    if res:
        return buffer.value
    else:
        return None


def getEa(ea):
    if __EA64__:
        return get_64bit(ea)
    else:
        return get_32bit(ea)

def getPlainTypeNameByVft(vft):
    col = getEa(vft-POINTER_SIZE)
    if not __EA64__:
        if not RTTICompleteObjectLocator_isValid2(col):
            return None
        td = getEa(col + RTTICompleteObjectLocator.typeDescriptor.offset)
    else:
        if not RTTICompleteObjectLocator_isValid(col):
            return None
        tdOffset = get_32bit(col + RTTICompleteObjectLocator.typeDescriptor.offset)
        objectLocator = get_32bit(col + RTTICompleteObjectLocator.objectBase.offset)
        colBase = col - objectLocator
        td = colBase + tdOffset
    colName = getTypeName(td)
    demangledColName = getPlainTypeName(colName)
    return demangledColName

def getVerify32(ea):
    if isLoaded(ea):
        return get_32bit(ea)
    return None

def getVerifyEa(ea):
    if isLoaded(ea):
        return getEa(ea)
    return None

def readIdaString(ea):
    if stringCache.has_key(ea):
        return stringCache.get(ea)
    else:
        len = get_max_ascii_length(ea, ASCSTR_C, ALOPT_IGNHEADS)
        if len > 0:
            s = get_ascii_contents2(ea, len, ASCSTR_C)
            if s:
                stringCache[ea] = s
                return s
    return ""

def isTypeName(name_ea):
    if get_byte(name_ea) == ord('.'):
        s = readIdaString(name_ea)
        if __unDName(s[1:], (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY)):
            return True
    return False

def RTTICompleteObjectLocator_doStruct(col):
    pass

def scanSeg4Cols(seg):
    name = get_true_segm_name(seg)
    if name <= 0:
        name = '???'
    msg((" N: \"%s\", A: "+EAFORMAT+" - "+EAFORMAT+", S: %d bytes.\n")%(name, seg.startEA, seg.endEA, seg.size()))
    found = 0
    if seg.size() >= ctypes.sizeof(RTTICompleteObjectLocator):
        padd = ctypes.sizeof(ctypes.c_uint)
        startEA = (seg.startEA + padd) & ~(padd-1)
        endEA = (seg.endEA-ctypes.sizeof(RTTICompleteObjectLocator))
        ptr = startEA
        while ptr < endEA:
            if __EA64__:
                if get_32bit(ptr + RTTICompleteObjectLocator.signature.offset) == 1:
                    if RTTICompleteObjectLocator_isValid(ptr):
                        colList.append(ptr)
                        RTTICompleteObjectLocator_doStruct(ptr)
                        ptr += ctypes.sizeof(RTTICompleteObjectLocator)
                        found += 1
                        continue
            else:
                ea = getEa(ptr)
                if ea >= 0x10000:
                    if TypeDescriptor_isValid(ea):
                        #print 'TD Found! 0x" + EAFORMAT + " from ptr = 0x" + EAFORMAT + "'%(ea, ptr)
                        col = ptr - RTTICompleteObjectLocator.typeDescriptor.offset
                        if RTTICompleteObjectLocator_isValid2(col):
                            colList.append(col)
                            RTTICompleteObjectLocator_doStruct(col)
                            ptr += ctypes.sizeof(RTTICompleteObjectLocator)
                            found += 1
                            continue
            ptr += padd
    if found:
        msg(" Count: %d\n"%found)
    return False

# Locate COL by descriptor list
def findCols():
    global colList
    segSet = set()
    colList = []
    seg = get_segm_by_name(".rdata")
    if seg:
        segSet.add(seg)
        if scanSeg4Cols(seg):
            return False
    segCount = get_segm_qty()

    # And ones named ".data"
    for i in xrange(segCount):
        seg = getnseg(i)
        if seg and seg.type==SEG_DATA:
            if seg not in segSet and get_true_segm_name(seg)=='.data':
                segSet.add(seg)
                if scanSeg4Cols(seg):
                    return False
    # If still none found, try any remaining data type segments
    if len(colList)==0:
        for i in xrange(segCount):
            seg = getnseg(i)
            if seg and seg.type==SEG_DATA and seg not in segSet:
                segSet.add(seg)
                if scanSeg4Cols(seg):
                    return False
    msg("     Total COL: %d\n"%(len(colList)))
    return False

def isEa(f):
    if not __EA64__:
        return isDwrd(f)
    else:
        return isQwrd(f)

def setUnknown(ea, size):
    while size > 0:
        isize = get_item_size(ea)
        if isize > size:
            break
        else:
            do_unknown(ea, DOUNK_SIMPLE)
            ea += isize
            size -= isize

def fixEa(ea):
    # TODO: 64 bit support
    if not __EA64__:
        if not isDwrd(get_flags_novalue(ea)):
            setUnknown(ea, POINTER_SIZE)
            doDwrd(ea, POINTER_SIZE)
    else:
        if not isQwrd(get_flags_novalue(ea)):
            setUnknown(ea, POINTER_SIZE)
            doQwrd(ea, POINTER_SIZE)

def fixFunction(ea):
    flags = get_flags_novalue(ea)
    if not isCode(flags):
        create_insn(ea)
        add_func(ea, BADADDR)
    elif not isFunc(flags):
        add_func(ea, BADADDR)

def getTableInfo(ea):
    vi = vtinfo()
    flags = get_flags_novalue(ea)
    if hasRef(flags) and has_any_name(flags) and (isEa(flags) or isUnknown(flags)):
        start = ea
        vi.start = ea
        while True:
            """
            Should be an ea_t offset to a function here (could be unknown if dirty IDB)
            Ideal flags for 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
            dumpFlags(ea);
            """
            indexFlags = get_flags_novalue(ea)
            if (not isEa(indexFlags)) or isUnknown(indexFlags):
                break
            # Look at what this (assumed vftable index) points too
            memberPtr = getEa(ea)
            if not (memberPtr and memberPtr!=BADADDR):
                # vft's often have a zero ea_t (NULL pointer?) following, fix it
                if memberPtr==0:
                    fixEa(ea)
                break
            # Should see code for a good vft method here, but it could be dirty
            flags = get_flags_novalue(memberPtr)
            if not (isCode(flags) or isUnknown(flags)):
                break
            if ea != start:
                if hasRef(indexFlags):
                    break
                if RTTICompleteObjectLocator_isValid(memberPtr):
                    break
            # As needed fix ea_t pointer, and, or, missing code and function def here
            fixEa(ea)
            fixFunction(memberPtr)
            ea += POINTER_SIZE
        vi.methodCount = (ea - start)/POINTER_SIZE
        if vi.methodCount > 0:
            vi.end = ea
            return vi
    return None

def getTypeName(td):
    return readIdaString(td + TypeDescriptor._M_d_name.offset)

def getPlainTypeName(col):
    dname = None
    print "'%s'" % col
    if col[0]=='.':
        dname = __unDName(col[1:], (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY | UNDNAME_NO_ECSU))
        if not dname:
            msg("** getPlainClassName:__unDName() failed to unmangle! input: \"%s\"\n"%col)
            return None
    else:
        dname = demangle_name(col, (MT_MSCOMP | MNG_NODEFINIT))
        if not dname:
            msg("** getPlainClassName:demangle_name() failed to unmangle! input: \"%s\"\n"%col)
            return None
        if dname.find("::`vftable'") >= 0:
            dname = dname[0:dname.find("::`vftable'")]
    return dname

def getBCDInfo(col):
    res = []
    if not __EA64__:
        chd = getEa(col+RTTICompleteObjectLocator.classDescriptor.offset)
    else:
        cdOffset = get_32bit(col + RTTICompleteObjectLocator.classDescriptor.offset)
        objectLocator = get_32bit(col + RTTICompleteObjectLocator.objectBase.offset)
        colBase = col - objectLocator
        chd = colBase + cdOffset
    if chd:
        numBaseClasses = get_32bit(chd + RTTIClassHierarchyDescriptor.numBaseClasses.offset)
        if numBaseClasses:
            if not __EA64__:
                baseClassArray = getEa(chd + RTTIClassHierarchyDescriptor.baseClassArray.offset)
            else:
                bcaOffset = get_32bit(chd + RTTIClassHierarchyDescriptor.baseClassArray.offset)
                baseClassArray = colBase + bcaOffset
            if baseClassArray and baseClassArray!=BADADDR:
                for i in xrange(numBaseClasses):
                    if not __EA64__:
                        bcd = getEa(baseClassArray)
                        td = getEa(bcd+RTTIBaseClassDescriptor.typeDescriptor.offset)
                    else:
                        bcdOffset = get_32bit(baseClassArray)
                        bcd = colBase + bcdOffset
                        tdOffset = get_32bit(bcd + RTTIBaseClassDescriptor.typeDescriptor.offset)
                        td = colBase + tdOffset
                    bi = bcdInfo()
                    print 'td %x name %s' % (td, getTypeName(td))
                    bi.m_name = getTypeName(td)
                    mdisp = get_32bit(bcd + RTTIBaseClassDescriptor.pmd_mdisp.offset)
                    pdisp = get_32bit(bcd + RTTIBaseClassDescriptor.pmd_pdisp.offset)
                    vdisp = get_32bit(bcd + RTTIBaseClassDescriptor.pmd_vdisp.offset)
                    bi.m_pmd.mdisp = mdisp
                    bi.m_pmd.pdisp = pdisp
                    bi.m_pmd.vdisp = vdisp
                    bi.m_attribute = get_32bit(bcd+RTTIBaseClassDescriptor.attributes.offset)
                    res.append(bi)
                    baseClassArray += ctypes.sizeof(ctypes.c_uint)
    return res

def hasUniqueName(ea):
    return has_name(get_flags_novalue(ea))

def serializeName(ea, name):
    for i in xrange(1000000):
        if set_name(ea, '%s_%d'%(name,i), (SN_NON_AUTO | SN_NOWARN)):
            return True
    return False

def processMembers(name, vi):
    global classVFuncDict
    msg(('%s vft ' + EAFORMAT + ' to ' + EAFORMAT + '\n')%(name, vi.start, vi.end))
    ea = vi.start
    while ea < vi.end:
        eaMember = getVerifyEa(ea)
        if eaMember:
            if not get_func(eaMember):
                fixFunction(eaMember)
            if not classVFuncDict.has_key(name):
                classVFuncDict[name] = []
            classVFuncDict[name].append(eaMember)
        ea += POINTER_SIZE

def processVftable(vft, col):
    global classVFtable
    if __EA64__:
        tdOffset = get_32bit(col + RTTICompleteObjectLocator.typeDescriptor.offset)
        objectLocator = get_32bit(col + RTTICompleteObjectLocator.objectBase.offset)
        colBase = col - objectLocator
        td = colBase + tdOffset
    vi = getTableInfo(vft)
    if vi:
        if not __EA64__:
            td = getEa(col + RTTICompleteObjectLocator.typeDescriptor.offset)
            chd = get_32bit(col + RTTICompleteObjectLocator.classDescriptor.offset)
        else:
            cdOffset = get_32bit(col + RTTICompleteObjectLocator.classDescriptor.offset)
            chd = colBase + cdOffset

        colName = getTypeName(td)
        demangledColName = getPlainTypeName(colName)
        chdAttributes =  get_32bit(chd+RTTIClassHierarchyDescriptor.attributes.offset)
        offset = get_32bit(col+RTTICompleteObjectLocator.offset.offset)

        print 'col %x' % col
        classList = getBCDInfo(col)
        numBaseClasses = len(classList)
        isTopLevel = False
        success = False
        cmt = ""
        # Simple or no inheritance
        if offset == 0 and (chdAttributes & (CHD_MULTINH | CHD_VIRTINH)) == 0:
            if not hasUniqueName(vft):
                decorated = FORMAT_RTTI_VFTABLE%(colName[len(TD_TAG):])
                if not set_name(vft, decorated, (SN_NON_AUTO | SN_NOWARN)):
                    serializeName(vft, decorated)
            if not hasUniqueName(col):
                decorated = FORMAT_RTTI_COL%(colName[len(TD_TAG):])
                if not set_name(col, decorated, (SN_NON_AUTO | SN_NOWARN)):
                    serializeName(col, decorated)
            placed = 0
            if numBaseClasses > 1:
                # parent
                plainName = getPlainTypeName(classList[0].m_name)
                cmt = '%s%s: '%(("" if classList[0].m_name[3] == 'V' else "struct "), plainName)
                placed += 1
                isTopLevel = (classList[0].m_name == colName)

                # children
                for i in xrange(1,numBaseClasses):
                    plainName = getPlainTypeName(classList[i].m_name)
                    cmt += '%s%s, '%(("" if classList[i].m_name[3] == 'V' else "struct "), plainName)
                    placed += 1

                # remove the ending ', '
                if placed > 1:
                    cmt = cmt[:-2]
            else:
                cmt = '%s%s: '%("" if colName[3] == 'V' else "struct ", demangledColName)
                isTopLevel = True
            if placed > 1:
                cmt += ';'
            success = True
        # Multiple inheritance, and, or, virtual inheritance hierarchies
        else:
            bi = None
            index = 0
            if offset == 0:
                if not colName==classList[0].m_name:
                    raise AssertionError
                bi = classList[0]
                isTopLevel = True
            else:
                # Get our object BCD level by matching COL offset to displacement
                for i in xrange(numBaseClasses):
                    if classList[i].m_pmd.mdisp == offset:
                        bi = classList[i]
                        index = i
                        break
                # If not found in classList, use the first base object instead
                if not bi:
                    #msg("** " + EAFORMAT + " MI COL class offset: %X(%d) not in BCD.\n" % (vft, offset, offset))
                    for i in xrange(numBaseClasses):
                        if classList[i].m_pmd.pdisp!=-1:
                            bi = classList[i]
                            index = i
                            break
            if bi:
                placed = 0
                if isTopLevel:
                    if not hasUniqueName(vft):
                        decorated = FORMAT_RTTI_VFTABLE%(colName[len(TD_TAG):])
                        if not set_name(vft, decorated, (SN_NON_AUTO | SN_NOWARN)):
                            serializeName(vft, decorated)
                    if not hasUniqueName(col):
                        decorated = FORMAT_RTTI_COL%(colName[len(TD_TAG):])
                        if not set_name(col, decorated, (SN_NON_AUTO | SN_NOWARN)):
                            serializeName(col, decorated)
                    plainName = getPlainTypeName(classList[0].m_name)
                    cmt = '%s%s: '%(("" if classList[0].m_name[3] == 'V' else "struct "), plainName)
                    placed += 1
                    for i in xrange(1,numBaseClasses):
                        plainName = getPlainTypeName(classList[i].m_name)
                        cmt += '%s%s, '%(("" if classList[i].m_name[3] == 'V' else "struct "), plainName)
                        placed += 1
                    if placed > 1:
                        cmt = cmt[:-2]
                else:
                    combinedName = "%s6B%s@"%(colName[len(TD_TAG):],bi.m_name[len(TD_TAG):])
                    if not hasUniqueName(vft):
                        decorated = FORMAT_RTTI_VFTABLE_PREFIX+combinedName
                        if not set_name(vft, decorated, (SN_NON_AUTO | SN_NOWARN)):
                            serializeName(vft, decorated)
                    if not hasUniqueName(col):
                        decorated = FORMAT_RTTI_COL_PREFIX+combinedName
                        if not set_name(col, decorated, (SN_NON_AUTO | SN_NOWARN)):
                            serializeName(col, decorated)
                    plainName = getPlainTypeName(bi.m_name)
                    cmt = '%s%s: '%("" if (bi.m_name[3] == 'V') else "struct ", plainName)
                    index += 1
                    if index < numBaseClasses:
                        while index < numBaseClasses:
                            plainName = getPlainTypeName(classList[index].m_name)
                            cmt += '%s%s, '%(("" if classList[index].m_name[3] == 'V' else "struct "), plainName)
                            placed += 1
                            index += 1
                        if placed > 1:
                            cmt = cmt[:-2]
                if placed>1:
                    cmt += ';'
                success = True
            else:
                msg((EAFORMAT + " ** Couldn't find a BCD for MI/VI hierarchy!\n") % (vft))
        if success:
            cmt += '  %s (#classinformer)'%(attributeLabel(chdAttributes))
            cmtPtr = vft-POINTER_SIZE
            #if not hasAnteriorComment(cmtPtr):
            delete_extra_cmts(cmtPtr, E_PREV)
            describe(cmtPtr, True, '\n; %s %s'%(("class" if (colName[3] == 'V') else "struct"), cmt))
            if not classVFtable.has_key(demangledColName):
                classVFtable[demangledColName] = []
            classVFtable[demangledColName].append(vi.start)
            processMembers(demangledColName, vi)
    else:
        try:
            msg((EAFORMAT + " ** Vftable attached to this COL, error?\n") % (vft))
        except:
            1
        if not hasUniqueName(col):
            td = getEa(col+RTTICompleteObjectLocator.typeDescriptor.offset)
            colName = getTypeName(td)
            decorated = FORMAT_RTTI_COL%(colName[len(TD_TAG):])
            if not set_name(col, decorated, (SN_NON_AUTO | SN_NOWARN)):
                serializeName(col, decorated)

def hasAnteriorComment(ea):
    return (get_first_free_extra_cmtidx(ea, E_PREV) != E_PREV)

def attributeLabel(attributes):
    if (attributes & 3) == CHD_MULTINH:
        return "[MI]"
    elif (attributes & 3) == CHD_VIRTINH:
        return "[VI]"
    elif (attributes & 3) == (CHD_MULTINH | CHD_VIRTINH):
        return "[MI VI]"
    return ""

def scanSeg4Vftables(seg):
    name = get_true_segm_name(seg)
    if name <= 0:
        name = '???'
    msg((" N: \"%s\", A: " + EAFORMAT + " - " + EAFORMAT + ", S: %d bytes.\n")%(name, seg.startEA, seg.endEA, seg.size()))
    found = 0
    if seg.size() >= POINTER_SIZE:
        padd = ctypes.sizeof(ctypes.c_uint)
        startEA = (seg.startEA + padd) & ~(padd-1)
        endEA = (seg.endEA-POINTER_SIZE)
        ptr = startEA
        while ptr < endEA:
            ea = getEa(ptr)
            if colMap.has_key(ea):
                vfptr = ptr+POINTER_SIZE
                method = getEa(vfptr)
                s = getseg(method)
                if s:
                    if s.type == SEG_CODE:
                        #print "vft " + EAFORMAT + " %s"%(vfptr, getPlainTypeName(getTypeName(getEa(ea+RTTICompleteObjectLocator.typeDescriptor.offset))))
                        processVftable(vfptr, ea)
                        colMap[ea] += 1
                        found += 1
            ptr += padd
    if found:
        msg(' Count: %d\n'%found)
        return True
    return False

def findVftables():
    global colMap
    global colList
    colMap = {}
    segSet = set()
    for c in colList:
        colMap[c] = 0
    seg = get_segm_by_name(".rdata")
    if seg:
        segSet.add(seg)
        if scanSeg4Vftables(seg):
            return True
    segCount = get_segm_qty()

    # And ones named ".data"
    for i in xrange(segCount):
        seg = getnseg(i)
        if seg and seg.type==SEG_DATA:
            if seg not in segSet and get_true_segm_name(seg)=='.data':
                segSet.add(seg)
                if scanSeg4Vftables(seg):
                    return True
    # If still none found, try any remaining data type segments
    if len(colList)==0:
        for i in xrange(segCount):
            seg = getnseg(i)
            if seg and seg.type==SEG_DATA and seg not in segSet:
                segSet.add(seg)
                if scanSeg4Vftables(seg):
                    return True
    # Rebuild 'colList' with any that were not located
    else:
        colList = []
        for col in colMap:
            if colMap[col] != 0:
                colList.append(col)
    return False

def getRTTIData():
    global classVFuncDict
    global classVFtable
    classVFuncDict = {}
    classVFtable = {}
    msg("Scanning for RTTI Complete Object Locator.\n")
    findCols()
    #    return True
    # typeDescList = TDs left that don't have a COL reference
    # colList = Located

    # == == Find and process vftables
    msg("Scanning for vtables.\n")
    if findVftables():
        return True
    return False

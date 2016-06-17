import idc

IMPORTS_START = 0x1001A3E8
END_ADDRESS = 0x100021B9


def nextProcName(startAddr, endAddr):
    addr = startAddr
    while addr < endAddr:
        mnem = idc.GetMnem(addr)
        if mnem == 'push':
            optype = idc.GetOpType(addr, 0)
            if optype == 5:
                procaddr = idc.GetOperandValue(addr, 0)
                procname = idc.GetString(procaddr, -1, idc.ASCSTR_C)
                return (procname, idc.NextHead(addr))
        addr = idc.NextHead(addr)
    return ('', addr)



def nextProcAddr(startAddr, endAddr):
    addr = startAddr
    while addr < endAddr:
        mnem = idc.GetMnem(addr)
        if mnem == 'mov':
            op1type = idc.GetOpType(addr, 0)
            op2type = idc.GetOpType(addr, 1)
            if op1type == 4 and op2type == 1:
                regname = idc.GetOpnd(addr, 1)
                if regname == 'eax':
                    offset = idc.GetOperandValue(addr, 0)
                    return (IMPORTS_START + offset, idc.NextHead(addr))
        addr = idc.NextHead(addr)
    return (-1, addr)


def main():
    addr = idc.ScreenEA()

    while addr < END_ADDRESS:
        name, addr = nextProcName(addr, END_ADDRESS)
        apiaddr, addr = nextProcAddr(addr, END_ADDRESS)
        print '%x -> %s' %(apiaddr, name)
        idc.MakeName(apiaddr, name)


if __name__ == '__main__'       :
    main()

def align4(val):
    return (val + 3) & ~3

def align8(val):
    return (val + 7) & ~7

def align16(val):
    return (val + 15) & ~15

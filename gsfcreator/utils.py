import struct
import sys
from . import googleplay_pb2

VERSION = sys.version_info[0]


def readInt(byteArray, start):
    """Read the byte array, starting from *start* position,
    as an 32-bit unsigned integer"""
    return struct.unpack("!L", byteArray[start:][0:4])[0]


def toBigInt(byteArray):
    """Convert the byte array to a BigInteger"""
    array = byteArray[::-1]  # reverse array
    out = 0
    for key, value in enumerate(array):
        if VERSION == 3:
            decoded = struct.unpack("B", bytes([value]))[0]
        else:
            decoded = struct.unpack("B", value)[0]
        out = out | decoded << key * 8
    return out

def hasPrefetch(obj):
    try:
        return len(obj.preFetch) > 0
    except ValueError:
        return False
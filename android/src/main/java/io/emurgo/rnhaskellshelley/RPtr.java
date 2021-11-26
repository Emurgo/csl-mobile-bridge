package io.emurgo.rnhaskellshelley;

import java.math.BigInteger;

public final class RPtr {
    private long ptr;

    public String toString() {
        return Long.toHexString(this.ptr);
    }

    final String toJs() {
        return this.toString();
    }

    final void free() {
        Native.I.ptrFree(this);
    }

    private RPtr(long ptr) {
        this.ptr = ptr;
    }

    RPtr(String str) {
        this(new BigInteger(str, 16).longValue());
    }
}

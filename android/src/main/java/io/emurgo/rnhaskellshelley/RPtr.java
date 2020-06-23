package io.emurgo.rnhaskellshelley;

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
        this(Long.parseLong(str, 16));
    }
}

package sun.misc;

@SuppressWarnings("ALL")
public final class Unsafe {
    private static final Unsafe theUnsafe = new Unsafe();

    public int arrayBaseOffset(Class clazz) {
        throw new RuntimeException("Stub!");
    }

    public native int addressSize();

    public native int pageSize();

    public native void putByte(long address, byte x);

    public native int getInt(long address);

    public native int getInt(Object obj, long offset);

    public native void putInt(long address, int x);

    public native long getLong(long address);

    public native long getLong(Object obj, long offset);

    public native void putLong(long address, long x);

    public native void putLong(Object obj, long offset, long x);

    public native void copyMemoryToPrimitiveArray(long srcAddr, Object dst, long dstOffset, long bytes);

    public native void copyMemoryFromPrimitiveArray(Object src, long srcOffset, long dstAddr, long bytes);

    public native void copyMemory(long srcAddr, long dstAddr, long bytes);
}

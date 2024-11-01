/*
 * Copyright (C) 2024 Eirv
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.eirv.elfloader;

import android.annotation.SuppressLint;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;

import sun.misc.Unsafe;

import java.io.FileDescriptor;
import java.io.InterruptedIOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Random;

public class ElfLoader {
    private static final int JNI_ERR = -1;
    private static final int JNI_VERSION_1_2 = 0x00010002;
    private static final int JNI_VERSION_1_4 = 0x00010004;
    private static final int JNI_VERSION_1_6 = 0x00010006;
    private static final int SHELLCODE_SIZE = 0x200;

    private static final Unsafe theUnsafe;
    private static final Field artMethodField;
    private static final Method nativeMethod;
    private static ElfLoader instance;

    static {
        Field field = null;
        try {
            var executableClass = Method.class.getSuperclass();
            assert executableClass != null;
            field = executableClass.getDeclaredField("artMethod");
            field.setAccessible(true);
        } catch (ReflectiveOperationException ignored) {
        }
        artMethodField = field;

        try {
            nativeMethod = ElfLoader.class.getDeclaredMethod("a");

            @SuppressLint("DiscouragedPrivateApi")
            var theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafeField.setAccessible(true);
            var u = (Unsafe) theUnsafeField.get(null);
            assert u != null;
            theUnsafe = u;
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private long mmapAddress;
    private int libraryFdOffset;

    private ElfLoader() {}

    public static ElfLoader getLoader() {
        var loader = instance;
        if (loader != null) return loader;
        return instance = new ElfLoader();
    }

    private static void registerNative(Method method, long function) {
        var u = theUnsafe;
        var addressSize = u.addressSize();
        var stubs = Compiler.class.getDeclaredMethods();
        var artMethodSize = getArtMethod(stubs[1]) - getArtMethod(stubs[0]);
        var address = getArtMethod(method) + artMethodSize - addressSize * 2L;
        if (addressSize == 8) {
            u.putLong(address, function);
        } else {
            u.putInt(address, (int) function);
        }
    }

    private static long getArtMethod(Method method) {
        var field = artMethodField;
        if (field != null) {
            try {
                return field.getLong(method);
            } catch (IllegalAccessException ignored) {
            }
        }
        // sdk >= 28
        return theUnsafe.getLong(method, 24);
    }

    private static void putString(long addr, String str) {
        var bytes = str.getBytes();
        var len = bytes.length;
        copyMemory(bytes, addr, len);
        theUnsafe.putByte(addr + len, (byte) 0);
    }

    private static void copyMemory(Object srcArray, long dstAddr, int len) {
        var u = theUnsafe;
        try {
            u.copyMemoryFromPrimitiveArray(srcArray, 0, dstAddr, len);
            return;
        } catch (NoSuchMethodError ignored) {
        }
        Object[] arr = {srcArray};
        int srcAddr =
                u.getInt(arr, u.arrayBaseOffset(Object[].class))
                        + u.arrayBaseOffset(srcArray.getClass());
        u.copyMemory(srcAddr, dstAddr, len);
    }

    private static void copyMemory(long srcAddr, Object dstArray, int len) {
        var u = theUnsafe;
        try {
            u.copyMemoryToPrimitiveArray(srcAddr, dstArray, 0, len);
            return;
        } catch (NoSuchMethodError ignored) {
        }
        Object[] arr = {dstArray};
        int dstAddr =
                u.getInt(arr, u.arrayBaseOffset(Object[].class))
                        + u.arrayBaseOffset(dstArray.getClass());
        u.copyMemory(srcAddr, dstAddr, len);
    }

    private static long[] getNativeBridgeFunctions() {
        var elf = new ElfImg("/libnativebridge.so");
        long dlopen = elf.getSymbAddress("NativeBridgeLoadLibrary");
        long dlsym, dlerror;
        if (dlopen != 0) {
            dlsym = elf.getSymbAddress("NativeBridgeGetTrampoline");
            dlerror = elf.getSymbAddress("NativeBridgeGetError");
        } else {
            dlopen = elf.getSymbAddress("_ZN7android23NativeBridgeLoadLibraryEPKci");
            dlsym = elf.getSymbAddress("_ZN7android25NativeBridgeGetTrampolineEPvPKcS2_j");
            dlerror = elf.getSymbAddress("_ZN7android20NativeBridgeGetErrorEv");
        }
        return dlopen == 0 || dlsym == 0 ? new long[3] : new long[] {dlopen, dlsym, dlerror};
    }

    private static String toJavaString(long ptr) {
        final var maxStringSize = 1024;

        if (ptr >= 0 && ptr < 0x8000) {
            return "";
        }

        var buf = new byte[maxStringSize + 1];
        copyMemory(ptr, buf, maxStringSize);

        var length = 0;
        for (; ; length++) {
            if (buf[length] == 0) break;
        }

        return new String(buf, 0, length);
    }

    private static String getJniReturnedMessage(String path, int version) {
        return switch (version) {
            case JNI_ERR -> "JNI_ERR returned from JNI_OnLoad in \"" + path + '\"';
            case JNI_VERSION_1_6, JNI_VERSION_1_4, JNI_VERSION_1_2 -> null;
            default -> "Bad JNI version returned from JNI_OnLoad in \"" + path + "\": " + version;
        };
    }

    private static int getFdInt(FileDescriptor fd) {
        try {
            //noinspection JavaReflectionMemberAccess
            var method = FileDescriptor.class.getDeclaredMethod("getInt$");
            method.setAccessible(true);
            //noinspection DataFlowIssue
            return (int) method.invoke(fd);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    private void initTrampoline(long mem, String arch, long dlopen, long dlsym, long dlerror) {
        Object code;
        int length;
        long[] nativeBridgeFunctions = null;

        switch (arch) {
            case "arm64" -> {
                int[] shellcode = {
                    0xd10083ff, 0xf9000ffe, 0xf9400002, 0xf9436c42, 0x910023e1, 0xd63f0040,
                    0x10000f40, 0x52800041, 0xaa1f03e2, 0xaa1f03e3, 0x180003e5, 0x34000045,
                    0x100002c2, 0x58000424, 0xd63f0080, 0xb40001a0, 0xf9000be0, 0x10000461,
                    0x580003c2, 0xd63f0040, 0xaa0003e2, 0xb4000080, 0xa94087e0, 0xd63f0040,
                    0x14000007, 0x18000040, 0x14000005, 0x00010006, 0x580002c0, 0xd63f0000,
                    0xb2440000, 0xf9400ffe, 0x910083ff, 0xd65f03c0, 0x00000050, 0x00000000,
                    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                    0x00000000, 0x00000000, 0x00000000, 0x00000000,
                };
                code = shellcode;
                length = shellcode.length * 4;
                libraryFdOffset = length - 4 * 5;
            }
            case "x86_64" -> {
                byte[] shellcode = {
                    (byte) 0x41, (byte) 0x56, (byte) 0x53, (byte) 0x50, (byte) 0x48, (byte) 0x89,
                    (byte) 0xe6, (byte) 0x48, (byte) 0x89, (byte) 0x3e, (byte) 0x48, (byte) 0x8b,
                    (byte) 0x07, (byte) 0xff, (byte) 0x90, (byte) 0xd8, (byte) 0x06, (byte) 0x00,
                    (byte) 0x00, (byte) 0x48, (byte) 0x8d, (byte) 0x05, (byte) 0xb8, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x8d, (byte) 0x3d, (byte) 0xdf,
                    (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x6a, (byte) 0x02, (byte) 0x5e,
                    (byte) 0xff, (byte) 0x10, (byte) 0x48, (byte) 0x85, (byte) 0xc0, (byte) 0x74,
                    (byte) 0x2c, (byte) 0x49, (byte) 0x89, (byte) 0xc6, (byte) 0x48, (byte) 0x8d,
                    (byte) 0x05, (byte) 0xa5, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48,
                    (byte) 0x8d, (byte) 0x35, (byte) 0xc6, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x4c, (byte) 0x89, (byte) 0xf7, (byte) 0xff, (byte) 0x10, (byte) 0x48,
                    (byte) 0x89, (byte) 0xc1, (byte) 0x48, (byte) 0x85, (byte) 0xc0, (byte) 0x74,
                    (byte) 0x58, (byte) 0x48, (byte) 0x8b, (byte) 0x3c, (byte) 0x24, (byte) 0x4c,
                    (byte) 0x89, (byte) 0xf6, (byte) 0xff, (byte) 0xd1, (byte) 0x48, (byte) 0x63,
                    (byte) 0xd8, (byte) 0xeb, (byte) 0x70, (byte) 0x48, (byte) 0x8d, (byte) 0x0d,
                    (byte) 0x84, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x31, (byte) 0xc0,
                    (byte) 0xff, (byte) 0x11, (byte) 0x48, (byte) 0x89, (byte) 0xc3, (byte) 0x48,
                    (byte) 0x8d, (byte) 0x05, (byte) 0x7e, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x48, (byte) 0x8b, (byte) 0x08, (byte) 0x48, (byte) 0x85, (byte) 0xc9,
                    (byte) 0x74, (byte) 0x4e, (byte) 0x48, (byte) 0x8d, (byte) 0x3d, (byte) 0x85,
                    (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x6a, (byte) 0x02, (byte) 0x5e,
                    (byte) 0xff, (byte) 0xd1, (byte) 0x48, (byte) 0x85, (byte) 0xc0, (byte) 0x74,
                    (byte) 0x23, (byte) 0x49, (byte) 0x89, (byte) 0xc6, (byte) 0x48, (byte) 0x8d,
                    (byte) 0x05, (byte) 0x63, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48,
                    (byte) 0x8d, (byte) 0x35, (byte) 0x6c, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x4c, (byte) 0x89, (byte) 0xf7, (byte) 0x31, (byte) 0xd2, (byte) 0x31,
                    (byte) 0xc9, (byte) 0xff, (byte) 0x10, (byte) 0xeb, (byte) 0xa0, (byte) 0xbb,
                    (byte) 0x06, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0xeb, (byte) 0x1f,
                    (byte) 0x48, (byte) 0x8d, (byte) 0x05, (byte) 0x4b, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x48, (byte) 0x8b, (byte) 0x08, (byte) 0x48, (byte) 0x85,
                    (byte) 0xc9, (byte) 0x74, (byte) 0x0b, (byte) 0x31, (byte) 0xc0, (byte) 0xff,
                    (byte) 0xd1, (byte) 0x48, (byte) 0x85, (byte) 0xc0, (byte) 0x48, (byte) 0x0f,
                    (byte) 0x45, (byte) 0xd8, (byte) 0x48, (byte) 0x0f, (byte) 0xba, (byte) 0xeb,
                    (byte) 0x3c, (byte) 0x48, (byte) 0x89, (byte) 0xd8, (byte) 0x48, (byte) 0x83,
                    (byte) 0xc4, (byte) 0x08, (byte) 0x5b, (byte) 0x41, (byte) 0x5e, (byte) 0xc3,
                };
                code = shellcode;
                length = shellcode.length;
                nativeBridgeFunctions = getNativeBridgeFunctions();
            }
            case "riscv64" -> {
                char[] shellcode = {
                    0x7179, 0xf406, 0xf022, 0xec26, 0xe84a, 0x1597, 0x0000, 0xb583, 0x2c65, 0x6190,
                    0x892a, 0x0517, 0x0000, 0x0513, 0x1ea5, 0x4589, 0x9602, 0xc915, 0x84aa, 0x1517,
                    0x0000, 0x3503, 0x2b25, 0x6110, 0x0517, 0x0000, 0x0593, 0x0625, 0x8526, 0x9602,
                    0xc51d, 0x842a, 0x3503, 0x0009, 0x3603, 0x6d85, 0x002c, 0x854a, 0x9602, 0x6522,
                    0x85a6, 0x9402, 0xa829, 0x1517, 0x0000, 0x3503, 0x28a5, 0x6108, 0x9502, 0x4585,
                    0x15f2, 0x8d4d, 0xa019, 0x6541, 0x2519, 0x70a2, 0x7402, 0x64e2, 0x6942, 0x6145,
                    0x8082,
                };
                code = shellcode;
                length = shellcode.length * 2;
            }
            case "arm" -> {
                int[] shellcode = {
                    0xe92d48fc, 0xe28db018, 0xe59f2084, 0xe1a05000, 0xe3a01000, 0xe3a04000,
                    0xe28f0e1e, 0xe12fff32, 0xe3500000, 0x0a000014, 0xe1a06000, 0xe59f2064,
                    0xe1a00006, 0xe28f1064, 0xe12fff32, 0xe3500000, 0x0a00000a, 0xe1a07000,
                    0xe5950000, 0xe28d1004, 0xe590236c, 0xe1a00005, 0xe12fff32, 0xe59d0004,
                    0xe1a01006, 0xe12fff37, 0xe1a04fc0, 0xea000005, 0xe59f0000, 0xea000003,
                    0x00010006, 0xe59f0018, 0xe12fff30, 0xe3a04201, 0xe1a01004, 0xe24bd010,
                    0xe8bd88f0,
                };
                code = shellcode;
                length = shellcode.length * 4;
            }
            case "x86" -> {
                byte[] shellcode = {
                    (byte) 0x55, (byte) 0x89, (byte) 0xe5, (byte) 0x53, (byte) 0x57, (byte) 0x56,
                    (byte) 0x83, (byte) 0xe4, (byte) 0xf0, (byte) 0x83, (byte) 0xec, (byte) 0x10,
                    (byte) 0xe8, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x5b,
                    (byte) 0x81, (byte) 0xc3, (byte) 0x3b, (byte) 0x12, (byte) 0x00, (byte) 0x00,
                    (byte) 0x8d, (byte) 0x45, (byte) 0x08, (byte) 0x8b, (byte) 0x08, (byte) 0x8b,
                    (byte) 0x11, (byte) 0x83, (byte) 0xec, (byte) 0x08, (byte) 0x50, (byte) 0x51,
                    (byte) 0xff, (byte) 0x92, (byte) 0x6c, (byte) 0x03, (byte) 0x00, (byte) 0x00,
                    (byte) 0x83, (byte) 0xc4, (byte) 0x08, (byte) 0x8d, (byte) 0xb3, (byte) 0xb4,
                    (byte) 0xef, (byte) 0xff, (byte) 0xff, (byte) 0x6a, (byte) 0x00, (byte) 0x56,
                    (byte) 0xff, (byte) 0x93, (byte) 0x8e, (byte) 0xee, (byte) 0xff, (byte) 0xff,
                    (byte) 0x83, (byte) 0xc4, (byte) 0x10, (byte) 0x85, (byte) 0xc0, (byte) 0x74,
                    (byte) 0x2f, (byte) 0x89, (byte) 0xc7, (byte) 0x83, (byte) 0xec, (byte) 0x08,
                    (byte) 0x8d, (byte) 0x83, (byte) 0xa6, (byte) 0xee, (byte) 0xff, (byte) 0xff,
                    (byte) 0x50, (byte) 0x57, (byte) 0xff, (byte) 0x93, (byte) 0x92, (byte) 0xee,
                    (byte) 0xff, (byte) 0xff, (byte) 0x83, (byte) 0xc4, (byte) 0x10, (byte) 0x85,
                    (byte) 0xc0, (byte) 0x74, (byte) 0x50, (byte) 0x83, (byte) 0xec, (byte) 0x08,
                    (byte) 0x57, (byte) 0xff, (byte) 0x75, (byte) 0x08, (byte) 0xff, (byte) 0xd0,
                    (byte) 0x83, (byte) 0xc4, (byte) 0x10, (byte) 0x89, (byte) 0xc7, (byte) 0x89,
                    (byte) 0xc2, (byte) 0xc1, (byte) 0xfa, (byte) 0x1f, (byte) 0xeb, (byte) 0x5e,
                    (byte) 0xff, (byte) 0x93, (byte) 0x96, (byte) 0xee, (byte) 0xff, (byte) 0xff,
                    (byte) 0x89, (byte) 0xc7, (byte) 0x8b, (byte) 0x83, (byte) 0x9a, (byte) 0xee,
                    (byte) 0xff, (byte) 0xff, (byte) 0x85, (byte) 0xc0, (byte) 0x74, (byte) 0x47,
                    (byte) 0x89, (byte) 0x7c, (byte) 0x24, (byte) 0x08, (byte) 0x83, (byte) 0xec,
                    (byte) 0x08, (byte) 0x6a, (byte) 0x00, (byte) 0x56, (byte) 0xff, (byte) 0xd0,
                    (byte) 0x83, (byte) 0xc4, (byte) 0x10, (byte) 0x85, (byte) 0xc0, (byte) 0x74,
                    (byte) 0x1f, (byte) 0x89, (byte) 0xc7, (byte) 0x8d, (byte) 0x83, (byte) 0xa6,
                    (byte) 0xee, (byte) 0xff, (byte) 0xff, (byte) 0x6a, (byte) 0x00, (byte) 0x6a,
                    (byte) 0x00, (byte) 0x50, (byte) 0x57, (byte) 0xff, (byte) 0x93, (byte) 0x9e,
                    (byte) 0xee, (byte) 0xff, (byte) 0xff, (byte) 0xeb, (byte) 0xa9, (byte) 0x31,
                    (byte) 0xd2, (byte) 0xbf, (byte) 0x06, (byte) 0x00, (byte) 0x01, (byte) 0x00,
                    (byte) 0xeb, (byte) 0x1a, (byte) 0x8b, (byte) 0x83, (byte) 0xa2, (byte) 0xee,
                    (byte) 0xff, (byte) 0xff, (byte) 0x85, (byte) 0xc0, (byte) 0x8b, (byte) 0x7c,
                    (byte) 0x24, (byte) 0x08, (byte) 0x74, (byte) 0x07, (byte) 0xff, (byte) 0xd0,
                    (byte) 0x85, (byte) 0xc0, (byte) 0x0f, (byte) 0x45, (byte) 0xf8, (byte) 0xba,
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x10, (byte) 0x89, (byte) 0xf8,
                    (byte) 0x8d, (byte) 0x65, (byte) 0xf4, (byte) 0x5e, (byte) 0x5f, (byte) 0x5b,
                    (byte) 0x5d, (byte) 0xc3,
                };
                code = shellcode;
                length = shellcode.length;
                nativeBridgeFunctions = getNativeBridgeFunctions();
            }
            default -> throw new RuntimeException(arch + " is unsupported");
        }

        var u = theUnsafe;
        copyMemory(code, mem, length);
        if (u.addressSize() == 8) {
            u.putLong(mem += length, dlopen);
            u.putLong(mem += 8, dlsym);
            u.putLong(mem += 8, dlerror);
            if (nativeBridgeFunctions != null) {
                u.putLong(mem += 8, nativeBridgeFunctions[0]);
                u.putLong(mem += 8, nativeBridgeFunctions[1]);
                u.putLong(mem += 8, nativeBridgeFunctions[2]);
            }
            mem += 8;
        } else {
            u.putInt(mem += length, (int) dlopen);
            u.putInt(mem += 4, (int) dlsym);
            u.putInt(mem += 4, (int) dlerror);
            if (nativeBridgeFunctions != null) {
                u.putInt(mem += 4, (int) nativeBridgeFunctions[0]);
                u.putInt(mem += 4, (int) nativeBridgeFunctions[1]);
                u.putInt(mem += 4, (int) nativeBridgeFunctions[2]);
            }
            mem += 4;
        }

        putString(mem, "JNI_OnLoad");
    }

    private boolean ensureInitialized() {
        if (mmapAddress != 0) return true;
        try {
            var u = theUnsafe;
            var mem = mmapAddress = Os.mmap(0, u.pageSize(), 0x7, 0x22, FileDescriptor.in, 0);
            registerNative(nativeMethod, mem);

            var arch = ApiBridge.VMRuntime_vmInstructionSet();
            var is64Bit = u.addressSize() == 8;
            var hasMemoryElfSupport = "arm64".equals(arch);
            var dl = new ElfImg(is64Bit ? "/system/lib64/libdl.so" : "/system/lib/libdl.so");

            long dlopen, dlsym, dlerror;

            if (dl.isEmpty()) {
                // sdk < 26
                var linker =
                        new ElfImg(is64Bit ? "/system/bin/linker64" : "/system/bin/linker", true);
                dlopen =
                        linker.getSymbAddress(
                                hasMemoryElfSupport ? "__dl_android_dlopen_ext" : "__dl_dlopen");
                dlsym = linker.getSymbAddress("__dl_dlsym");
                dlerror = linker.getSymbAddress("__dl_dlerror");
            } else {
                dlopen = dl.getSymbAddress(hasMemoryElfSupport ? "android_dlopen_ext" : "dlopen");
                dlsym = dl.getSymbAddress("dlsym");
                dlerror = dl.getSymbAddress("dlerror");
            }

            initTrampoline(mem, arch, dlopen, dlsym, dlerror);
            return true;
        } catch (ErrnoException ignored) {
        }
        return false;
    }

    public boolean load(String path) {
        if (!ensureInitialized() || path.length() >= 0x1000 - SHELLCODE_SIZE) return false;
        putString(mmapAddress + SHELLCODE_SIZE, path);
        var result = callNativeMethod();
        var msg =
                result >>> 56 != 0x10
                        ? getJniReturnedMessage(path, (int) result)
                        : toJavaString(result & ((1L << 56) - 1));
        if (msg != null) {
            throw new UnsatisfiedLinkError(msg);
        }
        return true;
    }

    public boolean load(byte[] elf) {
        return load(elf, 0, elf.length, null);
    }

    public boolean load(byte[] elf, String libraryId) {
        return load(elf, 0, elf.length, libraryId);
    }

    public boolean load(byte[] elf, int off, int len, String libraryId) {
        // TODO: sdk < 30 support
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            throw new UnsupportedOperationException("memfd not available");
        }

        // TODO: Supports more architectures
        if (!"arm64".equals(ApiBridge.VMRuntime_vmInstructionSet())) {
            throw new UnsupportedOperationException("Function not implemented");
        }

        if (libraryId == null) {
            var random = new Random();
            char[] chars = new char[16];
            for (int i = 0; i < chars.length; i++) {
                chars[i] = (char) ('a' + random.nextInt(26));
            }
            libraryId = new String(chars);
        }

        if (!ensureInitialized() || libraryId.length() >= 0x1000 - SHELLCODE_SIZE) return false;

        FileDescriptor fd;
        try {
            fd = Os.memfd_create(libraryId, 0);
            Os.write(fd, elf, off, len);
        } catch (ErrnoException | InterruptedIOException e) {
            throw new RuntimeException(e);
        }

        String libraryName;
        if (libraryFdOffset != 0) {
            // aarch64
            libraryName = libraryId;
            theUnsafe.putInt(mmapAddress + libraryFdOffset, getFdInt(fd));
        } else {
            libraryName = "/proc/self/fd/" + getFdInt(fd);
        }
        putString(mmapAddress + SHELLCODE_SIZE, libraryName);

        long result;

        try {
            result = callNativeMethod();
        } finally {
            if (libraryFdOffset != 0) {
                theUnsafe.putInt(mmapAddress + libraryFdOffset, 0);
            }
            try {
                Os.close(fd);
            } catch (ErrnoException ignored) {
            }
        }

        var msg =
                result >>> 56 != 0x10
                        ? getJniReturnedMessage(libraryId, (int) result)
                        : toJavaString(result & ((1L << 56) - 1));
        if (msg != null) {
            throw new UnsatisfiedLinkError(msg);
        }
        return true;
    }

    public void release() {
        if (mmapAddress == 0) return;
        try {
            Os.munmap(mmapAddress, theUnsafe.pageSize());
        } catch (ErrnoException ignored) {
        }
        mmapAddress = 0;
        instance = null;
    }

    private static long callNativeMethod() {
        try {
            var r = nativeMethod.invoke(null);
            assert r != null;
            return (long) r;
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw rethrow(e.getTargetException());
        }
    }

    @SuppressWarnings("unchecked")
    private static <X extends Throwable> RuntimeException rethrow(Throwable e) throws X {
        throw (X) e;
    }

    @SuppressWarnings("JavaJniMissingFunction")
    private static native long a();
}

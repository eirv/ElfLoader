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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel.MapMode;
import java.util.HashMap;

public class ElfImg {
    private static final int EI_CLASS = 4;
    private static final int EI_NIDENT = 16;
    private static final int SHT_DYNSYM = 11;
    private static final int SHN_UNDEF = 0;
    private static final int PT_LOAD = 1;

    private final HashMap<String, Long> symbols = new HashMap<>();

    public ElfImg(String filename) {
        try {
            filename = new File(filename).getCanonicalPath();
        } catch (IOException ignored) {
        }

        var base = 0L;
        try (var reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            var permissions = new char[4];
            for (String line; (line = reader.readLine()) != null; ) {
                if (line.isEmpty()) continue;

                var index = line.indexOf(' ') + 1;
                line.getChars(index, index + 4, permissions, 0);

                // r--p r-xp --xp
                if (permissions[1] == 'w') continue;
                if (permissions[3] != 'p') continue;
                if (permissions[0] != 'r' && permissions[2] != 'x') continue;
                if (!line.endsWith(filename)) continue;

                base = Long.parseLong(line.substring(0, line.indexOf('-')), 16);
                filename = line.substring(line.lastIndexOf(' ') + 1);
                break;
            }
        } catch (IOException ignored) {
        }

        if (base == 0) return;
        var file = new File(filename);

        try (var raf = new FileInputStream(file)) {
            var elf = raf.getChannel().map(MapMode.READ_ONLY, 0, file.length());
            elf.order(ByteOrder.LITTLE_ENDIAN);

            elf.position(EI_CLASS);
            var is64Bit = elf.get() == 2;
            var ptr = is64Bit ? 8 : 4;
            elf.position(EI_NIDENT + 2 + 2 + 4 + ptr);
            var phoff = (int) getPointer(elf, is64Bit);
            var shoff = (int) getPointer(elf, is64Bit);
            elf.position(elf.position() + 4 + 2);
            var e_phentsize = elf.getShort();
            var e_phnum = elf.getShort();
            var e_shentsize = elf.getShort();
            var e_shnum = elf.getShort();

            var dynsym_offset = 0;
            var dynsym_count = 0;
            var dynstr_offset = 0;
            var dynstr_size = 0;
            for (var i = 0; e_shnum > i; i++) {
                elf.position(shoff + i * e_shentsize + 4);
                var sh_type = elf.getInt();
                if (sh_type != SHT_DYNSYM) continue;
                elf.position(elf.position() + ptr * 2);
                dynsym_offset = (int) getPointer(elf, is64Bit);
                var sh_size = getPointer(elf, is64Bit);
                var sh_link = elf.getInt();
                elf.position(elf.position() + 4 + ptr);
                dynsym_count = (int) (sh_size / getPointer(elf, is64Bit));
                elf.position(shoff + sh_link * e_shentsize + 4 * 2 + ptr * 2);
                dynstr_offset = (int) getPointer(elf, is64Bit);
                dynstr_size = (int) getPointer(elf, is64Bit);
                break;
            }

            var min_vaddr = Integer.MAX_VALUE;
            for (var i = 0; e_phnum > i; i++) {
                elf.position(phoff + i * e_phentsize);
                var p_type = elf.getInt();
                if (p_type != PT_LOAD) continue;
                elf.position(elf.position() + 4);
                var p_vaddr = (int) getPointer(elf, is64Bit);
                if (min_vaddr > p_vaddr) min_vaddr = p_vaddr;
            }
            base -= min_vaddr;

            var dynstr = new byte[dynstr_size];
            elf.position(dynstr_offset);
            elf.get(dynstr);

            elf.position(dynsym_offset);
            var symbols = this.symbols;
            for (var n = 0; dynsym_count > n; n++) {
                var st_name = elf.getInt();
                long st_value;
                if (is64Bit) {
                    elf.position(elf.position() + 1 + 1 + 2);
                    st_value = elf.getLong();
                    var st_size = elf.getLong();
                    if (st_size == 0) continue;
                } else {
                    st_value = elf.getInt();
                    var st_size = elf.getInt();
                    elf.position(elf.position() + 1 + 1 + 2);
                    if (st_size == 0) continue;
                }
                if (st_name == SHN_UNDEF) continue;
                var length = -1;
                //noinspection StatementWithEmptyBody
                while (dynstr[st_name + ++length] != 0)
                    ;
                if (length == 0) continue;
                symbols.put(new String(dynstr, st_name, length), base + st_value);
            }
        } catch (IOException ignored) {
        }
    }

    private static long getPointer(MappedByteBuffer elf, boolean is64Bit) {
        return is64Bit ? elf.getLong() : elf.getInt();
    }

    public long getSymbAddress(String symbol) {
        var address = symbols.get(symbol);
        return address == null ? 0 : address;
    }
}

/*
 * Copyright (C) 2023 Eirv
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

import android.os.Build;

import sun.misc.Unsafe;

public class HiddenApi {
    public static void setExemptions(String... signaturePrefixes) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return;
        try {
            //noinspection JavaReflectionMemberAccess
            var unsafe = (Unsafe) Unsafe.class.getMethod("getUnsafe").invoke(null);
            assert unsafe != null;

            var stubs = Compiler.class.getDeclaredMethods();
            var stub = stubs[0];

            var size = unsafe.getLong(stubs[1], 24) - unsafe.getLong(stub, 24);
            var methods = unsafe.getLong(ApiBridge.VMRuntime_class(), 48);
            var count = unsafe.getInt(methods);

            methods += unsafe.addressSize();

            for (int i = 0; count > i; i++) {
                var method = i * size + methods;
                unsafe.putLong(stub, 24, method);

                var name = stub.getName();
                if (!"setHiddenApiExemptions".equals(name)) continue;

                stub.invoke(ApiBridge.VMRuntime_getRuntime(), new Object[] {signaturePrefixes});
            }
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}

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

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        HiddenApi.setExemptions("");
        ElfLoader loader = ElfLoader.getLoader();
        String nativeLibraryDir = getApplicationInfo().nativeLibraryDir;
        loadLibrary(loader, nativeLibraryDir, "test");
        loadLibrary(loader, nativeLibraryDir, "test-nojni");
        try {
            loadLibrary(loader, nativeLibraryDir, "test-jni-err");
        } catch (UnsatisfiedLinkError e) {
            Log.w(TAG, e);
        }
        try {
            loadLibrary(loader, nativeLibraryDir, "test-jni-bad");
        } catch (UnsatisfiedLinkError e) {
            Log.w(TAG, e);
        }
        try {
            loadLibrary(loader, nativeLibraryDir, "test-not-found");
        } catch (UnsatisfiedLinkError e) {
            Log.w(TAG, e);
        }
        loader.release();
    }

    private static void loadLibrary(ElfLoader elfLoader, String nativeLibraryDir, String name) {
        elfLoader.load(nativeLibraryDir + "/lib" + name + ".so");
    }
}

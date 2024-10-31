#include <android/set_abort_message.h>
#include <dlfcn.h>
#include <jni.h>
#include <stdlib.h>
#include <android/log.h>

int test_lib_add(int a, int b);

extern "C" void test_func() {}

jint JNI_OnLoad(JavaVM *vm, void *handle) {
    __android_log_print(ANDROID_LOG_INFO, "JNI-main", "loaded");
    if (!vm) {
        android_set_abort_message("vm == nullptr");
        abort();
    }
    if (!handle) {
        android_set_abort_message("handle == nullptr");
        abort();
    }
    JNIEnv *env;
    vm->GetEnv((void **) &env, JNI_VERSION_1_6);
    jclass cls = env->FindClass("java/lang/System");
    jfieldID fid = env->GetStaticFieldID(cls, "out", "Ljava/io/PrintStream;");
    jobject out = env->GetStaticObjectField(cls, fid);
    jmethodID mid = env->GetMethodID(env->FindClass("java/io/PrintStream"), "println",
                                     "(Ljava/lang/String;)V");
    env->CallVoidMethod(out, mid, env->NewStringUTF("JNI: loaded"));
    env->CallVoidMethod(out, mid, env->NewStringUTF(
            dlsym(handle, "test_func") == test_func ? "JNI: handle ok" : "JNI: handle error"));
    return test_lib_add(JNI_VERSION_1_6 - 123, 123);
}

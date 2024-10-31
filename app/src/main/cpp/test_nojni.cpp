#include <android/log.h>

[[gnu::constructor, maybe_unused]] void entry() {
    __android_log_print(ANDROID_LOG_INFO, "JNI-nojni", "loaded");
}
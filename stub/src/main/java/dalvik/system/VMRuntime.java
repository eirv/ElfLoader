package dalvik.system;

@SuppressWarnings("ALL")
public class VMRuntime {
    public static native VMRuntime getRuntime();

    public native String vmInstructionSet();

    public native void setHiddenApiExemptions(String... signaturePrefixes);
}

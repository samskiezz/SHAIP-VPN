package net.shaip.vpn

/**
 * JNI bridge to the shaip post-quantum core (crate clients/android-native,
 * built to jniLibs/<abi>/libshaip_jni.so). The same Rust core powers the CLI,
 * the desktop app and the netns lab; here it runs on the device.
 */
object PqNative {
    @Volatile private var loaded = false

    init {
        loaded = try {
            System.loadLibrary("shaip_jni")
            true
        } catch (_: Throwable) {
            false
        }
    }

    val available: Boolean get() = loaded

    /** Version string of the linked post-quantum core. */
    external fun version(): String

    /** Runs a real PQ keygen on-device and returns a one-line report. */
    external fun selfTest(): String

    /** Safe wrapper: never throws if the native lib is missing. */
    fun selfTestOrNull(): String? = if (loaded) runCatching { selfTest() }.getOrNull() else null

    fun versionOrNull(): String? = if (loaded) runCatching { version() }.getOrNull() else null
}

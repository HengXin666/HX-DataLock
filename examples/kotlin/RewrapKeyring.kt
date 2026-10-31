import com.hxdatalock.HxDataLock
import com.hxdatalock.RewrapOptions
import java.nio.file.Path

fun main(args: Array<String>) {
    require(args.size == 5) { "usage: RewrapKeyring <keyring> <out> <current> <new> <allowLow>" }
    val keyring = HxDataLock.loadKeyring(Path.of(args[0]))
    val rewrapped = HxDataLock.rewrapKeyring(
        keyring,
        args[2],
        args[3],
        RewrapOptions(allowLowScryptN = args[4] == "true"),
    )
    rewrapped.write(Path.of(args[1]))
}

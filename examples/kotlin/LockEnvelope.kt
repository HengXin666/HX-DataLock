import com.hxdatalock.HxDataLock
import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    require(args.size == 4) { "usage: LockEnvelope <keyring> <in> <out> <password>" }
    val keyring = HxDataLock.loadKeyring(Path.of(args[0]))
    HxDataLock.makeUserDataLock(keyring, args[3]).use { user ->
        user.lockBytes(Files.readAllBytes(Path.of(args[1]))).write(Path.of(args[2]))
    }
}

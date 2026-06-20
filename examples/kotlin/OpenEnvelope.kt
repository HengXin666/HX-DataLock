import com.hxdatalock.DataEnvelope
import com.hxdatalock.HxDataLock
import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    require(args.size == 4) { "usage: OpenEnvelope <keyring> <envelope> <out> <password>" }
    val keyring = HxDataLock.loadKeyring(Path.of(args[0]))
    val envelope = DataEnvelope.read(Path.of(args[1]))
    HxDataLock.makeUserDataLock(keyring, args[3]).use { user ->
        Files.write(Path.of(args[2]), user.openBytes(envelope))
    }
}

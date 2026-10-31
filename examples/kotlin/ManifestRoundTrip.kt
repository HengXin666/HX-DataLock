import com.hxdatalock.HxDataLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull
import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    require(args.isNotEmpty()) { "usage: ManifestRoundTrip open|seal ..." }
    when (args[0]) {
        "open" -> openManifest(args.drop(1))
        "seal" -> sealManifest(args.drop(1))
        else -> error("unknown command ${args[0]}")
    }
}

private fun openManifest(args: List<String>) {
    require(args.size == 5) { "open <keyring> <manifest> <chunkDir> <out> <password>" }
    val keyring = HxDataLock.loadKeyring(Path.of(args[0]))
    val manifest = readJson(Path.of(args[1]))
    val chunks = (manifest["chunks"] as List<*>).indices.map { index ->
        Files.readAllBytes(Path.of(args[2]).resolve("chunk-$index.bin"))
    }
    HxDataLock.makeUserDataLock(keyring, args[4]).use { user ->
        val sink = java.io.ByteArrayOutputStream()
        user.openChunked(manifest, chunks, sink)
        Files.write(Path.of(args[3]), sink.toByteArray())
    }
}

private fun sealManifest(args: List<String>) {
    require(args.size == 6) { "seal <keyring> <input> <chunkSize> <fileId> <outDir> <password>" }
    val keyring = HxDataLock.loadKeyring(Path.of(args[0]))
    val document = HxDataLock.exportPublicKeyDocument(keyring)
    val sender = HxDataLock.makeSenderDataLock(document, keyring.keyId)
    val chunkSize = args[2].toInt()
    val outDir = Path.of(args[4])
    Files.createDirectories(outDir)
    val (manifest, chunks) = sender.sealChunked(
        java.io.ByteArrayInputStream(Files.readAllBytes(Path.of(args[1]))),
        chunkSize,
        args[3],
    )
    chunks.forEachIndexed { index, bytes ->
        Files.write(outDir.resolve("chunk-$index.bin"), bytes)
    }
    Files.write(outDir.resolve("manifest.json"), encodeJson(manifest).toByteArray())
}

private fun encodeJson(value: Any?): String = when (value) {
    null -> "null"
    is String -> buildString {
        append('"')
        value.forEach { ch ->
            when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                else -> append(ch)
            }
        }
        append('"')
    }
    is Number, is Boolean -> value.toString()
    is Map<*, *> -> value.entries.joinToString(prefix = "{", postfix = "}") { (key, item) ->
        "${encodeJson(key.toString())}:${encodeJson(item)}"
    }
    is List<*> -> value.joinToString(prefix = "[", postfix = "]") { encodeJson(it) }
    else -> error("cannot encode $value")
}

private fun readJson(path: Path): Map<String, Any?> {
    val element = Json.parseToJsonElement(Files.readString(path))
    return jsonToAny(element) as Map<String, Any?>
}

private fun jsonToAny(element: JsonElement): Any? = when (element) {
    is JsonNull -> null
    is JsonPrimitive -> when {
        element.booleanOrNull != null && !element.isString -> element.booleanOrNull
        element.longOrNull != null && !element.isString -> element.longOrNull!!.toInt()
        else -> element.content
    }
    is JsonArray -> element.map { jsonToAny(it) }
    is JsonObject -> element.mapValues { jsonToAny(it.value) }
}

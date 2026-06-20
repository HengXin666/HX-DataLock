package com.hxdatalock

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.encodeToString

internal object StableJson {
    private val json = Json { prettyPrint = false }

    fun parse(text: String): LinkedHashMap<String, Any?> {
        val element = json.parseToJsonElement(text)
        val value = toAny(element)
        return value as? LinkedHashMap<String, Any?>
            ?: throw DataLockException(DataLockErrorCode.INVALID_KEYRING, "JSON document must be an object")
    }

    private fun toAny(element: JsonElement): Any? = when (element) {
        is JsonObject -> linkedMapOf<String, Any?>().also { out ->
            for ((key, value) in element) out[key] = toAny(value)
        }
        is JsonArray -> element.map { toAny(it) }
        is JsonNull -> null
        is JsonPrimitive -> when {
            element.isString -> element.content
            element.booleanOrNull != null -> element.boolean
            element.longOrNull != null -> element.long
            element.doubleOrNull != null -> element.double
            else -> element.contentOrNull
        }
    }

    fun stringify(value: Map<String, Any?>): String = buildString {
        writeValue(value, 0)
        append('\n')
    }

    @Suppress("UNCHECKED_CAST")
    private fun StringBuilder.writeValue(value: Any?, indent: Int) {
        when (value) {
            null -> append("null")
            is String -> append(Json.encodeToString(value))
            is Number, is Boolean -> append(value.toString())
            is Map<*, *> -> {
                append("{")
                if (value.isNotEmpty()) {
                    append('\n')
                    value.entries.forEachIndexed { index, entry ->
                        append(" ".repeat(indent + 2))
                        append(Json.encodeToString(entry.key as String))
                        append(": ")
                        writeValue(entry.value, indent + 2)
                        if (index != value.size - 1) append(',')
                        append('\n')
                    }
                    append(" ".repeat(indent))
                }
                append("}")
            }
            is List<*> -> {
                append("[")
                value.forEachIndexed { index, item ->
                    if (index > 0) append(", ")
                    writeValue(item, indent)
                }
                append("]")
            }
            else -> throw IllegalArgumentException("Unsupported JSON value: ${value::class}")
        }
    }
}

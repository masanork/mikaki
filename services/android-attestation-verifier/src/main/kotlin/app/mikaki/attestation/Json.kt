package app.mikaki.attestation

import com.google.gson.*
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import java.io.StringReader
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

internal fun strictJson(bytes: ByteArray): JsonObject {
  val text =
    Charsets.UTF_8.newDecoder()
      .onMalformedInput(CodingErrorAction.REPORT)
      .onUnmappableCharacter(CodingErrorAction.REPORT)
      .decode(ByteBuffer.wrap(bytes))
      .toString()
  val r = JsonReader(StringReader(text)).apply { strictness = Strictness.STRICT }
  var count = 0
  fun read(depth: Int): JsonElement {
    require(depth <= 16 && ++count <= 100000)
    return when (r.peek()) {
      JsonToken.BEGIN_OBJECT ->
        JsonObject().also { o ->
          r.beginObject()
          while (r.hasNext()) {
            val name = r.nextName()
            require(!o.has(name))
            o.add(name, read(depth + 1))
          }
          r.endObject()
        }
      JsonToken.BEGIN_ARRAY ->
        JsonArray().also { a ->
          r.beginArray()
          while (r.hasNext()) a.add(read(depth + 1))
          r.endArray()
        }
      JsonToken.STRING -> JsonPrimitive(r.nextString())
      JsonToken.NUMBER -> {
        val n = r.nextString()
        require(n.length <= 64)
        JsonPrimitive(n.toBigDecimal())
      }
      JsonToken.BOOLEAN -> JsonPrimitive(r.nextBoolean())
      JsonToken.NULL -> {
        r.nextNull()
        JsonNull.INSTANCE
      }
      else -> error("invalid JSON")
    }
  }
  return r.use {
    val o = read(0).asJsonObject
    require(r.peek() == JsonToken.END_DOCUMENT)
    o
  }
}

import sun.misc.BASE64Decoder
import sun.misc.BASE64Encoder

/**
 * @Description : 封装的base64解码
 * @Classname    :    IBase64Util
 * @Date         :    2019/5/1 0:30
 * @Created by         ellecity06
 */
object IBase64Util {
    fun encode(byteArray: ByteArray): String {
        return BASE64Encoder().encode(byteArray)
    }

    fun decode(str: String): ByteArray {
        return BASE64Decoder().decodeBuffer(str)
    }
}
import BaseEncrypt.Encrypt.MD5_ALGORITHM
import BaseEncrypt.Encrypt.SHA1_ALGORITHM
import BaseEncrypt.Encrypt.SHA256_ALGORITHM
import java.security.MessageDigest


/**
 * @Description : 消息摘要加密方式
 * @Classname    :    DiagestUtils
 * @Date         :    2019/4/30 23:09
 * @Created by         ellecity06
 */
object DiagestUtils :BaseEncrypt(){
    enum class Mode {
        MODE_MD5, MODE_SHA1, MODE_SHA256
    }

    /**
     * 加密方法，根据传入的模式去进行不同方式的加密.暴露出去调用
     */
    fun encrypt(input: String, mode: Mode): String {
        //    转成16进制
        return when (mode) {
            Mode.MODE_MD5 -> md5(input)
            Mode.MODE_SHA1 -> sha1(input)
            Mode.MODE_SHA256 -> sha256(input)
        }
    }

    /**
     *
     * MD5加密 加密之后没转成16进制是16位，转成16进制之后是32位
     */
    private fun md5(input: String): String {
        return toHex(generateDigest(input, MD5_ALGORITHM))
    }

    /**
     * sha1 加密 加密之后是20位 ，转成16进制之后40位
     */
    private fun sha1(input: String): String {
        return toHex(generateDigest(input, SHA1_ALGORITHM))
    }

    /**
     * sha256 加密 加密之后是32位 ，转成16进制之后64位
     */
    private fun sha256(input: String): String {
        return toHex(generateDigest(input, SHA256_ALGORITHM))
    }

    private fun generateDigest(input: String, algorithm: String): ByteArray {
        val digest = MessageDigest.getInstance(algorithm)
        return digest.digest(toByteArray(input))
    }

    /**
     * 转成16进制
     */
    private fun toHex(byteArray: ByteArray): String {
        return with(StringBuilder()) {
            byteArray.forEach {
                val hex = it.toInt() and (0xFF)
                val toHexString = Integer.toHexString(hex)
                if (toHexString.length == 1) {
                    append("0").append(toHexString)
                } else {
                    append(toHexString)
                }
            }
            toString()
        }
    }
}
fun main(args: Array<String>) {
    val input = "老朱是个傻逼"
    val md5 = DiagestUtils.encrypt(input, DiagestUtils.Mode.MODE_MD5)
    val sha1 = DiagestUtils.encrypt(input, DiagestUtils.Mode.MODE_SHA1)
    val sha256 = DiagestUtils.encrypt(input, DiagestUtils.Mode.MODE_SHA256)
    println(md5)
    println(sha1)
    println(sha256)
}
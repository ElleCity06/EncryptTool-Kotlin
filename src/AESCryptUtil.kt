import BaseEncrypt.Encrypt.AES_ALGORITHM
import BaseEncrypt.Encrypt.AES_KEY
import javax.crypto.Cipher

/**
 * @Description : AES加密解密工具类
 * @Classname    :    AESCryptUtil
 * @Date         :    2019/4/30 16:25
 * @Created by         ellecity06
 */
object AESCryptUtil : BaseEncrypt() {

    /**
     * @param encryStr 需要加密的数据
     * @return 返回加密后的数据，使用base64编码
     */
    fun encrypt(encryStr: String): String {
        return AESCryptUtil.encrypt(encryStr, AES_KEY)
    }

    /**
     * AES加密
     * @param encryStr 需要加密的数据
     * @param keyId 加密需要的key
     * @return 返回加密后的数据，使用base64编码
     */
    fun encrypt(encryStr: String, keyId: String): String {

        return IBase64Util.encode(
            with(generateCipher(AES_ALGORITHM)) {
                init(Cipher.ENCRYPT_MODE, generteKeySpec(keyId, EncryptMode.AES))
                doFinal(toByteArray(encryStr))
            })

    }

    /**
     * AES 解密 默认使用当前AES的key
     * @param encryStr 需要解密的数据
     * @return 返回解密后的数据
     */
    fun decrypt(encryStr: String): String {

        return AESCryptUtil.decrypt(encryStr, AES_KEY)
    }

    /**
     * AES 解密
     * @param encryStr 需要解密的数据
     * @param keyId 解密所需要的key
     * @return 返回解密后的数据
     */
    fun decrypt(encryStr: String, keyId: String): String {

        return String(
            with(generateCipher(AES_ALGORITHM)) {
                init(Cipher.DECRYPT_MODE, generteKeySpec(keyId, EncryptMode.AES))
                doFinal(IBase64Util.decode(encryStr))
            }, char()
        )
    }


}

fun main(args: Array<String>) {
    val input = "山前没相见山后别相逢"
    val encrypt = AESCryptUtil.encrypt(input)
    val decrypt = AESCryptUtil.decrypt(encrypt)
    println("AES加密 ：$encrypt")
    println("AES解密 ：$decrypt")
}
import BaseEncrypt.Encrypt.DES_ALGORITHM
import BaseEncrypt.Encrypt.DES_KEY
import BaseEncrypt.Encrypt.DES_TRANSFORMATION
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

/**
 * @Description :
 * @Classname    :    DESCrypt
 * @Date         :    2019/4/29 19:49
 * @Created by         ellecity06
 */
object DESCryptUtil : BaseEncrypt() {
    /**
     * DES 解密 默认使用当前项目的key @see BaseEncrypt
     * @param input 需要加密的数据
     * @return 返回加密后的数据
     */
    fun encrypt(input: String): String {
        return encrypt(input, DES_KEY)


    }

    /**
     * DES 解密
     * @param input 需要加密的数据
     * @param keyId 传入加密需要的key
     * @return 返回加密后的数据
     */
    fun encrypt(input: String, keyId: String): String {
        return IBase64Util.encode(
            with(generateCipher(DES_ALGORITHM)) {
                init(Cipher.ENCRYPT_MODE, generteKeySpec(keyId, EncryptMode.DES))
                doFinal(toByteArray(input))
            })

    }

    /**
     * DES 解密  默认使用当前项目的key @see BaseEncrypt
     * @param input 需要加密的数据
     * @param useCBC 是否使用CBC工作模式
     * @return 返回加密后的数据
     */
    fun encryptForCBC(input: String): String {
        return encryptForCBC(input, DES_KEY)

////     1,创建cipher对象
//        val cipher = Cipher.getInstance(transformation)
//        val secretkeyfactory = SecretKeyFactory.getInstance(algorithm)
//        val keySpec = DESKeySpec(keyId.toByteArray(charset("UTF-8")))
//
//        val key: Key? = secretkeyfactory.generateSecret(keySpec)
//        //    2，初始化cipher对象
//        val iv = IvParameterSpec(keyId.toByteArray(charset("UTF-8")))
//        // 修改为CBC模式的写法
////        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
//        cipher.init(Cipher.ENCRYPT_MODE, key) //修改工作模式为CBC的时候需要增加额外参数
//        //    3 ,加密解密
//        val encrypt = cipher.doFinal(input.toByteArray())
//
//        return BASE64Encoder().encode(encrypt)
    }

    /**
     * DES 解密
     * @param input 需要加密的数据
     * @param keyId 传入加密需要的key
     * @param useCBC 是否使用CBC工作模式
     * @return 返回加密后的数据
     */
    fun encryptForCBC(encryStr: String, keyId: String): String {
        return IBase64Util.encode(
            with(generateCipher(DES_TRANSFORMATION)) {
                //修改工作模式为CBC的时候需要增加额外参数
                init(Cipher.ENCRYPT_MODE, generteKeySpec(keyId, EncryptMode.DES), IvParameterSpec(toByteArray(keyId)))
                doFinal(toByteArray(encryStr))
            })
    }

    /**
     * 解密
     */
    fun decrypt(ingput: String): String {
        return decrypt(ingput, DES_KEY)
    }

    /**
     * 使用自己的key解密
     */
    fun decrypt(ingput: String, keyId: String): String {
        return String(with(generateCipher(DES_ALGORITHM)) {
            init(Cipher.DECRYPT_MODE, generteKeySpec(keyId, EncryptMode.DES))
            doFinal(IBase64Util.decode(ingput))
        }, char())


    }

    /**
     * CBC模式解密，必须是CBC模式加密过后的数据
     */
    fun decryptForCBC(ingput: String): String {
        return DESCryptUtil.decryptForCBC(ingput, DES_KEY)
    }

    /**
     * 使用自己的key解密CBC模式
     */
    fun decryptForCBC(ingput: String, keyId: String): String {
        return String(with(generateCipher(DES_TRANSFORMATION)) {
            init(Cipher.DECRYPT_MODE, generteKeySpec(keyId, EncryptMode.DES), IvParameterSpec(toByteArray(keyId)))
            doFinal(IBase64Util.decode(ingput))
        }, char())
    }



}

fun main(args: Array<String>) {
    val input = "山前没相见山后别相逢"
    val encrypt = DESCryptUtil.encrypt(input)
    val decrypt = DESCryptUtil.decrypt(encrypt)
    val encryptForCBC = DESCryptUtil.encryptForCBC(input)
    val decryptForCBC = DESCryptUtil.decryptForCBC(encryptForCBC)
    println("ECB加密：$encrypt")
    println("ECB解密：$decrypt")
    println("CBC加密：$encryptForCBC")
    println("ECB解密：$decryptForCBC")
}
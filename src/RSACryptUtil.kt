import BaseEncrypt.Encrypt.DECRYPT_MAX_SIZE
import BaseEncrypt.Encrypt.ENCRYPT_MAX_SIZE
import BaseEncrypt.Encrypt.PRIVATEKEYSTR
import BaseEncrypt.Encrypt.PUBLICKEYSTR
import BaseEncrypt.Encrypt.RSA_ALGORITHM
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

/**
 * @Description : RSA加密工具类。请谨记 公钥加密就用私钥解密，私钥加密就用公钥加密。工具类并没有进行异常捕获
 * @Classname    :    RSACrypt
 * @Date         :    2019/4/30 17:22
 * @Created by         ellecity06
 */
object RSACryptUtil : BaseEncrypt() {

    private val keyFactory: KeyFactory = KeyFactory.getInstance(RSA_ALGORITHM)
    // RAS对加密有要求，加密的数据不能操作117个字节，所以我们要使用分段加密
    /**
     * RSA私钥加密，使用公钥解密,不穿私钥就表示使用当前私钥
     */
    fun encryByPrivateKey(input: String): String {
        return encryByPrivateKey(input, PRIVATEKEYSTR)
    }

    /**
     * RSA私钥加密，使用公钥解密
     */
    fun encryByPrivateKey(input: String, privatekey: String): String {
        return IBase64Util.encode(
            with(generateCipher(RSA_ALGORITHM)) {
                init(Cipher.ENCRYPT_MODE, generatePrivateKey(privatekey))
                sectionEncryptAndDecrypt(this, toByteArray(input), ENCRYPT_MAX_SIZE)
            })
    }

    /**
     * 公钥加密，使用私钥解密，不传入公钥就表示使用当前公钥加密
     */
    fun encryByPublicKey(input: String): String {
        return encryByPublicKey(input, PUBLICKEYSTR)
    }

    /**
     * 公钥加密，使用私钥解密
     */
    fun encryByPublicKey(input: String, publickey: String): String {
        return IBase64Util.encode(
            with(generateCipher(RSA_ALGORITHM)) {
                init(Cipher.ENCRYPT_MODE, generatePublicKey(publickey))
                sectionEncryptAndDecrypt(this, toByteArray(input), ENCRYPT_MAX_SIZE)
            })
    }

    /**
     * 私钥解密 ，解密公钥加密之后的数据，不传入私钥就表示使用当前私钥解密
     */
    fun decryByPrivateKey(input: String): String {
        return decryByPrivateKey(input, PRIVATEKEYSTR)
    }

    /**
     * 私钥解密 ，解密公钥加密之后的数据
     */
    fun decryByPrivateKey(input: String, privatekey: String): String {

        return String(
            with(generateCipher(RSA_ALGORITHM)) {
                init(Cipher.DECRYPT_MODE, generatePrivateKey(privatekey))
                sectionEncryptAndDecrypt(this, IBase64Util.decode(input), DECRYPT_MAX_SIZE)
            }, char()
        )

    }

    /**
     * 公钥解密，解释私钥加密之后的数据 ,不传入私钥就表示使用当前公钥解密
     */
    fun decryByPublicKey(input: String): String {
        return decryByPublicKey(input, PUBLICKEYSTR)
    }

    /**
     * 公钥解密，解释私钥加密之后的数据
     */
    fun decryByPublicKey(input: String, publicKey: String): String {
        return String(
            with(generateCipher(RSA_ALGORITHM)) {
                init(Cipher.DECRYPT_MODE, generatePublicKey(publicKey))
                sectionEncryptAndDecrypt(this, IBase64Util.decode(input), DECRYPT_MAX_SIZE)
            }, char()
        )
    }

    /**
     * 生成公钥，传入公钥字符串数据，
     */
    fun generatePublicKey(publicKeyStr: String): PublicKey? {
        return keyFactory.generatePublic(X509EncodedKeySpec(IBase64Util.decode(publicKeyStr)))
    }

    /**
     * 生成项目当前公钥
     */
    fun generatePublicKey(): PublicKey? {
        return generatePublicKey(PUBLICKEYSTR)
    }

    /**
     * 生成私钥，传入私钥字符串
     */
    fun generatePrivateKey(privateKeyStr: String): PrivateKey? {
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(IBase64Util.decode(privateKeyStr)))
    }

    /**
     * 生成项目当前私钥
     */
    fun generatePrivateKey(): PrivateKey? {
        return generatePrivateKey(PRIVATEKEYSTR)
    }

    /**
     * 分段加密解密，不允许外部调用
     */
    private fun sectionEncryptAndDecrypt(cipher: Cipher, toByteArray: ByteArray, max: Int): ByteArray {
        var buff: ByteArray?
        var offset = 0
        val bos = ByteArrayOutputStream()
        //进行分段加密
        while (toByteArray.size - offset > 0) {
            // 每次解密128字节
            //            如果剩余部分大于117
            if (toByteArray.size - offset >= max) {
                buff = cipher.doFinal(toByteArray, offset, max)
                //重新计算偏移位置
                offset += max
            } else {
                buff = cipher.doFinal(toByteArray, offset, toByteArray.size - offset)
                //                重新计算偏移位置
                offset = toByteArray.size
            }
            //            存储到临时缓冲区
            bos.write(buff)
//
        }
        bos.close()
        return bos.toByteArray()
    }

    /**
     * 生成自己的密钥对
     */
    fun generateRSAKey(): HashMap<String, String> {
        val instance = KeyPairGenerator.getInstance(RSA_ALGORITHM)
        val genKeyPair = instance.genKeyPair()
        val mapOf = hashMapOf<String, String>()
        mapOf["公钥"] = IBase64Util.encode(genKeyPair.public.encoded)
        mapOf["私钥"] = IBase64Util.encode(genKeyPair.private.encoded)

        return mapOf
    }


}

fun main(args: Array<String>) {
    val input = "山前没相见山后别相逢"
    val encryByPrivateKey = RSACryptUtil.encryByPrivateKey(input)
    val encryByPublicKey = RSACryptUtil.encryByPublicKey(input)
    val decryByPrivateKey = RSACryptUtil.decryByPrivateKey(encryByPublicKey)
    val decryByPublicKey = RSACryptUtil.decryByPublicKey(encryByPrivateKey)

    println("私钥加密：$encryByPrivateKey")
    println("私钥解密：$decryByPrivateKey")
    println("公钥加密：$encryByPublicKey")
    println("公钥解密：$decryByPublicKey")
}

import BaseEncrypt.Encrypt.PRIVATEKEYSTR
import BaseEncrypt.Encrypt.PUBLICKEYSTR
import BaseEncrypt.Encrypt.SHA256WITHRSA
import java.security.Signature

/**
 * @Description : 数字签名
 * @Classname    :    SignatureDemo
 * @Date         :    2019/5/1 0:09
 * @Created by         ellecity06
 */
fun main(args: Array<String>) {
    val input = "老朱是傻逼"
    val encode = SignUtil.sign(input)
    val unSign = SignUtil.unSign(input, encode)
    println(encode)
    println(unSign)
}

object SignUtil : BaseEncrypt() {

    /**
     *  默认使用当前私钥
     * @param input 需要加签的数据
     */
    fun sign(input: String): String {
        return sign(input, PRIVATEKEYSTR)
    }

    /**
     * @param input 需要签名的数据
     * @param privateKey 签名需要的私钥
     * @return 返回加签过后的数据
     */
    fun sign(input: String, privateKey: String): String {
        return IBase64Util.encode(with(generateSign(SHA256WITHRSA)) {
            //获取私钥          //初始化
            initSign(RSACryptUtil.generatePrivateKey(privateKey))
            // 设置数据源
            update(toByteArray(input))
            sign()
        })
    }

    /**
     * 校验签名 不传入公钥默认使用当前项目的公钥
     * @param input 原始数据
     * @param sign 签名过后的数据
     */
    fun unSign(input: String, sign: String): Boolean {
        return unSign(input, sign, PUBLICKEYSTR)
    }

    /**
     * 校验签名 ，
     * @param input 原始数据
     * @param sign 签名过后的数据
     * @param publicKey 公钥校验
     */
    fun unSign(input: String, sign: String, publicKey: String): Boolean {
        return with(generateSign(SHA256WITHRSA)) {
            // 初始化签名
            initVerify(RSACryptUtil.generatePublicKey(publicKey))
            update(toByteArray(input))
            verify(IBase64Util.decode(sign))
        }
    }

    private fun generateSign(algorithm: String): Signature {
        //    获取数字签名实例
        return Signature.getInstance(algorithm)
    }
}
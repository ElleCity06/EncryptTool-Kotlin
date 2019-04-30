import BaseEncrypt.Encrypt.AES_ALGORITHM
import BaseEncrypt.Encrypt.AES_KEY
import BaseEncrypt.Encrypt.DES_ALGORITHM
import BaseEncrypt.Encrypt.DES_KEY
import BaseEncrypt.Encrypt.ENCODING
import java.nio.charset.Charset
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * @Description : 加密工具的基类
 * @Classname    :    BaseEncrypt
 * @Date         :    2019/5/1 0:56
 * @Created by         ellecity06
 */
open class BaseEncrypt {
    fun generateCipher(algorithm: String): Cipher {
        return Cipher.getInstance(algorithm)
    }


    fun generteKeySpec(keyStr: String, algorithm: EncryptMode): SecretKeySpec {
        return when (algorithm) {
            EncryptMode.AES -> SecretKeySpec(toByteArray(keyStr), AES_ALGORITHM)
            EncryptMode.DES -> SecretKeySpec(toByteArray(keyStr), DES_ALGORITHM)
        }
    }

    fun generteKeySpec(algorithm: EncryptMode): SecretKeySpec {
        return generteKeySpec(AES_KEY, algorithm)
    }


    fun toByteArray(str: String): ByteArray {
        return str.toByteArray(char())
    }

    fun char(): Charset {
        return charset(ENCODING)
    }

    object Encrypt {
        const val AES_ALGORITHM = "AES"
        const val DES_ALGORITHM = "DES"
        const val RSA_ALGORITHM = "RSA"
        const val MD5_ALGORITHM = "MD5"
        const val SHA1_ALGORITHM = "SHA-1"
        const val SHA256_ALGORITHM = "SHA-256"

     const val SHA256WITHRSA = "SHA256withRSA"
        const val DES_TRANSFORMATION = "DES/CBC/PKCS5Padding"

        const val ENCODING = "UTF-8"
        // AES 加密所需要的key长度为16位
        const val AES_KEY = "1234567812345678"
        // AES 加密所需要的key长度为8位
        const val DES_KEY = "12345678"

        const val PUBLICKEYSTR =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC08e9P1rTL1waGm/nkCONRakBMhzyaISq7EwcJbufgl1cOPaD6LbC94uQVlqWig/ujVrXIpL1Om3W6pJV68N0YHsVIxcw+V39emOKq4BeaAiiM2NWVeAIoExl2JbKPpfOvbJ5LTGCa5BC6wub3yXX9l4ttVHGT7iRmFLbeFyOSDwIDAQAB"
        const val PRIVATEKEYSTR =
            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALTx70/WtMvXBoab+eQI41FqQEyHPJohKrsTBwlu5+CXVw49oPotsL3i5BWWpaKD+6NWtcikvU6bdbqklXrw3RgexUjFzD5Xf16Y4qrgF5oCKIzY1ZV4AigTGXYlso+l869snktMYJrkELrC5vfJdf2Xi21UcZPuJGYUtt4XI5IPAgMBAAECgYAuNoQqXem7DeXqxzdhWCvGhV56rSd7LfFd6hQoAp1SLRTc3Dya6MR1Gtep89nF0fOY2fJ/liOLSgUdcB+FULMGoLPO/3ALWbpN+oZcJq9uCppXUbrpFP76GOx4q/N09vKCPgAAi5qKPgb/zLTIlt5So90ZNuKnq5gvAxxSP5QyAQJBAPwj1x+9bHBKYcnEHUoxzaBPeV69pUvPPTXdcTV3Fux4GJT2nTzijG9pGHlI3V90///Wb2IJyuOwHtiGgc+pp4ECQQC3txMzfGDB9GshlRNOFLX9kjPO+YUsaYCRlDa7ILEvkI4d4j/qT2FAa5cYsl0qLlyZdF8RRZQGsalIrfA9d4GPAkEAsYt7O/pilV+LJExYY5pWNQBBcpkQACXZ8EgSI5fMKI8YoCxX5DuSsBDNDvpkB4eXjEsu+1Xx7Apkbguo9NV+AQJARNSYow+UiNZ0VO6vfu+Ph+OA+ajO1mbovqJTJyUGfZWhSVz9KWJ4Q1SMFbqt4SHhm7TX8XaqER/7FrnkaoMdzQJAbaNPSVrKyk2DTBO6Y1s8fFAhmZGL8bLNrqi+7bUVWXquh5F9K04QdxAZ9Fl5vpJ3zzHOTFs8BaRWtUMVBYR2gA=="

        const val ENCRYPT_MAX_SIZE = 117 // 最大加密长度
        const val DECRYPT_MAX_SIZE = 128 // 最大加密长度
    }

    enum class EncryptMode {
        AES, DES
    }
}

package com.example.banknetsyariah

import android.annotation.TargetApi
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.example.banknetsyariah.utils.hasMarshmallow
import com.example.banknetsyariah.utils.toByteArray
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.JSONObject
import java.io.IOException
import java.security.*
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher


class RSAKeystore {
    companion object{
//        const val RSA_OAEP_PADDING = "RSA/ECB/OAEPPadding"
//        const val RSA_OAEP_PADDING = "RSA/None/OAEPWithSHA256AndMGF1Padding"
        const val RSA_OAEP_PADDING = "RSA/ECB/PKCS1Padding"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "BNSMobile"
    }

    private fun createKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        return keyStore
    }

    fun createAsymmetricKeyPair(): KeyPair {
        val generator: KeyPairGenerator

        if (hasMarshmallow()) {
            generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                ANDROID_KEYSTORE
            )
            getKeyGenParameterSpec(generator)
        } else {
            generator = KeyPairGenerator.getInstance("RSA")
            generator.initialize(2048)
        }

        return generator.generateKeyPair()
    }

    @TargetApi(23)
    private fun getKeyGenParameterSpec(generator: KeyPairGenerator) {

        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
//            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setUserAuthenticationRequired(false)
            .setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512
            )
            .build()

        generator.initialize(builder)
    }

    fun getAsymmetricKeyPair(): KeyPair? {
        val keyStore: KeyStore = createKeyStore()

        val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey?
        val publicKey = keyStore.getCertificate(KEY_ALIAS)?.publicKey

        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }

    fun removeKeyStoreKey() = createKeyStore().deleteEntry(KEY_ALIAS)

    fun encryptJson(data: JSONObject, key: Key?): String {
        val cipher: Cipher = Cipher.getInstance(RSA_OAEP_PADDING)
//        val oaepParams = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val bytes = cipher.doFinal(data.toString().toByteArray(charset("UTF-8")))
        println("this is encrypt value :: ${Base64.encodeToString(bytes, Base64.DEFAULT)}")
        return Base64.encodeToString(bytes, Base64.DEFAULT)
    }

    @Throws(Exception::class)
    fun encrypt(data: String, key: Key?): String? {
        var encryptData : String? = null
    try {
        val cipher: Cipher = Cipher.getInstance(RSA_OAEP_PADDING)
//        val oaepParams = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val bytes = cipher.doFinal(data.toString().toByteArray(charset("UTF-8")))
        println("this is encrypt value :: ${Base64.encodeToString(bytes, Base64.DEFAULT)}")
        encryptData = Base64.encodeToString(bytes, Base64.DEFAULT)
//        println("this is encrypt value :: ${Base64.encodeToString(bytes, Base64.NO_WRAP)}")
    } catch (e: IOException) {
        e.printStackTrace()
    } catch (e: GeneralSecurityException) {
        e.printStackTrace()
    }
        return encryptData
    }

    @Throws(Exception::class)
    fun decrypt(data: String?, key: Key?): String?  {
        var decryptData : String? = null
        try {
            val cipher: Cipher = Cipher.getInstance(RSA_OAEP_PADDING )
//        val oaepParams = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
            cipher.init(Cipher.DECRYPT_MODE, key)
            val encryptedData = Base64.decode(data, Base64.DEFAULT)
            val decodedData = cipher.doFinal(encryptedData)
//        return String(decodedData, charset("UTF-8"))
//        val dec = cipher.doFinal(decodedData)
            decryptData = String(decodedData, charset("UTF-8"))
        } catch (e: IOException) {
            e.printStackTrace()
        } catch (e: GeneralSecurityException) {
            e.printStackTrace()
        }
        return decryptData
    }

    @Throws(Exception::class)
    fun encryptText(text: String, key: Key?): String? {
        var resultText: String? = null
        try {
            Security.addProvider(BouncyCastleProvider())
            val cipher = Cipher.getInstance(RSA_OAEP_PADDING, "BC")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val data = cipher.doFinal(text.toByteArray())
            val encodeData = Base64.encode(data, Base64.DEFAULT)
            resultText = String(encodeData, charset("UTF-8"))
        } catch (e: IOException) {
            e.printStackTrace()
        } catch (e: GeneralSecurityException) {
            e.printStackTrace()
        }
        return resultText
    }



    @Throws(java.lang.Exception::class)
    fun decryptText(text: String?, key: Key?): String? {
        var resultText: String? = null
        try {
            Security.addProvider(BouncyCastleProvider())
            val cipher = Cipher.getInstance(RSA_OAEP_PADDING, "BC")
            cipher.init(Cipher.DECRYPT_MODE, key)
            val data = cipher.doFinal(text?.toByteArray())
            val decodeData = Base64.decode(data, Base64.DEFAULT)
            resultText = String(decodeData, charset("UTF-8"))
        } catch (e: IOException) {
            e.printStackTrace()
        } catch (e: GeneralSecurityException) {
            e.printStackTrace()
        }
        return resultText
    }


}
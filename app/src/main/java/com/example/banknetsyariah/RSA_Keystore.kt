package com.example.banknetsyariah

import android.annotation.TargetApi
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.example.banknetsyariah.utils.hasMarshmallow
import com.example.banknetsyariah.utils.toByteArray
import com.google.gson.JsonObject
import org.json.JSONObject
import java.security.*
import java.security.spec.MGF1ParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

class RSAKeystore {
    companion object{
//        const val RSA_OAEP_PADDING = "RSA/ECB/OAEPPadding"
//        const val RSA_OAEP_PADDING = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"
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
            generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
            getKeyGenParameterSpec(generator)
        } else {
            generator = KeyPairGenerator.getInstance("RSA")
            generator.initialize(4096)
        }

        return generator.generateKeyPair()
    }

    @TargetApi(23)
    private fun getKeyGenParameterSpec(generator: KeyPairGenerator) {

        val builder = KeyGenParameterSpec.Builder(KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setUserAuthenticationRequired(false)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
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

    fun encrypt(data: String, key: Key?): String {
        val cipher: Cipher = Cipher.getInstance(RSA_OAEP_PADDING)
//        val oaepParams = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val bytes = cipher.doFinal(data.toString().toByteArray(charset("UTF-8")))
        println("this is encrypt value :: ${Base64.encodeToString(bytes, Base64.DEFAULT)}")
        return Base64.encodeToString(bytes, Base64.DEFAULT)
//        println("this is encrypt value :: ${Base64.encodeToString(bytes, Base64.NO_WRAP)}")
    }

    fun decrypt(data: String, key: Key?): String  {
        val cipher: Cipher = Cipher.getInstance(RSA_OAEP_PADDING)
//        val oaepParams = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        cipher.init(Cipher.DECRYPT_MODE, key)
        val encryptedData = Base64.decode(data, Base64.DEFAULT)
        val decodedData = cipher.doFinal(encryptedData)
//        return String(decodedData, charset("UTF-8"))
//        val dec = cipher.doFinal(decodedData)
        return  String(decodedData, charset("UTF-8"))
    }

}
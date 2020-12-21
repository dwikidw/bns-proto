package com.example.banknetsyariah


import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.androidnetworking.AndroidNetworking
import com.androidnetworking.common.Priority
import com.androidnetworking.error.ANError
import com.androidnetworking.interceptors.HttpLoggingInterceptor
import com.androidnetworking.interfaces.JSONArrayRequestListener
import com.example.banknetsyariah.utils.RestApiService
import com.example.banknetsyariah.utils.hasMarshmallow
import com.example.banknetsyariah.utils.isDeviceSecure
import com.example.banknetsyariah.utils.showDeviceSecurityAlert
import kotlinx.android.synthetic.main.activity_login.*
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.*


class LoginActivity : AppCompatActivity() {

    private var publicKeyServer : PublicKey? = null
    private var privateKeyServer : PrivateKey? = null
    private lateinit var dataHashMap : HashMap<String, ByteArray>

    private lateinit var rsaKeystore : RSAKeystore
    private lateinit var rsaKeyPair : KeyPair
    private var encrypteData : String? = null

    @RequiresApi(Build.VERSION_CODES.M)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)
        AndroidNetworking.initialize(applicationContext);

        //To Check Lock Screen Enabled or not
        val keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if(!isDeviceSecure(keyguardManager)) showDeviceSecurityAlert(this)

        rsaKeystore = RSAKeystore()
        generateKey()

        btnLogin.setOnClickListener() {
            requestKey()
        }


        btnRegister.setOnClickListener() {
            onLogin()
        }



    }



    private fun generateKey() {
        if (hasMarshmallow()) {
            rsaKeystore.createAsymmetricKeyPair()
            rsaKeyPair = rsaKeystore.getAsymmetricKeyPair()!!
        }else{
            rsaKeyPair = rsaKeystore.createAsymmetricKeyPair()
        }
    }





//    Get Public Key Backend
    private fun getPublicKey(pbKey: String?) : PublicKey {
        val pbKeyServ = Base64.decode(pbKey, Base64.DEFAULT)
        val key = String(pbKeyServ, StandardCharsets.UTF_8)
            .replace("-----BEGIN RSA PUBLIC KEY-----", "")
            .replace(System.lineSeparator(), "")
            .replace("-----END RSA PUBLIC KEY-----", "");
        val decodeKey = Base64.decode(key, Base64.DEFAULT)
        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = X509EncodedKeySpec(decodeKey)
        return keyFactory.generatePublic(keySpec)
    }

//    Get Key Local
    private fun getKey() : String {
        rsaKeyPair = rsaKeystore.getAsymmetricKeyPair()!!
        val encodedPublicKey: ByteArray = rsaKeyPair.public.encoded
        println("Public Key Mine rsaKeyPair.public ::: ${String(encodedPublicKey, charset("UTF-8"))}")
        val publicKeyString = Base64.encodeToString(encodedPublicKey, Base64.DEFAULT);
        val beginPem = "-----BEGIN RSA PUBLIC KEY-----\n"
        val endPem = "-----END RSA PUBLIC KEY-----"
        val pemFile = "$beginPem$publicKeyString$endPem"
        Log.d("Ready Public Key ::", "${Base64.encodeToString(pemFile.toByteArray(), Base64.DEFAULT)}")
        return Base64.encodeToString(pemFile.toByteArray(), Base64.DEFAULT)
    }

//    Get Timestamp Formatted yyyy-MM-dd HH:mm:ss
    private fun getCurrentTime(): String {
        val timezone = ZoneId.systemDefault()
        return ZonedDateTime.now(timezone).format(
            DateTimeFormatter
                .ofPattern("yyyy-MM-dd HH:mm:ss")
        )
    }

//    Create Signature
    private fun createSignature(partnerId: String, timestamp: String) : String {
        val baseSignature = "$partnerId|$timestamp"
        val digest : MessageDigest = MessageDigest.getInstance("SHA-256");
        val hash = digest.digest(baseSignature.toByteArray())
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

//  Try On Login
    private fun onLogin() {
        val id = "Partner-001"
        val timestamp = getCurrentTime()
        val signature = createSignature(id, timestamp)
        val encrypt = encryptPassword("${field_pw.text}")
        val user = "Semeru"
        val apiService = RestApiService()

        val userLogin = UserLogin(
            "$id",
            "$timestamp",
            "$signature",
            "$encrypt",
            "$user"
        )
        apiService.loginUser(userLogin) {
            Log.d("User info Login ::", "$it")
        }
    }

//    Generate Backend Key
    private fun requestKey() {
            val idPartner = "Partner-001"
            val timestamp = getCurrentTime()
            val signature = createSignature(idPartner, timestamp)
            val pbKey = getKey()
            val apiService = RestApiService()
            val userInfo = UserInfo(
                "$idPartner",
                "$timestamp",
                "$signature",
                "Semeru",
                "$pbKey"
            )

            apiService.requestKey(userInfo) {
                Log.d("user Info Result ::", "$it")
                publicKeyServer = getPublicKey(it?.publicKey)
                Log.d("Public Key Server on Bytes :: ", "${getPublicKey(it?.publicKey)}")
            }


    }



//    Encrypt Password
    private fun encryptPassword(pw: String) : String {
        var encryptPas : String? = null
        val jsonPassword = JSONObject()
        try {
            jsonPassword.put("password", "$pw")
        } catch (e: JSONException) {
            e.printStackTrace()
            println("JsonException error :: $e")
        }
        println("JSON PASSWORD :: $jsonPassword")
        encryptPas = rsaKeystore.encryptJson(jsonPassword, publicKeyServer)
        encryptPas = encryptPas?.replace("\n", "")
        println("ENCRYPT PAS :: $encryptPas")
       return  encryptPas

    }

//    Decrypt Local
    private fun decrypt() {
//    need data : String
    val data = ""
    resultTextView.text = rsaKeystore.decrypt("$data", rsaKeyPair.private)
    }

//    Encrypt Local
    private fun encrypt() {
//        need data : String & public key : PublicKey
        val data = ""
        val publicKey : PublicKey? = null
       resultTextView.text = rsaKeystore.encrypt("$data", publicKey)
    }

    private fun getPvServ() {
        val pvKey = "MIIEpAIBAAKCAQEAmEeSkr+ewIBfCkj0V0v64gpR+YBkkd7Wx4/+ZCwbOYDkpb/P\n" +
                "no50ehyYdqGRjvuDv8y6M9VxBsEIDvo4QMmyJnWzTYpSpw5ijDf20IPnpCUl8VP1\n" +
                "wDIoo4uvsinascKEM/t+RWEl4NJVEtnlzdy3kiQUX01FHHJhoKCwDpyY2l/rFapB\n" +
                "mEiPtyCHyHXrwrfcWECABwfMQb7/1KeXmfy5UFneV3C+Gl1fXMOZnupmP6WJFcqX\n" +
                "F/XLfJWmF0XMfqYLsR4dLo6lnaiVHe1JXGVBnd5MzNyX+SjFaVQoqrL4V/yUcCqq\n" +
                "cSxX0GLmQQWQOa8aIk9rQJSoBV3Y1NvUcHbZ0QIDAQABAoIBAG9LUArE1afnqo5/\n" +
                "x2TN+SyfUk5B0j7yWJM94DUiLzuVwoaJa5p8jxB4Oc3qQ9H2bNIPNL+Rbav8BIG9\n" +
                "ysM/Jl8JguRXBhVmZAwLEu5OmUvUgqigLmorvpvZCa3y/Q0SF0FOu3jFicOItfiz\n" +
                "HEua1ueOSv1kIfCqgEO/bS0gsm5WrNIS4cLsAEZyu5yE7Pdvef6t1i+SFw9W9OVw\n" +
                "1jM4nBHQ395Q+ti8BZhRbrriW3pvF6XEY0OO5IrZE0N477YXm8S3T55Df8C/0Y08\n" +
                "dZ11msnCkkO3yfP2aBghesmEy2LdymOtMtqWqDSIKUTqbMsUICWmTERBPgPBvHUv\n" +
                "RuN/XkkCgYEA4lcy96z6Edjx5LH0BeiZRknV3SS9JjnvjpGU87QJu9ht5dhYoxLo\n" +
                "2uC0E6urXFU/n0NT34bgIHXv9M/TqCkF3O94RMdKWD/d2hGyGH3FsB+vUscSFJGg\n" +
                "r5yqayVzeE+orWpEYtLS4o44qJCu6VHGDfpixZWzwTfn0wsoHTfKK1MCgYEArDvt\n" +
                "yAtSlE1xS7TK++GDoA+M7xIB7OH9v2C8vgXUzp1XGfKnDGhWzJ1fuxMgedGK0Auh\n" +
                "X3RXDfJnUcF/BCzhpSk2I7ZcvPDZGHejV/uFWJCNIOtzv9Uz5TElQE941Ug7t2Ih\n" +
                "NR3KdkHEfWRLvVsze1ZgyafbJjTnS/2nYTiepcsCgYEAh6X08MTlVj7rscEI22Ws\n" +
                "PpjPqGp1Reyg6pPLbkbvMnoiWwbPEGSr00mqAsP2vi6FI8DpCmS9/BZSiijn07dK\n" +
                "QT/vl2DM6JjWL/Q9BTqTeNt0aqrN5i/k2nqNFAvs6STslYnDlGp/YrITuMqFWWXd\n" +
                "ydDO01XF1j3YHP5puyENc+sCgYAqafutdrRYVxXeaeBO1QNACHRRb2LP/fsqBN2W\n" +
                "AgOc+fw4JJxkntE5REwN2rD1rtd7UlHkGtdRVO+Cn57y3UaYEKUHeGIwGTOtJdEw\n" +
                "2nzFCZvnjnQLuqoz971PsAJ2q3ohN+YrmXGBW8LSij9omyv7ZJMjNdXu+7o16Xot\n" +
                "o+7VrwKBgQDNL7po0R4FP7he5AZPY81cBqp1mGGga9GxOAM9rJM3I1YnO3+14MFw\n" +
                "D9DW3isi9Ub5x0aZuT57qdiAQcBar/4LeJZ4d4DIEtl19b/KFqqrAXfmnJgbQBzB\n" +
                "FlpkFU3yB04rDGtrGbGLbtp618BGvnH5Vqmv4q3vdG23PHx6ZBJ69g=="

        val pvKeyServ = Base64.decode(pvKey, Base64.DEFAULT)
        println("privateKeyServer :: ${String(pvKeyServ, charset("UTF-8"))}")

//    val key = String(pvKeyServ, StandardCharsets.UTF_8)
//            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
//            .replace(System.lineSeparator(), "")
//            .replace("-----END RSA PRIVATE KEY-----", "");
//
//        val publicKeySvr = Base64.decode(key, Base64.DEFAULT)
        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = PKCS8EncodedKeySpec(pvKeyServ)
        privateKeyServer = keyFactory.generatePrivate(keySpec)
        println("privateKeyServer :: $privateKeyServer")

//        val modulus = BigInteger(1, pbKey)

//        val spec = RSAPublicKeySpec(modulus);
//        val pbSer = keyFactor.generatePublic(spec)
//        println("modulussss :: $pbSer")
    }
    private fun getPbServ(pb: String?) : PublicKey {
//        val pbkkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0UdRvG2VhqgGNV/PsvUcMPMGzVA57c7rVuVISgpJnSxwgewWk3JHPz7faEiumCVyPBavl0Ev4ZJuxOGMvnsWfwurORGi3PgjdTceWva2x6urNm6ci2SL0vkUMMCkGL6vaUXsciXoL3tDYAfEmExEBdSjwYXt3dNZJ92eIAB2L9xe7kmh349t9/wWrgpptriGrhiJwtAEfG4pUB6nGtIUnF2KOM4605meOiQA4VbpxdVV+pLLWu94NydIvE21aqnH2NtOu9oLIu+KQBL1DCt2H13HYF6lJcKJTqQ1BeZJ+VsmTEAxcfkVmzLPdzEmmxMoYhlQPP+iY0yaPzr5Fe03swIDAQAB"
        val pbk = pb?.replace("\n", "")
        val pbKeyServ = Base64.decode(pbk, Base64.DEFAULT)
//        val key = String(pbKeyServ, StandardCharsets.UTF_8)
//            .replace("-----BEGIN RSA PUBLIC KEY-----", "")
//            .replace(System.lineSeparator(), "")
//            .replace("-----END RSA PUBLIC KEY-----", "");

//        val publicKeySvr = Base64.decode(key, Base64.DEFAULT)
        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = X509EncodedKeySpec(pbKeyServ)
        publicKeyServer = keyFactory.generatePublic(keySpec)
        return  keyFactory.generatePublic(keySpec)

//        val modulus = BigInteger(1, pbKey)

//        val spec = RSAPublicKeySpec(modulus);
//        val pbSer = keyFactor.generatePublic(spec)
//        println("modulussss :: $pbSer")
    }

    override fun onDestroy() {
        if(::rsaKeyPair.isInitialized)rsaKeystore.removeKeyStoreKey()
        super.onDestroy()
    }

}


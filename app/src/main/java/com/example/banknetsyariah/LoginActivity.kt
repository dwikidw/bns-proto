package com.example.banknetsyariah


import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.view.KeyEvent
import android.view.View
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
import java.security.interfaces.RSAPublicKey
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
    private var encrypteData : String = ""

    @RequiresApi(Build.VERSION_CODES.M)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)
        AndroidNetworking.initialize(applicationContext);

        //To Check Lock Screen Enabled or not
        val keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if(!isDeviceSecure(keyguardManager)) showDeviceSecurityAlert(this)


//        val timezone = TimeZone.getDefault()
//        println("timezone :: $timezone")
        rsaKeystore = RSAKeystore()
        generateKey()

        btnLogin.setOnClickListener() {
//            getDummyKey()
//            Log.d("Public Key", "$publicKeyServer")
//            Log.d("Private Key", "$privateKeyServer")
//        requestKey()
            getKey()
            //GET PUBLIC KEY
//         val data = field_pw.text.toString()
//            resultTextView.text = encryptPassword(data)
//            getPvServ()
//           encrypteData = rsaKeystore.encrypt("$data", rsaKeyPair.public).toString()
//            resultTextView.text = encrypteData
        }


        btnRegister.setOnClickListener() {
            val data = "ZDAVjURA+4FAmC1MNi8+R+p4gj5+iim66yS9RekO+b72P2iYvcjU54iJnhdPay9wbbYZdKcnFIvc/OfJMuDyA2gVjWF2BhAKXjqaQpZwe1i69H3wwExFJbJ6Hu0KYzhLTX96eaffjt+vmmEQHGZYHWWNLAG6+45/MmrJdnte0rXvVyBbvx/KgJTvK4vK8+dqQXXE8ZWZE4YJsb8hAsiFIyN4/YJWxpUGoVLpv4kkeODB1LxirT6kJh6WFDVSluR3YQgD/mxPdnTg5xyMdjq5JSlRHzP8Tky3JS/XJwDP0sBE1fih1uv7Krvn0Dr433bWVFawVIVK9jEsSTC3j4dBpg=="
            println("encryptt : ${rsaKeystore.encrypt("$data",rsaKeyPair.private)}")
//            onLogin()
//            requestBalance()
//            println("this is server public key :: $publicKeyServer" )
//            println("this is my public key :: ${rsaKeyPair.public}")
        }



    }


//    private fun getDummyKey() {
//        getPbServ()
//        getPvServ()
//    }
    private fun generateKey() {
        if (hasMarshmallow()) {
            rsaKeystore.createAsymmetricKeyPair()
            rsaKeyPair = rsaKeystore.getAsymmetricKeyPair()!!
        }else{
            rsaKeyPair = rsaKeystore.createAsymmetricKeyPair()
        }
    }

    private fun getPvKey() {
        rsaKeyPair = rsaKeystore.getAsymmetricKeyPair()!!

        println("PRIVATE KEY :: ${Base64.encodeToString(rsaKeyPair.private.encoded, Base64.NO_WRAP)}")

    }

    private fun getKey() : String {
        rsaKeyPair = rsaKeystore.getAsymmetricKeyPair()!!
//        println("Public Key Mine rsaKeyPair.public ::: ${rsaKeyPair.public}")
        val publicKeyString = Base64.encodeToString(rsaKeyPair.public.encoded, Base64.NO_WRAP);
        val beginPem = "-----BEGIN RSA PUBLIC KEY-----\n"
        val endPem = "\n-----END RSA PUBLIC KEY-----"
        val pemFile = "$beginPem $publicKeyString $endPem"
//        println("Pem FILE :: $pemFile")
        println("public key :: ${Base64.encodeToString(pemFile.toByteArray(), Base64.NO_WRAP)}")
//        println("publicKeyString from getKey() :: $publicKeyString")
//        val keyFactor = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
//        val pbKey = Base64.encodeToString(pemFile.toByteArray(), Base64.NO_WRAP)
//        Log.d("STRINGPBKEYMINE ::", "${Base64.encodeToString(pemFile.toByteArray(), Base64.NO_WRAP)}")
        return Base64.encodeToString(pemFile.toByteArray(), Base64.NO_WRAP)
    }

    private fun createSignature(partnerId: String, timestamp: String) : String {
        val baseSignature = "$partnerId|$timestamp"
        val digest : MessageDigest = MessageDigest.getInstance("SHA-256");
        val hash = digest.digest(baseSignature.toByteArray())
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    private fun getPublicKey(pbKey: String?) : PublicKey {
        println("Public Key Server :: $pbKey")
        val pbKeyServ = Base64.decode(pbKey, Base64.NO_WRAP)
        val key = String(pbKeyServ, StandardCharsets.UTF_8)
            .replace("-----BEGIN RSA PUBLIC KEY-----", "")
            .replace(System.lineSeparator(), "")
            .replace("-----END RSA PUBLIC KEY-----", "");

        val publicKeySvr = Base64.decode(key, Base64.NO_WRAP)
//        Log.d("key public server", "$publicKeySvr")
        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = X509EncodedKeySpec(publicKeySvr)
        return keyFactory.generatePublic(keySpec)

//        val modulus = BigInteger(1, pbKey)

//        val spec = RSAPublicKeySpec(modulus);
//        val pbSer = keyFactor.generatePublic(spec)
//        println("modulussss :: $pbSer")

    }
//    private fun getPbServ() : PublicKey {
//        val pbkkey = "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeTRqWmRPTkhZNkVXSEhXdmxpajcKbUlzT1BpdW15aXJKUHhxNTFqbXFiUnlwUEVaRWpXZWxFUVFRN1cyclVEQlZzVmQ0Q010eXlFZWhuZXd2NjNULwovcjhNSEgxcnRvamlxQWZMOGZpZmR1cDFNTmdzV05SWlBITjdOMUhDRnFpTzhsSGFLUDBKdFdET0grQUNBYXhpCmRScUJtUVdHV21CV2pFRGs2OE1lY2xKcll3Y3Rwem9DUXpSM3h6ZTJGc2lCYU1pakZpNlU3N1V1UEdBSDE4VVgKUnBDdzRGM2ZXVERWRUU1OVlzdnBFdlBMQkxhNGhKejNJTm9EVGgra1IycE9NM2N6VlVGRERjall4NC82b2hpagpDVVZmbHVMRW4wQVptYmtTOVh0VTY0THFuVXNXMFVlb2J0Nm1HRkNrK01MK3ZGWTI5NFZjZjgrN2s1QkxIaG9yCjB3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K"
//        val pbKeyServ = Base64.decode(pbkkey, Base64.DEFAULT)
//        val key = String(pbKeyServ, StandardCharsets.UTF_8)
//            .replace("-----BEGIN RSA PUBLIC KEY-----", "")
//            .replace(System.lineSeparator(), "")
//            .replace("-----END RSA PUBLIC KEY-----", "");
//
//        val publicKeySvr = Base64.decode(key, Base64.DEFAULT)
//        val keyFactory = KeyFactory.getInstance("RSA")
//        val keySpec = X509EncodedKeySpec(publicKeySvr)
//        publicKeyServer = keyFactory.generatePublic(keySpec)
//        return  keyFactory.generatePublic(keySpec)
//
////        val modulus = BigInteger(1, pbKey)
//
////        val spec = RSAPublicKeySpec(modulus);
////        val pbSer = keyFactor.generatePublic(spec)
////        println("modulussss :: $pbSer")
//    }
    private fun getPvServ() {
        val pvkkey = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb2dJQkFBS0NBUUVBb0tENDdObElVTEFUdksxYjMvUzQzK3BUaE1VdTFtWDNQYUF5T3V0d2dFamlhTVpNCmtsdjM5cVVYcm5MRXRjdTVmWEZHMWhBUytuMWQvNGpXdU0xTTQ4TXVBV0RYOUVoTnRoWmJVZlJKeHh4THFIaVMKVkpHbk1kVUpDSE5GOVNIUUx3OG92dVhNTm9LbGdBVE4yUmlMSkxCRGRwejZoUkFvcG1lZ3JiSyt4UGxZMHhZdAppZnpLSnFyeUJvbHhwSUpuSXJoTWllRDl2OVdyZGF4QkhCbHZQc2pxb3N3VGpibFdOaW1uUjdOWmlUSlp6dFRVClBBZFBVSTljSE1CcDZNN2tiUTdsZ3FiODBFVjFLdGQ0VklIcVBCemVSQkl0SEVGSitnb1R5UVd4Q09KM01wVjEKOVNINnVRbnpEV0s5aUVoVGRiVmNxaTNGbzI2N0JtUnA1WWk3U1FJREFRQUJBb0lCQUdnRTFpNUs1eEdaZEs2UwpkUlNxbmE0alNNS0tEcks0aFV0Ykdpd2RtMVQzM2VhTHc3cGo1RWZNMFhFZTBWUUpBYTNDVldUNk05QVNyM1J6CllObDcyWGNGUmgyT1lVcklKOHJxMzJoTEVodm1ydmdDWElCM2NoWkxKdlpaNzh1MmdlSjNwcU00bk80UDNLenkKYjN0TzhZeG91TWR2RUt4cXNtaFFZelVZczRGS0VOSDd3ZFRSZytHVVBDTU50eHVMRFdLdWpkOFBzd09vTTI3ZwpOWE5La1JJVGVLemdmZjBlYS9IcVVTUVdNMHJGTXpmdEFWY1A1WjB3WmRhK1JTWHdWWmNGSkZxbmk0d0ZsN0RhCk53Z2hCVkpGQTh4K0VwSFRnZTlMSVFpS21EbUJSZURvZHc1a002RU0zcEV6UEJBdGdNYnJ2dVRWRzJMU0pCWWgKeUpkMUNvRUNnWUVBMU14QTdIWXNYWWJvd3RqT0FVcFpsdUpnSmViMDNCOXFLVWZYeWJXZDh1eVdsb0FhV2ROSApaL0RnOE1BdGVaQktxcVpXUTBJMFFON3Q3b1hZWElzVWx4S25ZbE5VNTAyckdHcjF2WnlvS2Vtd2FFdTFzTk9YCldJUHdzYmVVYTdmb25rUjZrSW9WMWlXTms5RjN0UjVlK09HOU0yUDMwNnErSTBvbEx6V3QreFVDZ1lFQXdUMVYKeVVEZGk3c1NLS3NYVGxMb2J4T2ltMjVpeC82TWVSekdBdndnRDlBUjdwb2ZKMVU1ajVieHZKSXhDMENjYXBwdApJMXh6OXBNVmtCa1R6QmtmVkdjSDhjb20yMit0K3ZGNlVSSWpUekJ2NWcrRFZtYzR3bVQ4WVFoWkw2dzRQeCs0CisvWDFOWHQvMlVrNTJoMkRKQjQrclV6WWtWeldNT1krTE9ETS9HVUNnWUE1TWhrMU5XSWhWVlNVb285a1cyYVAKSHBOM1BJZU43c2VyQnN0aVJQV0tTTHNGQXJPU2R5NVhLckJiSlZ4VHMwdk9hRjBCUVBjb2hJTHhQSHAyRFUvZwpkendVT28rMGgvUzM0Ry9pb2d1MUVFSEJGckJrTWNzWkdJV0dUdkNPcjJUUHZWb3dKVjFQTE5MTDYxNUFpVVEvCm92VW1yZlQ3cUlYb21GSThTVEpWTFFLQmdIWFFBMEZUL3I1Mkt6Z0lONGxWR3NpOTIrR1BoMElQZTIxTGtaMjQKUVlQaWcweEpRcjBrUkplNm0xOHdjaDQrSWg4TVQ0WERsQis4eE9TNXBVeEY5TWZzbVBkZEhCdWxGeGxycC90TgpaNkdjRWx6ZEVHSFpSTTJmN0E3c25CTm9tRkpEOFBBTW9KY2UyRytOS1d4Rm1mS25UZWN5ZHNjSkpyMWhZbjdSCi82ZlJBb0dBY25ubnA1a2t0WG50Qjh6amgwdFo5ZlgxaGZWLzFJV2lMREdrV1hyTlcrVVFXMU8weFIydlRaWloKaS9hUUhDSkNQVGd2b2lsM3FRK0ZkRVM4N2lqbHNXVFhZR1pKL2pJdGFGNmJVWm95R3JhcnZUcXZuQlVZaWJpZgo2SGozRHp6eWpuWnRMa2ZiVWlXMlkranRZTG11c1RlSzRDbnE4UGZFaC9EOG5yYVNrZTg9Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=="
        val pvKeyServ = Base64.decode(pvkkey, Base64.DEFAULT)
        println("privateKeyServer :: ${String(pvKeyServ, charset("UTF-8"))}")

    val key = String(pvKeyServ, StandardCharsets.UTF_8)
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace(System.lineSeparator(), "")
            .replace("-----END RSA PRIVATE KEY-----", "");

        val publicKeySvr = Base64.decode(key, Base64.DEFAULT)
        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = PKCS8EncodedKeySpec(publicKeySvr)
        privateKeyServer = keyFactory.generatePrivate(keySpec)
        println("privateKeyServer :: $privateKeyServer")

//        val modulus = BigInteger(1, pbKey)

//        val spec = RSAPublicKeySpec(modulus);
//        val pbSer = keyFactor.generatePublic(spec)
//        println("modulussss :: $pbSer")
    }

    private fun getCurrentTime(): String {
        val timezone = ZoneId.systemDefault()
        return ZonedDateTime.now(timezone).format(
            DateTimeFormatter
                .ofPattern("yyyy-MM-dd HH:mm:ss")
        )
    }


    private fun onLogin() {
        val id = "Partner-001"
        val timestamp = getCurrentTime()
        val signature = createSignature(id,timestamp)
        val encrypt = encryptPassword("${field_pw.text}")
        val user = "Rinjani"
        val apiService = RestApiService()

        val userLogin = UserLogin(
            "$id",
            "$timestamp",
            "$signature",
            "$encrypt",
            "$user"
        )
        apiService.loginUser(userLogin) {
            Log.d("JSON SENT", "$userLogin")
            Log.d("Success", "$it")
        }
    }

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
                "Rinjani",
                "$pbKey"
            )

            apiService.requestKey(userInfo) {
                getPublicKey(it?.publicKey)
//                publicKeyServer = getPublicKey(it?.publicKey)
                Log.d("PUBLIC KEY SERVER", "$it")
            }


    }
    // Rinjani
    // Pasword 123456
    // POSTMAN security
    //[B@565547c public key from server
    //response Login
    //responseCode
    //responseMessage
    //sessionID

    private fun requestBalance() {
        val idPartner = "Partner-001"
        val timestamp = getCurrentTime()
        val signature = createSignature(idPartner, timestamp)
        val apiService = RestApiService()
        val userInfo = UserBalance(
            "$idPartner",
            "$timestamp",
            "$signature",
            "111666666"
        )

        apiService.inqBalance(userInfo) {
            resultTextView.text = "${it?.accountCurrency} ${it?.accountBalance} "
        }

    }

    private fun getBalance() {
        val partnerId = "Partner-001"
        val currentTimestamp = getCurrentTime()
        val signature = createSignature(partnerId, currentTimestamp)
        val jsonObject = JSONObject()

        try {
            jsonObject.put("PartnerID", "$partnerId")
//            jsonObject.put("RequestTimestamp", "$currentTimestamp")
            jsonObject.put("RequestTimestamp", "$currentTimestamp")
            jsonObject.put("Signature", "$signature")
            jsonObject.put("AccountNo", "111666666")
//            jsonObject.put("UserID", "Fery")
//            jsonObject.put("PublicKey", "$pbKey")
//            jsonObject.put("name", "Dwiki Baskoro")
//            jsonObject.put("job", "Software Engineer")
        } catch (e: JSONException) {
            e.printStackTrace()
            println("JsonException error :: $e")
        }
//        AndroidNetworking.enableLogging(HttpLoggingInterceptor.Level.BODY);
//        AndroidNetworking.post("http://34.101.200.120:9090/security/generatepartnerkey")
        AndroidNetworking.post("http://34.101.200.120:9090/account/inqbalance")
            .setContentType("application/json")
            .addJSONObjectBody(jsonObject)
            .setPriority(Priority.HIGH)
            .build()
            .getAsJSONArray(object : JSONArrayRequestListener {
                override fun onResponse(response: JSONArray) {
                    // do anything with response
                    val data = response.toString()
                    resultTextView.text = data
                    println("RESPONSE :: $data")
                }

                override fun onError(error: ANError) {
                    println("this is error body :: ${error.errorBody}")
                }
            })
    }
    private fun sendPost() {
        val pbKey = getKey()
        val partnerId = "Partner-001"
        val currentTimestamp = getCurrentTime()
        val signature = createSignature(partnerId, currentTimestamp)
        val jsonObject = JSONObject()
        try {
            jsonObject.put("PartnerID", "$partnerId")
//            jsonObject.put("RequestTimestamp", "$currentTimestamp")
            jsonObject.put("RequestTimestamp", "$currentTimestamp")
            jsonObject.put("Signature", "$signature")
//            jsonObject.put("AccountNo", "111666666")
            jsonObject.put("UserID", "Fery")
            jsonObject.put("PublicKey", "$pbKey")
//            jsonObject.put("name", "Dwiki Baskoro")
//            jsonObject.put("job", "Software Engineer")

            Log.d("JSON DATA", "${jsonObject.toString()}")
        } catch (e: JSONException) {
            e.printStackTrace()
            println("JsonException error :: $e")
        }
        AndroidNetworking.enableLogging(HttpLoggingInterceptor.Level.BODY);
        AndroidNetworking.post("http://34.101.200.120:9090/security/generatepartnerkey")
//        AndroidNetworking.post("http://34.101.200.120:9090/account/inqbalance")
//        AndroidNetworking.post("https://reqres.in/api/users")
            .setContentType("application/json")
            .addJSONObjectBody(jsonObject)
            .setPriority(Priority.HIGH)
            .build()
            .getAsJSONArray(object : JSONArrayRequestListener {
                override fun onResponse(response: JSONArray) {
                    // do anything with response
                    Log.d("Response", "$response")
                }

                override fun onError(error: ANError) {
                    // handle error
                    resultTextView.text = "Error Response :: ${error.errorBody}"
                    println("this is error detail  :: ${error.errorDetail}")
                    println("this is error body :: ${error.errorBody}")
                    println("this is error code :: ${error.errorCode}")
                }
            })
    }

    override fun onDestroy() {
        if(::rsaKeyPair.isInitialized)rsaKeystore.removeKeyStoreKey()
        super.onDestroy()
    }

    private fun encryptPassword(pw: String) : String {
        val jsonPassword = JSONObject()
        try {
            jsonPassword.put("password", "123456")
        } catch (e: JSONException) {
            e.printStackTrace()
            println("JsonException error :: $e")
        }
//       encrypteData = rsaKeystore.encryptJson(jsonPassword , rsaKeyPair.public)
//        resultTextView.text = "THIS IS ENCRYPT VALUE :: $encrypteData"
//        Log.d("ENCRYPTVALUE", "$encrypteData")
       return  rsaKeystore.encryptJson(jsonPassword , rsaKeyPair.public)

    }

    private fun decrypt() {
        val data = "GY8G8ZaM8zBReMGr0ff5gRBC2HUzb5TYXPkTh3Ym7S0qc7tJCRGx5P/9WK7hCu76fjqlf/UBQ8jTzjkxW2ku4VB7pU7bZpfD477NEw3lMf9/UFqWD/cTIOjSke4CTeFT0yHj2r9jEjPaQX8ps3InwmVfrgHUrr+lj0k5cprJjZ5guLxxSh6qnh8TR9XE+Wd4nr6aKogXn+bqSMvGt6TulOb+P76niuZixa85mFBTP92AuNOgyCisOOpBHCwCUFypYqwT13RuUSmkkzDTafRgBelb2NPqr3afFTAeD4eAUbRs4HVr3OkMUPbptXUTF+WBYVCtU3Ww6BegGReXap6YXQ=="
       resultTextView.text = rsaKeystore.decrypt("$data", privateKeyServer)
    }

}


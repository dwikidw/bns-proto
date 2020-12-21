package com.example.banknetsyariah

import com.google.gson.annotations.SerializedName

class User {
    var PartnerId: String? = null
    var RequestTimestamp: String? = null
    var Signature: String? = null
    var UserId: String? = null
    var PublicKey: String? = null
}

class Tes {
    var name: String? = null
    var job: String? = null
}


data class UserInfo (
    @SerializedName("PartnerID") val PartnerID: String?,
    @SerializedName("RequestTimestamp") val RequestTimestamp: String?,
    @SerializedName("Signature") val Signature: String?,
    @SerializedName("UserID") val UserID: String?,
    @SerializedName("PublicKey") val PublicKey: String?
    )

data class UserInfoResult (
    @SerializedName("responseCode") val responseCode: String?,
    @SerializedName("responseMessage") val responseMessage: String?,
    @SerializedName("publicKey") val publicKey: String?
    )

data class UserBalance (
    @SerializedName("PartnerID") val PartnerId: String?,
    @SerializedName("RequestTimestamp") val timestamp: String?,
    @SerializedName("Signature") val signature: String?,
    @SerializedName("AccountNo") val accountNo: String?
    )

data class UserLogin (
    @SerializedName("PartnerID") val PartnerId: String?,
    @SerializedName("RequestTimestamp") val timestamp: String?,
    @SerializedName("Signature") val signature: String?,
    @SerializedName("EncryptValue") val encryptValue: String?,
    @SerializedName("UserID") val userId: String?
    )
data class UserInfoLogin (
    @SerializedName("responseCode") val responseCode: String?,
    @SerializedName("responseMessage") val responseMessage: String?,
    @SerializedName("sessionId") val sessionId: String?
    )

data class UserInfoBalance (
    @SerializedName("responseCode") val responseCode: String?,
    @SerializedName("responseMessage") val responseMessage: String?,
    @SerializedName("responseTimestamp") val responseTimestamp: String?,
    @SerializedName("accountNo") val accountNo: String?,
    @SerializedName("accountCurrency") val accountCurrency: String?,
    @SerializedName("accountBalance") val accountBalance: String?
    )

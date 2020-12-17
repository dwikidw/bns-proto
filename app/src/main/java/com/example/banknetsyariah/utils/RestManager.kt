package com.example.banknetsyariah.utils

import com.example.banknetsyariah.*
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response

class RestApiService {
    fun requestKey(userData: UserInfo, onResult: (UserInfoResult?) -> Unit){
        val retrofit = ServiceBuilder.buildService(RestApi::class.java)
        retrofit.requestKey(userData).enqueue(
            object : Callback<UserInfoResult> {
                override fun onFailure(call: Call<UserInfoResult>, t: Throwable) {
                    t.printStackTrace()
                    println("error ${t.message}")
                    onResult(null)
                }
                override fun onResponse( call: Call<UserInfoResult>, response: Response<UserInfoResult>) {
                    val raw = response.raw()
                    val code = response.code()
                    val message = response.message()
                    val errorBody = response.errorBody()?.string()
                    val body = response.body()
//
//                    println("RAW:: $raw")
//                    println("CODE:: $code")
//                    println("MESSAGE:: $message")
//                    println("ERROR BODY:: $errorBody")
//                    println("BODY:: $body")
                    onResult(body)
                }
            }
        )
    }

    fun inqBalance (userData: UserBalance, onResult: (UserInfoBalance?) -> Unit) {
        val retrofit = ServiceBuilder.buildService(RestApi::class.java).also {
            it.inquiryBalance(userData).enqueue(
                object : Callback<UserInfoBalance> {
                    override fun onFailure(call: Call<UserInfoBalance>, t: Throwable) {
                        t.printStackTrace()
                        println("error ${t.message}")
                        onResult(null)
                    }
                    override fun onResponse( call: Call<UserInfoBalance>, response: Response<UserInfoBalance>) {
                        val raw = response.toString()
                        val code = response.code()
                        val message = response.message()
                        val errorBody = response.errorBody()?.string()
                        val body = response.body()

                        println("RAW:: $raw")
                        println("CODE:: $code")
                        println("MESSAGE:: $message")
                        println("ERROR BODY:: $errorBody")
                        println("BODY:: $body")
                        onResult(body)
                    }
                }
            )
        }
    }

    fun loginUser (userData: UserLogin, onResult: (UserInfoLogin?) -> Unit) {
        val retrofit = ServiceBuilder.buildService(RestApi::class.java).also {
            it.inquiryBalance(userData).enqueue(
                object : Callback<UserInfoLogin> {
                    override fun onFailure(call: Call<UserInfoLogin>, t: Throwable) {
                        t.printStackTrace()
                        println("error ${t.message}")
                        onResult(null)
                    }
                    override fun onResponse( call: Call<UserInfoLogin>, response: Response<UserInfoLogin>) {
                        val raw = response.toString()
                        val code = response.code()
                        val message = response.message()
                        val errorBody = response.errorBody()?.string()
                        val body = response.body()

                        println("RAW:: $raw")
                        println("CODE:: $code")
                        println("MESSAGE:: $message")
                        println("ERROR BODY:: $errorBody")
                        println("BODY:: $body")
                        onResult(body)
                    }
                }
            )
        }
    }
}
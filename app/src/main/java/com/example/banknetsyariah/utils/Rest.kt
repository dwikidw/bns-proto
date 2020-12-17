package com.example.banknetsyariah.utils

import com.example.banknetsyariah.*
import retrofit2.Call
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST


interface RestApi {

    @Headers("Content-Type: application/json")
    @POST("security/generatepartnerkey")
    fun requestKey(@Body userData: UserInfo): Call<UserInfoResult>

    // UserBalance is interface request params for this Method Post
    // UserInfoBalance is interface for collect response params from the server
    // Request<UserBalance> will return response body which collecting by UserInfoBalance

    @Headers("Content-Type: application/json")
    @POST("account/inqbalance")
    fun inquiryBalance(@Body userData: UserBalance): Call<UserInfoBalance>

    @Headers("Content-Type: application/json")
    @POST("security/login")
    fun inquiryBalance(@Body userData: UserLogin): Call<UserInfoLogin>
}



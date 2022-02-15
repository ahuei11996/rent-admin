<?php

use think\facade\Db;

/**
 * 获取用户id
 * @return string
 */
function getUid() {
    if(getToken()) {
        if(redis()->has(getToken())) {
            return redis()->get(getToken());
        }
    }
    return "";
}

/**
 * 自定义redis缓存函数
 * @return object
 */
function redis() {
    return cache()->store('redis');
}

/**
 * 获取token
 * @return object
 */
function getToken() {
    return request()->header(config('app.token'));
}

/**
 * 获取用户信息
 * @return object
 */
function getUserInfo($userId) {
    $user = Db::name('users')
            ->alias('u')
            ->leftJoin('users_type ut', 'u.type_id = ut.id')
            ->field('u.*,ut.name as type_name')
            ->where('u.id', $userId)
            ->find();
    return $user;
}

function postRequest($url,$params = null) {
    $timeout = 10;
    $ch = curl_init();
    if (is_array($params)) {
        $urlparam = http_build_query($params);
    } else if (is_string($params)) { //json字符串
        $urlparam = $params;
    }
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout); //设置超时时间
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); //返回原生的（Raw）输出
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
    curl_setopt($ch, CURLOPT_POST, 1); //POST
    curl_setopt($ch, CURLOPT_POSTFIELDS, $urlparam); //post数据
    if ($params) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $params);
    }
    $data = curl_exec($ch);
    // if ($log) {
    //     $data .= "\r\n";
    //     $data .= self::logInfo($ch, $param, $data);
    // }
     
    curl_close($ch);
    return $data;
}

function getRequest($url,$params = null) {
    $timeout = 10;
    $ch = curl_init();
    if (is_array($params)) {
        $url = $url . '?' . http_build_query($params);
    }
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout); // 允许 cURL 函数执行的最长秒数
    $data = curl_exec($ch);
    // if ($log) {
    //     $data .= "\r\n";
        // $data .= self::logInfo($ch, $params, $data);
    // }
    curl_close($ch);
    return $data;
}
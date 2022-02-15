<?php

/**
 * +----------------------------------------------------------------------
 * | 用户中心控制器
 * +----------------------------------------------------------------------
 *                      .::::.
 *                    .::::::::.            | AUTHOR: siyu
 *                    :::::::::::           | EMAIL: 407593529@qq.com
 *                 ..:::::::::::'           | QQ: 407593529
 *             '::::::::::::'               | DATETIME: 2019/07/19
 *                .::::::::::
 *           '::::::::::::::..
 *                ..::::::::::::.
 *              ``::::::::::::::::
 *               ::::``:::::::::'        .:::.
 *              ::::'   ':::::'       .::::::::.
 *            .::::'      ::::     .:::::::'::::.
 *           .:::'       :::::  .:::::::::' ':::::.
 *          .::'        :::::.:::::::::'      ':::::.
 *         .::'         ::::::::::::::'         ``::::.
 *     ...:::           ::::::::::::'              ``::.
 *   ```` ':.          ':::::::::'                  ::::..
 *                      '.:::::'                    ':'````..
 * +----------------------------------------------------------------------
 */

namespace app\api\controller;


use app\api\service\JwtAuth;
use app\common\model\Users;
use app\common\model\UsersThird;
use think\facade\Db;
use think\facade\Request;

use app\api\service\wechat\WechatBizDataCrypt;

class User extends Base
{

    /**
     * 控制器中间件 [登录、注册 不需要鉴权]
     * @var array
     */
    protected $middleware = [
        'app\api\middleware\Api' => ['except' => ['login', 'register', 'thirdLogin','wxLogin']],
    ];

    /**
     * @api {post} /User/login 01、会员登录
     * @apiGroup User
     * @apiVersion 6.0.0
     * @apiDescription 系统登录接口，返回 token 用于操作需验证身份的接口

     * @apiParam (请求参数：) {string}     		username 登录用户名
     * @apiParam (请求参数：) {string}     		password 登录密码

     * @apiParam (响应字段：) {string}     		token    Token

     * @apiSuccessExample {json} 成功示例
     * {"code":200,"msg":"登录成功","time":1563525780,"data":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhcGkuc2l5dWNtcy5jb20iLCJhdWQiOiJzaXl1Y21zX2FwcCIsImlhdCI6MTU2MzUyNTc4MCwiZXhwIjoxNTYzNTI5MzgwLCJ1aWQiOjEzfQ.prQbqT00DEUbvsA5M14HpNoUqm31aj2JEaWD7ilqXjw"}}
     * @apiErrorExample {json} 失败示例
     * {"code":500,"msg":"帐号或密码错误","time":1563525638,"data":[]}
     */
    public function login(string $username, string $password)
    {
        // 校验用户名密码
        $user = Users::where('email|mobile', $username)
            ->where('password', md5($password))
            ->find();
        if (empty($user)) {
            $this->result([], 500, '帐号或密码错误');
        } else {
            // if ($user['status'] == 1) {
            //     //获取jwt的句柄
            //     $jwtAuth = JwtAuth::getInstance();
            //     $token = $jwtAuth->setUid($user['id'])->encode()->getToken();
            //     //更新信息
            //     // Users::where('id', $user['id'])
            //     //     ->update(['last_login_time' => time(), 'last_login_ip' => Request::ip()]);

            //     // 更新信息2022-02-08，使用模型更新
            //     $user->last_login_time = time();
            //     $user->last_login_ip = Request::ip();
            //     $user->save();

            //     // 设置redis缓存，有效时间为30天
            //     redis()->set($token,json_encode($user->id), config('app.redis_time'));
            //     $this->result(['token' => $token], 200, '登录成功');
            // } else {
            //     $this->result([], 500, '用户已被禁用');
            // }
            $this->setToken($user);
        }
    }

    /**
     * @api {post} /User/register 02、会员注册
     * @apiGroup User
     * @apiVersion 6.0.0
     * @apiDescription  系统注册接口，返回是否成功的提示，需再次登录

     * @apiParam (请求参数：) {string}     		email 邮箱
     * @apiParam (请求参数：) {string}     		password 密码

     * @apiSuccessExample {json} 成功示例
     * {"code":200,"msg":"注册成功","time":1563526721,"data":[]}
     * @apiErrorExample {json} 失败示例
     * {"code":500,"msg":"邮箱已被注册","time":1563526693,"data":[]}
     */
    public function register(string $email, string $password)
    {
        // 密码长度不能低于6位
        if (strlen($password) < 6) {
            $this->result([], 500, '密码长度不能低于6位');
        }

        // 邮箱合法性判断
        if (!is_email($email)) {
            $this->result([], 500, '邮箱格式错误');
        }

        // 防止重复
        $id = Db::name('users')->where('email|mobile', '=', $email)->find();
        if ($id) {
            $this->result([], 500, '邮箱已被注册');
        }

        // 注册入库
        $data = [];
        $data['email']           = $email;
        $data['password']        = md5($password);
        $data['last_login_time'] = $data['create_time'] = time();
        $data['create_ip']       = $data['last_login_ip'] = Request::ip();
        $data['status']          = 1;
        $data['type_id']         = 1;
        $data['sex']             = Request::post('sex') ? Request::post('sex') : 0;
        $id = Db::name('users')->insertGetId($data);
        if ($id) {
            $this->result([], 200, '注册成功');
        } else {
            $this->result([], 500, '注册失败');
        }
    }

    /**
     * @api {post} /User/index 03、会员中心首页
     * @apiGroup User
     * @apiVersion 6.0.0
     * @apiDescription  会员中心首页，返回用户个人信息

     * @apiParam (请求参数：) {string}     		token Token

     * @apiSuccessExample {json} 响应数据样例
     * {"code":200,"msg":"","time":1563517637,"data":{"id":13,"email":"test110@qq.com","password":"e10adc3949ba59abbe56e057f20f883e","sex":1,"last_login_time":1563517503,"last_login_ip":"127.0.0.1","qq":"123455","mobile":"","mobile_validated":0,"email_validated":0,"type_id":1,"status":1,"create_ip":"127.0.0.1","update_time":1563507130,"create_time":1563503991,"type_name":"注册会员"}}
     */
    public function index()
    {
        $userId = getUid();
        if (!$userId) {
            return $this->result([], 500, 'token已失效');
        }
        // $user = Db::name('users')
        //     ->alias('u')
        //     ->leftJoin('users_type ut', 'u.type_id = ut.id')
        //     ->field('u.*,ut.name as type_name')
        //     ->where('u.id', $userId)
        //     ->find();
        // redis()->set(getToken(),$userId, config('app.redis_time'));
        $user = getUserInfo($userId);
        redis()->set(getToken(), $userId, config('app.redis_time'));
        return $this->result($user, 200, '');
    }

    /**
     * @api {post} /User/editPwd 04、修改密码
     * @apiGroup User
     * @apiVersion 6.0.0
     * @apiDescription  修改会员密码，返回成功或失败提示

     * @apiParam (请求参数：) {string}     		token Token
     * @apiParam (请求参数：) {string}     		oldPassword 原密码
     * @apiParam (请求参数：) {string}     		newPassword 新密码

     * @apiSuccessExample {json} 成功示例
     * {"code":200,"msg":"密码修改成功","time":1563527107,"data":[]}
     * @apiErrorExample {json} 失败示例
     * {"code":500,"msg":"token已过期","time":1563527082,"data":[]}
     */
    public function editPwd(string $oldPassword, string $newPassword)
    {
        // 密码长度不能低于6位
        if (strlen($newPassword) < 6) {
            $this->result([], 500, '密码长度不能低于6位');
        }

        // 查看原密码是否正确
        $user = Users::where('id', $this->getUid())
            ->where('password', md5($oldPassword))
            ->find();
        if (!$user) {
            $this->result([], 500, '原密码输入有误');
        }

        //更新信息
        $user = Users::find($this->getUid());
        $user->password = md5($newPassword);
        $user->save();
        $this->result([], 200, '密码修改成功');
    }

    /**
     * @api {post} /User/editInfo 05、修改信息
     * @apiGroup User
     * @apiVersion 6.0.0
     * @apiDescription  修改用户信息，返回成功或失败提示

     * @apiParam (请求参数：) {string}     		token Token
     * @apiParam (请求参数：) {string}     		sex 性别 [1男/0女]
     * @apiParam (请求参数：) {string}     		qq  qq
     * @apiParam (请求参数：) {string}     		mobile  手机号

     * @apiSuccessExample {json} 成功示例
     * {"code":200,"msg":"修改成功","time":1563507660,"data":[]}
     * @apiErrorExample {json} 失败示例
     * {"code":500,"msg":"token已过期","time":1563527082,"data":[]}
     */
    public function editInfo()
    {
        $data['sex']    = trim(Request::param("sex"));
        $data['qq']     = trim(Request::param("qq"));
        $data['mobile'] = trim(Request::param("mobile"));
        if ($data['mobile']) {
            // 不可和其他用户的一致
            $id = Users::where('mobile', $data['mobile'])
                ->where('id', '<>', $this->getUid())
                ->find();
            if ($id) {
                $this->result([], 0, '手机号已存在');
            }
        }
        // 更新信息
        Users::where('id', $this->getUid())
            ->update($data);
        $this->result([], 0, '修改成功');
    }

    /**
     * 获取用户id
     * @return mixed
     */
    protected function getUid()
    {
        if ($this->userInfo) {
            return $this->userInfo->id;
        } else {
            return '';
        }

        // $jwtAuth = JwtAuth::getInstance();
        // return $jwtAuth->getUid();
    }

    /**
     * @api {post} /User/thirdLogin 06、第三方账号绑定
     * @apiGroup User
     * @apiVersion 6.0.0
     * @apiDescription  修改用户信息，返回成功或失败提示
     * 
     * @apiParam (请求参数：) {string}     		openid openid
     * @apiParam (请求参数：) {string}     		unionid unionid
     * @apiParam (请求参数：) {string}     		type 类型 [wechat微信公众号/wechat微信小程序]
     * @apiParam (请求参数：) {string}     		info '{"sex":"性别","nickname":"用户昵称","province":"省份","city":"城市","country":"国家","headimgurl":"用户头像","privilege":"特权信息"}'

     * @apiSuccessExample {json} 成功示例
     * {"code":200,"msg":"修改成功","time":1563507660,"data":[]}
     * @apiErrorExample {json} 失败示例
     * {"code":500,"msg":"token已过期","time":1563527082,"data":[]}
     */
    public function thirdBind(string $openid, string $unionid, string $type, string $info)
    {
        // 校验用户名密码
        $data = UsersThird::where('openid', '=', $openid)->where('unionid', '=', $unionid)->find();
        if ($data) {
            $this->result([], 500, '该微信已被绑定');
        }

        // 注册入库
        $data = [];
        $data['openid']          = $openid;
        $data['unionid']         = $unionid;
        $data['type']            = $type;
        $data['info']            = $info;

        $id = UsersThird::insertGetId($data);
        if ($id) {
            $this->result([], 200, '绑定成功');
        } else {
            $this->result([], 500, '绑定失败');
        }
    }

    /**
     * @api {post} /User/thirdLogin 07、第三方账号一键登陆
     * @apiGroup User
     * @apiVersion 6.0.0
     * @apiDescription  修改用户信息，返回成功或失败提示
     * 
     * @apiParam (请求参数：) {string}     		openid openid
     * @apiParam (请求参数：) {string}     		unionid unionid
     * @apiParam (请求参数：) {string}     		type 类型 [wechat微信公众号/wechat微信小程序]
     * @apiParam (请求参数：) {string}     		info '{"sex":"性别","nickname":"用户昵称","province":"省份","city":"城市","country":"国家","headimgurl":"用户头像","privilege":"特权信息"}'

     * @apiSuccessExample {json} 成功示例
     * {"code":200,"msg":"修改成功","time":1563507660,"data":[]}
     * @apiErrorExample {json} 失败示例
     * {"code":500,"msg":"token已过期","time":1563527082,"data":[]}
     */
    public function thirdLogin(string $openid, string $unionid, string $type, string $info)
    {

        // 校验用户名密码
        $data = UsersThird::where('openid', $openid)->where('unionid', $unionid)->find();
        if ($data) {
            $user = $user = Users::where('id', $data->user_id)->find();
        } else {
            // 密码长度不能低于6位

            $_info = json_decode($info);
            // 注册入库
            $data = [];
            $data['email']           = "";
            $data['password']        = "";
            $data['nickname']        = $_info->nickname;
            $data['last_login_time'] = $data['create_time'] = time();
            $data['create_ip']       = $data['last_login_ip'] = Request::ip();
            $data['status']          = 1;
            $data['type_id']         = 1;
            $data['sex']             = $_info->sex ? $_info->sex : 0;
            $id = Db::name('users')->insertGetId($data);
            if ($id) {
                $thirdData = [];
                $thirdData["openid"] = $openid;
                $thirdData["unionid"] = $unionid;
                $thirdData["type"] = $type;
                $thirdData["info"] = $info;
                $thirdData["user_id"] = $id;
                UsersThird::insertGetId($thirdData);
                // $this->result([], 200, '注册成功');
                $user = $user = Users::where('id', $id)->find();
            } else {
                $this->result([], 500, '注册失败');
            }
        }

        $this->setToken($user);
    }

    /**
     * @api  {post} /User/thirdLogin 08、微信小城登陆
     */
    public function wxLogin(string $code,string $rawData, string $signature, string $encryptedData, string $iv)
    {
        /**
         * 3.小程序调用server获取token接口, 传入code, rawData, signature, encryptData.
         * 配置appid,secret信息
         */

        $appid = "wxa5fe908a6043cf1b";
        $secret = "b1a0960710a41fea71ed97a07e9384db";
        $url = "https://api.weixin.qq.com/sns/jscode2session";
        $grant_type = "authorization_code";     

        /**
         * 4.server调用微信提供的jsoncode2session接口获取openid, session_key, 调用失败应给予客户端反馈
         * , 微信侧返回错误则可判断为恶意请求, 可以不返回. 微信文档链接
         * 这是一个 HTTP 接口，开发者服务器使用登录凭证 code 获取 session_key 和 openid。其中 session_key 是对用户数据进行加密签名的密钥。
         * 为了自身应用安全，session_key 不应该在网络上传输。
         * 接口地址："https://api.weixin.qq.com/sns/jscode2session?appid=APPID&secret=SECRET&js_code=JSCODE&grant_type=authorization_code"
         */
        $params = [
            'appid' => $appid,
            'secret' => $secret,
            'js_code' => $code,
            'grant_type' => $grant_type
        ];
        $res = getRequest($url,$params);
        $reqData = json_decode($res, true);
        
        if (isset($reqData['errcode'])) {
            $this->result([], 500, 'requestTokenFailed');
        }
        if (!isset($reqData['session_key'])) {
            $this->result([], 500, 'requestTokenFailed');
        }
        $sessionKey = $reqData['session_key'];
        /**
         * 5.server计算signature, 并与小程序传入的signature比较, 校验signature的合法性, 不匹配则返回signature不匹配的错误. 不匹配的场景可判断为恶意请求, 可以不返回.
         * 通过调用接口（如 wx.getUserInfo）获取敏感数据时，接口会同时返回 rawData、signature，其中 signature = sha1( rawData + session_key )
         *
         * 将 signature、rawData、以及用户登录态发送给开发者服务器，开发者在数据库中找到该用户对应的 session-key
         * ，使用相同的算法计算出签名 signature2 ，比对 signature 与 signature2 即可校验数据的可信度。
         */
        $signature2 = sha1($rawData . $sessionKey);
        if ($signature2 !== $signature)  $this->result([], 500, 'signNotMatch'); // return ret_message("signNotMatch");

        /**
         *
         * 6.使用第4步返回的session_key解密encryptData, 将解得的信息与rawData中信息进行比较, 需要完全匹配,
         * 解得的信息中也包括openid, 也需要与第4步返回的openid匹配. 解密失败或不匹配应该返回客户相应错误.
         * （使用官方提供的方法即可）
         */
        $pc = WechatBizDataCrypt::getInstance();
        $pc->init($appid,$sessionKey);
        $errCode = $pc->decryptData($encryptedData, $iv, $data);

        if ($errCode !== 0) {
            $this->result([], 500, 'encryptDataNotMatch');
        }


        /**
         * 7.生成第三方3rd_session，用于第三方服务器和小程序之间做登录态校验。为了保证安全性，3rd_session应该满足：
         * a.长度足够长。建议有2^128种组合，即长度为16B
         * b.避免使用srand（当前时间）然后rand()的方法，而是采用操作系统提供的真正随机数机制，比如Linux下面读取/dev/urandom设备
         * c.设置一定有效时间，对于过期的3rd_session视为不合法
         *
         * 以 $session3rd 为key，sessionKey+openId为value，写入memcached
         */

        cache()->store("redis")->set($reqData['openid'],$data);
        $data = json_decode($data, true);
        // $session3rd = randomFromDev(16);

        // $data['session3rd'] = $session3rd;

        $this->result($data,200,'');
    }

    /**
     * 设置token
     * @return mixed
     */
    private function setToken($user)
    {
        if ($user['status'] == 1) {
            //获取jwt的句柄
            $jwtAuth = JwtAuth::getInstance();
            $token = $jwtAuth->setUid($user['id'])->encode()->getToken();

            // 更新信息，使用模型更新
            $user->last_login_time = time();
            $user->last_login_ip = Request::ip();
            $user->save();

            // 设置redis缓存，有效时间为30天
            redis()->set($token, json_encode($user->id), config('app.redis_time'));
            $this->result(['token' => $token], 200, '登录成功');
        } else {
            $this->result([], 500, '用户已被禁用');
        }
    }
}

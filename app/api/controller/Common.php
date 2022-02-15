<?php

namespace app\api\controller;

class Controller extends Base {

    /**
     * @var object 
     */
    protected $userInfo;
    
    /**
     * @var string 
     */
    protected $token;

     /**
     * 构造方法
     * @access public
     * @param  App $app 应用对象
     */
    public function __construct(App $app)
    {
        parent::__construct();

        $this->token = $this->request->header(config('app.token'));
        if($this->token) {
            $this->userInfo = json_decode(cache()->store("redis")->get($this->token));
        }
        
        
    }

    /**
     * 获取用户id
     * @return mixed
     */
    protected function getUid(){
        if($this->userInfo) {
            return $this->userInfo->id;
        } else {
            return '';
        }
    }

}
<?php
/**
 * +----------------------------------------------------------------------
 * | 菜单规则验证器
 * +----------------------------------------------------------------------
 *                      .::::.
 *                    .::::::::.            | AUTHOR: siyu
 *                    :::::::::::           | EMAIL: 407593529@qq.com
 *                 ..:::::::::::'           | DATETIME: 2020/02/03
 *             '::::::::::::'
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
namespace app\admin\validate;

use think\Validate;

class AuthRule extends Validate
{
    protected $rule = [
        'status|菜单状态' => [
            'require' => 'require',
            'max' => '1',
        ],
        'name|控制器/方法' => [
            'require' => 'require',
            'unique'  => 'auth_rule', // 唯一
        ],
        'title|权限名称' => [
            'require' => 'require',
        ]
    ];
}
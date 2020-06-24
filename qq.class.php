<?php
class qqlogin
{
    public $appid; //QQ互联 APPID
    public $appkey; //QQ互联 APPKEY
    public $redirect_uri; //QQ互联 回调地址
    /**
     * 登录地址
     *
     * @return string 返回URL链接进行登录
     */
    public function login()
    {
        $state  = state();
        $params = [
            'response_type' => 'code',
            'client_id'     => $this->appid,
            'redirect_uri'  => $this->redirect_uri,
            'state'         => $state,
        ];
        $url = 'https://graph.qq.com/oauth2.0/authorize?' . http_build_query($params);
        return $url;
    }

    /**
     * 通过Authorization Code获取Access Token
     *
     * @param string $code 上一步返回的authorization code
     * @param string $state 唯一随机串
     * @param string $refresh_token 如有则进行权限更新
     * @return bool|array 成功则返回数组['access_token','expires_in','refresh_token']
     */
    public function access_token(string $code, string $state, string $refresh_token = "")
    {
        if (empty($refresh_token) && !state($state, '600')) {
            return false;
        }
        if (empty($refresh_token)) {
            $params = [
                'grant_type'    => 'authorization_code',
                'client_id'     => $this->appid,
                'client_secret' => $this->appkey,
                'code'          => $code,
                'redirect_uri'  => $this->redirect_uri,
                'fmt'           => 'json',
            ];
        } else {
            $params = [
                'grant_type'    => 'refresh_token',
                'client_id'     => $this->appid,
                'client_secret' => $this->appkey,
                'refresh_token' => $refresh_token,
                'fmt'           => 'json',
            ];
        }
        $url  = 'https://graph.qq.com/oauth2.0/token?' . http_build_query($params);
        $data = $this->curl($url);
        $data = json_decode($data, true);
        if (empty($data)) {
            return false;
        } elseif (!empty($data['code']) || !empty($data['error_description'])) {
            return false;
        } elseif (empty($data['access_token']) || empty($data['expires_in']) || empty($data['refresh_token'])) {
            return false;
        }
        $arr = [
            'access_token'  => $data['access_token'], //授权令牌，Access_Token。
            'expires_in'    => date('Y-m-d H:i:s', time() + $data['expires_in']), //该access token的有效期，单位为秒。
            'refresh_token' => $data['refresh_token'], //在授权自动续期步骤中，获取新的Access_Token时需要提供的参数。注：refresh_token仅一次有效
        ];
        return $arr;
    }

    /**
     * openID获取
     *
     * @param array $access_token 上一步的access_token数组
     * @return bool|array 成功则返回数组['client_id','openid']
     */
    public function OpenID(array $token)
    {
        $params = ['access_token' => $token['access_token'], 'fmt' => 'json'];
        $url    = 'https://graph.qq.com/oauth2.0/me?' . http_build_query($params);
        $data   = $this->curl($url);
        $data   = json_decode($data, true);
        if (empty($data)) {
            return false;
        } elseif (!empty($data['code']) || !empty($data['error_description'])) {
            return false;
        } elseif (empty($data['client_id']) || empty($data['openid'])) {
            return false;
        }
        $arr = [
            'client_id' => $data['client_id'],
            'openid'    => $data['openid'],
        ];
        return $arr;
    }

    /**
     * QQ登录的用户信息
     *
     * @param string $access_token 上一步的
     * @param string $client_id 上一步的client_id
     * @param string $openid 上一步的openid
     * @return void
     */
    public function user_info(string $access_token, string $client_id, string $openid)
    {
        $params = ['access_token' => $access_token, 'oauth_consumer_key' => $client_id, 'openid' => $openid];
        $url    = 'https://graph.qq.com/user/get_user_info?' . http_build_query($params);
        $data   = $this->curl($url);
        $q      = json_decode($data, true);
        if (empty($q)) {
            return false;
        } elseif ($q['ret'] != 0 || !empty($q['msg'])) {
            return false;
        }
        return $q;
    }

    /**
     * CURL请求
     *
     * @param string $url URL地址
     * @return void
     */
    public function curl(string $url)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
    }
}

/**
 * 服务器端数值校验规则，检测发给用户的验证值是否正确
 *
 * @param string $str 字符串
 * @param int $timeout 时间差内有效
 * @return void
 */
function state(string $str = '', int $timeout = 0)
{
    $position = [9, 1, 14, 18, 28, 21, 24]; //加密位置（前3位校验值，后4位是时间校验值）
    sort($position);
    if (empty($str)) {
        $time   = time();
        $md5    = md5(uniqid(rand(), true));
        $md5arr = str_split($md5);
        $pass   = 0;
        foreach ($md5arr as $v) {
            if (is_numeric($v)) {
                $pass += $v;
            }
        }
        if (strlen($pass) == 2) {
            $pass = (string) $pass . '0';
        }
        $passStr = (string) $pass . substr($time, 3, 4);
        $passArr = str_split($passStr);
        $i       = 0;
        foreach ($position as $v) {
            array_splice($md5arr, $v, 0, $passArr[$i]);
            $i++;
        }
        $str = implode('', $md5arr) . substr($time, 0, 3) . substr($time, 7);
        return base64_encode(strtoupper($str));
    } else {
        //验证值合法
        $str = base64_decode($str);
        if (strlen($str) != 45) {
            return false;
        }
        $arr     = str_split($str); //分隔字符串
        $passArr = [];
        foreach ($position as $v) { //提取加密值
            $passArr[] = $arr[$v];
            unset($arr[$v]);
        }
        $str     = implode('', $arr); //拼接字符串
        $passStr = implode('', $passArr); //拼接字符串
        $md5     = str_split(substr($str, 0, 32)); //MD5
        $key     = intval(substr($passStr, 0, 3)); //校验值
        $time    = intval(substr($str, 32, 3) . substr($passStr, 3) . substr($str, 35)); //参数时间
        if (time() - $time > $timeout) {
            return false;
        }
        $num = 0; //校验值
        foreach ($md5 as $v) {
            if (is_numeric($v)) {
                $num += $v;
            }
        }
        if (strlen($num) == 2) { //不足3位补3位，例：92
            $num = (string) $num . '0'; //转换成920
        }
        if (intval($num) == $key) {
            return true;
        }
        return false;
    }
}

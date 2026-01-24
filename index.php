<?php
define('KMG_CAMPAIGN_ID', 'camp_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx');//将camp_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx替换为你设置的活动ID(登录xn--l5xp3gi58a.com,左侧-活动管理,复制对应的活动ID)
define('KMG_API_KEY', 'key_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx');//将key_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx替换为你的API Key(登录xn--l5xp3gi58a.com,左侧-API Key,复制API Key)
define('KMG_TOKEN_KEY', strtoupper(substr(md5(KMG_CAMPAIGN_ID), 0, 16)));
define('KMG_TOKEN_EXPIRE', 10);
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    $token = encrypt_KMG(time(),KMG_TOKEN_KEY);
    $tracker = file_get_contents('tracker.min.js');
    $tracker = str_replace('KMG_TOKEN', $token, $tracker);
    echo '<html><body><script>' . $tracker . '</script></body></html>';
} elseif ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $token = isset(array_keys($_POST)[0]) ? array_keys($_POST)[0] : "";
    $data = isset($_POST[$token]) ? $_POST[$token] : "";
    if (decrypt_KMG($token,KMG_TOKEN_KEY) < time() - KMG_TOKEN_EXPIRE) {
        echo json_encode(['html_content' => encrypt_KMG(error_page_KMG(401),$token)]);
        exit;
    }
    $data = decrypt_KMG($data,$token);
    if (
                $result = request_KMG(
            [
                'campaign_id' => KMG_CAMPAIGN_ID,
                'ip' => ip_KMG(),
                'data' => $data
            ]
        )
    ) {
        $return = [
            'vid_key' => $result['vid_key'] ?? null,
            'vid_value' => $result['vid_value'] ?? null
        ];
        if ($result['action'] == 'SHOW') {
            if (file_exists($result['target'])) {
                ob_start();
                require_once $result['target'];
                $file_content = ob_get_clean();
                $return['html_content'] = encrypt_KMG($file_content,$token);
            } else {
                $return['html_content'] = encrypt_KMG(error_page_KMG(500),$token);
            }
        } else if ($result['action'] == 'REDIRECT') {
            $return['html_content'] = encrypt_KMG('<html><body><script>window.location.href = ' . json_encode($result['target']) . ';</script></body></html>',$token);
        } else if ($result['action'] == 'ERROR') {
            $return['html_content'] = encrypt_KMG(error_page_KMG($result['target']),$token);
        }
        echo json_encode($return);
    } else {
        echo json_encode(['html_content' => encrypt_KMG(error_page_KMG(400),$token)]);
    }
} else {
    echo json_encode(['html_content' => encrypt_KMG(error_page_KMG(405),$token)]);
}
function error_page_KMG($code)
{
    $error_code = [
        400 => '400 Bad Request',
        401 => '401 Unauthorized',
        403 => '403 Forbidden',
        404 => '404 Not Found',
        405 => '405 Method Not Allowed',
        500 => '500 Internal Server Error',
        502 => '502 Bad Gateway',
        503 => '503 Service Unavailable',
    ];
    return '<html><head><title>' . $error_code[$code] . '</title></head><body><center><h1>' . $error_code[$code] . '</h1></center><hr><center>KanMenGou</center></body></html>';
}
function encrypt_KMG($text,$key)
{
    return crypt_KMG($text, $key, 'encrypt');
}
function decrypt_KMG($text,$key)
{
    return crypt_KMG($text, $key, 'decrypt');
}
function crypt_KMG($text, $key, $type = 'encrypt')
{
    $tmp = $type == 'encrypt' ? json_encode($text) : base64url_decode($text);
    $result = '';
    $keyLength = strlen($key);
    for ($i = 0; $i < strlen($tmp); $i++) {
        $result .= chr(ord($tmp[$i]) ^ ord($key[$i % $keyLength]));
    }
    return $type == 'encrypt' ? base64url_encode($result) : json_decode($result, true);
}

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}
function ip_KMG()
{
    if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip_arr = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return $ip_arr[0];
    } else {
        return $_SERVER['REMOTE_ADDR'];
    }
}
function request_KMG($data)
{
    $url = 'https://xn--l5xp3gi58a.com/api/v1/verify';
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . KMG_API_KEY
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $result = curl_exec($ch);
    curl_close($ch);
    if ($result = json_decode($result, true)) {
        return $result;
    } else {
        return false;
    }
}
?>

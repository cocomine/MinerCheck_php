<?php
require_once 'config.inc.php';
require_once 'AEScrypt.php';
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header("Access-Control-Allow-Methods: POST, OPTIONS");
    header("Access-Control-Allow-Origin: https://localhost");
    header("Access-Control-Allow-Headers: Content-Type, x-android-cert");
    exit();
}

#認證客戶端
if (!($_SERVER['HTTP_X_REQUESTED_WITH'] === PACKAGE_NAME && $_SERVER['HTTP_X_ANDROID_CERT'] === SHA1)) {
    header("Content-type: text/json; charset=utf-8");
    header("Access-Control-Allow-Methods: POST, OPTIONS");
    header("Access-Control-Allow-Origin: https://localhost");
    http_response_code(403);
    echo json_encode(array("error" => 403, 'reason' => 'Client not authenticated.'));
    exit;
}

$output = array();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $contact = file_get_contents("php://input");

    #解密
    $AES = new AEScrypt(API_KEY);
    $contact = $AES->decrypt($contact);
    if(!$contact){
        header("Content-type: text/json; charset=utf-8");
        header("Access-Control-Allow-Methods: POST");
        header("Access-Control-Allow-Origin: https://localhost");
        http_response_code(403);
        echo json_encode(array("error" => 403, 'reason' => 'Unable to confirm client identity. Please check if the API_KEY is the same'));
        exit;
    }
    $contact = json_decode($contact, true);
    $output = add($contact);
} else {
    $output['error'] = 405;
    $output['reason'] = 'Method Not Allowed';
}

/* output */
header("Content-type: text/json; charset=utf-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Origin: https://localhost");
if (isset($output['error'])) { //如果是錯誤
    http_response_code($output['error']);
}
if (isset($output['success'])) { //如果成功
    http_response_code($output['success']);
}
echo json_encode($output); //output

/**
 * @param $contact
 * @return array
 */
function add($contact) {
    $output = array();
    if (preg_match('/^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}$/', $contact['data']['url']) >= 1) {
        $sqlcon = new mysqli(SQL_SETTING['hostname'], SQL_SETTING['username'], SQL_SETTING['password'], SQL_SETTING['database'], SQL_SETTING['port']); //sql
        if ($sqlcon->connect_errno) { //檢查連線
            #sql錯誤
            $output['error'] = 500;
            $output['reason'] = "SQL server error";
            return $output;
        }
        #插入資料
        $stmt = $sqlcon->prepare("INSERT INTO Miner VALUES (?, FALSE, SYSDATE(), SYSDATE(), 0, NULL)");
        $stmt->bind_param("s", $contact['data']['url']);
        if (!$stmt->execute()) {
            $output['error'] = 400;
            $output['reason'] = "Url addition failed";
        } else {
            #成功執行
            $output['success'] = 200;
            $output['reason'] = "Url added successfully";
        }
    } else {
        #url格式不符
        $output['error'] = 400;
        $output['reason'] = "The provided url is malformed.";
    }
    return $output;
}
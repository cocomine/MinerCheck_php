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
    if (!$contact) {
        header("Content-type: text/json; charset=utf-8");
        header("Access-Control-Allow-Methods: POST");
        header("Access-Control-Allow-Origin: https://localhost");
        http_response_code(403);
        echo json_encode(array("error" => 403, 'reason' => 'Unable to confirm client identity. Please check if the API_KEY is the same'));
        exit;
    }
    $contact = json_decode($contact, true);
    $output = edit($contact);
} else {
    $output['error'] = 405;
    $output['reason'] = 'Method Not Allowed';
}

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

function edit($contact) {
    $output = array();
    if (preg_match('/^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}$/', $contact['url']) >= 1) {
        $sqlcon = new mysqli(SQL_SETTING['hostname'], SQL_SETTING['username'], SQL_SETTING['password'], SQL_SETTING['database'], SQL_SETTING['port']); //sql
        if ($sqlcon->connect_errno) { //檢查連線
            #sql錯誤
            $output['error'] = 500;
            $output['reason'] = "SQL server error";
            return $output;
        }
        //修改ip
        if (!empty($contact['data']['url'])) {
            if (preg_match('/([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}/', $contact['data']['url']) >= 1) {
                $stmt = $sqlcon->prepare("UPDATE Miner SET IP = ? WHERE IP = ?");
                $stmt->bind_param("ss", $contact['data']['url'], $contact['url']);
                if (!$stmt->execute()) {
                    $output['error'] = 400;
                    $output['reason'] = "Url modified failed";
                } else {
                    #成功執行
                    $output['success'] = 200;
                    $output['reason'] = "Url modified successfully";
                }
            } else {
                #url格式不符
                $output['error'] = 400;
                $output['reason'] = "The provided url is malformed. #data";
            }
        }
        //修改密碼
        if (!empty($contact['data']['pass'])) {
            $stmt = $sqlcon->prepare("UPDATE Miner SET Pass = ? WHERE IP = ?");
            $contact['data']['pass'] = filter_var($contact['data']['pass'], FILTER_SANITIZE_STRING);
            $stmt->bind_param("ss", $contact['data']['pass'], $contact['url']);
            if (!$stmt->execute()) {
                $output['error'] = 400;
                $output['reason'] = "Url modified failed";
            } else {
                #成功執行
                $output['success'] = 200;
                $output['reason'] = "Url modified successfully";
            }
        }
        //修改Miner 0=none, 1=trex, 2=nbminer, 3=lolminer, 4=Gminer
        if (isset($contact['data']['miner'])) {
            if (preg_match('/[0-4]/', $contact['data']['miner']) >= 1) {
                $stmt = $sqlcon->prepare("UPDATE Miner SET Miner = ? WHERE IP = ?");
                $stmt->bind_param("is", $contact['data']['miner'], $contact['url']);
                if (!$stmt->execute()) {
                    $output['error'] = 400;
                    $output['reason'] = "Miner type modified failed";
                } else {
                    #成功執行
                    $output['success'] = 200;
                    $output['reason'] = "Miner type modified successfully";
                }
            } else {
                #miner選擇範圍不正確
                $output['error'] = 400;
                $output['reason'] = "Miner selection range is incorrect.";
            }
        }
        if (empty($contact['data']['url']) && !isset($contact['data']['miner'])) {
            #沒有任何改動
            $output['success'] = 200;
            $output['reason'] = 'Not changes.';
        }
    } else {
        #url格式不符
        $output['error'] = 400;
        $output['reason'] = "The provided url is malformed.";
    }
    return $output;
}
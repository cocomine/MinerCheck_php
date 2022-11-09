<?php
require_once 'config.inc.php';
require_once 'AEScrypt.php';
if($_SERVER['REQUEST_METHOD'] === 'OPTIONS'){
    header("Access-Control-Allow-Methods: GET, OPTIONS");
    header("Access-Control-Allow-Origin: https://localhost");
    header("Access-Control-Allow-Headers: Content-Type, x-android-cert");
    exit();
}

#認證客戶端
if (!($_SERVER['HTTP_X_REQUESTED_WITH'] === PACKAGE_NAME && $_SERVER['HTTP_X_ANDROID_CERT'] === SHA1)) {
    header("Content-type: text/json; charset=utf-8");
    header("Access-Control-Allow-Methods: GET");
    header("Access-Control-Allow-Origin: https://localhost");
    http_response_code(403);
    echo json_encode(array("error" => 403, 'reason' => 'Client not authenticated.'));
    exit;
}

$output = array();
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $output = getOutput();
} else {
    $output['error'] = 405;
    $output['reason'] = 'Method Not Allowed';
}

/* output */
header("Content-type: text/plain; charset=utf-8");
header("Access-Control-Allow-Methods: GET");
header("Access-Control-Allow-Origin: https://localhost");
if (isset($output['error'])) { //如果是錯誤
    http_response_code($output['error']);
}
if (isset($output['success'])) { //如果成功
    http_response_code($output['success']);
}

/* AES encrypt */
$AES = new AEScrypt(API_KEY);
$encrypt = $AES->encrypt(json_encode($output));
echo $encrypt; //output

/**
 * @param array $output
 * @return array
 */
function getOutput() {
    $output = array();
    $sqlcon = new mysqli(SQL_SETTING['hostname'], SQL_SETTING['username'], SQL_SETTING['password'], SQL_SETTING['database'], SQL_SETTING['port']); //sql
    if ($sqlcon->connect_errno) { //檢查連線
        #sql錯誤
        $output['error'] = 500;
        $output['reason'] = "SQL server error";
    } else {
        #檢查在線
        $stmt = $sqlcon->prepare("SELECT IP, Online, Last_online, Last_check, Miner FROM Miner");
        if (!$stmt->execute()) {
            $output['error'] = 500;
            $output['reason'] = "Failed to request url";
        } else {
            #成功執行
            /* 分析結果 */
            $result = $stmt->get_result();
            $stmt->close();

            while ($row = $result->fetch_assoc()) {
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, 'http://' . $row['IP']);
                curl_setopt($ch, CURLOPT_TIMEOUT, 3);
                curl_setopt($ch, CURLOPT_NOBODY, TRUE);
                curl_exec($ch);
                if (curl_error($ch)) {
                    # is offline
                    array_push($output, array('url' => $row['IP'], 'online' => false, 'last_online' => $row['Last_online'], 'last_check' => $row['Last_check'], 'minerType' => 0));
                    $stmt = $sqlcon->prepare("UPDATE Miner SET Online = FALSE, Last_check = SYSDATE() WHERE IP = ?");
                    $stmt->bind_param("s", $row['IP']);
                    if (!$stmt->execute()) {
                        $output['error'] = 500;
                        $output['reason'] = "SQL server error";
                    }
                } else {
                    # is online
                    array_push($output, array('url' => $row['IP'], 'online' => true, 'last_online' => $row['Last_online'], 'last_check' => $row['Last_check'], 'minerType' => $row['Miner']));
                    $stmt = $sqlcon->prepare("UPDATE Miner SET Online = TRUE, Last_online = SYSDATE(), Last_check = SYSDATE() WHERE IP = ?");
                    $stmt->bind_param("s", $row['IP']);
                    if (!$stmt->execute()) {
                        $output['error'] = 500;
                        $output['reason'] = "SQL server error";
                    }
                }
                curl_close($ch);
            }

        }
    }
    return $output;
}
<?php
require_once 'config.inc.php';
require_once 'AEScrypt.php';
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
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
    $output = detail();
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
 * @return array output
 */
function detail() {
    $output = array();
    $sqlcon = new mysqli(SQL_SETTING['hostname'], SQL_SETTING['username'], SQL_SETTING['password'], SQL_SETTING['database'], SQL_SETTING['port']); //sql
    if ($sqlcon->connect_errno) { //檢查連線
        #sql錯誤
        $output['error'] = 500;
        $output['reason'] = "SQL server error";
        return $output;
    }

    $stmt = $sqlcon->prepare("SELECT IP, Online, Miner, Pass FROM Miner");
    if (!$stmt->execute()) {
        $output['error'] = 500;
        $output['reason'] = "Failed to request url";
        return $output;
    }

    #成功執行
    /* 分析結果 */
    $result = $stmt->get_result();
    $stmt->close();
    while ($row = $result->fetch_assoc()) {
        if($row['Online'] == 0) continue;

        //trex
        if ($row['Miner'] === 1) {
            /* get login sid */
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, 'http://' . $row['IP'] . '/login?password='.$row['Pass']);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
            $sid = curl_exec($ch);

            if (!curl_error($ch)) {
                /* get summary */
                $sid = json_decode($sid, true);
                curl_setopt($ch, CURLOPT_URL, 'http://' . $row['IP'] . '/summary?sid=' . $sid['sid']);
                $body = curl_exec($ch);

                if (!curl_error($ch)) {
                    //is online
                    //分析結果
                    $body = json_decode($body, true);

                    $x = array(
                        "url" => $row['IP'],
                        "hashrate" => round($body['hashrate'] / 1000000,2),
                        "hashrate_day" => round($body['hashrate_day'] / 1000000,2),
                        "gpus" => array(),
                    );

                    foreach ($body['gpus'] as $gpu) {
                        $x['gpus'][] = array(
                            'gpu_id' => $gpu['gpu_id'],
                            'hashrate' => round($gpu['hashrate'] / 1000000,2),
                            'invalid_count' => $gpu['shares']['invalid_count'],
                            'accepted_count' => $gpu['shares']['accepted_count'],
                            'rejected_count' => $gpu['shares']['rejected_count'],
                            'power' => $gpu['power'],
                            'info' => $gpu['vendor'] . ' ' . $gpu['name'],
                            'cclock' => $gpu['cclock'],
                            'mclock' => $gpu['mclock'],
                            'temp' => $gpu['temperature'],
                            'mtemp' => $gpu['memory_temperature'] !== null ? $gpu['memory_temperature'] : 0,
                            'fan' => $gpu['fan_speed'],
                            'efficiency' => round($gpu['hashrate'] / 1000 / $gpu['power'],2)
                        );
                    }

                    $output[] = $x; //put data

                    curl_setopt($ch, CURLOPT_URL, 'http://' . $row['IP'] . '/logout?sid=' . $body['sid']);
                    curl_exec($ch);

                }
            }
        }

        //nbminer
        if ($row['Miner'] === 2) {
            /* get summary */
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, 'http://' . $row['IP'] . '/api/v1/status');
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
            $body = curl_exec($ch);

            if (!curl_error($ch)) {
                //is online
                //分析結果
                $body = json_decode($body, true);

                $x = array(
                    "url" => $row['IP'],
                    "hashrate" => round($body['miner']['total_hashrate_raw'] / 1000000,2),
                    "hashrate_day" => round(doubleval(substr($body['stratum']['pool_hashrate_24h'], 0, 5)),2),
                    "gpus" => array(),
                );

                foreach ($body['miner']['devices'] as $gpu) {
                    $x['gpus'][] = array(
                        'gpu_id' => $gpu['id'],
                        'hashrate' => round($gpu['hashrate_raw'] / 1000000,2),
                        'invalid_count' => $gpu['invalid_shares'],
                        'accepted_count' => $gpu['accepted_shares'],
                        'rejected_count' => $gpu['rejected_shares'],
                        'power' => $gpu['power'],
                        'info' => $gpu['info'],
                        'cclock' => $gpu['core_clock'],
                        'mclock' => $gpu['mem_clock'],
                        'temp' => $gpu['temperature'],
                        'mtemp' => $gpu['memTemperature'],
                        'fan' => $gpu['fan'],
                        'efficiency' => round($gpu['hashrate_raw'] / 1000 / $gpu['power'],2)
                    );
                }

                $output[] = $x; //put data
            }
        }

        //lolminer
        if ($row['Miner'] === 3) {
            /* get summary */
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, 'http://' . $row['IP']);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
            $body = curl_exec($ch);

            if (!curl_error($ch)) {
                //is online
                //分析結果
                $body = json_decode($body, true);

                $x = array(
                    "url" => $row['IP'],
                    "hashrate" => round($body['Algorithms'][0]['Total_Performance'],2),
                    "hashrate_day" => 'N/A',
                    "gpus" => array(),
                );

                for ($i = 0;$i<sizeof($body['Workers']);$i++) {
                    $gpu = $body['Workers'][$i];
                    $x['gpus'][] = array(
                        'gpu_id' => $gpu['Index'],
                        'hashrate' => $body['Algorithms'][0]['Worker_Performance'][$i],
                        'invalid_count' => $body['Algorithms'][0]['Worker_Rejected'][$i],
                        'accepted_count' => $body['Algorithms'][0]['Worker_Accepted'][$i],
                        'rejected_count' => $body['Algorithms'][0]['Worker_Rejected'][$i],
                        'power' => round($gpu['Power']),
                        'info' => $gpu['Name'],
                        'cclock' => $gpu['CCLK'],
                        'mclock' => $gpu['MCLK'],
                        'temp' => $gpu['Core_Temp'],
                        'mtemp' => $gpu['Mem_Temp'],
                        'fan' => $gpu['Fan_Speed'],
                        'efficiency' => round($body['Algorithms'][0]['Worker_Performance'][$i] * 1000000 / 1000 / round($gpu['Power']),2)
                    );
                }

                $output[] = $x; //put data
            }
        }

        //Gminer
        if ($row['Miner'] === 4) {
            /* get summary */
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, 'http://' . $row['IP'] . '/stat');
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
            $body = curl_exec($ch);

            if (!curl_error($ch)) {
                //is online
                //分析結果
                $body = json_decode($body, true);

                $x = array(
                    "url" => $row['IP'],
                    "hashrate_day" => 'N/A',
                    "gpus" => array(),
                );

                $total_hashrate = 0;
                foreach ($body['devices'] as $gpu) {
                    $total_hashrate += $gpu['speed'];
                    $x['gpus'][] = array(
                        'gpu_id' => $gpu['gpu_id'],
                        'hashrate' => round($gpu['speed'] / 1000000, 2),
                        'invalid_count' => $gpu['invalid_shares'],
                        'accepted_count' => $gpu['accepted_shares'],
                        'rejected_count' => $gpu['rejected_shares'],
                        'power' => $gpu['power_usage'],
                        'info' => $gpu['name'],
                        'cclock' => $gpu['core_clock'],
                        'mclock' => $gpu['memory_clock'],
                        'temp' => $gpu['temperature'],
                        'mtemp' => $gpu['memory_temperature'],
                        'fan' => $gpu['fan'],
                        'efficiency' => round($gpu['speed'] / 1000 / $gpu['power_usage'],2)
                    );
                }

                $x['hashrate'] = round($total_hashrate / 1000000, 2);
                $output[] = $x; //put data
            }
        }
    }
    return $output; //output
}
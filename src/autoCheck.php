<?php
require_once 'vendor/autoload.php';
require_once 'config.inc.php';

$client  = getClient();

$sqlcon = new mysqli(SQL_SETTING['hostname'], SQL_SETTING['username'], SQL_SETTING['password'], SQL_SETTING['database'], 3306); //sql
if ($sqlcon->connect_errno) { //檢查連線
    #sql錯誤
    echo "SQL server error";
    exit();
} else {
    #插入資料
    $stmt = $sqlcon->prepare("SELECT IP, Online, (Last_check - Last_online) AS offTime FROM Miner");
    if (!$stmt->execute()) {
        echo "Failed to request url";
        exit();
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
                $stmt = $sqlcon->prepare("UPDATE Miner SET Online = FALSE, Last_check = SYSDATE() WHERE IP = ?");
                $stmt->bind_param("s", $row['IP']);
                if (!$stmt->execute()) {
                    echo "SQL server error";
                    exit();
                }

                #Send alert
                if($row['offTime'] <= 300){
                    push_alert('Miner is Offline', $row['IP'].' is go to offline! Please check!', $client);
                }else if($row['offTime'] <= 86400){
                    push_alert('Miner is Offline', $row['IP'].' is still offline! Please check!', $client);
                }
            } else {
                # is online
                $stmt = $sqlcon->prepare("UPDATE Miner SET Online = TRUE, Last_online = SYSDATE(), Last_check = SYSDATE() WHERE IP = ?");
                $stmt->bind_param("s", $row['IP']);
                if (!$stmt->execute()) {
                    echo "SQL server error";
                    exit();
                }

                #Send alert
                if($row['Online'] === 0) push_alert('Miner is Online', $row['IP'].' is back to online.', $client);
            }
            curl_close($ch);
        }

    }
}

//Google Client
function getClient() {
    $client = new Google_Client();
    $client->setApplicationName('MinerCheck_php');
    $client->setScopes(Google_Service_FirebaseCloudMessaging::CLOUD_PLATFORM);
    $client->setAuthConfig(__DIR__.'/cart.json');
    $client->setAccessType('offline');

    // Load previously authorized credentials from a file.
    $credentialsPath = __DIR__.'/token.json';
    if (file_exists($credentialsPath)) {
        $accessToken = json_decode(file_get_contents($credentialsPath), true);
    } else {
        $client->fetchAccessTokenWithAssertion();
        $accessToken = $client->getAccessToken();

        // Store the credentials to disk.
        if (!file_exists(dirname($credentialsPath))) {
            mkdir(dirname($credentialsPath), 0700, true);
        }
        file_put_contents($credentialsPath, json_encode($accessToken));
    }
    $client->setAccessToken($accessToken);

    // Refresh the token if it's expired.
    if ($client->isAccessTokenExpired()) {
        $client->fetchAccessTokenWithAssertion();
        $accessToken = $client->getAccessToken();
        $client->setAccessToken($accessToken);
        file_put_contents($credentialsPath, json_encode($accessToken));
    }

    return $client;
}

//Push alert
function push_alert($title, $body, $client){
    $oauthToken = $client->getAccessToken()['access_token'];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://fcm.googleapis.com/v1/projects/project-name/messages:send');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Bearer '.$oauthToken));
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );

    $payload = json_encode(array(
        "validate_only"=> false,
        'message' => array(
            'name' => 'Test',
            'data' => array(
                'title' => $title,
                'body' => $body
            ),
            'android' => array(
                'priority' => 'HIGH'
            ),
            'token' => 'device token'
        )
    ));
    curl_setopt( $ch, CURLOPT_POSTFIELDS, $payload );
    curl_exec($ch);
}
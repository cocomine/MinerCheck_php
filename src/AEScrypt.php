<?php

class AEScrypt {
    private String $key;
    private String $cipher = "aes-128-gcm";

    public function __construct(String $key) {
        $this->key = substr($key,0,4).substr($key,16, 4).substr($key,32, 4).substr($key,-4);
    }

    public function encrypt(String $data){
        $iv_length = openssl_cipher_iv_length($this->cipher);
        $iv = openssl_random_pseudo_bytes($iv_length);
        $ciphertext = openssl_encrypt($data, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        return base64_encode($iv.$ciphertext.$tag);
    }

    public function decrypt(String $data){
        $c = base64_decode($data);
        $iv_length = openssl_cipher_iv_length($this->cipher);
        $iv = substr($c, 0, $iv_length);
        $tag = substr($c, -16);
        $ciphertext = substr($c, $iv_length, -16);
        return openssl_decrypt($ciphertext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv, $tag);
    }
}
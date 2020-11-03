<?php

namespace GarantexIo;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class Api{

    protected $host = 'garantex.io';
    protected $uid;
    protected $private_key;
    protected $token_file_path;
    protected $token;

    public function __construct(string $uid, string $private_key, string $token_file_path){

        $this->uid = $uid;
        $this->private_key = $private_key;
        $this->token_file_path = $token_file_path;

        if(empty($this->uid)){
            throw new \Exception('Argument uid empty.');
        }else if(empty($this->private_key)){
            throw new \Exception('Argument private_key empty.');
        }else if(empty($this->token_file_path)){
            throw new \Exception('Argument token_file_path empty.');
        }

        //Check current token
        if(file_exists($token_file_path)){
            $this->token = file_get_contents($token_file_path);
        }else{
            $this->generate_jwt();
        }

        //$this->token = !empty($token) ? $token : NULL;

    }

    public function show_var(){
        return([
                'uid' => $this->uid, 
                'private_key' => substr($this->private_key, 0, 24).'..',
                'token' => substr($this->token, 0, 24).'..'
            ]);
    }

    private function generate_jwt(){

        $host = 'garantex.io';
        
        $time = time();
        $signer = new Sha256();

        //dd(base64_decode($private_key, true));

        try {
            $privateKey = new Key(base64_decode($this->private_key, true));
        }catch (\Exception $e) {
            throw new \Exception('Key:>'. $e->getMessage());
        }

        try {
            $token = (new Builder())->issuedBy('external')
                                    ->relatedTo('api_key_jwt')
                                    ->identifiedBy(bin2hex(random_bytes(12)))
                                    ->issuedAt($time)
                                    ->expiresAt($time + 24 * 3600) // JWT TTL in seconds since epoch
                                    ->getToken($signer,  $privateKey);
        }catch (\Exception $e) {
            throw new \Exception('Builder:> '. $e);
        }
            
        $post_data = [ 
                        'kid' => $this->uid,
                        'jwt_token' => strval($token) 
                    ];

        $ch = curl_init("https://dauth.$this->host/api/v1/sessions/generate_jwt");

        curl_setopt_array($ch, array(
            CURLOPT_POST => TRUE,
            CURLOPT_RETURNTRANSFER => TRUE,
            CURLOPT_HTTPHEADER => [ 'Content-Type: application/json' ],
            CURLOPT_POSTFIELDS => json_encode($post_data)
        ));

        $response = curl_exec($ch);

        if ($response === FALSE)
            die(curl_error($ch));

        $data = json_decode($response, TRUE);

        if(isset($data['error'])){
            throw new \Exception($data['error']);
        }

        $token = $data['token'];

        $this->token = $token;

        return file_put_contents($this->token_file_path, $token);

        //dd($post_data, $data);

    }

    //Отправка запросов
    protected function httpRequest(string $url, string $method = 'GET', array $params = []){

        if(function_exists('curl_init') === false){
            throw new \Exception("Sorry cURL is not installed.");
        }

        if(substr($url, 0, 4) != 'http'){

            $url = 'https://'.$this->host.'/api/v2'.$url;

            if($method == 'GET' && $params){
                $url = $url . '?' . http_build_query($params, '', '&');
            }    

        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'Authorization: Bearer '.$this->token
        ]);
        if($method == 'POST'){
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        }
        
        $response = curl_exec($ch);
        
        if($response === FALSE){
            die(curl_error($ch));
        }
        
        $info = curl_getinfo($ch);
        curl_close($ch);

        if($info['http_code'] == 404){
            throw new \Exception($url.' = '.$info['http_code'].'.');
        }

        $response_o = json_decode($response);

        //Errors
        if(isset($response_o->error)){

            $errors = explode(': ', $response_o->error->message);

            //refresf token
            //if(in_array('Failed to decode and verify JWT', $errors)
            //if(in_array('Signature has expired', $errors) || in_array('Not enough or too many segments', $errors)){
            if(in_array('Signature has expired', $errors)){
                $this->generate_jwt();
                return $this->httpRequest($url, $method, $params);
            }else{
                //dd($errors);

                $err = $url.'('.$info['http_code'].'): '.$response_o->error->code.' = '.$response_o->error->message;
                
                if($response_o->error->code == 2000){
                    throw new \Exception($err);
                }else{
                    throw new \Exception($err);
                }

            }

        }

        //dd($response_o, $info);

        return $response_o;

    }

    //Получить список всех активных валют
    public function currencies(string $type = ''){

        $params = [];

        if(!empty($type)) $params += [ 'type' => $type ];
        return $this->httpRequest('/currencies', 'GET', $params);

    }

    //Получить список всех пользовательских счетов
    public function accounts(string $currency_id = ''){

        return $this->httpRequest('/accounts');

    }

    //Получение списка депозитов пользователя
    public function deposits(string $currency_id = '', string $state = '', int $limit = 50){

        $params = [];

        if(!empty($currency_id)) $params += [ 'currency_id' => $currency_id ];
        if(!empty($state)) $params += [ 'state' => $state ];
        if(!empty($limit)) $params += [ 'limit' => $limit ];

        return $this->httpRequest('/deposits', 'GET', $params);

    }

    //Получение списка выводов пользователя
    public function withdraws(string $currency_id = '', $page = 1, int $limit = 100){

        $params = [];

        if(!empty($currency_id)) $params += [ 'currency_id' => $currency_id ];
        if(!empty($page)) $params += [ 'page' => $page ];
        if(!empty($limit)) $params += [ 'limit' => $limit ];

        return $this->httpRequest('/withdraws', 'GET', $params);

    }

    //Получения истории сделок пользователя по выбранному рынку
    public function trades(string $market = 'btcrub', int $limit = 100, int $timestamp = 0, int $from = 0, int $to = 0, string $order_by = 'desc'){

        $params = [];

        if(!empty($market)) $params += [ 'market' => $market ];
        if(!empty($limit)) $params += [ 'limit' => $limit ];
        if($timestamp > 0) $params += [ 'timestamp' => $timestamp ];
        if($from > 0) $params += [ 'from' => $from ];
        if($to > 0) $params += [ 'to' => $to ];
        if(!empty($order_by)) $params += [ 'order_by' => $order_by ];

        return $this->httpRequest('/trades/my', 'GET', $params);

    }

    //Получения истории заявок по выбранному рынку
    public function orders(string $market = 'btcrub', string $state = '', int $page = 1, int $limit = 100, string $order_by = 'desc'){

        $params = [];

        if(!empty($market)) $params += [ 'market' => $market ];
        if(!empty($state)) $params += [ 'state' => $state ];
        if(!empty($page)) $params += [ 'page' => $page ];
        if(!empty($limit)) $params += [ 'limit' => $limit ];
        if(!empty($order_by)) $params += [ 'order_by' => $order_by ];

        return $this->httpRequest('/orders', 'GET', $params);

    }

}

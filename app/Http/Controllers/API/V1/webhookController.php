<?php

namespace App\Http\Controllers\API\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Cache;

class webhookController extends Controller
{
    //
    private $ref = '';

    public function UssdWebhook(Request $request){
        // Read the variables sent via POST from our API
        $sessionId   = $request->sessionId;
        $serviceCode = $request->serviceCode;
        $phoneNumber = $request->phoneNumber;
        $text        = $request->text;



        if ($text == "") {
            // This is the first request. Note how we start the response with CON
            $response  = "CON This service is only for Offline Payment \n";
            $response .= "1. Make Payment for Goods or Services \n";
            $response .= "2. Just saying Hello";

        } else if ($text == "1") {
            // Business logic for first level response
            $accountNumber  = "ACC1001";

            // This is a terminal request. Note how we start the response with END
            $response = "END Your account number is ".$accountNumber;


        } else if ($text == "2") {
            // Business logic for first level response
            // This is a terminal request. Note how we start the response with END
            $response = "END Your phone number is ".$phoneNumber. " Thank you for saying Hello";

        } else if(strlen($text) == 6) { 
            // This is a second level response where the user selected 1 in the first instance

            $key = Cache::get('ref');
            
            $reference  =  $key;

            $result = $this->validateCharge($text, $reference);

            $resolved = json_decode($result, true);
            if($resolved['status'] == 'success'){
                if( $resolved['data']["status"] == "successful"){
                    echo $resolved['data']["status"];
                    // This is a terminal request. Note how we start the response with END
                    $response = "END Your account number is ".$resolved['data']["status"];
                }
            }else{
                     // This is a terminal request. Note how we start the response with END
                    $response = "END Your account number is ".$reference;
            }
          
           

        }else{
            $response = $text;
    
            $results = [];
            // $results = explode('*', $text);
            // $amount = $results[0];
            // $card = $results[1];
            // $exp_month = $results[2];
            // $exp_year = $results[3];
            // $cvv = $result[4];
            // $pin = $result[5];
        
            $results['card_number']="5531886652142950";
            $results['cvv'] = "564";
            $results['expiry_month']= "09";
            $results['expiry_year']="32";
            $results['currency']="NGN";
            $results['amount']="1000";
            $results['email']="user@example.com";
            $results['tx_ref'] = Str::random(32);
            $results['redirect_url']="https://www.flutterwave.ng";
            $results['authorization']= [
                "mode" => "pin",
                "pin"  => "3310"
            ];
            $details = $this->initiateCard($results);

            $response = "CON ".$details;

        }
       
        // Echo the response back to the API
        header('Content-type: text/plain');
        Log::info($response);
        // Log::info($results);
        Log::info(strlen($response));
    }

    public function initiateCard(array $transaction){
        $key = Cache::get('ref');
        echo $key;
        $results['card_number']="5531886652142950";
        $results['cvv'] = "564";
        $results['expiry_month']= "09";
        $results['expiry_year']="32";
        $results['currency']="NGN";
        $results['amount']="1000";
        $results['email']="user@example.com";
        $results['tx_ref'] = Str::random(32);
        $results['redirect_url']="https://www.flutterwave.ng";
        $results['authorization']= [
            "mode" => "pin",
            "pin"  => "3310"
        ];

        // $payload = [
        //     "card_number"=>"5531886652142950",
        //     "cvv"=>"564",
        //     "expiry_month"=>"09",
        //     "expiry_year"=>"32",
        //     "currency"=>"NGN",
        //     "amount"=>"1000",
        //     "email"=>"user@example.com",
        //     "tx_ref"=>"MC343243e",
        //     "redirect_url"=>"https://www.flutterwave.ng",
        //     "authorization"=> [
        //         "mode"=> "pin",
        //         "pin" => "3310"
        //     ]
        // ];

        $result = $this->encrypt('FLWSECK_TESTb4a819567789', $transaction);

        $data = json_encode(["client"=>$result]);

        $curl = curl_init();

        curl_setopt_array($curl, array(
        CURLOPT_URL => 'https://api.flutterwave.com/v3/charges?type=card',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => '',
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 0,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => 'POST',
        CURLOPT_POSTFIELDS => ($data),
        CURLOPT_HTTPHEADER => array(
            'Authorization: Bearer FLWSECK_TEST-d15cfaa48c307753150255076058e054-X',
            'content-type: application/json'
        ),
        ));

        $response = curl_exec($curl);

        curl_close($curl);
        echo $response;

        $res = json_decode($response, true);
        // echo $res['data']['flw_ref'];
        if($res['status']=='success'){
            if( $res['data']["status"] == "pending"){

                $data = [
                    'payment_reference' => $res['data']['flw_ref']
                ];
                
                // Config::write('ref', $data);
                Cache::put('ref',$res['data']['flw_ref'], 60);
                // Cache::store('ref')->put('bar', 'baz', 10);
               return $res['data']['processor_response'];

                // $result = $this->validateCharge('123456', $res['data']['flw_ref']);

                // $resolved = json_decode($result, true);
                // if($resolved['status'] == 'success'){
                //     if( $resolved['data']["status"] == "successful"){
                //         return $resolved['data']["status"];
                //     }
                // }
    
            }
        }

    

    }

    public function encrypt(string $encryptionKey, array $payload){
        $encrypted = openssl_encrypt(json_encode($payload), 'DES-EDE3', $encryptionKey, OPENSSL_RAW_DATA);
        return base64_encode($encrypted);
    }


    public function validateCharge(string $otp, string $reference){
        
        $data = json_encode(["otp"=>$otp, "flw_ref"=>$reference, "type"=>"card"]);

        $curl = curl_init();
        
        curl_setopt_array($curl, array(
        CURLOPT_URL => 'https://api.flutterwave.com/v3/validate-charge',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => '',
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 0,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => 'POST',
        CURLOPT_POSTFIELDS =>($data),
        CURLOPT_HTTPHEADER => array(
            'Authorization: Bearer FLWSECK_TEST-d15cfaa48c307753150255076058e054-X',
            'Content-Type: application/json',
            'accept: application/json'
        ),
        ));

        $response = curl_exec($curl);

        curl_close($curl);
        return $response;

    }
}

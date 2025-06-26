<?php

namespace App\Services;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use DateTime;
use DateTimeZone;
use Exception;
use ParagonIE\Sodium\Compat;
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;
use Illuminate\Http\Request;

class InterSwitchService
{
    protected string $merchantCode;
    protected string $clientId;
    protected string $secret;
    protected string $payItemId;
    protected string $baseUrl;
    protected string $host;
    private string $modulus;
    private string $publicExponent;

    public function __construct()
    {
        $this->merchantCode = config('services.interswitch.merchant_code');
        $this->clientId = config('services.interswitch.client_id');
        $this->secret = config('services.interswitch.secret');
        $this->payItemId = config('services.interswitch.payitem_id');
        // $this->environment = config('services.cybersource.environment', 'test');
        $this->baseUrl = 'https://apitest.cybersource.com';
        $this->modulus = '009c7b3ba621a26c4b02f48cfc07ef6ee0aed8e12b4bd11c5cc0abf80d5206be69e1891e60fc88e2d565e2fabe4d0cf630e318a6c721c3ded718d0c530cdf050387ad0a30a336899bbda877d0ec7c7c3ffe693988bfae0ffbab71b25468c7814924f022cb5fda36e0d2c30a7161fa1c6fb5fbd7d05adbef7e68d48f8b6c5f511827c4b1c5ed15b6f20555affc4d0857ef7ab2b5c18ba22bea5d3a79bd1834badb5878d8c7a4b19da20c1f62340b1f7fbf01d2f2e97c9714a9df376ac0ea58072b2b77aeb7872b54a89667519de44d0fc73540beeaec4cb778a45eebfbefe2d817a8a8319b2bc6d9fa714f5289ec7c0dbc43496d71cf2a642cb679b0fc4072fd2cf';
        $this->publicExponent = '010001';
    }

    public function generateToken(): string
    {
        $con  = $this->clientId .':'. $this->merchantCode;
        $token = base64_encode($con);
        return $token;
        
    }

    // public function accessToken()
    // {
    //     try {
    //         $concatenatedString = $this->clientId . ":" . $this->secret;
    //         $encodedString = base64_encode($concatenatedString);
    //         $response = Http::asForm()->withHeaders([
    //             'Authorization' => 'Basic' . ' ' . $encodedString,
    //             'Accept' => 'application/json',
    //         ])->post('https://passport.k8.isw.la/passport/oauth/token', [
    //             'grant_type' => 'client_credentials',
    //         ]);
    //         $token = json_decode($response, true);
    //         return $token['access_token'];
            
    //     } catch (\Exception $e){
    //         return response()->json(['error'=> $e->getMessage()]);
    //     }
    // }

    // public function accessToken(){
    //     $concatenatedString = $this->clientId . ":" . $this->secret;
    //     $encodedString = base64_encode($concatenatedString);
    //     $url = "https://passport.k8.isw.la/passport/oauth/token?grant_type=client_credentials";
    //     $headers = array(
    //         'Content-Type: application/json',
    //         'Authorization' => 'Basic' . ' ' . $encodedString,
    //     );
    //     $response = Http::withHeaders($headers)
    //     // ->baseUrl($this->baseUrl)
    //     ->post($url);
    //     dd($response->json());
    
    //     return $response;
    // }

    public function accessToken(){
        $concatenatedString = $this->clientId . ":" . $this->secret;
        $encodedString = base64_encode($concatenatedString);
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => "https://apps.qa.interswitchng.com/passport/oauth/token?grant_type=client_credentials",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            // CURLOPT_POSTFIELDS => ($data),
            CURLOPT_HTTPHEADER => array(
                'Authorization: Basic SUtJQTNCODI3OTUxRUEzRUMyRTE5M0M1MURBMUQyMjk4OEYwNTVGRDI3REU6YWprZHBHaUY2UEhWcndL',
                'content-type: application/json'
            ),
            ));
    
            $response = curl_exec($curl);
            curl_close($curl);
            $res = json_decode($response, true);
            return $res['access_token'];
    }

    
    /**
     * Create a payment request.
     *
     * @param array $paymentData
     * @return array
     * @throws Exception
     */
    public function createPayment(array $paymentData): array
    {
        $path = '/pts/v2/payments';
        $httpMethod = 'post';
        
        try {
            // Generate the digest for the payload
            $digest = $this->generateDigest($paymentData);
            
            // Get the RFC1123 formatted date
            $date = $this->getDate();
            
            // Generate the signature
            $signature = $this->generateSignature($httpMethod, $path, $digest, $date);
            
            // Prepare headers
            $headers = [
                'v-c-merchant-id' => $this->merchantId,
                'Date' => $date,
                'Host' => $this->host,
                'Content-Type' => 'application/json',
                'Digest' => $digest,
                'Signature' => $signature
            ];

            $response = Http::withHeaders($headers)
                ->baseUrl($this->baseUrl)
                ->post($path, $paymentData);
                dd($response->json());
            return $this->handleResponse($response);
        } catch (Exception $e) {
            return [
                'error' => $e->getMessage(),
                'status' => 'error'
            ];
        }
    }

    public function payWithInterswitchCard(Request $request){
        // try {
                // $ip = $request->ip();
    
                $cardType = $this->detectCardType($request->card_number);

                // return $cardType;
    
                $accessToken = $this->accessToken();
                $access = 'Bearer'.' '.$accessToken;
    
                // $authData = $this->generateAuthData($data);
                $authData = "UXkWjeEhriu0Sn0TkwD7avRNpbwd8b1GFBp3pF4AqWE+xh7g0NslORTk8Tj6N1Ujug7UkuVKtDbjedEJadvHQht8D37RJqaljE1J1BWkbftfHhETMnLmAhthr6jFnrVXKGNRRCEaDxqj+ssw5Yh4zInVQGAAc2R5l/nSgBiMP+4wThanlJyB+xPL8F7smByidJZy0FpuEEDBzjxdqXfVyEwLzYJH9zIFSCxeogINtx4W4UVWm7z/ObCom+oJXT2jmRhx3xrFmTFvL2HJV1Gwzcu1dAIzq2arGfc+z+9gDzWEo3tzRuH/mSE739c5bC4dxRpaKHIeokNVtOUxZpCBcA==";
    
                $endpoint = 'https://qa.interswitchng.com/api/v3/purchases';
    
                if($cardType == 'Visa'){
                  $req = [
                    'authData' => 'CHAd30bRaSTJwKsY+v+KCgqKI1VcH2g73ZpafCRan4VbLmc8VtywAtUeljk29Uyru7adZHt6mxddHKBxXCYkYnkINml2Nv4t46IkvaoFPZ0DwzI66h3X9TWn5a4Ang7sDrWXZ/vuNbRXqlD8/RAdsFN9fOkz4BJMdJJrBYXkoLe+cMVkscnSeNETVolc7pdwY4vUmXPUZFKjnKPVH6OTc9YacVbULu1LhTIloZT92BofN9bOpT0ldDowUW7Ejddyl49mS1wvkyma4yOpYVY1nOzmPKHrUH/YBFUAx3y4umCBHbjRyQAVTskXUec7Nc5eV+Ob5d+tXFThRjI2HhSaCw==',
                    'amount' => $request->amount,
                    'currency' => 'NGN',
                    'customerId' => $this->merchantCode,
                    'transactionRef' => $this->randomString(),
                    'deviceInformation' => $request->deviceInformation,
                    'callbackUrl'=> $request->redirectUrl,
                  ];
                }else{
                  $req = [
                    'authData' => $authData,
                    'amount' => $request->amount,
                    'currency' => 'NGN',
                    'customerId' => $this->merchantCode,
                    'transactionRef' => $this->randomString(),
                  ];
                }
    
              $res = Http::withHeaders([
                  'Authorization' => $access,
                  'Content-Type' => 'application/json',
                  'Accept' => 'application/json',
              ])->post("https://qa.interswitchng.com/api/v3/purchases",$req);
    
                
                $data = json_decode($res, true);
    
                if ( array_key_exists('responseCode', $data)) {
                //   $data['reference'] = $payment->reference;
                  
    
                   $response = $data;
      
                } else {
                 
                  $response = $data;
                }
                
        // } catch (Throwable $e) {
        //   Loggable::error($e);
    
        //   $response = $this->jsonResponse('Something went wrong while or when attempting this payment.', __($this->errorCode), 500, [], __($this->serverError));
        // }
    
        return $response;
    }

    protected function detectCardType(string $number): string
    {
        $patterns = [
          'Visa' => '/^4[0-9]{6,}$/',
          'MasterCard' =>'/ ^5[1-5][0-9]{5,}|222[1-9][0-9]{3,}|22[3-9][0-9]{4,}|2[3-6][0-9]{5,}|27[01][0-9]{4,}|2720[0-9]{3,}$/',
          'Verve' => '/^(?:50[067][180]|6500)(?:[0-9]{15})$/',
        ];
  
        foreach ($patterns as $type => $pattern) {
            if (preg_match($pattern, $number)) {
                return $type;
            }
        }
  
        return 'unknown';
    }

    /**
     * Generate digest for the payload
     * 
     * @param array $payload
     * @return string
     */
    protected function generateDigest(array $payload): string
    {
        $jsonPayload = json_encode($payload);
        $hash = hash('sha256', $jsonPayload, true);
        $base64Hash = base64_encode($hash);
        return "SHA-256=$base64Hash";
    }

    /**
     * Get RFC1123 formatted date
     * 
     * @return string
     */
   

    /**
     * Handle the API response
     *
     * @param Response $response
     * @return array
     */
    protected function handleResponse(Response $response): array
    {
        if ($response->successful()) {
            return [
                'data' => $response->json(),
                'status' => 'success'
            ];
        }

        return [
            'error' => $response->json()['message'] ?? 'Unknown error occurred',
            'status' => 'error',
            'statusCode' => $response->status()
        ];
    }

    /**
     * Generate encrypted authentication data
     *
     * @param array $options
     * @return string
     * @throws Exception
     */
    public function generateAuthData(array $options): string
    {
        try {

            // Create auth string in the same format: "1Z{card}Z{pin}Z{exp}Z{cvv}"
            $authString = "1Z{$options['card']}Z{$options['pin']}Z{$options['exp']}Z{$options['cvv']}";
            // dd($authString);
            // Convert to hex
            $hexString = $this->stringToHex($authString);
            
            // Create RSA instance
            $rsa = RSA::load([
                'n' => new BigInteger($options['publicKeyModulus'], 16),
                'e' => new BigInteger($options['publicKeyExponent'], 16)
            ]);
            
            // Set encryption padding
            $rsa = $rsa->withPadding(RSA::ENCRYPTION_PKCS1);
            
            // Encrypt the hex string
            $encrypted = $rsa->encrypt(hex2bin($hexString));
            
            // Return base64 encoded result
            return base64_encode($encrypted);
        } catch (Exception $e) {
            throw new Exception("Error generating auth data: " . $e->getMessage());
        }
    }

    /**
     * Convert string to hexadecimal
     *
     * @param string $str
     * @return string
     */
    private function stringToHex(string $str): string
    {
        $hex = '';
        for ($i = 0; $i < strlen($str); $i++) {
            $hex .= dechex(ord($str[$i]));
        }
        return $hex;
    }

    // public function resendOTP($paymentId, $amount)
    // {
        
    //     $concatenatedString = $this->clientId . ":" . $this->secret;
    //     $accessToken = $this->accessToken();
    //     $access = 'Bearer '.$accessToken;
    //     $data = json_encode(
    //         [
    //             "paymentId" => $paymentId, 
    //             "amount" => $amount, 
    //             "currency" =>"NGN"
    //         ]);
    //     $curl = curl_init();
    //     curl_setopt_array($curl, array(
    //         CURLOPT_URL => 'https://qa.interswitchng.com/api/v3/purchases/otps/resend ',

    //         CURLOPT_RETURNTRANSFER => true,
    //         CURLOPT_ENCODING => '',
    //         CURLOPT_MAXREDIRS => 10,
    //         CURLOPT_TIMEOUT => 0,
    //         CURLOPT_FOLLOWLOCATION => true,
    //         CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    //         CURLOPT_CUSTOMREQUEST => 'POST',
    //         CURLOPT_POSTFIELDS => ($data),
    //         CURLOPT_HTTPHEADER => array(
    //             'Content-Type: application/json',
    //             'Authorization: Bearer '. $accessToken
    //         ),
    //         ));
    
    //         $response = curl_exec($curl);
    //         curl_close($curl);
    //         return $response;
    //        $res = json_decode($response, true);
    //        return $res;
    // }

    public function resendOTP($paymentId, $amount)
    {
        $accessToken = $this->accessToken();
        $access = 'Bearer'.' '.$accessToken;
        $data = [
            "paymentId" => $paymentId,
            "amount"=> $amount,
            'currency' => "NGN",
        ];
        $verifyStatus = Http::withHeaders([
            'Authorization' => $access,
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        ])->post("https://qa.interswitchng.com/api/v3/purchases/otps/resend",$data);
        
        return response()->json(json_decode($verifyStatus));
    }

    public  function randomString($length = 10): string
  { 
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
      $randomString .= $characters[random_int(0, strlen($characters) - 1)];
    }
    return $randomString;
  }

    
    // public function generateAuthData(array $options): string
    // {
    //     try {
    //         // 1. Build the auth string in the format: "1Z{card}Z{pin}Z{exp}Z{cvv}"
    //         $authString = "1Z" 
    //                     . $options['card'] . "Z" 
    //                     . $options['pin']  . "Z" 
    //                     . $options['exp']  . "Z" 
    //                     . $options['cvv'];
    
    //         // 2. Convert the auth string to hex (mimicking the JS toHex function)
    //         $hexString = $this->toHex($authString);
    //         // Convert the hex string back to binary data.
    //         // (For typical alphanumeric input, using bin2hex vs. our custom toHex is equivalent,
    //         //  but here we replicate the JS logic.)
    //         $authDataBytes = hex2bin($hexString);
            
    //         // 3. Create a PEM-formatted RSA public key from the modulus and exponent
    //         $publicKeyPem = $this->createPemFromModulusAndExponent(
    //             $options['publicKeyModulus'],
    //             $options['publicKeyExponent']
    //         );
            
    //         // 4. Encrypt the binary data using the public key with PKCS#1 padding
    //         $encrypted = '';
    //         $result = openssl_public_encrypt($authDataBytes, $encrypted, $publicKeyPem, OPENSSL_PKCS1_PADDING);
    //         if (!$result) {
    //             throw new Exception('Encryption failed: ' . openssl_error_string());
    //         }
            
    //         // 5. Return the base64-encoded encrypted data
    //         $authData = base64_encode($encrypted);
    //         return $authData;
    //     } catch (Exception $e) {
    //         throw new Exception("Error generating auth data: " . $e->getMessage());
    //     }
    // }
    
    // /**
    //  * Converts a string to its hexadecimal representation.
    //  * (This function mimics the JavaScript version which does not pad single-digit hex values.)
    //  *
    //  * @param string $str The input string.
    //  *
    //  * @return string The hexadecimal representation.
    //  */
    // private function toHex(string $str): string
    // {
    //     $hex = '';
    //     $len = strlen($str);
    //     for ($i = 0; $i < $len; $i++) {
    //         // Note: dechex() does not pad values less than 16.
    //         $hex .= dechex(ord($str[$i]));
    //     }
    //     return $hex;
    // }
    
    // /**
    //  * Creates a PEM-formatted RSA public key from hexadecimal modulus and exponent.
    //  *
    //  * @param string $modulusHex  The modulus in hexadecimal.
    //  * @param string $exponentHex The exponent in hexadecimal.
    //  *
    //  * @return string The PEM-formatted RSA public key.
    //  */
    // private function createPemFromModulusAndExponent(string $modulusHex, string $exponentHex): string
    // {
    //     // Convert hex values to binary
    //     $modulus = hex2bin($modulusHex);
    //     $exponent = hex2bin($exponentHex);
        
    //     // Encode the two integers in ASN.1 DER format
    //     $modulusDer = $this->asn1EncodeInteger($modulus);
    //     $exponentDer = $this->asn1EncodeInteger($exponent);
        
    //     // Create a sequence containing both INTEGERs
    //     $sequence = $this->asn1EncodeSequence($modulusDer . $exponentDer);
        
    //     // Format the DER-encoded key in PEM format
    //     $pem = "-----BEGIN RSA PUBLIC KEY-----\n" .
    //            chunk_split(base64_encode($sequence), 64, "\n") .
    //            "-----END RSA PUBLIC KEY-----\n";
    //     return $pem;
    // }
    
    // /**
    //  * Encodes the length for ASN.1 DER.
    //  *
    //  * @param int $length The length to encode.
    //  *
    //  * @return string The encoded length.
    //  */
    // private function asn1EncodeLength(int $length): string
    // {
    //     if ($length < 0x80) {
    //         return chr($length);
    //     } else {
    //         $lenHex = dechex($length);
    //         if (strlen($lenHex) % 2 !== 0) {
    //             $lenHex = '0' . $lenHex;
    //         }
    //         $lenBin = hex2bin($lenHex);
    //         return chr(0x80 | strlen($lenBin)) . $lenBin;
    //     }
    // }
    
    // /**
    //  * Encodes an INTEGER for ASN.1 DER.
    //  *
    //  * @param string $data The binary data representing the integer.
    //  *
    //  * @return string The DER-encoded INTEGER.
    //  */
    // private function asn1EncodeInteger(string $data): string
    // {
    //     // If the first byte is greater than 0x7f, prepend a null byte
    //     if (ord($data[0]) > 0x7f) {
    //         $data = "\x00" . $data;
    //     }
    //     $length = $this->asn1EncodeLength(strlen($data));
    //     return "\x02" . $length . $data;
    // }
    
    // /**
    //  * Encodes a sequence for ASN.1 DER.
    //  *
    //  * @param string $data The data to include in the sequence.
    //  *
    //  * @return string The DER-encoded sequence.
    //  */
    // private function asn1EncodeSequence(string $data): string
    // {
    //     $length = $this->asn1EncodeLength(strlen($data));
    //     return "\x30" . $length . $data;
    // }




   
// public function generateAuthData(array $options): string
// {
//     try {
//         // 1. Build the auth string: "1Z{card}Z{pin}Z{exp}Z{cvv}"
//         $authString = "1Z" . $options['card'] . "Z" . $options['pin'] . "Z" . $options['exp'] . "Z" . $options['cvv'];
        
//         // 2. Convert the auth string to hex (mimics the JS toHex)
//         $hexString = $this->toHex($authString);
//         // Then convert the hex back to binary data
//         $authDataBytes = hex2bin($hexString);
        
//         // 3. Build a PEM-formatted RSA public key in X.509 SubjectPublicKeyInfo format.
//         $publicKeyPem = $this->createPemFromModulusAndExponent(
//             $options['publicKeyModulus'],
//             $options['publicKeyExponent']
//         );
        
//         // 4. Encrypt using the public key (PKCS#1 padding)
//         $encrypted = '';
//         if (!openssl_public_encrypt($authDataBytes, $encrypted, $publicKeyPem, OPENSSL_PKCS1_PADDING)) {
//             throw new Exception('Encryption failed: ' . openssl_error_string());
//         }
        
//         // 5. Return the base64-encoded encrypted data.
//         return base64_encode($encrypted);
        
//     } catch (Exception $e) {
//         throw new Exception("Error generating auth data: " . $e->getMessage());
//     }
// }

// /**
//  * Converts a string to its hexadecimal representation.
//  *
//  * @param string $str Input string.
//  * @return string Hexadecimal representation.
//  */
// private function toHex(string $str): string
// {
//     $hex = '';
//     for ($i = 0, $len = strlen($str); $i < $len; $i++) {
//         $hex .= dechex(ord($str[$i]));
//     }
//     return $hex;
// }

// /**
//  * Creates a PEM-formatted RSA public key (SubjectPublicKeyInfo) from modulus and exponent.
//  *
//  * @param string $modulusHex  RSA modulus in hexadecimal.
//  * @param string $exponentHex RSA exponent in hexadecimal.
//  *
//  * @return string PEM-formatted public key.
//  */
// private function createPemFromModulusAndExponent(string $modulusHex, string $exponentHex): string
// {
//     // Convert hex to binary
//     $modulus  = hex2bin($modulusHex);
//     $exponent = hex2bin($exponentHex);
    
//     // Build the RSAPublicKey structure (PKCS#1 format)
//     $modulusEncoded  = $this->asn1EncodeInteger($modulus);
//     $exponentEncoded = $this->asn1EncodeInteger($exponent);
//     $rsaPublicKey    = $this->asn1EncodeSequence($modulusEncoded . $exponentEncoded);
    
//     // Wrap the RSA key in a BIT STRING.
//     // A BIT STRING has a preceding byte that indicates the number of unused bits (0).
//     $bitString = "\x00" . $rsaPublicKey;
//     $bitStringEncoded = "\x03" . $this->asn1EncodeLength(strlen($bitString)) . $bitString;
    
//     // Create the AlgorithmIdentifier for rsaEncryption.
//     // rsaEncryption OID is: 1.2.840.113549.1.1.1, DER encoded as: 06 09 2A 86 48 86 F7 0D 01 01 01
//     $oid = "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01";
//     // The parameters field is a NULL: 05 00.
//     $null = "\x05\x00";
//     $algId = $this->asn1EncodeSequence($oid . $null);
    
//     // Construct the SubjectPublicKeyInfo structure.
//     $spki = $this->asn1EncodeSequence($algId . $bitStringEncoded);
    
//     // Convert to PEM format.
//     $pem = "-----BEGIN PUBLIC KEY-----\n" .
//            chunk_split(base64_encode($spki), 64, "\n") .
//            "-----END PUBLIC KEY-----\n";
    
//     return $pem;
// }

// /**
//  * Encodes a length in ASN.1 DER format.
//  *
//  * @param int $length Length to encode.
//  * @return string DER encoded length.
//  */
// private function asn1EncodeLength(int $length): string
// {
//     if ($length < 0x80) {
//         return chr($length);
//     }
    
//     // Convert length to hexadecimal string.
//     $lenHex = dechex($length);
//     if (strlen($lenHex) % 2 !== 0) {
//         $lenHex = '0' . $lenHex;
//     }
//     $lenBin = hex2bin($lenHex);
//     return chr(0x80 | strlen($lenBin)) . $lenBin;
// }

// /**
//  * Encodes binary data as an ASN.1 INTEGER.
//  *
//  * @param string $data Binary representation of the integer.
//  * @return string DER-encoded INTEGER.
//  */
// private function asn1EncodeInteger(string $data): string
// {
//     // If the highest bit is set, prepend a zero byte.
//     if (ord($data[0]) > 0x7f) {
//         $data = "\x00" . $data;
//     }
//     $length = $this->asn1EncodeLength(strlen($data));
//     return "\x02" . $length . $data;
// }

// /**
//  * Encodes data as an ASN.1 SEQUENCE.
//  *
//  * @param string $data Data to encode.
//  * @return string DER-encoded SEQUENCE.
//  */
// private function asn1EncodeSequence(string $data): string
// {
//     $length = $this->asn1EncodeLength(strlen($data));
//     return "\x30" . $length . $data;
// }





// public function generateAuthData(array $options): string
// {
//     // 1. Build the auth string in the format: "1Z{card}Z{pin}Z{exp}Z{cvv}"
//     $authString = "1Z{$options['card']}Z{$options['pin']}Z{$options['exp']}Z{$options['cvv']}";

//     // 2. (Replicating the Node.js behavior)
//     // Convert the auth string to its hex representation and then back to binary.
//     // (Note: This conversion returns the original string in binary form.)
//     $hexString     = bin2hex($authString);
//     $dataToEncrypt = hex2bin($hexString);

//     // 3. Create a PEM-formatted RSA public key from modulus and exponent.
//     $pem = $this->createPemFromModExp($options['publicKeyModulus'], $options['publicKeyExponent']);

//     // 4. Encrypt the data using the RSA public key with PKCS#1 v1.5 padding.
//     $encrypted = '';
//     $result = openssl_public_encrypt($dataToEncrypt, $encrypted, $pem, OPENSSL_PKCS1_PADDING);
//     if (!$result) {
//         throw new Exception("Encryption failed: " . openssl_error_string());
//     }

//     // 5. Return the Base64-encoded encrypted data.
//     return base64_encode($encrypted);
// }

// /**
//  * Creates a PEM-formatted RSA public key from a hexadecimal modulus and exponent.
//  *
//  * @param string $modulusHex  The RSA modulus in hex.
//  * @param string $exponentHex The RSA exponent in hex.
//  *
//  * @return string The PEM-formatted RSA public key.
//  */
// private function createPemFromModExp(string $modulusHex, string $exponentHex): string
// {
//     // Convert hexadecimal values to binary.
//     $modulus  = pack("H*", $modulusHex);
//     $exponent = pack("H*", $exponentHex);

//     // Ensure positive integers by prepending a zero byte if the highest bit is set.
//     if (ord($modulus[0]) > 0x7f) {
//         $modulus = "\x00" . $modulus;
//     }
//     if (ord($exponent[0]) > 0x7f) {
//         $exponent = "\x00" . $exponent;
//     }

//     // Encode each as a DER INTEGER.
//     $modulusEnc  = "\x02" . $this->encodeLength(strlen($modulus)) . $modulus;
//     $exponentEnc = "\x02" . $this->encodeLength(strlen($exponent)) . $exponent;

//     // Create the DER SEQUENCE for the RSAPublicKey structure.
//     $rsaPublicKey = "\x30" . $this->encodeLength(strlen($modulusEnc . $exponentEnc)) . $modulusEnc . $exponentEnc;

//     // Convert the DER-encoded key to PEM format.
//     $pem = "-----BEGIN RSA PUBLIC KEY-----\n" .
//            chunk_split(base64_encode($rsaPublicKey), 64, "\n") .
//            "-----END RSA PUBLIC KEY-----\n";

//     return $pem;
// }









// public function generateAuthData(
//     string $pan,
//     string $pin,
//     string $expiryDate,
//     string $cvv2,
//     string $version = '1'): string {
//     try {
//         // Create the auth data cipher string
//         $authDataCipher = implode('Z', [
//             $version,
//             $pan,
//             $pin,
//             $expiryDate,
//             $cvv2
//         ]);

//         // Get RSA key components
//         $rsa = array(
//             'n' => $this->hexToBase64($this->modulus),
//             'e' => $this->hexToBase64($this->publicExponent)
//         );

//         // Create public key in PEM format
//         $rsaPublicKey = $this->rsaPublicKey($rsa['n'], $rsa['e']);
        
//         // Check if key is valid
//         if (!$rsaPublicKey) {
//             throw new Exception('Failed to create public key');
//         }

//         // Encrypt data
//         $encrypted = '';
//         $result = openssl_public_encrypt(
//             $authDataCipher,
//             $encrypted,
//             $rsaPublicKey,
//             OPENSSL_PKCS1_PADDING
//         );

//         if ($result === false) {
//             throw new Exception('Encryption failed');
//         }

//         // Convert to base64 and remove any line breaks
//         return str_replace(["\r", "\n"], '', base64_encode($encrypted));
//     } catch (Exception $e) {
//         throw new Exception("Error generating auth data: " . $e->getMessage());
//     }
// }

/**
 * Convert hexadecimal to base64
 */
private function hexToBase64(string $hex): string
{
    $binary = hex2bin(trim($hex));
    if ($binary === false) {
        throw new Exception('Invalid hex string');
    }
    return base64_encode($binary);
}

/**
 * Create RSA public key in PEM format
 */
private function rsaPublicKey(string $modulus, string $exponent): string
{
    $keyData = [
        'modulus' => base64_decode($modulus),
        'publicExponent' => base64_decode($exponent)
    ];

    $template = "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n";
    
    // Create ASN.1 RSA public key structure
    $der = chr(0x30).chr(0x82);
    $der .= chr(0x01).chr(0x22); // Length of the remaining data
    $der .= chr(0x30).chr(0x0D);
    $der .= chr(0x06).chr(0x09);
    $der .= chr(0x2A).chr(0x86).chr(0x48).chr(0x86).chr(0xF7).chr(0x0D).chr(0x01).chr(0x01).chr(0x01); // RSA OID
    $der .= chr(0x05).chr(0x00);
    $der .= chr(0x03).chr(0x82);
    $der .= chr(0x01).chr(0x0F);
    $der .= chr(0x00);
    $der .= chr(0x30).chr(0x82);
    $der .= chr(0x01).chr(0x0A);
    $der .= chr(0x02).chr(0x82);
    $der .= chr(0x01).chr(0x01);
    $der .= $keyData['modulus'];
    $der .= chr(0x02).chr(0x03);
    $der .= $keyData['publicExponent'];

    return sprintf($template, chunk_split(base64_encode($der), 64, "\n"));
}

         
}



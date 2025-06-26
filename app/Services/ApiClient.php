<?php
namespace App\Services;

use CyberSource\Authentication\Core\AuthenticationSDK;
use CyberSource\Authentication\Util\GlobalSignatureInformation;
use CyberSource\Authentication\PayloadDigest\PayloadDigest;
use CyberSource\Logging\LogFactory;

class ApiClient
{
    public static $OPEN_TIMEOUT = 60;
    public static $CONNECT_TIMEOUT = 60;
    public static $WRITE_TIMEOUT = 60;
    public static $READ_TIMEOUT = 60;
    
    private $merchantConfig;
    private $authenticationSDK;
    private $curlClient;
    private $logger;

    public function __construct($merchantConfig)
    {
        $this->merchantConfig = $merchantConfig;
        $this->authenticationSDK = new AuthenticationSDK($merchantConfig);
        $this->logger = LogFactory::getLogger(get_class($this));
        $this->initializeCurlClient();
    }

    private function initializeCurlClient()
    {
        $this->curlClient = curl_init();
        
        // Set default cURL options
        curl_setopt($this->curlClient, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->curlClient, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($this->curlClient, CURLOPT_ENCODING, "");
        curl_setopt($this->curlClient, CURLOPT_MAXREDIRS, 10);
        curl_setopt($this->curlClient, CURLOPT_TIMEOUT, self::$READ_TIMEOUT);
        curl_setopt($this->curlClient, CURLOPT_CONNECTTIMEOUT, self::$CONNECT_TIMEOUT);
        
        // SSL verification
        if ($this->merchantConfig['runEnvironment'] === 'production') {
            curl_setopt($this->curlClient, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($this->curlClient, CURLOPT_SSL_VERIFYHOST, 2);
        } else {
            // For sandbox environment
            curl_setopt($this->curlClient, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($this->curlClient, CURLOPT_SSL_VERIFYHOST, 0);
        }
    }

    public function callApi($resourcePath, $method, $queryParams, $body, $headerParams, 
                          $responseType, $formParams = null, $fileParams = null, $merchantConfig = null)
    {
        try {
            // Build the URL
            $url = $this->buildUrl($resourcePath, $queryParams);
            
            // Get authentication headers
            $signatureHeaders = $this->getAuthenticationHeaders($url, $method, $body);
            $headerParams = array_merge($headerParams, $signatureHeaders);
            
            // Set up cURL request
            curl_setopt($this->curlClient, CURLOPT_URL, $url);
            curl_setopt($this->curlClient, CURLOPT_CUSTOMREQUEST, $method);
            
            // Set headers
            $curlHeaders = [];
            foreach ($headerParams as $key => $value) {
                $curlHeaders[] = "$key: $value";
            }
            curl_setopt($this->curlClient, CURLOPT_HTTPHEADER, $curlHeaders);
            
            // Set request body
            if ($method !== 'GET' && !empty($body)) {
                curl_setopt($this->curlClient, CURLOPT_POSTFIELDS, $body);
            }
            
            // Execute request
            $response = curl_exec($this->curlClient);
            $httpCode = curl_getinfo($this->curlClient, CURLINFO_HTTP_CODE);
            
            // Handle response
            if ($response === false) {
                throw new ApiException(
                    "cURL error: " . curl_error($this->curlClient),
                    curl_errno($this->curlClient)
                );
            }
            
            // Log response
            $this->logger->debug("Response Code: " . $httpCode);
            $this->logger->debug("Response Body: " . $response);
            
            // Process response
            if ($httpCode >= 200 && $httpCode < 300) {
                return $this->processResponse($response, $responseType);
            } else {
                $this->handleErrorResponse($httpCode, $response);
            }
            
        } catch (Exception $e) {
            $this->logger->error("API Call Error: " . $e->getMessage());
            throw $e;
        }
    }

    private function buildUrl($resourcePath, $queryParams)
    {
        $baseUrl = $this->getBaseUrl();
        $url = $baseUrl . $resourcePath;
        
        if (!empty($queryParams)) {
            $url .= '?' . http_build_query($queryParams);
        }
        
        return $url;
    }

    private function getBaseUrl()
    {
        if ($this->merchantConfig['runEnvironment'] === 'production') {
            return 'https://api.cybersource.com';
        } else {
            return 'https://apitest.cybersource.com';
        }
    }

    private function getAuthenticationHeaders($url, $method, $body)
    {
        if ($this->merchantConfig['authenticationType'] === 'HTTP_SIGNATURE') {
            return $this->getSignatureHeaders($url, $method, $body);
        } else {
            // JWT authentication or other types
            return $this->getJWTHeaders();
        }
    }

    private function getSignatureHeaders($url, $method, $body)
    {
        $signatureInfo = new GlobalSignatureInformation($this->merchantConfig);
        
        // Generate digest for POST/PUT requests with body
        if (($method === 'POST' || $method === 'PUT') && !empty($body)) {
            $payloadDigest = new PayloadDigest();
            $digest = $payloadDigest->generateDigest($body);
            $signatureInfo->setDigest($digest);
        }
        
        // Generate signature
        $signatureInfo->setRequestUrl($url);
        $signatureInfo->setRequestMethod($method);
        $signatureInfo->setRequestType('RAW');
        
        return $this->authenticationSDK->generateSignature($signatureInfo);
    }

    private function getJWTHeaders()
    {
        // JWT authentication implementation
        return ['Authorization' => 'Bearer ' . $this->generateJWTToken()];
    }

    private function processResponse($response, $responseType)
    {
        if ($responseType) {
            $data = json_decode($response, true);
            $obj = ObjectSerializer::deserialize($data, $responseType);
            return [$obj, $response];
        }
        return [json_decode($response, true), $response];
    }

    private function handleErrorResponse($httpCode, $response)
    {
        $data = json_decode($response, true);
        $message = isset($data['message']) ? $data['message'] : 'Unknown error occurred';
        
        throw new ApiException(
            "HTTP Response Code: $httpCode\nError Message: $message",
            $httpCode,
            null,
            $data
        );
    }

    public function __destruct()
    {
        if ($this->curlClient) {
            curl_close($this->curlClient);
        }
    }
}

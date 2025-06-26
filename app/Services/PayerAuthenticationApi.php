<?php
namespace App\Services;

use CyberSource\ApiClient;
use CyberSource\ApiException;
use CyberSource\ObjectSerializer;
use CyberSource\Model\RiskV1AuthenticationSetupsPost201Response;
use CyberSource\Model\RiskV1AuthenticationResultsPost201Response;
use CyberSource\Model\RiskV1AuthenticationsPost201Response;

class PayerAuthenticationApi
{
    private $apiClient;
    private $merchantConfig;

    /**
     * Constructor with merchantConfig parameter for authentication
     */
    public function __construct($merchantConfig)
    {
        $this->merchantConfig = $merchantConfig;
        $this->apiClient = new ApiClient($merchantConfig);
    }

    /**
     * Setup Payer Authentication (3DS)
     */
    public function payerAuthSetup($setupRequest)
    {
        $resourcePath = "/risk/v1/authentication-setups";
        $method = "POST";
        
        // Create request path
        $resourcePath = str_replace("{format}", "json", $resourcePath);

        // Create query parameters
        $queryParams = [];
        
        // Create header parameters
        $headerParams = [];
        $headerParams['Content-Type'] = "application/json;charset=utf-8";

        // Create form parameters
        $formParams = [];
        $fileParams = [];

        // Authentication setting
        $merchantConfig = $this->merchantConfig;
        
        // Body parameters
        $body = json_encode($setupRequest);

        // Make the API Call
        try {
            $response = $this->apiClient->callApi(
                $resourcePath,
                $method,
                $queryParams,
                $body,
                $headerParams,
                '\CyberSource\Model\RiskV1AuthenticationSetupsPost201Response',
                $formParams,
                $fileParams,
                $merchantConfig
            );
            return $response[0];
        } catch (ApiException $e) {
            throw $e;
        }
    }

    /**
     * Check Payer Auth Enrollment
     */
    public function checkPayerAuth($checkRequest)
    {
        $resourcePath = "/risk/v1/authentications";
        $method = "POST";
        
        // Create request path
        $resourcePath = str_replace("{format}", "json", $resourcePath);

        // Create query parameters
        $queryParams = [];
        
        // Create header parameters
        $headerParams = [];
        $headerParams['Content-Type'] = "application/json;charset=utf-8";

        // Create form parameters
        $formParams = [];
        $fileParams = [];

        // Authentication setting
        $merchantConfig = $this->merchantConfig;
        
        // Body parameters
        $body = json_encode($checkRequest);

        // Make the API Call
        try {
            $response = $this->apiClient->callApi(
                $resourcePath,
                $method,
                $queryParams,
                $body,
                $headerParams,
                '\CyberSource\Model\RiskV1AuthenticationsPost201Response',
                $formParams,
                $fileParams,
                $merchantConfig
            );
            return $response[0];
        } catch (ApiException $e) {
            throw $e;
        }
    }

    /**
     * Validate Authentication Results
     */
    public function validateAuthenticationResults($validateRequest)
    {
        $resourcePath = "/risk/v1/authentication-results";
        $method = "POST";
        
        // Create request path
        $resourcePath = str_replace("{format}", "json", $resourcePath);

        // Create query parameters
        $queryParams = [];
        
        // Create header parameters
        $headerParams = [];
        $headerParams['Content-Type'] = "application/json;charset=utf-8";

        // Create form parameters
        $formParams = [];
        $fileParams = [];

        // Authentication setting
        $merchantConfig = $this->merchantConfig;
        
        // Body parameters
        $body = json_encode($validateRequest);

        // Make the API Call
        try {
            $response = $this->apiClient->callApi(
                $resourcePath,
                $method,
                $queryParams,
                $body,
                $headerParams,
                '\CyberSource\Model\RiskV1AuthenticationResultsPost201Response',
                $formParams,
                $fileParams,
                $merchantConfig
            );
            return $response[0];
        } catch (ApiException $e) {
            throw $e;
        }
    }

    /**
     * Get Authentication Results
     */
    public function getAuthenticationResults($getResultsRequest)
    {
        $resourcePath = "/risk/v1/authentication-results/{id}";
        $method = "GET";
        
        // Create request path with ID
        $resourcePath = str_replace(
            "{id}",
            $getResultsRequest->consumerAuthenticationInformation->authenticationTransactionId,
            $resourcePath
        );
        $resourcePath = str_replace("{format}", "json", $resourcePath);

        // Create query parameters
        $queryParams = [];
        
        // Create header parameters
        $headerParams = [];
        $headerParams['Content-Type'] = "application/json;charset=utf-8";

        // Create form parameters
        $formParams = [];
        $fileParams = [];

        // Authentication setting
        $merchantConfig = $this->merchantConfig;

        // Make the API Call
        try {
            $response = $this->apiClient->callApi(
                $resourcePath,
                $method,
                $queryParams,
                null,
                $headerParams,
                '\CyberSource\Model\RiskV1AuthenticationResultsPost201Response',
                $formParams,
                $fileParams,
                $merchantConfig
            );
            return $response[0];
        } catch (ApiException $e) {
            throw $e;
        }
    }
}

    
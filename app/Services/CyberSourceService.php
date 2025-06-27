<?php

namespace App\Services;

use DateTime;
use Exception;
use DateTimeZone;
use Illuminate\Support\Str;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;

class CyberSourceService
{
    protected string $merchantId;
    protected string $apiKey;
    protected string $sharedSecret;
    protected string $environment;
    protected string $baseUrl;
    protected string $host;

    public function __construct()
    {
        $this->merchantId = config('services.cybersource.merchant_id');
        $this->apiKey = config('services.cybersource.api_key');
        $this->sharedSecret = config('services.cybersource.shared_secret');
        $this->environment = config('services.cybersource.environment', 'test');
        $this->baseUrl = $this->environment === 'test'
            ? 'https://apitest.cybersource.com'
            : 'https://api.cybersource.com';
        // $this->baseUrl = 'https://apitest.cybersource.com';
        $this->host = parse_url($this->baseUrl, PHP_URL_HOST);
    }

    /**
     * Setup Payer Authentication
     *
     * @param array $paymentInfo Payment information including card details
     * @return array Response from CyberSource API
     * @throws \Exception
     */
    public function setupPayerAuthentication(array $paymentInfo)
    {
        try {
            // Generate the required headers for CyberSource API
            $digest = $this->generateDigest($paymentInfo);

            // Get the RFC1123 formatted date
            $date = $this->getDate();

            $path = '/risk/v1/authentication-setups';

            // Generate the signature
            $signature = $this->generateSignature('post', $path, $digest, $date);

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
                ->post($path, $paymentInfo);

            $responseBody = json_decode($response->getBody()->getContents(), true);
            return $responseBody;
        } catch (GuzzleException $e) {
            Log::error('CyberSource API Error: ' . $e->getMessage());
            throw new \Exception('Failed to setup payer authentication: ' . $e->getMessage());
        }
    }

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
                // dd($response->json());
            return $this->handleResponse($response);
        } catch (Exception $e) {
            return [
                'error' => $e->getMessage(),
                'status' => 'error'
            ];
        }
    }

    public function checkPayerAuthEnrollment(array $paymentInfo)
    {
        try {
            // Generate the required headers for CyberSource API
            $digest = $this->generateDigest($paymentInfo);

            // Get the RFC1123 formatted date
            $date = $this->getDate();

            // $path = '/risk/v1/authentication-setups';
            $path = '/risk/v1/authentications';

            // Generate the signature
            $signature = $this->generateSignature('post', $path, $digest, $date);

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
                ->post($path, $paymentInfo);

             $response = json_decode($response->getBody()->getContents(), true);
            if (is_array($response)) {
                $response = json_decode(json_encode($response));
            }
            return $response;
        } catch (GuzzleException $e) {
            Log::error('CyberSource API Error: ' . $e->getMessage());
            throw new \Exception('Failed to setup payer authentication: ' . $e->getMessage());
        }
    }

    public function validateAuthEnrollment(array $paymentInfo)
    {
        try {
            // Generate the required headers for CyberSource API
            $digest = $this->generateDigest($paymentInfo);

            // Get the RFC1123 formatted date
            $date = $this->getDate();

            // $path = '/risk/v1/authentication-setups';
            $path = '/risk/v1/authentication-results';

            // Generate the signature
            $signature = $this->generateSignature('post', $path, $digest, $date);

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
                ->post($path, $paymentInfo);

            $responseBody = json_decode($response->getBody()->getContents(), true);
            return $responseBody;
        } catch (GuzzleException $e) {
            Log::error('CyberSource API Error: ' . $e->getMessage());
            throw new \Exception('Failed to setup payer authentication: ' . $e->getMessage());
        }
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
    protected function getDate(): string
    {
        $date = new DateTime('now', new DateTimeZone('GMT'));
        return $date->format('D, d M Y H:i:s T');
    }

    /**
     * Generate HTTP signature
     *
     * @param string $httpMethod
     * @param string $path
     * @param string $digest
     * @param string $date
     * @return string
     */
    protected function generateSignature(string $httpMethod, string $path, string|null $digest, string $date): string
    {
        // Create the validation string as per CyberSource specifications
        $signatureString = implode("\n", [
            "host: {$this->host}",
            "date: {$date}",
            "(request-target): {$httpMethod} {$path}",
            "digest: {$digest}",
            "v-c-merchant-id: {$this->merchantId}"
        ]);

        // Generate HMAC SHA256 hash
        $decodedSecret = base64_decode($this->sharedSecret);
        $hash = hash_hmac('sha256', $signatureString, $decodedSecret, true);
        $signatureHash = base64_encode($hash);

        // Format the signature header according to CyberSource specifications
        return sprintf(
            'keyid="%s", algorithm="HmacSHA256", headers="host date (request-target) digest v-c-merchant-id", signature="%s"',
            $this->apiKey,
            $signatureHash
        );
    }

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
     * Detect card type based on BIN ranges
     */

    public function detectCardType(string $number): string
    {
        $patterns = [
            'amex' => '/^3[47][0-9]{13}$/',
            '001' => '/^4[0-9]{12}(?:[0-9]{3})?$/',
            '002' => '/^5[1-5][0-9]{14}$/',
            '004' => '/^6(?:011|5[0-9]{2})[0-9]{12}$/'
        ];

        foreach ($patterns as $type => $pattern) {
            if (preg_match($pattern, $number)) {
                return $type;
            }
        }

        return 'unknown';
    }

    public function validateOTPAndPay(array $cardData,float $amount,string $currency,string $otpCode,string $authenticationTransactionId,array $orderDetails = []): array {
        try {
            $paymentRequest = [
                'clientReferenceInformation' => [
                    'code' => Str::uuid()->toString()
                ],
                'processingInformation' => [
                    'commerceIndicator' => 'internet',
                    'actionList' => ['VALIDATE_CONSUMER_AUTHENTICATION']
                ],
                'paymentInformation' => [
                    'card' => [
                        'number' => $cardData['number'],
                        'expirationMonth' => $cardData['expiry_month'],
                        'expirationYear' => $cardData['expiry_year'],
                        'securityCode' => $cardData['cvv'],
                        'type' => $this->detectCardType($cardData['number'])
                    ]
                ],
                'orderInformation' => [
                    'amountDetails' => [
                        'totalAmount' => number_format($amount, 2, '.', ''),
                        'currency' => $currency
                    ],
                    'billTo' => [
                        'firstName' => $orderDetails['billing']['first_name'] ?? '',
                        'lastName' => $orderDetails['billing']['last_name'] ?? '',
                        'address1' => $orderDetails['billing']['address_line1'] ?? '',
                        'locality' => $orderDetails['billing']['city'] ?? '',
                        'administrativeArea' => $orderDetails['billing']['state'] ?? '',
                        'postalCode' => $orderDetails['billing']['postal_code'] ?? '',
                        'country' => $orderDetails['billing']['country'] ?? '',
                        'email' => $orderDetails['billing']['email'] ?? '',
                        'phoneNumber' => $orderDetails['billing']['phone'] ?? ''
                    ]
                ],
                'consumerAuthenticationInformation' => [
                    'authenticationTransactionId' => $authenticationTransactionId,
                    'oneTimePassword' => $otpCode
                ]
            ];

            return $this->createPayment($paymentRequest);
        } catch (Exception $e) {
            return [
                'status' => 'error',
                'error' => $e->getMessage()
            ];
        }
    }

    public function verifyPayment(string $transactionId): array
    {
        try {
            $path = "/pts/v2/transactions/{$transactionId}";
                // Generate the digest for the payload
                $digest = null; // $this->generateDigest($paymentData);

                // Get the RFC1123 formatted date
                $date = $this->getDate();

                // Generate the signature
                $signature = $this->generateSignature('get', $path, $digest, $date);

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
                    ->get($path);
                dd($response->json());
            if ($result['status'] === 'success') {
                return $this->processVerificationResponse($result['data']);
            }

            return $result;
        } catch (Exception $e) {
            return [
                'status' => 'error',
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Process verification response
     */
    protected function processVerificationResponse(array $response): array
    {
        $status = $response['status'] ?? '';
        $reasonCode = $response['errorInformation']['reasonCode'] ?? '';

        return [
            'status' => 'success',
            'data' => [
                'transactionStatus' => $this->mapTransactionStatus($status),
                'amount' => $response['orderInformation']['amountDetails']['totalAmount'] ?? 0,
                'currency' => $response['orderInformation']['amountDetails']['currency'] ?? '',
                'paymentStatus' => $response['status'] ?? '',
                'reasonCode' => $reasonCode,
                'reasonMessage' => $this->getReasonMessage($reasonCode),
                'authorizationCode' => $response['processorInformation']['approvalCode'] ?? '',
                'submitTime' => $response['submitTimeUtc'] ?? '',
                'reconciliationId' => $response['reconciliationId'] ?? '',
                'paymentMethod' => [
                    'type' => $response['paymentInformation']['card']['type'] ?? '',
                    'lastFourDigits' => $response['paymentInformation']['card']['suffix'] ?? ''
                ]
            ]
        ];
    }
    /**
     * Map transaction status to readable format
     */
    protected function mapTransactionStatus(string $status): string
    {
        return match ($status) {
            'AUTHORIZED' => 'Authorized',
            'AUTHORIZED_PENDING_REVIEW' => 'Authorized Pending Review',
            'AUTHORIZED_RISK_DECLINED' => 'Declined by Risk',
            'DECLINED' => 'Declined',
            'INVALID_REQUEST' => 'Invalid Request',
            'PENDING_AUTHENTICATION' => 'Pending Authentication',
            'PENDING_REVIEW' => 'Pending Review',
            'REVERSED' => 'Reversed',
            'SUCCESS' => 'Success',
            'TRANSMITTED' => 'Transmitted',
            default => 'Unknown'
        };
    }

    /**
     * Get reason message for response code
     */
    protected function getReasonMessage(string $code): string
    {
        return match ($code) {
            '100' => 'Successful transaction',
            '101' => 'Declined - The request is missing one or more fields',
            '102' => 'Declined - One or more fields contains invalid data',
            '150' => 'Error - General system failure',
            '151' => 'Error - The request was received but a server timeout occurred',
            '152' => 'Error - The request was received, but a service timeout occurred',
            '200' => 'Declined - The authorization request was approved by the issuing bank but declined by CyberSource because it did not pass the Address Verification System (AVS)',
            '201' => 'Declined - The issuing bank has questions about the request',
            '202' => 'Declined - Expired card',
            '203' => 'Declined - General decline of the card',
            '204' => 'Declined - Insufficient funds in the account',
            '205' => 'Declined - Stolen or lost card',
            '207' => 'Declined - Issuing bank unavailable',
            '208' => 'Declined - Inactive card or card not authorized for card-not-present transactions',
            '210' => 'Declined - The card has reached the credit limit',
            '211' => 'Declined - Invalid card verification number (CVN)',
            default => 'Unknown reason code'
        };
    }

    public function payCyberSource($paymentData){

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

             $temp = Http::withHeaders($headers)
                ->baseUrl($this->baseUrl)
                ->post($path, $paymentData);

            $response = json_decode($temp->getBody(), true);
            if (is_array($temp)) {
                $response = json_decode(json_encode($response));
            }

            if(isset($response->status) && $response->status != 'AUTHORIZED'){
                return response()->json(['PAYMENT_OR_VALIDATE_FAILED', '01', 400, $response,$response->message??"Something went wrong"]);
            }

            return $response;

        } catch (Exception $e) {
            return [
                'error' => $e->getMessage(),
                'status' => 'error'
            ];
        }


    }

}

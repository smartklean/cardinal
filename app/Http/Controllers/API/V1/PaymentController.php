<?php

namespace App\Http\Controllers\API\V1;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Services\CyberSourceService;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;


class PaymentController extends Controller
{
    protected $cyberSourceService;
    private $clientReference;
    private $cardNumber = 'card_number';
    private $cvv = 'cvv';
    private $currency = 'currency';
    private $expiryMonth = 'expiry_month';
    private $expiryYear = 'expiry_year';
    private $pin = 'pin';
    private $email = 'email';
    private $amount = 'amount';
    private $address = 'address';
    private $country = 'country';
    private $state = 'state';
    private $city = 'city';
    private $zipcode = 'zipcode';
    private $rememberCard = 'remember_card';
    private $redirectUrl = 'redirect_url';
    private $firstName = 'first_name';
    private $lastName = 'last_name';
    private $phoneNumber = 'phone_number';
    private $browserInfo = 'browser_info';
    private $returnUrl = 'return_url';
    private $payload = 'payload';
    private $isRequiredArray = 'required';
    private $isNullableString = 'nullable|string';
    private $isNullableBoolean = 'nullable|boolean';
    private $isNullableArray = 'nullable|array';
    private $isRequiredInteger = 'required|integer';
    private $isRequiredBin = 'required|string|max:6';
    private $isRequiredString = 'required|string|max:255';
    private $isRequiredExpiryYear = 'required|string|max:4';
    private $isRequiredBiCharString = 'required|string|max:2';
    private $isRequiredEmail = 'required|email';
    private $isRequiredCvv = 'required|string|max:4';
    private $isNullablePin = 'nullable|string|max:4';
    private $isRequiredExpiryMonth = 'required|string|max:2';
    private $isRequiredCardNumber = 'required|string|max:19';

    public function __construct(CyberSourceService $cyberSourceService)
    {
        $this->clientReference = 'ESL' . random_int(1000000000, 9999999999);
        $this->cyberSourceService = $cyberSourceService;
    }

   /**
     * Setup payer authentication
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */


    //first call
    public function cyberSourceAuthentication(Request $request){
        $rules = [
            $this->cardNumber => $this->isRequiredCardNumber,
            $this->expiryMonth => $this->isRequiredExpiryMonth,
            $this->expiryYear => $this->isRequiredExpiryYear,
        ];

        $validator =  Validator::make($request->all(), $rules);
        if($validator->fails()){
            return $this->jsonValidationError($validator);
        }
            
        $cardType = $this->cyberSourceService->detectCardType($request->card_number);
        $cardDetails= [
            "clientReferenceInformation" => [
                "code" => $this->clientReference
            ],
                
            'paymentInformation' => [
                'card' => [
                    'number' => $request->card_number,
                    'expirationMonth' => $request->expiry_month,
                    'expirationYear' => $request->expiry_year,
                    'type' => $cardType
                ]
            ]
        ];

        $res = $this->cyberSourceService->setupPayerAuthentication($cardDetails);

      if(isset($res->status) && $res->status == 'error'){
        return $this->jsonResponse($res['error'], __($this), 400, [], __('response.errors.invalid_payment_info'));
      }
      return  $res;
    }

    //second call

    public function checkPayerAuth(Request $request)
    {

        $rules = [
            $this->cardNumber => $this->isRequiredCardNumber,
            $this->expiryMonth => $this->isRequiredExpiryMonth,
            $this->expiryYear => $this->isRequiredExpiryYear,
            $this->pin => $this->isNullablePin,
            $this->firstName => $this->isRequiredString,
            $this->lastName => $this->isRequiredString,
            $this->city => $this->isRequiredString,
            $this->phoneNumber=>$this->isRequiredString,
            $this->address => $this->isRequiredString,
            $this->state => $this->isRequiredString,
            $this->country => $this->isRequiredString,
            $this->zipcode => $this->isRequiredString,
            $this->browserInfo => [
                'ipAddress' => 'required',
                'httpAcceptContent' =>'required',
                'httpBrowserLanguage' => 'required',
                'httpBrowserJavaEnabled' => 'required',
                'httpBrowserJavaScriptEnabled' => 'required',
                'httpBrowserColorDepth' => 'required',
                'httpBrowserScreenHeight' => 'required',
                'httpBrowserScreenWidth' => 'required',
                'httpBrowserTimeDifference' => 'required',
                'userAgentBrowserValue' => 'required',
            ],
            "reference_id"=>  $this->isRequiredString,
             $this->returnUrl => $this->isRequiredString,
        ];

        $validator =  Validator::make($request->all(), $rules);
        if($validator->fails()){
            return $this->jsonValidationError($validator);
        }

        $cardType = $this->cyberSourceService->detectCardType($request->card_number);
        $amountDetails = [
            "currency" => $request->currency,
            "totalAmount" =>$request->amount,
        ];
        $billTo = [
            "address1" => $request->address,
            "address2" => $request->address,
            "administrativeArea" => $request->state,
            "country" =>  $request->country,
            "locality" => $request->city,
            "firstName" => $request->first_name,
            "lastName" => $request->last_name,
            "phoneNumber" => $request->phone_number,
            "email" => $request->email,
            "postalCode" => $request->zipcode
        ];
        $cardInfo = [
            "type" =>      $cardType,
            "expirationMonth" =>  $request->expiry_month,
            "expirationYear" =>  $request->expiry_year,
            "number" =>$request->card_number
        ];
        $deviceInfo = $request->browser_info;
        $payload = [
            
            "clientReferenceInformation" => [
                "code" => $this->clientReference
            ],

            "orderInformation" => [
                "amountDetails" => $amountDetails,
                "billTo" => $billTo
            ],
            "paymentInformation" => [
                "card" => $cardInfo
            ],
            "buyerInformation" => [
                "mobilePhone" => $request->phone_number
            ],
            "deviceInformation" => $deviceInfo,
            "consumerAuthenticationInformation" => [
                "deviceChannel" => "BROWSER",
                "returnUrl" => $request->return_url,
                "transactionMode" => "eCommerce",
                "referenceId" => $request->reference_id
            ]
        ];

        try {
            $cyber = $this->cyberSourceService->checkPayerAuthEnrollment($payload);
            // return $cyber;
            $stepUp = $cyber->consumerAuthenticationInformation->stepUpUrl??false;
            $cavv =isset($cyber->consumerAuthenticationInformation->cavv)??false;
            $ucaf = isset($cyber->consumerAuthenticationInformation->ucafAuthenticationData)??false;
            $merchantInformation =[
              "salesOrganizationId" => '00000265327',
              "merchantDescriptor" => [
                  "locality" => 'Lagos',
                  "country" => 'NG',
                  "address1" => '13A, Hughes Avenue, Alagomeji, Yaba, Lagos.',
                  "name" => 'Alakada',
                  "postalCode" => ""
              ],
              //categoryCode is a mandatory field  it is used to identify the type of business
              "categoryCode" => '9399',
          ];
          $aggregatorId ="";
          $aggregatorName = "";
          $consumerAuthenticationInformation=[];
          if ($cardType == '002'){
              $consumerAuthenticationInformation = [
                  "ucafCollectionIndicator" => $cyber->consumerAuthenticationInformation->ucafCollectionIndicator??"",
                  "ucafAuthenticationData"=>$cyber->consumerAuthenticationInformation->ucafAuthenticationData??"",
                  "authenticationTransactionId" => $cyber->consumerAuthenticationInformation->authenticationTransactionId??"",
                  "referenceId" => $request->reference_id,
                  "directoryServerTransactionId" => $cyber->consumerAuthenticationInformation->directoryServerTransactionId??"",
                  "authenticationBrand" => $cyber->paymentInformation->card->type??"",
              ];
              $aggregatorId = '00000265327';
              //MasterCard
              $aggregatorName = 'Esettlement Limited';
          }else{
              $consumerAuthenticationInformation = [
                  "cavv" => $cyber->consumerAuthenticationInformation->cavv??"",
                  "xid" => $cyber->consumerAuthenticationInformation->xid??"",
                  "authenticationTransactionId" => $cyber->consumerAuthenticationInformation->authenticationTransactionId??"",
                  "referenceId" => $request->reference_id,
                  "directoryServerTransactionId" => $cyber->consumerAuthenticationInformation->directoryServerTransactionId??"",
                  "authenticationBrand" => $cyber->paymentInformation->card->type??"",
              ];
              $aggregatorId = '00010082463';
              //Visa Card
              $aggregatorName = 'Esettlement Limited';
          }
          $aggregatorInformation = [
              "name" => $aggregatorName,
              "subMerchant" => [
                  "name" => "Esettlement*".'Alakada',
                  "id" => "PFY000123",
                  "locality" => 'Lagos',
                  "address1" => '13A, Hughes Avenue, Alagomeji, Yaba, Lagos',
                  "country" => 'NG',
              ],
              "aggregatorId" => $aggregatorId
              
          ];
          $stepUp = $cyber->consumerAuthenticationInformation->stepUpUrl??false;
          $cavv =isset($cyber->consumerAuthenticationInformation->cavv)??false;
          $ucaf = isset($cyber->consumerAuthenticationInformation->ucafAuthenticationData)??false;
          if($stepUp || $cavv || $ucaf){
              $payload2 = [
                  "clientReferenceInformation" => $cyber->clientReferenceInformation,
                  "paymentInformation" => [
                      "card" => $cardInfo
                  ],
                  "orderInformation" => [
                      "amountDetails" => $amountDetails,
                      "billTo" => $billTo
                  ],
                  "consumerAuthenticationInformation" =>  $consumerAuthenticationInformation,
                  "merchantInformation" => $merchantInformation,
                  "aggregatorInformation" => $aggregatorInformation
              ];
              if(!$stepUp){
                  $payload2 += ["processingInformation" =>[
                      "capture"=>true,
                      "commerceIndicator"=>$ucaf?"spa":"vbv"
                  ]
                  ];
                  $response = $this->cyberSourceService->payCyberSource($payload2);
                   return response()->json([
                'success' => true,
                'message' => "Payment successful",
                'data' => $response
            ]);
              }
              $payload2 += [
                  "processingInformation" =>[
                      "actionList" => ["VALIDATE_CONSUMER_AUTHENTICATION"],
                      "capture"=>true,
                  ]
              ];
              $message = 'HIGH_RISK_STEP_UP';
              $response = [
                  "authenticationTransactionId" =>$cyber->consumerAuthenticationInformation->authenticationTransactionId,
                  "stepUpUrl" => $stepUp,
                  "accessToken" => $cyber->consumerAuthenticationInformation->accessToken,
                  "payload" => $payload2
              ];
          }else{
              $message = 'FAILED_FIRST_CARDINAL';
              $response = [
                  "card" =>$cardInfo,
                  "raw" =>$cyber];
          }
             return response()->json([
                'success' => true,
                'message' =>  $message,
                'data' => $response
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage()
            ], 500);
        }

    }

    //last call
    public function validateCyberAuth(Request $request){

          $rules = [
              $this->payload => $this->isRequiredArray,
          ];
          $validator =  Validator::make($request->all(), $rules);

          if($validator->fails()){
              return $this->jsonValidationError($validator);
          }
        //   dd($request);
      $response = $this->cyberSourceService->payCyberSource($request->payload);
      return response()->json(['status'=>true,
                "message"=>"Payment Successful",
                "data" => $response]);
    }



    // others for testing
    public function validateAuth(Request $request)
    {
        // Validate the request
        // $validator = Validator::make($request->all(), [
        //     'paymentInformation.card.type' => 'required|string',
        //     'paymentInformation.card.expirationMonth' => 'required|string|size:2',
        //     'paymentInformation.card.expirationYear' => 'required|string|size:4',
        //     'paymentInformation.card.number' => 'required|string',
        // ]);

        // if ($validator->fails()) {
        //     return response()->json([
        //         'success' => false,
        //         'message' => 'Validation failed',
        //         'errors' => $validator->errors()
        //     ], 422);
        // }

        // $paymentInformation = [

        //     'paymentInformation' => [
        //         'card' => [
        //             'type' => $request->input('card_type'),
        //             'expirationMonth' => $request->input('expirationMonth'),
        //             'expirationYear' => $request->input('expirationYear'),
        //             'number' => $request->input('card_number'),
        //         ],
        //     ],

        // ];



        $paymentInformation = [
            "paymentInformation" => [
                "card" => [
                    'type' => $request->input('card_type'),
                    'expirationMonth' => $request->input('expirationMonth'),
                    'expirationYear' => $request->input('expirationYear'),
                    'number' => $request->input('card_number'),
            ],
            "consumerAuthenticationInformation" => [
                "authenticationTransactionId" => "7411747154396754004806"
            ]

            ]
        ];



        try {
            // Extract payment information from request
            // $paymentInfo = $request->input('paymentInformation');

            // dd($paymentInformation);

            // Call CyberSource service to setup payer authentication
            $result = $this->cyberSourceService->validateAuthEnrollment($paymentInformation);

            return response()->json([
                'success' => true,
                'data' => $result
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage()
            ], 500);
        }
    }


    public function processPayment(Request $request)
    {
          $cardType = $this->cyberSourceService->detectCardType($request->card_number);

        $paymentData = [
            'clientReferenceInformation' => [
                'code' => 'test_payment',
            ],
            'processingInformation' => [
                'commerceIndicator' => 'internet',
                'actionList' => 'validate,payment',
            ],
            'paymentInformation' => [
                'card' => [
                    'number' => $request->input('card_number'),
                    'expirationMonth' => $request->input('expiration_month'),
                    'expirationYear' => $request->input('expiration_year'),
                    'securityCode' => $request->input('cvv'),
                ],
            ],
            'orderInformation' => [
                'amountDetails' => [
                    'totalAmount' => $request->input('amount'),
                    'currency' => $request->input('currency'),
                ],
                'billTo' => [
                    'firstName' => $request->input('first_name'),
                    'lastName' => $request->input('last_name'),
                    'email' => $request->input('email'),
                    // 'address' => $request->input('address'),
                    // 'city' => $request->input('city'),
                    'locality' => $request->input('locality'),
                    'address1' => $request->input('address1'),
                    'country' => $request->input('country'),
                    // 'postalCode' => $request->input('postal_code'),
                ],
            ],
        ];
        // dd($paymentData);
        $response = $this->cyberSourceService->createPayment($paymentData);

        return response()->json($response);
    }

    public function initializePayment(Request $request)
    {
        $validator = $this->validate($request, [
            'card.number' => 'required|string',
            'card.expiry_month' => 'required|string|size:2',
            'card.expiry_year' => 'required|string|size:4',
            'card.cvv' => 'required|string|min:3|max:4',
            'amount' => 'required|numeric|min:0.01',
            'currency' => 'required|string|size:3',
            'billing.first_name' => 'required|string',
            'billing.last_name' => 'required|string',
            'billing.email' => 'required|email',
            'billing.address_line1' => 'required|string',
            'billing.city' => 'required|string',
            'billing.state' => 'required|string',
            'billing.postal_code' => 'required|string',
            'billing.country' => 'required|string|size:2',
            'billing.phone' => 'required|string',
        ]);

        // Store payment details in cache for the second step
        $paymentData = $request->all();
        $cacheKey = 'payment_' . uniqid();
        Cache::put($cacheKey, $paymentData, now()->addMinutes(15));

        // Initialize payment and request OTP
        $result = $this->cyberSourceService->setupPaymentWithOTP(
            $request->input('card'),
            $request->input('amount'),
            $request->input('currency'),
            [
                'billing' => $request->input('billing')
            ]
        );

        if ($result['status'] === 'success') {
            return response()->json([
                'status' => 'success',
                'paymentKey' => $cacheKey,
                'authenticationTransactionId' => $result['data']['consumerAuthenticationInformation']['authenticationTransactionId'] ?? null,
                'message' => 'OTP has been sent to your registered mobile number/email'
            ]);
        }

        return response()->json($result, 400);
    }

    public function testCard(Request $request){

        $mia = '[{"payment":"mama"}]';
        $mia = json_decode($mia, true);
        return $mia[0]['payment'];
        // return $this->cyberSourceService->detectCardType($request->card_number);
        $mama = $request->deviceInformation;
        return json_decode($mama);
    }


    /**
     * Verify payment by transaction ID
     */
    public function verifyPayment($transactionId)
    {

        $result = $this->cyberSourceService->verifyPayment($transactionId );

        return response()->json($result);
    }

}
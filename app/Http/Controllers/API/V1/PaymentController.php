<?php

namespace App\Http\Controllers\API\V1;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Services\CyberSourceService;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Cache;


class PaymentController extends Controller
{
    protected $cyberSourceService;

    private $cardNumber = 'card_number';
    private $cvv = 'cvv';
    private $currency = 'currency';
    private $expiryMonth = 'expiry_month';
    private $expiryYear = 'expiry_year';
    private $isRequiredExpiryYear = 'required|string|max:4';
    private $isRequiredExpiryMonth = 'required|string|max:2';
    private $isRequiredCardNumber = 'required|string|max:19';

    public function __construct(CyberSourceService $cyberSourceService)
    {
        $this->cyberSourceService = $cyberSourceService;
    }

   /**
     * Setup payer authentication
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function setupAuthentication(Request $request)
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

        $paymentInformation = [
           
            'paymentInformation' => [
                'card' => [
                    'type' => $request->input('card_type'),
                    'expirationMonth' => $request->input('expirationMonth'),
                    'expirationYear' => $request->input('expirationYear'),
                    'number' => $request->input('card_number'),
                ],
            ],
           
        ];

        try {
            // Extract payment information from request
            // $paymentInfo = $request->input('paymentInformation');

            // dd($paymentInformation);
            
            // Call CyberSource service to setup payer authentication
            $result = $this->cyberSourceService->setupPayerAuthentication($paymentInformation);
            
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

    public function checkPayerAuth(Request $request)
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
            "orderInformation" => [
                "amountDetails" => [
                    "currency" => $request->input('currency'),
                    "totalAmount" => $request->input('amount')
                ],
                "billTo" => [
                    "address1" => "1 Market St",
                    "address2" => "Address 2",
                    "administrativeArea" => "CA",
                    "country" => $request->input('country'),
                    "locality" => "san francisco",
                    "firstName" => "John",
                    "lastName" => "Doe",
                    "phoneNumber" => "4158880000",
                    "email" => "test@cybs.com",
                    "postalCode" => "94105"
                ]
            ],
            "paymentInformation" => [
                'card' => [
                    'type' => $request->input('card_type'),
                    'expirationMonth' => $request->input('expirationMonth'),
                    'expirationYear' => $request->input('expirationYear'),
                    'number' => $request->input('card_number'),
                ],
            ],
            "buyerInformation" => [
                "mobilePhone" => "1245789632"
            ],
            "deviceInformation" => [
                "ipAddress" => "139.130.4.5",
                "httpAcceptContent" => "test",
                "httpBrowserLanguage" => "en_us",
                "httpBrowserJavaEnabled" => "N",
                "httpBrowserJavaScriptEnabled" => "Y",
                "httpBrowserColorDepth" => "24",
                "httpBrowserScreenHeight" => "100000",
                "httpBrowserScreenWidth" => "100000",
                "httpBrowserTimeDifference" => "300",
                "userAgentBrowserValue" => "GxKnLy8TFDUFxJP1t"
            ],
            "consumerAuthenticationInformation" => [
                "deviceChannel" => "BROWSER",
                "returnUrl" => $request->input('returnUrl'),
                "referenceId" => $request->input('referenceId'),
                "transactionMode" => "eCommerce"
            ]
        ];
        
        

        try {
            // Extract payment information from request
            // $paymentInfo = $request->input('paymentInformation');

            // dd($paymentInformation);
            
            // Call CyberSource service to setup payer authentication
            $result = $this->cyberSourceService->checkPayerAuthEnrollment($paymentInformation);

            $stepUp = $result->consumerAuthenticationInformation->stepUpUrl??false;
            $cavv =isset($result->consumerAuthenticationInformation->cavv)??false;
            $ucaf = isset($result->consumerAuthenticationInformation->ucafAuthenticationData)??false;
            dd($stepUp, $cavv, $ucaf);
            
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


    ///trial for esettlements

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


    public function cyberCheckPayerAuth(Request $request){
    //   $rules = [
    //       $this->cardNumber => $this->isRequiredCardNumber,
    //       $this->expiryMonth => $this->isRequiredBiCharString,
    //       $this->expiryYear => $this->isRequiredExpiryYear,
    //       $this->accessCode => $this->isRequiredString,
    //       $this->rememberCard => $this->isNullableBoolean,
    //       $this->pin => $this->isNullablePin,
    //       $this->firstName => $this->isRequiredString,
    //       $this->lastName => $this->isRequiredString,
    //       $this->city => $this->isRequiredString,
    //       $this->phoneNumber=>$this->isRequiredString,
    //       $this->address => $this->isRequiredString,
    //       $this->state => $this->isRequiredString,
    //       $this->country => $this->isRequiredString,
    //       $this->zipcode => $this->isRequiredString,
    //       $this->browserInfo => [
    //           'ipAddress' => 'required',
    //           'httpAcceptContent' =>'required',
    //           'httpBrowserLanguage' => 'required',
    //           'httpBrowserJavaEnabled' => 'required',
    //           'httpBrowserJavaScriptEnabled' => 'required',
    //           'httpBrowserColorDepth' => 'required',
    //           'httpBrowserScreenHeight' => 'required',
    //           'httpBrowserScreenWidth' => 'required',
    //           'httpBrowserTimeDifference' => 'required',
    //           'userAgentBrowserValue' => 'required',
    //       ],
    //       "reference_id"=>  $this->isRequiredString,
    //        $this->returnUrl => $this->isRequiredString,
    //   ];
    //   $validator =  Validator::make($request->all(), $rules);
  
    //   if($validator->fails()){
    //       return $this->jsonValidationError($validator);
    //   }

    \Log::info('im hereeeee');
      $payment = 'payment';
      if($payment != null) {
          $cardType = $this->cyberSourceService->detectCardType($request->card_number);
          $paymentReturnUrl = $request->return_url;
          $userPhone = $request->phone_number;
          $amount = $request->amount;
          //taking care of the charges
  
          $amountDetails = [
              "currency" => $request->currency,
              "totalAmount" => $amount,
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
              "type" =>   $cardType,
              "expirationMonth" =>  $request->expirationMonth,
              "expirationYear" =>  $request->expirationYear,
              "number" =>$request->card_number
          ];
          $deviceInfo = $request->browser_info;
          $payload = [
              "orderInformation" => [
                  "amountDetails" => $amountDetails,
                  "billTo" => $billTo
              ],
              "paymentInformation" => [
                  "card" => $cardInfo
              ],
              "buyerInformation" => [
                  "mobilePhone" => $userPhone
              ],
              "deviceInformation" => $deviceInfo,
              "consumerAuthenticationInformation" => [
                  "deviceChannel" => "BROWSER",
                  "returnUrl" => $request->returnUrl,
                  "transactionMode" => "eCommerce",
                  "referenceId" => $request->referenceId
              ]
          ];

          
          $cyber = $this->cyberSourceService->checkPayerAuthEnrollment($payload);
            //   $cyber = $this->cyberSourceCaller($payload,'/risk/v1/authentications');
          $merchantInformation =[
              "salesOrganizationId" => '00000265327',
              "merchantDescriptor" => [
                  "locality" => 'Lagos',
                  "country" => 'NG',
                  "address1" => '8, Ibadan Street, Ilupeju',
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
              $aggregatorName = 'Innovate1Pay Ltd.';
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
              //Visa
              $aggregatorName = 'Esettlement Limited';
          }
          $aggregatorInformation = [
              "name" => $aggregatorName,
              "subMerchant" => [
                  "name" => "Esettlement*".'Alakada',
                  "id" => "PFY000123",
                  "locality" => 'Lagos',
                  "address1" => '8, Ibadan Street, Ilupeju',
                  "country" => 'NG',
              ],
              "aggregatorId" => $aggregatorId
          ];
          $stepUp = $cyber->consumerAuthenticationInformation->stepUpUrl??false;
          $cavv =isset($cyber->consumerAuthenticationInformation->cavv)??false;
          $ucaf = isset($cyber->consumerAuthenticationInformation->ucafAuthenticationData)??false;
          dd($stepUp, $cavv, $ucaf);
          if($stepUp || $cavv || $ucaf){
            \Log::info('set up and raw');
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
                  \Log::info('chheheheheheh');
                  $response = $this->cyberSourceService->payCyberSource($payload2);
                  return $response;
              }
              $payload2 += [
                  "processingInformation" =>[
                      "actionList" => ["VALIDATE_CONSUMER_AUTHENTICATION"],
                      "capture"=>true,
                  ]
              ];
              $message = 'HIGH_RISK_STEP_UP';
              \Log::info('brotherhood');
              $response = [
                  "authenticationTransactionId" =>$cyber->consumerAuthenticationInformation->authenticationTransactionId,
                  "stepUpUrl" => $stepUp,
                  "accessToken" => $cyber->consumerAuthenticationInformation->accessToken,
                  "payload" => $payload2
              ];
          }else{
            \Log::info('failed');
              $message = 'FAILED_FIRST_CARDINAL';
              $response = [
                  "card" =>$cardInfo,
                  "raw" =>$cyber];
          }
      }
      return $response;
  }
  
    public function validateCyberAuth(Request $request){
    //   $rules = [
    //       $this->payload => $this->isRequiredArray,
    //   ];
    //   $validator =  Validator::make($request->all(), $rules);
  
    //   if($validator->fails()){
    //       return $this->jsonValidationError($validator);
    //   }
    //   dd($request);
      $response = $this->cyberSourceService->payCyberSource($request->payload);
      return $response;
  }

  //ends trial
    

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


// $amountDetails = [
//     "currency" => $payment->currency,
//     "totalAmount" => $amount,
// ];
// $billTo = [
//     "address1" => $request->address,
//     "address2" => $request->address,
//     "administrativeArea" => $request->state,
//     "country" =>  $request->country,
//     "locality" => $request->city,
//     "firstName" => $request->first_name,
//     "lastName" => $request->last_name,
//     "phoneNumber" => $userPhone,
//     "email" => $payment->email,
//     "postalCode" => $request->zipcode
// ];
// $cardInfo = [
//     "type" =>   $cardType,
//     "expirationMonth" =>  $request->expiry_month,
//     "expirationYear" =>  $request->expiry_year,
//     "number" =>$request->card_number
// ];
// $deviceInfo = $request->browser_info;
// $payload = [
//     "orderInformation" => [
//         "amountDetails" => $amountDetails,
//         "billTo" => $billTo
//     ],
//     "paymentInformation" => [
//         "card" => $cardInfo
//     ],
//     "buyerInformation" => [
//         "mobilePhone" => $userPhone
//     ],
//     "deviceInformation" => $deviceInfo,
//     "consumerAuthenticationInformation" => [
//         "deviceChannel" => "BROWSER",
//         "returnUrl" => env('TRANSACTIONWS_CYBER_RETURN_URL'),//$paymentReturnUrl,
//         "transactionMode" => "eCommerce",
//         "referenceId" => $request->reference_id
//     ]
// ];
// $cyber = $this->cyberSourceCaller($payload,'/risk/v1/authentications');
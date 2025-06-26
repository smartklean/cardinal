<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Mailgun, Postmark, AWS and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'mailgun' => [
        'domain' => env('MAILGUN_DOMAIN'),
        'secret' => env('MAILGUN_SECRET'),
        'endpoint' => env('MAILGUN_ENDPOINT', 'api.mailgun.net'),
    ],

    'postmark' => [
        'token' => env('POSTMARK_TOKEN'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    'cybersource' => [
        'merchant_id' => env('CYBERSOURCE_MERCHANT_ID'),
        'api_key' => env('CYBERSOURCE_API_KEY'),
        'shared_secret' => env('CYBERSOURCE_SHARED_SECRET'),
        'environment' => env('CYBERSOURCE_ENVIRONMENT', 'test'),
    ],

    'interswitch' => [
        'merchant_code' => env('INTERSWITCH_MERCHANT_CODE'),
        'client_id' => env('INTERSWITCH_CLIENT_ID'),
        'secret' => env('INTERSWITCH_SECRET'),
        'payitem_id'=> env('INTERSWITCH_PAYITEM_ID'),
       
    ],

];

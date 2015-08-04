Oauth2 DynamoDB v3 adapter
==========================

[![Build Status](https://travis-ci.org/eoko/oauth2-adapter-dynamodb.svg?branch=master)](https://travis-ci.org/eoko/oauth2-adapter-dynamodb)
[![Code Climate](https://codeclimate.com/github/eoko/oauth2-adapter-dynamodb/badges/gpa.svg)](https://codeclimate.com/github/eoko/oauth2-adapter-dynamodb)
[![Test Coverage](https://codeclimate.com/github/eoko/oauth2-adapter-dynamodb/badges/coverage.svg)](https://codeclimate.com/github/eoko/oauth2-adapter-dynamodb/coverage)

Overview
--------

Uses the [DynamoDB](http://aws.amazon.com/dynamodb/) NoSQL Database Service for storing and retrieving objects in OAuth.

Requirements
------------
  
Please see the [composer.json](composer.json) file.

Installation
------------

Run the following `composer` command:

```console
$ composer require "eoko/oauth2/dynamodb"
```

Alternately, manually add the following to your `composer.json`, in the `require` section:

```javascript
"require": {
    "eoko/oauth2/dynamodb": "master-dev"
}
```

And then run `composer update` to ensure the module is installed.

Get Started
-----------

If you haven't already created an `~/.aws/credentials` file, this is the easiest way to get up and running with DynamoDB.


```php
// @see http://docs.aws.amazon.com/aws-sdk-php/guide/latest/credentials.html#credential-profiles
$config = array(
	'profile' => 'default',
	'region'  =>  Aws\Common\Enum\Region::US_EAST_1, // Your region may differ
);
```

Alternatively, you can configure your client to run directly with your credentials

```php
// These credentials are found in your AWS management console
$config = [
    'profile'   => 'default',
    'version'     => 'latest',
    'region'      => 'us-west-2',
    'credentials' => [
        'key'    => 'my-access-key-id',
        'secret' => 'my-secret-access-key',
];
```

Next, instantiate the AWS client by creating your configuration array and using the `factory` method:

```php
$dynamo = new Aws\DynamoDb\DynamoDbClient($config);
```

Finally, create the storage object using the `DynamoDB` storage class:

```php
$storage = new Eoko\OAuth2\Storage\DynamoDBv3($dynamo);
// now you can perform storage functions, such as the one below
$storage->setClientDetails($client_id, $client_secret, $redirect_uri);
```

> To see an example of the default table structure, check out the [`Bootstrap::createDynamoDB`](https://github.com/bshaffer/oauth2-server-php/blob/develop/test/lib/OAuth2/Storage/Bootstrap.php#L519) function in this library, or just create the tables yourself using DynamoDB's management UI.

Usage
-----

The DynamoDB storage engine implements all the standard Storage Interfaces supported
in this library.  See [interfaces](../custom) for more information.


Credits
-------

Mainly based on the original DynamoDB adapter from oauth2-server-php.

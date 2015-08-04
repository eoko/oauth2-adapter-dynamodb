<?php

namespace Eoko\OAuth2\Storage;

use Aws\DynamoDb\DynamoDbClient;
use Aws\DynamoDb\Marshaler;
use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\AuthorizationCodeInterface;
use OAuth2\Storage\ClientCredentialsInterface;
use OAuth2\Storage\JwtBearerInterface;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\Storage\RefreshTokenInterface;
use OAuth2\Storage\ScopeInterface;
use OAuth2\Storage\UserCredentialsInterface;

/**
 * DynamoDB storage for all storage types
 *
 * To use, install "aws/aws-sdk-php" via composer
 * <code>
 *  composer require aws/aws-sdk-php:dev-master
 * </code>
 *
 * Once this is done, instantiate the DynamoDB client
 * <code>
 *  $storage = new OAuth2\Storage\Dynamodb(array("key" => "YOURKEY", "secret" => "YOURSECRET", "region" => "YOURREGION"));
 * </code>
 *
 * Table :
 *  - oauth_access_tokens (primary hash key : access_token)
 *  - oauth_authorization_codes (primary hash key : authorization_code)
 *  - oauth_clients (primary hash key : client_id)
 *  - oauth_jwt (primary hash key : client_id, primary range key : subject)
 *  - oauth_public_keys (primary hash key : client_id)
 *  - oauth_refresh_tokens (primary hash key : refresh_token)
 *  - oauth_scopes (primary hash key : scope, secondary index : is_default-index hash key is_default)
 *  - oauth_users (primary hash key : username)
 *
 * @author Frederic AUGUSTE <frederic.auguste at gmail dot com>
 */
class DynamoDB implements
    AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    ScopeInterface,
    PublicKeyInterface,
    UserClaimsInterface,
    OpenIDAuthorizationCodeInterface
{
    protected $client;
    protected $config;

    /**
     * @param $connection
     * @param array $config
     */
    public function __construct($connection, $config = [])
    {
        if (!($connection instanceof DynamoDbClient)) {
            if (!is_array($connection)) {
                throw new \InvalidArgumentException('First argument to OAuth2\Storage\Dynamodb must be an instance a configuration array containt key, secret, region');
            }
            if (!array_key_exists("key", $connection) || !array_key_exists("secret", $connection) || !array_key_exists("region", $connection)) {
                throw new \InvalidArgumentException('First argument to OAuth2\Storage\Dynamodb must be an instance a configuration array containt key, secret, region');
            }
            $this->client = new DynamoDbClient([
                'region' => $connection["region"],
                'credentials' => [
                    'key' => $connection["key"],
                    'secret' => $connection["secret"]
                ]
            ]);
        } else {
            $this->client = $connection;
        }

        $this->config = array_merge([
            'client_table' => 'oauth_clients',
            'access_token_table' => 'oauth_access_tokens',
            'refresh_token_table' => 'oauth_refresh_tokens',
            'code_table' => 'oauth_authorization_codes',
            'user_table' => 'oauth_users',
            'jwt_table' => 'oauth_jwt',
            'scope_table' => 'oauth_scopes',
            'public_key_table' => 'oauth_public_keys',
        ], $config);
    }

    /**
     * @param $client_id
     * @param null $client_secret
     * @return bool
     */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $result = $this->client->getItem([
            "TableName" => $this->config['client_table'],
            "Key" => ['client_id' => ['S' => $client_id]]
        ]);

        return $result->count() == 1 && $result["Item"]["client_secret"]["S"] == $client_secret;
    }

    /**
     * @param $client_id
     * @return bool
     */
    public function isPublicClient($client_id)
    {
        $result = $this->client->getItem([
            "TableName" => $this->config['client_table'],
            "Key" => ['client_id' => ['S' => $client_id]]
        ]);

        if ($result->count() == 0) {
            return false;
        }

        return empty($result["Item"]["client_secret"]);
    }

    /**
     * @param $client_id
     * @return array|bool
     */
    public function getClientDetails($client_id)
    {
        $result = $this->client->getItem([
            "TableName" => $this->config['client_table'],
            "Key" => ['client_id' => ['S' => $client_id]]
        ]);
        if ($result->count() == 0) {
            return false;
        }
        $result = $this->dynamo2array($result);
        foreach (['client_id', 'client_secret', 'redirect_uri', 'grant_types', 'scope', 'user_id'] as $key => $val) {
            if (!array_key_exists($val, $result)) {
                $result[$val] = null;
            }
        }

        return $result;
    }

    /**
     * @param $client_id
     * @param null $client_secret
     * @param null $redirect_uri
     * @param null $grant_types
     * @param null $scope
     * @param null $user_id
     * @return bool
     */
    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        $clientData = compact('client_id', 'client_secret', 'redirect_uri', 'grant_types', 'scope', 'user_id');
        $clientData = array_filter($clientData, function ($value) {
            return !is_null($value);
        });

        $result = $this->client->putItem([
            'TableName' => $this->config['client_table'],
            'Item' => (new Marshaler())->marshalItem($clientData)
        ]);

        return true;
    }

    /**
     * @param $client_id
     * @param $grant_type
     * @return bool
     */
    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        $details = $this->getClientDetails($client_id);
        if (isset($details['grant_types'])) {
            $grant_types = explode(' ', $details['grant_types']);

            return in_array($grant_type, (array)$grant_types);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    /**
     * @param $access_token
     * @return array|bool
     */
    public function getAccessToken($access_token)
    {
        $result = $this->client->getItem([
            "TableName" => $this->config['access_token_table'],
            "Key" => ['access_token' => ['S' => $access_token]]
        ]);
        if ($result->count() == 0) {
            return false;
        }
        $token = $this->dynamo2array($result);
        if (array_key_exists('expires', $token)) {
            $token['expires'] = strtotime($token['expires']);
        }

        return $token;
    }

    /**
     * @param \OAuth2\Storage\oauth_token $access_token
     * @param \OAuth2\Storage\client $client_id
     * @param \OAuth2\Storage\user $user_id
     * @param int $expires
     * @param null $scope
     * @return bool
     */
    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        $clientData = compact('access_token', 'client_id', 'user_id', 'expires', 'scope');
        $clientData = array_filter($clientData, function ($value) {
            return !empty($value);
        });

        $result = $this->client->putItem([
            'TableName' => $this->config['access_token_table'],
            'Item' => (new Marshaler())->marshalItem($clientData)
        ]);

        return true;
    }

    /**
     * @param $code
     * @return array|bool
     */
    public function getAuthorizationCode($code)
    {
        $result = $this->client->getItem([
            "TableName" => $this->config['code_table'],
            "Key" => ['authorization_code' => ['S' => $code]]
        ]);
        if ($result->count() == 0) {
            return false;
        }
        $token = $this->dynamo2array($result);
        if (!array_key_exists("id_token", $token)) {
            $token['id_token'] = null;
        }
        $token['expires'] = strtotime($token['expires']);

        return $token;
    }

    /**
     * @param \OAuth2\OpenID\Storage\authorization|string $authorization_code
     * @param mixed|\OAuth2\OpenID\Storage\client $client_id
     * @param mixed|\OAuth2\OpenID\Storage\user $user_id
     * @param string $redirect_uri
     * @param int $expires
     * @param null $scope
     * @param null $id_token
     * @return bool
     */
    public function setAuthorizationCode($authorization_code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        $clientData = compact('authorization_code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'id_token', 'scope');
        $clientData = array_filter($clientData, function ($value) {
            return !empty($value);
        });

        $result = $this->client->putItem([
            'TableName' => $this->config['code_table'],
            'Item' => (new Marshaler())->marshalItem($clientData)
        ]);

        return true;
    }

    /**
     * @param $code
     * @return bool
     */
    public function expireAuthorizationCode($code)
    {
        $result = $this->client->deleteItem([
            'TableName' => $this->config['code_table'],
            'Key' => (new Marshaler())->marshalItem(["authorization_code" => $code])
        ]);

        return true;
    }

    /**
     * @param $username
     * @param $password
     * @return bool
     */
    public function checkUserCredentials($username, $password)
    {
        if ($user = $this->getUser($username)) {
            return $this->checkPassword($user, $password);
        }

        return false;
    }

    /**
     * @param $username
     * @return array|bool
     */
    public function getUserDetails($username)
    {
        return $this->getUser($username);
    }

    /**
     * @param $user_id
     * @param $claims
     * @return array|bool
     */
    public function getUserClaims($user_id, $claims)
    {
        if (!$userDetails = $this->getUserDetails($user_id)) {
            return false;
        }

        $claims = explode(' ', trim($claims));
        $userClaims = [];

        // for each requested claim, if the user has the claim, set it in the response
        $validClaims = explode(' ', self::VALID_CLAIMS);
        foreach ($validClaims as $validClaim) {
            if (in_array($validClaim, $claims)) {
                if ($validClaim == 'address') {
                    // address is an object with subfields
                    $userClaims['address'] = $this->getUserClaim($validClaim, $userDetails['address'] ?: $userDetails);
                } else {
                    $userClaims = array_merge($userClaims, $this->getUserClaim($validClaim, $userDetails));
                }
            }
        }

        return $userClaims;
    }

    /**
     * @param $claim
     * @param $userDetails
     * @return array
     */
    protected function getUserClaim($claim, $userDetails)
    {
        $userClaims = [];
        $claimValuesString = constant(sprintf('self::%s_CLAIM_VALUES', strtoupper($claim)));
        $claimValues = explode(' ', $claimValuesString);

        foreach ($claimValues as $value) {
            if ($value == 'email_verified') {
                $userClaims[$value] = $userDetails[$value] == 'true' ? true : false;
            } else {
                $userClaims[$value] = isset($userDetails[$value]) ? $userDetails[$value] : null;
            }
        }

        return $userClaims;
    }

    /**
     * @param $refresh_token
     * @return array|bool
     */
    public function getRefreshToken($refresh_token)
    {
        $result = $this->client->getItem([
            "TableName" => $this->config['refresh_token_table'],
            "Key" => ['refresh_token' => ['S' => $refresh_token]]
        ]);
        if ($result->count() == 0) {
            return false;
        }
        $token = $this->dynamo2array($result);
        $token['expires'] = strtotime($token['expires']);

        return $token;
    }

    /**
     * @param $refresh_token
     * @param $client_id
     * @param $user_id
     * @param $expires
     * @param null $scope
     * @return bool
     */
    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        $clientData = compact('refresh_token', 'client_id', 'user_id', 'expires', 'scope');
        $clientData = array_filter($clientData, function ($value) {
            return !empty($value);
        });

        $result = $this->client->putItem([
            'TableName' => $this->config['refresh_token_table'],
            'Item' => (new Marshaler())->marshalItem($clientData)
        ]);

        return true;
    }

    /**
     * @param $refresh_token
     * @return bool
     */
    public function unsetRefreshToken($refresh_token)
    {
        $result = $this->client->deleteItem([
            'TableName' => $this->config['refresh_token_table'],
            'Key' => (new Marshaler())->marshalItem(["refresh_token" => $refresh_token])
        ]);

        return true;
    }

    /**
     * Plaintext passwords are bad!  Override this for your application
     *
     * @param $user
     * @param $password
     * @return bool
     */
    protected function checkPassword($user, $password)
    {
        return $user['password'] == sha1($password);
    }

    /**
     * @param $username
     * @return array|bool
     */
    public function getUser($username)
    {
        $result = $this->client->getItem([
            "TableName" => $this->config['user_table'],
            "Key" => ['username' => ['S' => $username]]
        ]);
        if ($result->count() == 0) {
            return false;
        }
        $token = $this->dynamo2array($result);
        $token['user_id'] = $username;

        return $token;
    }

    /**
     * @param $username
     * @param $password
     * @param null $first_name
     * @param null $last_name
     * @return bool
     */
    public function setUser($username, $password, $first_name = null, $last_name = null)
    {
        // do not store in plaintext
        $password = sha1($password);

        $clientData = compact('username', 'password', 'first_name', 'last_name');
        $clientData = array_filter($clientData, function ($value) {
            return !is_null($value);
        });

        $result = $this->client->putItem([
            'TableName' => $this->config['user_table'],
            'Item' => (new Marshaler())->marshalItem($clientData)
        ]);

        return true;
    }

    /**
     * @param $scope
     * @return bool
     */
    public function scopeExists($scope)
    {
        $scope = explode(' ', $scope);
        $scope_query = [];
        $count = 0;
        foreach ($scope as $key => $val) {
            $result = $this->client->query([
                'TableName' => $this->config['scope_table'],
                'Select' => 'COUNT',
                'KeyConditions' => [
                    'scope' => [
                        'AttributeValueList' => [['S' => $val]],
                        'ComparisonOperator' => 'EQ'
                    ]
                ]
            ]);
            $count += $result['Count'];
        }

        return $count == count($scope);
    }

    /**
     * @param null $client_id
     * @return null|string|void
     */
    public function getDefaultScope($client_id = null)
    {
        $result = $this->client->query([
            'TableName' => $this->config['scope_table'],
            'IndexName' => 'is_default-index',
            'Select' => 'ALL_ATTRIBUTES',
            'KeyConditions' => [
                'is_default' => [
                    'AttributeValueList' => [['S' => 'true']],
                    'ComparisonOperator' => 'EQ',
                ],
            ]
        ]);
        $defaultScope = [];
        if ($result->count() > 0) {
            $array = $result->toArray();
            foreach ($array["Items"] as $item) {
                $defaultScope[] = $item['scope']['S'];
            }

            return empty($defaultScope) ? null : implode(' ', $defaultScope);
        }

        return;
    }

    /**
     * @param $client_id
     * @param $subject
     * @return bool
     */
    public function getClientKey($client_id, $subject)
    {
        $result = $this->client->getItem([
            "TableName" => $this->config['jwt_table'],
            "Key" => ['client_id' => ['S' => $client_id], 'subject' => ['S' => $subject]]
        ]);
        if ($result->count() == 0) {
            return false;
        }
        $token = $this->dynamo2array($result);

        return $token['public_key'];
    }

    /**
     * @param $client_id
     * @return bool|void
     */
    public function getClientScope($client_id)
    {
        if (!$clientDetails = $this->getClientDetails($client_id)) {
            return false;
        }

        if (isset($clientDetails['scope'])) {
            return $clientDetails['scope'];
        }

        return;
    }

    /**
     * @todo
     * @param $client_id
     * @param $subject
     * @param $audience
     * @param $expires
     * @param $jti
     */
    public function getJti($client_id, $subject, $audience, $expires, $jti) {
        //TODO not use.
    }

    /**
     * @todo
     * @param $client_id
     * @param $subject
     * @param $audience
     * @param $expires
     * @param $jti
     */
    public function setJti($client_id, $subject, $audience, $expires, $jti)
    {
        //TODO not use.
    }

    /**
     * @param string $client_id
     * @return bool
     */
    public function getPublicKey($client_id = '0')
    {
        $result = $this->client->getItem([
            "TableName" => $this->config['public_key_table'],
            "Key" => ['client_id' => ['S' => $client_id]]
        ]);
        if ($result->count() == 0) {
            return false;
        }
        $token = $this->dynamo2array($result);

        return $token['public_key'];
    }

    /**
     * @param string $client_id
     * @return bool
     */
    public function getPrivateKey($client_id = '0')
    {
        $result = $this->client->getItem([
            "TableName" => $this->config['public_key_table'],
            "Key" => ['client_id' => ['S' => $client_id]]
        ]);
        if ($result->count() == 0) {
            return false;
        }
        $token = $this->dynamo2array($result);

        return $token['private_key'];
    }

    /**
     * @param null $client_id
     * @return string
     */
    public function getEncryptionAlgorithm($client_id = null)
    {
        $result = $this->client->getItem([
            "TableName" => $this->config['public_key_table'],
            "Key" => ['client_id' => ['S' => $client_id]]
        ]);
        if ($result->count() == 0) {
            return 'RS256';
        }
        $token = $this->dynamo2array($result);

        return $token['encryption_algorithm'];
    }

    /**
     * Transform dynamodb resultset to an array.
     *
     * @param $dynamodbResult
     * @return array $array
     */
    private function dynamo2array($dynamodbResult)
    {
        $result = [];

        // Prevent inconsistent resultSet
        $resultSet = (is_array($dynamodbResult["Item"])) ? $dynamodbResult["Item"] : [];

        foreach ($resultSet as $key => $val) {
            $result[$key] = $val["S"];
            $result[] = $val["S"];
        }

        return $result;
    }
}

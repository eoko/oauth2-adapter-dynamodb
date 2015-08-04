<?php

namespace Eoko\OAuth2\Test\Storage;

use Eoko\OAuth2\Storage\DynamoDBv3;
use PHPUnit_Framework_TestCase;

class DynamoDBv3Test extends PHPUnit_Framework_TestCase
{
    public function testGetDefaultScope()
    {
        $client = $this->getMockBuilder('\Aws\DynamoDb\DynamoDbClient')
            ->disableOriginalConstructor()
            ->setMethods(['query'])
            ->getMock();

        $return = $this->getMockBuilder('\Guzzle\Service\Resource\Model')
            ->setMethods(['count', 'toArray'])
            ->getMock();

        $data = [
            'Items' => [],
            'Count' => 0,
            'ScannedCount'=> 0
        ];

        $return->expects($this->once())
            ->method('count')
            ->will($this->returnValue(count($data)));

        $return->expects($this->once())
            ->method('toArray')
            ->will($this->returnValue($data));

        // should return null default scope if none is set in database
        $client->expects($this->once())
            ->method('query')
            ->will($this->returnValue($return));

        $storage = new DynamoDBv3($client);
        $this->assertNull($storage->getDefaultScope());
    }
}

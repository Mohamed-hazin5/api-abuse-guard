const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");

const dynamo = new DynamoDBClient({
    region: "ap-south-1"
});

module.exports = dynamo;

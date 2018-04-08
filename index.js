var crypto = require('crypto');
var path = require('path');
var sign = require('./encrypt');

var dateISOString = new Date().toISOString();

const config = {
    accessKey: process.env.S3_ACCESS_KEY,
    secretKey: process.env.S3_SECRET_KEY,
    bucket: process.env.S3_BUCKET,
    region: process.env.S3_REGION,
    expectedMinSize: 0,
    expectedMaxSize: 15000000,
    amzAlgorithm: "AWS4-HMAC-SHA256",
    successUrl: "http://success.com",
    date: dateISOString
};

exports.handler = (event, context, callback) => {
    const url = event.body;
    const params = {
        filename: filename,
        contentType: event.contentType
    };

    sign.s3Signature(params, config);


    // TODO implement
    callback(null, 'Hello from Lambda');
};
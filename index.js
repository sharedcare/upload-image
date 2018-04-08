'use strict';

const uuid = require("uuid");
const sign = require("./encrypt");


const dateISOString = new Date().toISOString();

const config = {
    accessKey: process.env.S3_ACCESS_KEY,
    secretKey: process.env.S3_SECRET_KEY,
    bucket: process.env.S3_BUCKET,
    region: process.env.S3_REGION,
    expectedMinSize: 0,
    expectedMaxSize: 15000000,
    amzAlgorithm: "AWS4-HMAC-SHA256",
    successUrl: "http://success.com",
    date: dateISOString,
    clientAccessKey: process.env.CLIENT_ACCESS_KEY
};

exports.handler = (event, context, callback) => {
    const params = event.queryStringParameters;
    const requiredParams = ["Content-Type", "clientAccessKey", "fileExtension"];
    var response;

    if (!params) {
        response = constResponse(400, 'Parameters are required', null);
        callback(null, response);
    } else {
        for (var i in requiredParams) {
            if (!params[requiredParams[i]]) {
                response = constResponse(400, requiredParams[i] + " is required", null);
                callback(null, response);
            }
        }
    }

    if (params.clientAccessKey !== config.clientAccessKey) {
        response = constResponse(403, "Client access is denied due to wrong access key", null);
        callback(null, response);
    }

    params["filename"] = uuid.v1() + params.fileExtension;
    const signedParams =  sign.signature(params, config);

    response = constResponse(200, "Request succeed", signedParams);

    callback(null, response);
};

function constResponse(statusCode, message, params) {
    const headers = { "Content-Type": "application/json" };
    return {
        statusCode: statusCode,
        headers: headers,
        body: JSON.stringify({
            message: message,
            params: params
        })
    };
}

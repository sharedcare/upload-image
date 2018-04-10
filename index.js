/**
 *  @fileOverview Main node.js handler for AWS lambda function
 *
 *  @author       Yizhen Chen
 *
 *  @requires     NPM:npm_module
 *  @requires     ./encrypt.js:signature
 */

'use strict';

const uuid = require("uuid");
const sign = require("./encrypt");

/**
 * amzDate used in signing signature,
 * should be specified in the ISO8601 formatted string.
 * @example 20130728T000000Z
 * @type {string}
 */
const dateISOString = new Date().toISOString();
const amzDate = getAmzDate(dateISOString);

/**
 * The global configuration
 * @type {{accessKey: *, secretKey: *, bucket: *, region: *, expectedMinSize: number, expectedMaxSize: number, amzAlgorithm: string, successUrl: string, date: *, clientAccessKey: *}}
 */
const config = {
    accessKey: process.env.S3_ACCESS_KEY,   // Your AWS access key ID
    secretKey: process.env.S3_SECRET_KEY,   // Your AWS secret access key ID
    bucket: process.env.S3_BUCKET,          // Your AWS s3 target bucket
    region: process.env.S3_REGION,          // Your AWS s3 region of target bucket
    expectedMinSize: 0,                     // Minimum file size to upload
    expectedMaxSize: 15000000,              // Maximum file size to upload
    amzAlgorithm: "AWS4-HMAC-SHA256",       // amzAlgorithm, default is AWS4-HMAC-SHA256 for AWS Signature Version 4
    successUrl: "http://success.com",       // Redirect Url when post request(upload to s3) succeed
    date: amzDate,                          // amzDate defined above
    clientAccessKey: process.env.CLIENT_ACCESS_KEY  // Your client access key
};

/**
 * This is AWS Lambda main handler function.
 * All parameters are passed through event.
 */
exports.handler = (event, context, callback) => {
    // Get all url query parameters
    const params = event.queryStringParameters;
    // Specify which parameters are required
    const requiredParams = ["Content-Type", "fileExtension"];
    var response;

    // Return 400 if query is empty
    if (!params) {
        response = constResponse(400, 'Parameters are required', null);
        callback(null, response);
    } else {
        // Return 400 if required parameters are not satisfied
        for (var i in requiredParams) {
            if (!params[requiredParams[i]]) {
                response = constResponse(400, requiredParams[i] + " is required", null);
                callback(null, response);
            }
        }
    }

    // This code is used for client authentication
    /*
    if (params.clientAccessKey !== config.clientAccessKey) {
        response = constResponse(403, "Client access is denied due to wrong access key", null);
        callback(null, response);
    }
    */

    // Generates unique name for uploading file
    params["filename"] = uuid.v1() + "." + params.fileExtension;

    /**
     * This contains all parameters that AWS s3 POST requires
     * includes signature
     * @type {{endpoint_url, params}|*}
     */
    const signedParams =  sign.Signature(params, config);

    response = constResponse(200, "Request succeed", signedParams);
    callback(null, response);
};

/**
 * This generates a valid response
 * based on given status code, message and return parameters.
 * @example
 * var statusCode = 400,
 *     message = "Bad request!",
 *     params = null;
 *
 * var response = constResponse(statusCode, message, params);
 * @param {number} statusCode - status code to return
 * @param {string} message
 * @param {object} params
 * @returns {object} valid response
 */
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

/**
 * Generates the amzDate based on the ISO date string.
 * @param {string} dateStr - ISO 8601 date string
 * @returns {string|*} - AWS ISO8601 formatted date string
 */
function getAmzDate(dateStr) {
    var chars = [":","-"];
    for (var i=0;i<chars.length;i++) {
        while (dateStr.indexOf(chars[i]) !== -1) {
            dateStr = dateStr.replace(chars[i],"");
        }
    }
    dateStr = dateStr.split(".")[0] + "Z";
    return dateStr;
}


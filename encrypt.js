/**
 *  @file Generates the signature for AWS s3 HTTP request
 *
 *  @author       Yizhen Chen
 *
 *  @requires     NPM:npm_module
 */

var crypto = require("crypto");

/**
 * Generates all required elements for http request
 * @generator
 * @param {object} params - query parameters
 * @param {object} config - global configuration
 * @return {object} - JSON object contains all required elements
 */
function signature(params, config) {
    var credential = amzCredential(config);
    var policy = updatePolicy(params, config, credential);
    var b64policy = new Buffer(JSON.stringify(policy, null, "\t")).toString("base64");
    return {
        endpoint_url: "https://" + config.bucket  + ".s3.amazonaws.com",
        params: {
            key: params.filename,
            acl: 'public-read',
            policy: b64policy,
            "Content-Type": params["Content-Type"],
            "x-amz-algorithm": config.algorithm,
            "x-amz-credential": credential,
            "x-amz-date": config.date,
            "x-amz-signature": signPolicy(b64policy, config)
        }
    };
}

/**
 * Generates s3 policy
 * @generator
 * @param {object} params - query parameters
 * @param {object} config - global configuration
 * @param {string} amzCredential
 * @return {{expiration: string, conditions: *[]}}
 */
function updatePolicy(params, config, amzCredential) {
    return {
        expiration: new Date((new Date).getTime() + (5 * 60 * 1000)).toISOString(),
        conditions: [
            { bucket: config.bucket },
            { key: params.filename },
            { acl: "public-read" },
            {"Content-Type": params["Content-Type"]},
            ["content-length-range", config.expectedMinSize, config.expectedMaxSize],
            {"x-amz-server-side-encryption": "AES256"},
            ["starts-with", "$x-amz-meta-tag", ""],

            {"x-amz-credential": amzCredential},
            {"x-amz-algorithm": config.amzAlgorithm},
            {"x-amz-date": config.date}
        ]
    };
}

/**
 * Generates amzCredential
 * @generator
 * @param {object} config - global configuration
 * @return {string} - amzCredential
 */
function amzCredential(config) {
    var dateString = config.date.split("T")[0];
    return [config.accessKey, dateString, config.region, 's3/aws4_request'].join('/');
}

/**
 * hmac hash function using crypto library
 * @param {string} key
 * @param {string} string
 * @return {void|*|Promise<any>} - hash value
 */
function hmac(key, string) {
    var hmac = crypto.createHmac('sha256', key);
    hmac.end(string);
    return hmac.read();
}

/**
 * Generates signature based on AWS Signature Version 4
 * @generator
 * @param {string} stringToSign - s3 policy in base64 encode
 * @param {object} config - global configuration
 * @returns {string} - signed signature
 */
function signPolicy(stringToSign, config) {
    var dateString = config.date.split("T")[0];
    var dateKey = hmac("AWS4" + config.secretKey, dateString);
    var dateRegionKey = hmac(dateKey, config.region);
    var dateRegionServiceKey = hmac(dateRegionKey, "s3");
    var signingKey = hmac(dateRegionServiceKey, "aws4_request");
    return hmac(signingKey, stringToSign).toString('hex');
}

/**
 * signature functions required for http request
 * @export Signature
 */
module.exports = { Signature: signature};
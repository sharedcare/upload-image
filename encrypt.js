var crypto = require("crypto");

function signature(params, config) {
    return {
        endpoint_url: "https://" + config.bucket  + ".s3.amazonaws.com.",
        params: signParams(params, config)
    }
}

function signParams(params, config) {
    var credential = amzCredential(config);
    var policy = updatePolicy(params, config, credential);
    var b64policy = new Buffer(JSON.stringify(policy, null, "\t")).toString("base64");
    return {
        key: params.filename,
        acl: 'public-read',
        policy: b64policy,
        "content-type": params.contentType,
        "x-amz-algorithm": config.algorithm,
        "x-amz-credential": credential,
        "x-amz-date": config.date,
        "x-amz-signature": signPolicy(b64policy, config)
    }
}

function updatePolicy(params, config, credential) {
    return {
        expiration: new Date((new Date).getTime() + (5 * 60 * 1000)).toISOString(),
        conditions: [
            { bucket: config.bucket },
            { key: params.filename },
            { acl: "public-read" },
            ["starts-with", "$Content-Type", "image/"],
            ["content-length-range", config.expectedMinSize, config.expectedMaxSize],
            {"x-amz-server-side-encryption": "AES256"},
            ["starts-with", "$x-amz-meta-tag", ""],

            {"x-amz-credential": credential},
            {"x-amz-algorithm": config.amzAlgorithm},
            {"x-amz-date": config.date}
        ]
    };
}

function amzCredential(config) {
    var dateString = config.date.split("T")[0];
    return [config.accessKey, dateString, config.region, 's3/aws4_request'].join('/')
}

function hmac(key, string) {
    return crypto.createHmac('sha256', key).update(string).digest('hex');
}

function signPolicy(stringToSign, config) {
    var dateString = config.date.split("T")[0];
    var dateKey = hmac("AWS4" + config.secretKey, dateString);
    var dateRegionKey = hmac(dateKey, config.region);
    var dateRegionServiceKey = hmac(dateRegionKey, "s3");
    var signingKey = hmac(dateRegionServiceKey, "aws4_request");
    return hmac(signingKey, stringToSign);

}

module.exports = { signature: signature};
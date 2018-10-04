var rp = require('request-promise');
var parseLH = require('parse-link-header');
var Promise = require('bluebird');

var userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36";


/**
 * get details from URL
 * 
 * @param {String} href
 * @returns
 */
function getLocation(href) {
    var match = href.match(/^(https?\:)\/\/(([^:\/?#]*)(?:\:([0-9]+))?)([\/]{0,1}[^?#]*)(\?[^#]*|)(#.*|)$/);
    return match && {
        protocol: match[1],
        host: match[2],
        hostname: match[3],
        port: match[4],
        pathname: match[5],
        search: match[6],
        hash: match[7],
        path: match[5].concat(match[6])
    };
}


module.exports = function (_config) {

    var config = Object.assign({
        hostName: null, // e.g. "https://dev14080.service-now.com" 
        proxy: {
            proxy: null,
            strictSSL: false
        },
        auth: {
            clientId: null,
            clientSecret: null,
            authCode: null,
            accessToken: null,
            refreshToken: null,

            username: null,
            password: null
        },
        debug: false,
        silent: false,
        jar: false,
        gzip: true
    }, _config);

    rp.debug = config.debug;

    var log = function () {
        if (!config.silent)
            console.log.apply(this, arguments);
    };


    var promiseFor = Promise.method(function (condition, action, value) {
        if (!condition(value))
            return value;
        return action(value).then(promiseFor.bind(null, condition, action));
    });

    /**
     *  Execute REST call. Verb to be provided as method property or use the convenience method e.g. get(), post() 
     *
     * @param {*} properties 
     * @param {Promise} callbackPromise if provided, will be executed after every page / block of results
     */
    var run = function (properties, callbackPromise) {

        var out = [];
        var failureCount = 0,
            error;
        var rpd = rp.defaults({
            json: true,
            baseUrl: config.hostName,
            gzip: config.gzip,
            strictSSL: config.proxy.strictSSL,
            proxy: config.proxy.proxy,
            encoding: "utf8",
            headers: {
                "User-Agent": userAgent
            },
            jar: config.jar
        });

        var index = 0;
        return promiseFor(function (next) {
            return (next);
        }, function (thisURL) {

            var options = Object.assign({
                rawResponse: false,
                autoPagination: true
            }, properties, {
                url: thisURL,
                resolveWithFullResponse: true
            });

            if (config.auth.username) {
                options.auth = {
                    username: config.auth.username,
                    password: config.auth.password
                };
            } else {
                options.auth = {
                    "bearer": config.auth.accessToken
                };
            }
            
            return rpd(options)
                .then(function (response) {
                    //log("options.simple ::: ", options.simple)

                    var hasNextURL = false;
                    if (options.autoPagination && response.headers.link) {
                        var links = parseLH(response.headers.link);
                        if (links.next) {
                            hasNextURL = getLocation(links.next.url).path;
                        }
                    }
                    //log("hasNextURL ", hasNextURL);

                    /* if module runs in simple mode (simple = true), non 2xx status code will not be handled automatically by it.
                       in a case of 4xx we throw an error to trigger the token refresh in the catch function below. */
                    if (options.simple === false && (/^4/.test('' + response.statusCode))) { // Status Codes 4xx
                        throw {
                            statusCode: response.statusCode,
                            message: 'WTF!'
                        };
                    }

                    if (options.rawResponse) { // this is used in XML update set export 
                        if (!hasNextURL) {
                            log("return raw response");
                            out = response;
                            return hasNextURL;
                        } else {
                            throw Error("cant return raw response as there is a next page!");
                        }
                    }

                    var body = response.body;
                    if (callbackPromise !== undefined) {
                        log("executing callback inline with results");
                        if (body && body.result) {
                            return callbackPromise(body.result)
                                .then(function () {
                                    return hasNextURL;
                                });
                        } else {
                            throw Error("response body has no results[] property, execute callback!");
                        }

                    } else {
                        log("appending chunk: ", ++index, " from URL:", options.url);
                        if (body && body.result) {
                            out = out.concat(body.result);
                        } else {
                            console.warn("response body has no results[] property, cant append to result!");
                        }
                    }
                    return hasNextURL;

                }).catch(function (err) {
                    if (config.auth.username)
                        throw err;
                    
                    error = err;
                    if ([400, 401].indexOf(err.statusCode) != -1 && failureCount < 1) { // 400 in case its the application or updateSet API
                        log("access_token expired, request new one");
                        failureCount++;
                        return rpd({
                                method: "POST",
                                url: "oauth_token.do",
                                form: {
                                    grant_type: "refresh_token",
                                    client_id: config.auth.clientId,
                                    client_secret: config.auth.clientSecret,
                                    refresh_token: config.auth.refreshToken
                                }
                            })
                            .then(function (body) {
                                if (!body.access_token) {
                                    throw new Error('No Access token found');
                                }
                                // update config with access_token
                                //log("body ACCESS TOKEN", body);
                                config.auth.accessToken = body.access_token;
                                config.auth.refreshToken = body.refresh_token;
                            })
                            .then(function () {
                                return thisURL;
                            })
                            .catch(function (err) {
                                throw error;
                            });
                    } else {
                        throw err;
                    }
                });

        }, properties.url).then(function () {
            return out;
        });
    };

    return {
        run: run,
        get: function (properties, callback) {
            return run(Object.assign({}, properties, {
                method: 'get'
            }), callback);
        },
        post: function (properties, body) {
            if (body === undefined) {
                return run(Object.assign({}, properties, {
                    method: 'post'
                }));
            } else {
                return run(Object.assign({}, properties, {
                    method: 'post',
                    body: body
                }));
            }
        },
        put: function (properties, body) {
            if (body === undefined) {
                return run(Object.assign({}, properties, {
                    method: 'put'
                }));
            } else {
                return run(Object.assign({}, properties, {
                    method: 'put',
                    body: body
                }));
            }
        },
        patch: function (properties, body) {
            if (body === undefined) {
                return run(Object.assign({}, properties, {
                    method: 'patch'
                }));
            } else {
                return run(Object.assign({}, properties, {
                    method: 'patch',
                    body: body
                }));
            }
        },
        del: function (properties, callback) {
            return run(Object.assign({}, properties, {
                method: 'delete'
            }), callback);
        },
        getRefreshToken: function () {
            return config.auth.refreshToken;
        },
        getAccessToken: function () {
            return config.auth.accessToken;
        },
        getHostName: function () {
            return config.hostName;
        }
    };
};
const rp = require('request-promise');
const parseLH = require('parse-link-header');
const Promise = require('bluebird');
const uuid = require('uuid/v4');

const USER_AGENT = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36";
const RETRY_CODES = ['ECONNRESET', 'ENOTFOUND', 'ESOCKETTIMEDOUT', 'ETIMEDOUT', 'ECONNREFUSED', 'EHOSTUNREACH', 'EPIPE', 'EAI_AGAIN'];

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

    const config = Object.assign({
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
        gzip: true,
        retry: 1,
        delay: 100,
    }, _config);

    rp.debug = config.debug;

    const rpd = rp.defaults({
        json: true,
        baseUrl: config.hostName,
        gzip: config.gzip,
        strictSSL: config.proxy.strictSSL,
        proxy: config.proxy.proxy,
        encoding: "utf8",
        headers: {
            "User-Agent": USER_AGENT
        },
        jar: config.jar
    });

    const log = function () {
        if (!config.silent)
            console.info.apply(this, arguments);
    };


    const promiseFor = Promise.method(function (condition, action, value) {
        if (!condition(value))
            return value;
        return action(value).then(promiseFor.bind(null, condition, action));
    });


    const retryRequest = function (options) {

        const tries = options.retry || config.retry || 1;
        const delay = options.delay || config.delay || 100;
        const ID = uuid();

        const _retryRequest = (tryCount) => {
            return rpd(options).then((result) => {
                if (options.verbose_logging) {
                    console.log(`Result obtained for ${options.method} request to ${options.url} run '${tryCount} of total ${tries}, req-id: ${ID}'`);
                }
                throw { statusCode: 202, name: 'StatusCodeError' };
                return Promise.resolve(result);
            }).catch((err) => {
                // oauth must throw err
                if (!config.auth.username && [400, 401].indexOf(err.statusCode) != -1) {
                    return Promise.reject(err)
                }

                const errorCode = (err.error && err.error.code) ? err.error.code : null;
                const statusCode = (err.statusCode !== undefined) ? err.statusCode : -1;

                if (err.name == 'RequestError') {
                    if (!RETRY_CODES.includes(errorCode))
                        return Promise.reject(err)

                } else if (err.name == 'StatusCodeError') {
                    if (!(statusCode === 429 || (500 <= statusCode && statusCode < 600)))  // 429 means "Too Many Requests" while 5xx means "Server Error"
                        return Promise.reject(err)
                } else {
                    console.error('[SN-REST-CLIENT] Unknown error: %j', err)
                    return Promise.reject(err)
                }

                console.warn(`[SN-REST-CLIENT] Encountered error '${errorCode || statusCode}' for '${options.method}' request to '${options.url}', retry run #${tries - tryCount + 1} of total ${tries} delay ${delay}ms, req-id: ${ID}`); //  (${err.message})

                tryCount -= 1;
                if (tryCount) {
                    return Promise.delay(delay).then(() => _retryRequest(tryCount));
                }
                return Promise.reject(err);
            });
        }
        return _retryRequest(tries);
    }


    /**
     *  Execute REST call. Verb to be provided as method property or use the convenience method e.g. get(), post() 
     *
     * @param {*} properties 
     * @param {Promise} callbackPromise if provided, will be executed after every page / block of results
     */
    const run = function (properties, callbackPromise) {

        let out = [];
        let failureCount = 0;
        let index = 0;

        return promiseFor((next) => {
            return (next);
        }, (thisURL) => {

            var options = Object.assign({
                rawResponse: false,
                autoPagination: true,
                retry: 1,
                delay: 100,
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

            return retryRequest(options)
                .then((response) => {
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
                    if (options.simple === false && ((/^4/).test(String(response.statusCode)))) { // Status Codes 4xx
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
                            return callbackPromise(body.result).then(() => {
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

                }).catch((err) => {
                    if (config.auth.username)
                        throw err;

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
                        }).then((body) => {
                            if (!body.access_token) {
                                throw new Error('No Access token found');
                            }
                            // update config with access_token
                            //log("body ACCESS TOKEN", body);
                            config.auth.accessToken = body.access_token;
                            config.auth.refreshToken = body.refresh_token;
                        }).then(() => {
                            return thisURL;
                        }).catch((e) => {
                            console.error("Oauth token refresh failed", e);
                            throw err;
                        });
                    } else {
                        throw err;
                    }
                });

        }, properties.url).then(() => {
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

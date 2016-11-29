function extendAPIOutput(req, res, next) {
    // 响应API成功的结果
    res.apiSuccess = function (data) {
        res.json({
            status: 'OK',
            result: data
        });
    };
    // 响应API出错结果，err是一个ERROR对象，
    res.apiError = function (err) {
        res.json({
            status: 'Error',
            error_code: err.error_code || 'UNKNOWN',
            error_message: err.error_message || err.toString()
        });
    };

    next();
}

app.use(extendAPIOutput);

// code=出错代码，msg=出错描述信息
function createApiError(code, msg) {
    var err = new Error(msg);
    err.error_code = code;
    err.error_message = msg;
    return err;
}

function callback(err, ret) {
    if (err) {
        return res.apiError(err);
    };
    // 其他操作...
}

function apiErrorHandle(err, req, res, next) {
    // 如果有res.apiError()则使用其来输出出错信息
    if (typeof res.apiError === 'function') {
        return res.apiError(err);

    }
    next();
}

app.use(apiErrorHandle);

app.get('/api/articles.json', function (req, res, next) {
    queryArticles({
        author_id: req.query.author_id,
        $skip: req.query.$skip,
        $limit: req.query.$limit,
        $sort: req.query.$sort
    }, function (err, ret) {
        if (err) {
            return res.apiError(err);
        };
        res.apiSuccess({ articles: ret });

    });
});

function ensureLogin(req, res, next) {
    // 先检查用户是否已在网站中登录
    // 如果未登录则跳转到登录界面
    // 如果已登录，记录用户相关的信息
    req.loginUserId = 'xxxx';
    next();
}

function missingParameterError(name) {
    return createApiError('MISSING_PARAMETER', '缺少参数`' + name + '`');
}

function redirectUriNotMatchError(url) {
    return createApiError('REDIRECT_URI_NOT_MATCH', '回调地址不正确：' + url);
}

function checkAuthorizeParams(req, res, next) {
    // 检查参数
    if (!req.query.client_id) {
        return next(missingParameterError('client_id'));

    }
    if (!req.query.redirect_uri) {
        return next(missingParameterError('redirect_uri'));
    }
    // 验证client_id是否正确，并查询应用的详细信息
    getAppInfo(req.query.client_id, function (err, ret) {
        if (err) {
            return next(err);
        };

        req.appInfo = ret;

        // 验证redirect_uri是否复合改应用设置的回调地址规则
        verifyAppRedirectUri(req.query.client_id, req.query.redirect_uri, function (err, ok) {
            if (err) {
                return next(err);
            };
            if (!ok) {
                return next(redirectUriNotMatchError(req.query.redicect_uri));
            }
            next();
        });
    });
}


app.get('/OAuth2/authorize', ensureLogin, checkAuthorizeParams, function (req, res, next) {
    res.locals.loginUserId = req.loginUserId;
    res.locals.appInfo = req.appInfo;
    res.render('authorize');

});

app.post('/OAuth2/authorize', ensureLogin, checkAuthorizeParams, function (req, res, next) {
    // 生成authorization_code
    generateAuthorizationCode(req.loginUserId, req.query.client_id, req.query.redicect_uri, function (err, ret) {
        if (err) {
            return next(err);
        };
        res.redirect(addQueryParamsToUrl(req.query.redicect_uri, {
            code: ret
        }));

    });
});

var parseUrl = require('url').parse;
var formatUrl = require('url').format;

function addQueryParamsToUrl(url, parmas) {
    var info = parseUrl(url, true);
    for (var i in parmas) {
        info.query[i] = parmas[i];
    }
    delete info.search;
    return formatUrl(info);
}


function randomString(size, chars) {
    size = size || 6;
    var codeString = chars || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    var maxNum = codeString.length + 1;
    var newPass = '';
    while (size > 0) {
        newPass += codeString.charAt(Math.floor(Math.random() * maxNum));
        size--;
    }
    return newPass;
}


function generateAuthorizationCode(userId, appKey, redicect_uri, callback) {
    // 生成code
    var code = randomString(20);

    // 将code、userId、appKey、redicetUri存储到数据库
    // 省略相关代码
    callback(null, code);

}


app.post('/OAuth2/access_token', function (req, res, next) {
    // 检查参数
    var client_id = req.body.client_id || req.query.client_id;
    var client_secret = req.body.client_secret || req.query.client_secret;
    var redicect_uri = req.body.redicect_uri || req.query.redicect_uri;
    var code = req.body.code || req.query.code;
    if (!client_id) {
        return next(missingParameterError('client_id'));

    }
    if (!client_secret) {
        return next(missingParameterError('client_secret'));

    }
    if (!redirect_uri) {
        return next(missingParameterError('redirect_uri'));

    }
    if (!code) {
        return next(missingParameterError('code'));

    }

    // 验证access_token
    generateAccessToken(userId, client_id, function (err, accessToken) {
        if (err) {
            return next(err);

            // 生成access_token后需要删除就得authrization_code
            deleteAuthorizationCode(code, function (err) {
                if (err) { console.error(err); };

            });

            res.apiSuccess({
                access_token: accessToken,
                expires_in: 3600 * 24 // access_token的有效期为1天
            });
        };
    });
});



function verifyAuthorizationCode(code, appKey, appSecret, redirectUri, callback) {
    // 从数据库中查找对应的code的记录
    // 检查appKey,appSecret和redirectUri是否正确
    // 省略相关代码
    // userId为该code对应的userId
    callback(null, userId);
}


function deleteAuthorizationCode(code, callback) {
    // 从数据库中删除对应的code记录
    // 省略相关代码
    callback(null, code);

}


function invalidParameterError(name) {
    return createApiError('INVALID_PARAMETER', '参数`' + name + '`不正确');

}

function getAccessTokenInfo(token, callback) {
    // 查询数据库中对应token的信息
    callback(null, info);

}

function verifyAccessToken(req, res, next) {
    var accessToken = (req.body && req.body.access_token) || req.query.access_token;
    var source = (req.body && req.body.source) || req.query.source;

    // 检查参数
    if (!accessToken) {
        return next(missingParameterError('access_token'));
    };
    if (!source) {
        return next(missingParameterError('source'));
    };
    // 查询Access_token的信息
    database.getAccessTokenInfo(accessToken, function (err, tokenInfo) {
        if (err) {
            return next(err);
        };
        // 检查appKey是否一致
        if (source !== tokenInfo.clientId) {
            return next(invalidParameterError('source'));

        }
        if (getTimestamp() > getTimestampFromAccessToken(accessToken)) {
            return next(accesstokenExpiredError());
        }
        // 保存当前access_token的详细信息
        req.accessTokenInfo = tokenInfo;

        next();

    });
}


app.use('/api', verifyAccessToken);


// access token过期的问题
function getTimestamp() {
    return parseInt(Date.now() / 1000, 10);
}


function generateAccessToken(userId, appKey, expires, callback) {
    // 生成code，后面为
    var code = randomString(20) + '.' + (getTimestamp() + expires);
    // 将code,userId,appKey存储到数据库
    // 此处省略相关代码
    callback(null, code);

}

// 从access_token中取出时间戳
function getTimestampFromAccessToken(token) {
    return Number(token.split('.').pop());
}

// access_token已过期，错误
function accessTokenExpiredError() {
    return createApiError('ACCESS_TOKEN_EXPIRED', 'access_token expired');
}


// api客户端
function APIClient(options) {
    this._appKey = options.appKey;
    this._appSecret = options.appSecret;
    this._callbackUrl = options.callbackUrl;

}

var request = require('request');

// 定义请求API的地址
var API_URL = 'http://example.com';
var API_OAUTH2_AUTHORIZE = API_URL + '/OAuth2/authorize';
var API_OAUTH2_ACCESS_TOKEN = API_URL + '/OAuth2/access_token';
// 生成获取授权的跳转地址
APIClient.prototype.getRedirectUrl = function () {
    return addQueryParamsToUrl(API_OAUTH2_AUTHORIZE, {
        client_id: this._appKey,
        redirect_uri: this._callbackUrl
    });
};

// 发送请求
APIClient.prototype._request = function (method, url, params, callback) {
    method = method.toUpperCase();
    // 如果已经获取了access_token,则字加上source和access_token两个参数
    if (this._acccessToken) {
        params.source = this._appKey;
        params.access_token = this._acccessToken;
    }

    // 根据不同的请求方法，生成用户request模块的参数
    var requestParams = {
        method: method,
        url: url
    };
    if (method === 'GET' || method === 'HEAD') {
        requestParams.qs = parmas;
    } else {
        requestParams.formData = params;
    }

    request(requestParams, function (err, res, body) {
        if (err) {
            return callback(err)
        };
        // 解析返回的数据
        try {
            var data = JSON.parse(body.toString());

        } catch (err) {
            return callback(err);

        }
        //判断是否出错
        if (data.status !== 'OK') {
            return callback({
                code: data.error_code,
                message: data.error_message
            });
        }
        callback(null, data.result);
    });
};

// 获取access_token
APIClient.prototype.requestAccessToken = function (code, callback) {
    var me = this;
    this._request('post', API_OAUTH2_ACCESS_TOKEN, {
        code: code,
        client_id: this._appKey,
        client_secret: this._appSecret,
        redicect_uri: this._callbackUrl
    }, function (err, ret) {
        // 如果请求成功，则保存获取的access_token
        if (ret) { me._acccessToken = ret.access_token; }
        callback(err, ret);

    });
};

app.get('/auth/callback', function (req, res, next) {
    client.requestAccessToken(req.query.code, function (err, ret) {
        if (err) {
            return next(err);
        };
        // ret.access_token即为获取的授权码
        // 显示授权成功页面
        res.end('获取授权成功');
    });
});

var API_ARTICLES = API_URL + '/api/v1/articles';

APIClient.prototype.getArticles = function (params, callback) {
    this._request('get', API_ARTICLES, params, callback);
};

// 请求频率
var redis = require('redis');

// 连接的redis
var redisClient = redis.createClient();

function outOfRateLimteError() {
    return createApiError('OUT_OF_RATE_LIMIT', '`超出请求频率限制');
}

// 生成检测请求频率的中间件
function generateRateLimiter(getKey, limit) {
    return function (req, res, next) {
        var source = req.body.source || req.query.source;
        var key = getKey(source);
        redisClient.incr(key, function (err, ret) {
            if (err) {
                return next(err);
            };
            if (ret > limit) {
                return next(outOfRateLimteError());

            }
            next();
        });
    };
}

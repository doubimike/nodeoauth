function extendAPIOutput(req, res, next) {
    // 响应API成功的结果
    res.apiSuccess = function (data) {
        res.json({
            status: 'OK',
            result: data
        });
    };
    // 响应API出错结果，err是一个ERROR对象，
    // 
    // 
}

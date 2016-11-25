function extendAPIOutput(req, res, next) {
    // 响应API成功的结果
    res.apiSuccess = function (data) {
        res.json({
            status: 'OK',
            result: data
        });
    };
}

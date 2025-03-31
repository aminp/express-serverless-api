const jwt = require('jsonwebtoken');

const checkToken = (req, res, next) => {
    let token = req.headers['x-access-token'] || req.headers.authorization;

    if(!token) {
        return res.status(401).json({
            message:'No token provided.',
            success: false
        })
    }

    if(token.startsWith('Bearer ')) {
        token = token.slice(7, token.length);
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decode) => {
        if(err) {
            return res.status(401).json({
                message: 'token is not valid.',
                success: false
            })
        }

        req.decode = decode; //can be attached here to the request, because we may add some info like userId on the client side to the token.
        return next();
    });

}

module.exports = {
    checkToken,
}
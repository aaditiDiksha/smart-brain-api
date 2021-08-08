const jwt = require('jsonwebtoken')

const requireAuth = (req,res,next) => {
    const {authorization} = req.headers;
    const token = authorization && authorization.split(' ')[1];
    if(!token){
        return res.status(401).json('Unauthorized')
    }
    return jwt.verify(token,`${process.env.JWT_SECRET_KEY}`,(err,jwtPayload)=>{
        if(err) return res.status(401).json('Unauthorized')
        return next()
    })
}

module.exports={
    requireAuth
}
const jwt = require('jsonwebtoken')
const config = require('config')

module.exports = (req, resp, next) => {
    if(req.method === 'OPTIONS'){
        return next()
    }

    try {
      const token = req.headers.authorization.split(' ')[1] //Bearer TOKEN  
      console.log('token', token)
      if (!token){
          return resp.status(401).json({message: 'Нет авторизации'})
      }

      const decoded = jwt.verify(token, config.get('jwtSecret'))
      req.user = decoded
      next()
    } catch (e) {
        resp.status(401).json({message: 'Нет авторизации'})
    }
}
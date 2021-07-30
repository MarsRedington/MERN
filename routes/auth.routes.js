const {Router} = require('express')
const bcrypt = require('bcryptjs')
const {check, validationResult} = require('express-validator')
const jwt = require('jsonwebtoken')
const User = require('../models/user')
const config = require('config')

const router = Router()

//  /api/auth/register
router.post(
    '/register',
    [
        check('email', 'Некорректный email').isEmail(),
        check('password', 'Минимальная длина пароля 6 символов').isLength({min: 6})
    ],
    async(req, resp) =>{
        try {
            console.log('pas', req.body)
            const errors = validationResult(req)
            if(!errors.isEmpty()){
                return resp.status(400).json({errors: errors.array(), message: 'Некорректные данные при регистрации'})
            }

            const {email, password} = req.body
            // console.log('pas', password)
            const candidate = await User.findOne({email: email})

            if (candidate){
            return resp.status(400).json({message: 'Такой пользователь уже существует'})
            }

            const hashedPassword = await bcrypt.hash(password, 8)
            const user = new User({email: email, password: hashedPassword})
            await user.save()
            resp.status(201).json({message:'Пользователь создан'})


        } catch (e) {
            resp.status(500).json({message: 'Something wrong, try again'})
        }
})


//  /api/auth/login
router.post('/login',
    [
        check('email', 'Введите корректный email').normalizeEmail().isEmail(),
        check('password', 'Введите пароль').exists()
    ],
    async(req, resp) =>{
        try {
            console.log('reqbody', req.body)
            const errors = validationResult(req)
            if(!errors.isEmpty()){
                return resp.status(400).json({errors: errors.array(), message: 'Некорректные данные при входе в систему'})
            }
            const {email, password} = req.body
            const user = await User.findOne({email})

            if(!user){
                return resp.status(400).json({message: 'Пользователь не найден'})
            }

            const isMatch = await bcrypt.compare(password, user.password)
            if(!isMatch){
                return resp.status(400).json({message: 'Неверный пароль'})
            }
            
            const token = jwt.sign(
                {userId: user.id},
                config.get('jwtSecret'),
                {expiresIn: '1h'}
            )
            resp.json({token, userId: user.id})
            
        } catch (e) {
            resp.status(500).json({message: 'Something wrong, try again'})
        }
})

module.exports = router
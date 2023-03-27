const express = require('express');

const authController = require('../controllers/auth');

const router = express.Router();

const User= require('../models/user')

const {check,body} = require('express-validator/check')

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post('/login',[
    body('email').isEmail().withMessage('please enter a valid email!')
    .custom((value,{req})=>{
        return User.findOne({email:value}).then(userDoc=>{
            if(!userDoc){
             return Promise.reject('this email is not registered')
            }
        })
        })
        .normalizeEmail(), 
    body('password','please enter a valid password').isLength({min:5}).isAlphanumeric().trim()
], authController.postLogin);

router.post('/signup',
[check('email').isEmail()
.withMessage('please eneter a valid email')
.custom((value,{req})=>{
// if(value==='test2@test.com'){
//      throw new Error('this email is forbidden')
// }
// return true;
return User.findOne({email:value}).then(userDoc=>{
    if(userDoc){
     return Promise.reject('this email already exists, pick different one')
    }
})
}).normalizeEmail(),
body('password','please enter alpha numeric charecters and atleast 5 ch').isLength({ min: 5 }).isAlphanumeric().trim(),
body('confirmPassword').trim().custom((value,{req})=>{
    if(value!==req.body.password){
        throw new Error('passwords have to be match!')
    }
    return true;
})
],
 authController.postSignup);

router.post('/logout', authController.postLogout);

router.get('/reset',authController.getReset)

router.post('/reset',authController.postReset)

router.get('/reset/:tokenId',authController.getNewPassword)

router.post('/new-password',authController.postNewPassword)

module.exports = router;
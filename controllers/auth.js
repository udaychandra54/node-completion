const User = require('../models/user');
const bcrypt= require('bcryptjs');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport')
const crypto = require('crypto')
const {validationResult} = require('express-validator/check')

const transporter = nodemailer.createTransport(sendgridTransport({
  auth:{
    api_key:"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"
  }
}))

exports.getLogin = (req, res, next) => {
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    isAuthenticated: false,
    errorMessage:req.flash('error'),
    oldInput:{
      email:"",
      password:""
    },
    validationErrors:[]
  });
};

exports.getSignup = (req, res, next) => {
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    isAuthenticated: false,
    errorMessage:req.flash('error'),
    oldInput:{
      email:"",
      password:"",
      confirmPassword:""
    },
    validationErrors:[]
  });
};

exports.postLogin = (req, res, next) => {
  const email= req.body.email;
  const password=req.body.password;
  const errors= validationResult(req);
  if(!errors.isEmpty()){
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      isAuthenticated: false,
      errorMessage:errors.array()[0].msg,
      oldInput:{
        email:email,
        password:password
      },
      validationErrors:errors.array()
    });
  }
  User.findOne({email:email}).then(user=>{
    if(!user){
      req.flash('error','Email does not exists')
      return res.redirect('/login')
    }
   return bcrypt.compare(password,user.password).then(doMatch=>{
    if(doMatch){
      req.session.isLoggedIn = true;
      req.session.user = user;
      return req.session.save(err => {
        console.log(err);
        res.redirect('/');
    });
    }
    if(!doMatch){
      req.flash('error','Invalid email or password')
      return res.redirect('/login')
    }
    
   })
  }).catch(err => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email= req.body.email;
  const password=req.body.password;
  const errors= validationResult(req);
  if(!errors.isEmpty()){
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      isAuthenticated: false,
      errorMessage:errors.array()[0].msg,
      oldInput:{
        email:email,
        password:password,
        confirmPassword:req.body.confirmPassword
      },
      validationErrors:errors.array()
    });
  }
   bcrypt.hash(password,12)
   .then((hashPassword)=>{
    const user = new User({
      email:email,
      password:hashPassword,
      cart:{items:[]}
    })
    return user.save()
  }).then(()=>{
    res.redirect('/login')
    return transporter.sendMail({
      to:email,
      from:"udaychandrag@gmail.com",
      subject:"signedup successfully",
      html:"<h1>you successfully signedup</h1>"
    })
  }).catch(err=>{
    console.log(err)
  })
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.getReset = (req, res, next) => {
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset',
    isAuthenticated: false,
    errorMessage:req.flash('error')
  });
};

exports.postReset = (req,res,next)=>{
  console.log('eneter')
  crypto.randomBytes(32,(err,buffer)=>{
    if(err){
     console.log('err1',err)
      return res.redirect('/reset')
    }
   const token= buffer.toString('hex')
   User.findOne({email:req.body.email}).then(user=>{
    if(!user){
      console.log('email not found')
      req.flash('error','no email found in the database');
      return res.redirect('/reset')
    }
    user.resetToken= token;
    user.resetTokenExpiration = Date.now() + 3600000;
    return user.save();
   })
   .then(()=>{
    transporter.sendMail({
      to:req.body.email,
      from:"udaychandrag@gmail.com",
      subject:"Reset Password",
      html:`
      You requested password reset
      please click <a href="http://localhost:3000/reset/${token}">Link</a> here to reset your password
      `
    })
   }).catch(err=>{
    console.log(err)
   })
  })
}
exports.getNewPassword=(req,res,next)=>{
  const token = req.params.tokenId;
  User.findOne({resetToken:token,resetTokenExpiration:{$gt:Date.now()}}).then(user=>{
    res.render('auth/new-password', {
      path: '/new-password',
      pageTitle: 'New Password',
      errorMessage:req.flash('error'),
      userId:user._id.toString(),
      passwordToken:token
    });
  }).catch(err=>{
    console.log(err)
  })
  
}

exports.postNewPassword=(req,res,next)=>{
  const newPassword = req.body.newpassword;
  const userId = req.body.userId;
  const passwordToken= req.body.passwordToken;
  let resetUser;
  User.findById(userId)
  .then(user=>{
    resetUser=user;
    return bcrypt.hash(newPassword,12)
  })
  .then((hashPassword)=>{
    resetUser.password = hashPassword;
    resetUser.resetToken=undefined;
    resetUser.resetTokenExpiration=undefined
   return resetUser.save()
 }).then(result=>{
  return res.redirect('/login')
 })
  .catch(err=>{
    console.log(err)
  })
}
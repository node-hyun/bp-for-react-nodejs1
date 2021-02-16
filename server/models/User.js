const mongoose = require('mongoose');
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require('jsonwebtoken');


const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})


userSchema.pre("save", function (next) {                                // save 하기 전에 뭔가를 해라 
    var user = this;                                                    // 현재 유저 모델

    if (user.isModified("password")) {                                  // 비밀번호가 수정되었을 경우 
        bcrypt.genSalt(saltRounds, function (err, salt) {               // saltRounds 만큼 반복문을 돌려서 salt를 적용
            if (err) return next(err);
            bcrypt.hash(user.password, salt, function (err, hash) {     // salt를 적용해 얻은 비밀번호를 hash로 얻어서
                if (err) return next(err);
                user.password = hash;                                   // user.password에 저장
                next();                                                 // 그 다음 과정을 진행
            });
        });
    } else {
        next();                                                   // 비밀번호를 바꾸는 경우가 아니더라도 다음으로 진행
    }

});

// plainPassword(클라이언트 비밀번호)와 콜백 함수를 인자로 받아 
userSchema.methods.comparePassword = function (plainPassword, cb) {

    bcrypt.compare(plainPassword, this.password, function (err, isMatch) {
        console.log("isMatch(비밀번호 확인 true or false) : ", isMatch);
        if (err) return cb(err);
        cb(null, isMatch);
    })
}


// generateToken 함수의 역할 
// 로그인 유저에 대해 토큰 발급 및 클라이언트로 보낼 토큰 정보 리턴 
userSchema.methods.generateToken = function (cb) {
    // user.generateToken 이렇게 호출했으므로 user는 findOne에서 찾은 유저이다.
    var user = this; 

    // 토큰 객체 생성(현재 유저의 id 정보를 이용해 토큰 정보 생성 하기  )
    var token = jwt.sign(user._id.toHexString(), 'secretToken');    
    console.log("token 생성 확인 : ", token);

    // 유저 모델의 토큰 필드에 위에서 생성한 토큰 정보 설정 하기 
    user.token = token

    // 유저 정보 저장 한뒤 콜백 함수로 토큰 정보를 리턴 하기 
    user.save(function (err, user) {
        if (err) return cb(err)
        cb(null, user);
    });
}

// 함수 만드는 목적: 
// 토큰으로 유저 찾은뒤 해당 유저 정보를 콜백으로 넘기는 함수
// 함수를 사용하는곳: 
// 미들웨어 auth 함수에서 토큰으로 유저 모델 검색한뒤 해당 유저 정보를 받기 위해 사용 
// 주요 로직 : 
// 토큰으로 유저 정보를 찾는 jwt.verify 함수를 호출하면 복호화된 user._id를 
// 콜백함수의 두번쨰 인자(err, decoded)로 받을수 있다.
// user._id로 유저 모델을 검색하여 찾은 유저 정보를 cb의 인자로 넘김 
userSchema.statics.findByToken = function (token, cb) {
    var user = this;
    console.log("유저 정보 조회를 위한 token 확인 : ", token);

    jwt.verify(token, 'secretToken', function (err, decoded) {
        user.findOne({ "_id": decoded, "token": token }, function (err, user) {
            if (err) return cb(err);
            cb(null, user);
        });
    });
}

const User = mongoose.model('User', userSchema)
module.exports = { User }

const express = require('express')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const { User } = require("./models/User");
const config = require('./config/key');
const cookieParser = require('cookie-parser');
const { auth } = require("./middleware/auth");


const app = express()
const port = 5000
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// mongodb + srv://test:<password>@boilerplate-hetcl.mongodb.net/<dbname>?retryWrites=true&w=majority
mongoose.connect(config.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB Connected...'))
    .catch((err) => console.log(err))

app.post('/register', (req, res) => {
    console.log("req.body : ", req.body);
    const user = new User(req.body)
    console.log('====================================');
    console.log("user : ", user);
    console.log('====================================');
    user.save((err, userInfo) => {
        if (err) return res.json({ success: false, err })
        return res.status(200).json({
            success: true
        })
    });
});



app.post("/login", (req, res) => {
    console.log("login 요청 확인 from Clinet");
    // 1. 클라이언트가 보낸 로그인 유저 이메일이 존재하는지 확인
    // 2. 클라이언트가 보낸 로그인 비밀 번호가 유효한지 판단
    // 3. 로그인 정보가 유효할 경우 해당 로그인 유저에 대해 jwt token을 생성한뒤 디비와 클라이언트에 저장
    User.findOne({ email: req.body.email }, (err, user) => {
        console.log("이메일로 검색한 유저 정보 : ", user);
        if (!user) {
            return res.json({
                loginSuccess: false,
                message: "제공된 이메일에 해당하는 유저가 없습니다"
            });
        }

        // 비밀번호가 맞는지 체크
        // 에러가 있을 경우 콜백으로 넘겨 받음 => err
        // 클라이언트 비밀번호와 디비 조회한 유저 비밀번호가 일치 하는지에 대해 콜백으로 넘겨 받음 => isMatch
        user.comparePassword(req.body.password, (err, isMatch) => {
            if (!isMatch) { // 비밀 번호가 틀릴 경우
                return res.json({ loginSuccess: false, message: "비밀번호가 틀려요" });
            }
            console.log("isMatch :: ", isMatch);
            console.log("비밀 번호 확인 ok");
        });

        // 해당 유저에 대해 토큰 생성 및 디비 저장 + 클라이언트에 저장 하기 
        user.generateToken((err, user) => {
            console.log("user.token : ", user.token);
            res.cookie("x_auth", user.token)
                .status(200)
                .json({ loginSuccess: true, userId: user._id })
        })

    }); // User.findOne() 끝

    // return res.status(200).json({
    //     message: "입력하신 정보에 해당하는 유저가 존재하며 비밀번호가 일치 합니다"
    // })


});  // login router 끝


// /api/users/auth 요청에 대해 로그인 유저인지 판별한뒤 로그인 유저일 경우 
// 해당 유저 정보 req.user에 설정 + 해당 유저 정보 응답 하는 라우터 로직 
app.get('/api/users/auth', auth, (req, res) => {
    console.log("로그인 유저 정보 응답 요청 req 확인 ", req);
    res.status(200).json({
        id: req.user._id,
        isAdmin: req.user.role === 0 ? false : true,
        isAuth: true,
        email: req.user.email,
        name: req.user.name,
        lastname: req.user.lastname,
        role: req.user.role,
        image: req.user.image
    })
});

app.get('/api/users/logout', auth, (req, res) => {
    console.log("req.user : ", req.user);
    User.findOneAndUpdate(
        { _id: req.user._id },
        { token: "" },
        (err, user) => {
            if (err) return res.json({ success: false, err });
            return res.status(200).send({
                success: true
            })
        });
});


app.get('/', (req, res) => res.send("Hello World 22"))

app.listen(port, () => console.log(`Example app listing on port ${port}!`))


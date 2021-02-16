// 유저 모델 임포트
const { User } = require('../models/User');
// 미들 웨어 함수
// 클라이언트의 쿠키로 유저 모델을 검색하여 해당 유저 정보가 존재할 경우 로그인 유저로 판단 
// 해당 유저 정보를 req.user에 저장한뒤 next() 함수로 다음 로직으로 넘기기 
let auth = (req, res, next) => {
    console.log("auth 함수 실행!! req check : ", req.cookies);
    // 클라이언트 쿠키에서 토큰 정보 가져오기
    let token = req.cookies.x_auth;
    console.log("token 확인 하기 : ", token);
    // 토큰 정보로 해당 유저 정보를 가져 오기
    User.findByToken(token, (err, user) => {
        if (err) throw err;
        if (!user) return res.json(
            { isAuth: false, error: true }
        );
        console.log("user check : ", user);

        // req.token=token;
        req.user = user;
        // 다음 로직으로 넘기기
        next();
    });
}

module.exports = { auth };


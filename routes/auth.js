var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
const { check_authentication, check_authorization } = require('../Utils/check_auth');
let constants = require('../Utils/constants');
let userSchema = require('../models/users');
let bcrypt = require('bcrypt');

router.post('/signup', async function(req, res, next) {
    try {
        let body = req.body;
        let result = await userController.createUser(
          body.username,
          body.password,
          body.email,
         'user'
        )
        res.status(200).send({
          success:true,
          data:result
        })
      } catch (error) {
        next(error);
      }

})
router.post('/login', async function(req, res, next) {
    try {
        let username = req.body.username;
        let password = req.body.password;
        let result = await userController.checkLogin(username,password);
        res.status(200).send({
            success:true,
            data:result
        })
      } catch (error) {
        next(error);
      }

})
router.get('/me',check_authentication, async function(req, res, next){
    try {
      res.status(200).send({
        success:true,
        data:req.user
      })
    } catch (error) {
        next();
    }
})

// Route để reset mật khẩu người dùng - chỉ admin có thể thực hiện
router.get('/resetPassword/:id', check_authentication, check_authorization(constants.ADMIN_PERMISSION), async function(req, res, next) {
  try {
    // Tìm người dùng theo ID
    let user = await userSchema.findById(req.params.id);
    
    if (!user) {
      return res.status(404).send({
        success: false,
        message: "Không tìm thấy người dùng"
      });
    }
    
    // Đặt lại mật khẩu về '123456'
    user.password = '123456';
    await user.save(); // Mật khẩu sẽ được mã hóa trong pre-save middleware
    
    res.status(200).send({
      success: true,
      message: "Đã đặt lại mật khẩu thành công"
    });
    
  } catch (error) {
    next(error);
  }
});

// Route để thay đổi mật khẩu - yêu cầu đăng nhập
router.post('/changePassword', check_authentication, async function(req, res, next) {
  try {
    const { password, newPassword } = req.body;
    
    // Kiểm tra mật khẩu hiện tại có đúng không
    if (!password || !newPassword) {
      return res.status(400).send({
        success: false,
        message: "Vui lòng cung cấp mật khẩu hiện tại và mật khẩu mới"
      });
    }
    
    // Kiểm tra xem mật khẩu hiện tại có khớp không
    const isMatch = bcrypt.compareSync(password, req.user.password);
    
    if (!isMatch) {
      return res.status(400).send({
        success: false,
        message: "Mật khẩu hiện tại không đúng"
      });
    }
    
    // Cập nhật mật khẩu mới
    req.user.password = newPassword;
    await req.user.save(); // Mật khẩu sẽ được mã hóa trong pre-save middleware
    
    res.status(200).send({
      success: true,
      message: "Đã thay đổi mật khẩu thành công"
    });
    
  } catch (error) {
    next(error);
  }
});

module.exports = router
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET, BCRYPT_ROUNDS } = require("../secrets"); // use this secret!
const User = require('../users/users-model')


router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body
  console.log(req.body);
  // bcrypting the password before saving
  const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS)
  // never save the plain text password in the db
  user.password = hash
  console.log(user.role);
  User.add(user)
    .then(saved => {
      let newUser = saved[0]
      console.log(newUser.username);
      res.status(201).json({ 
        message: `Great to have you, ${newUser.username}`, 
        role_name: newUser.role_name,
        user_id: newUser.user_id,
        username: newUser.username
      })
    })
    .catch(next) // our custom err handling middleware in server.js will trap this
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  let { username, password } = req.body

  User.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user);
        res.status(200).json({
          message: `${user.username} is back`,
          token,
        })
      } else {
        next({ status: 401, message: 'Invalid Credentials' })
      }
    })
    .catch(next)
});

function generateToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role
  };
  const options = {
    expiresIn: '1d',
  };
  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;

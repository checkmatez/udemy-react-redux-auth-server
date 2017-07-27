const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user._id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(422).send({ error: 'You must provide email and password.'});
  }

  User.findOne({ email })
    .then(existingUser => {
      if (existingUser) {
        throw new Error('Email is in use');
      }

      const user = new User({
        email,
        password
      });
      return user.save();
    })
    .then(savedUser => res.json({ token: tokenForUser(savedUser) }))
    .catch(err => {
      if (err.message === 'Email is in use') {
        res.status(422).send({ error: err.message });
      } else {
        next(err);
      }
    });
}

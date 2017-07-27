const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create local strategy
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy(localOptions, (email, password, done) => {
  User.findOne({ email })
    .then(user => {
      if (!user) {
        done(null, false);
      } else {
        user.comparePassword(password, (err, isMatch) => {
          if (err) {
            done(err);
          } else if (!isMatch) {
            done(null, false);
          } else {
            done(null, user);
          }
        })
      }
    })
    .catch(err => done(err, false));
});

// setup options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret,
};

// Create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {
  User.findById(payload.sub)
    .then(user => {
      if (user) {
        done(null, user);
      } else {
        done(null, false);
      }
    })
    .catch(err => done(err, false));
});

// Tell passport to use this Strategy
passport.use(jwtLogin);
passport.use(localLogin);

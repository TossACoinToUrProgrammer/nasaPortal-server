const { Router } = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { check, validationResult } = require("express-validator");
const config = require("config");
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const User = require("../models/user");

const router = Router();

passport.serializeUser(function(user, done) {
    done(null, user);
  });
passport.deserializeUser(function(user, done) {
    done(null, user);
});

let user = {};

passport.use(new GoogleStrategy({
    clientID: "41237912117-m39mh17ccgs3gad7024cikpn4t0t648v.apps.googleusercontent.com",
    clientSecret: "S94sZ599zkodZiqJZWS1I73N",
    callbackURL: "/api/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    user = { ...profile }
    return done(null, profile);
  }
));

// Initializes passport and passport sessions
router.use(passport.initialize());
router.use(passport.session());

// Auth Routes
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);
router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "https://nasa-portal.netlify.app/#/auth/failed" }),
  (req, res) => {
    res.redirect("https://nasa-portal.netlify.app/#/auth-success");
  }
);

router.get(
  "/profile",
  async(req, res) => {
    try {
      let profile = await User.findOne({ sourceId: user.id });
      if (!profile) {
        const hashPassword = await bcrypt.hash(Date.now() + '', 12);
        profile = new User({
          email: user.emails[0].value,
          password: hashPassword,
          sourceId: user.id,
        });
        await profile.save();
      }
  
      const token = jwt.sign(
        { userId: profile.id, email: profile.email },
        config.get("jwtSecret"),
        {
          expiresIn: "1h",
        }
      );
  
      return res.status(200).json({
        email: profile.email,
        token,
        userId: profile.id,
        message: "Вы успешно вошли в систему",
      }); 
    } catch (e) {
      res.status(500).json({message: e.message});
    }
  }
)

router.post(
  "/register",
  [
    check("email", "Некорректный email").isEmail(),
    check("password", "Минимальная длина пароля 6 символов").isLength({
      min: 6,
    }),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: "Введены некорректные данные",
        });
      }

      const { email, password } = req.body;

      const condidate = await User.findOne({ email });
      if (condidate) {
        return res.status(400).json({
          message: "Такой пользователь уже существует",
        });
      }

      const hashPassword = await bcrypt.hash(password, 12);
      const user = new User({ email, password: hashPassword });

      await user.save();

      return res.status(201).json({ message: "Регистрация прошла успешно" });
    } catch (e) {
      res
        .status(500)
        .json({ message: "Что-то пошло не так, попробуйте снова" });
    }
  }
);

router.post(
  "/login",
  [
    check("email", "Некорркетный email").normalizeEmail().isEmail(),
    check("password", "Введите пароль").exists(),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: "Введены некорректные данные",
        });
      }

      const { email, password } = req.body;

      const user = await User.findOne({ email });
      if (!user)
        return res.status(400).json({ message: "Пользователь не найден" });

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(400).json({ message: "Неверный пароль или email" });
      }

      const token = jwt.sign(
        { userId: user.id, email: user.email },
        config.get("jwtSecret"),
        {
          expiresIn: "1h",
        }
      );

      return res.status(200).json({
        token,
        userId: user.id,
        message: "Вы успешно вошли в систему",
      });
    } catch (e) {
      res
        .status(500)
        .json({ message: "Что-то пошло не так, попробуйте снова" });
    }
  }
);
router.get('/logout', (req, res) => {
  user = {};
  res.status(201).json({message: 'Вы успешно вышли из системы'});
})
module.exports = router;

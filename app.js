//jshint esversion:6
//Initialize node modules
require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate')





const app = express();

//Set view engine to ejs
app.set("view engine", "ejs");
//Server use bodyParser
app.use(bodyParser.urlencoded({
  extended: true
}));
//Static files
app.use(express.static("public"));

//Server use session
app.use(session({
  secret: "ThisisOurLittleSecret",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize()); //Initialize passport
app.use(passport.session()); //Use passport to manage session



//Initialize mongoose
mongoose.set('strictQuery', true);
mongoose.connect('mongodb://127.0.0.1/userDB');

//Create userSchema and model
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

//userSchema use passportLocalMongoose as a plugin
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = mongoose.model("User", userSchema);


passport.use(User.createStrategy()); //Create a configured strategy for passport
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
//Set up Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));


//Server GET root route
app.get("/", function(req, res) {
  res.render("home");
});

//Server GET /login route
app.get("/login", function(req, res) {
  res.render("login");
});

//Server GET /register route
app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/logout", function(req, res) {
  req.logout(function(err) {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});

app.get("/secrets", function(req, res) {
  User.find({
    secret: {
      $ne: null
    }
  }, function(err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {
          usersWithSecrets: foundUsers
        });
      }
    }
  });
});

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

//Google Authentication route
app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile"]
  }));

//Facebook Authentication route
app.get("/auth/facebook",
  passport.authenticate("facebook", {
    scope: ["public_profile"]
  }));



//Google callback route
app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

//Facebook callback route
app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });


//POST /register route
app.post("/register", function(req, res) {
  //register new user
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});


//POST /login route
app.post("/login", function(req, res) {
  //check the DB to see if the username that was used to login exists in the DB
  User.findOne({
    username: req.body.username
  }, function(err, foundUser) {
    //if username is found in the database, create an object called "user" that will store the username and password
    //that was used to login
    if (foundUser) {
      const user = new User({
        username: req.body.username,
        password: req.body.password
      });
      //use the "user" object that was just created to check against the username and password in the database
      //in this case below, "user" will either return a "false" boolean value if it doesn't match, or it will
      //return the user found in the database
      passport.authenticate("local", function(err, user) {
        if (err) {
          console.log(err);
        } else {
          //this is the "user" returned from the passport.authenticate callback, which will be either
          //a false boolean value if no it didn't match the username and password or
          //a the user that was found, which would make it a truthy statement
          if (user) {
            //if true, then log the user in, else redirect to login page
            req.login(user, function(err) {
              res.redirect("/secrets");
            });
          } else {
            res.redirect("/login");
          }
        }
      })(req, res);
      //if no username is found at all, redirect to login page.
    } else {
      //user does not exists
      res.redirect("/login")
    }
  });
});

app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save();
        res.redirect("/secrets");
      }
    }
  });
});


//Listen on localhost:3000
app.listen(3000, function() {
  console.log("Server started on port 3000");
});
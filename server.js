require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();
const port = Number(process.env.PORT) || 3000;

if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
  throw new Error("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file.");
}

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL || `http://localhost:${port}/auth/google/callback`
}, (_accessToken, _refreshToken, profile, done) => done(null, {
  id: profile.id,
  displayName: profile.displayName || "Google user"
})));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.use(session({
  secret: process.env.SESSION_SECRET || "development-session-secret-change-me",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 24 * 60 * 60 * 1000
  }
}));
app.use(passport.initialize());
app.use(passport.session());

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[character]));

app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Google Sign-In</title></head>
<body><main><h1>OAuth-Based Login</h1><p>Sign in securely with your Google account.</p><a href="/auth/google">Login with Google</a></main></body></html>`);
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));
app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login-failure" }),
  (_req, res) => res.redirect("/dashboard")
);

app.get("/dashboard", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/");
  const name = escapeHtml(req.user.displayName);
  res.type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dashboard</title></head>
<body><main><h1>Welcome, ${name}!</h1><p>You are signed in with Google.</p><a href="/logout">Log out</a></main></body></html>`);
});

app.get("/login-failure", (_req, res) => {
  res.status(401).type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login failed</title></head>
<body><main><h1>Login failed</h1><p>Google sign-in could not be completed. Please try again.</p><a href="/auth/google">Try again</a></main></body></html>`);
});

app.get("/logout", (req, res, next) => {
  req.logout((error) => {
    if (error) return next(error);
    req.session.destroy((sessionError) => {
      if (sessionError) return next(sessionError);
      res.clearCookie("connect.sid");
      res.redirect("/");
    });
  });
});

app.listen(port, () => console.log(`Server listening at http://localhost:${port}`));

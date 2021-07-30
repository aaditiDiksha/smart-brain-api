/*"start": "node server.js" */
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt-nodejs");
const cors = require("cors");
const knex = require("knex");
const { response } = require("express");

const register = require("./controllers/register");
const signin = require("./controllers/signin");
const profile = require("./controllers/profile");
const image = require("./controllers/image");
const auth = require("./controllers/authorization");

const db = knex({
  client: "pg",
  connection: {
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false,
    },
  },
});

const app = express();
console.log('checking log')
app.use(cors());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.get("/", (req, res) => {
  res.send("working");
});
app.post("/signin", (req, res) =>
  signin.signinAuthentication(req, res, db, bcrypt)
);
app.post("/register", (req, res) => {
  register.generateAuthToken(req, res, db, bcrypt);
});
// app.get('/profile/:id', auth.requireAuth, (req, res) => { profile.handleProfileGet(req, res, db)})
app.get("/profile/:id", (req,res) => console.log('mpmp'));

app.put("/image",auth.requireAuth, (req, res) => {
  image.handleImage(req, res, db);
});
app.post("/imageurl", auth.requireAuth,(req, res) => {
  image.handleApiCall(req, res);
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`app is running on port ${process.env.PORT}`);
});

/*
/ --> res = this is working

/signin --> Post = success/fail
/register --> post = user
/profile/:userId --> GET = user
/image --> PUT --> user
*/

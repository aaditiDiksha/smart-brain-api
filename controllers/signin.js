const jwt = require("jsonwebtoken");

const handleSignin = (req, db, bcrypt) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return Promise.reject("incorrect form submission");
  }
  return db.select("email", "hash")
    .from("login")
    .where("email", "=", email)
    .then((data) => {
      const isValid = bcrypt.compareSync(password, data[0].hash);
      if (isValid) {
        return db
          .select("*")
          .from("users")
          .where("email", "=", email)
          .then(user => user[0])
          .catch((err) => Promise.reject("unable to get user"));
      } else {
        return Promise.reject("wrong credentials");
      }
    })
    .catch((err) => {
      console.log(err);
      return Promise.reject("wrong credentials");
    });
};

const signToken = (id, email) => {
  const jwtPayLoad = { id, email };
  return jwt.sign(jwtPayLoad, process.env.JWT_SECRET_KEY, { expiresIn: "2d" });
};

const createSession = (data) => {
  const { email, id } = data;
  const token = signToken(id, email);
  return { success: true, userId: id, token };
};

const getAuthTokenId = (req, res) => {
  const { authorization } = req.headers;
  const token = authorization.split(" ")[1];
  return jwt.verify(token, process.env.JWT_SECRET_KEY, (err, jwtPayLoad) => {
    if (err) return res.status(401).json("Unauthorized");
    return res.json({ success: true, userId: jwtPayLoad.id, token });
  });
};

const signinAuthentication = (req, res, db, bcrypt) => {
  const { authorization } = req.headers;
  const token = authorization && authorization.split(" ")[1];
  return token
    ? getAuthTokenId(req, res)
    : handleSignin(req, db, bcrypt).then(user => {
          return user.id && user.email
            ? createSession(user)
            : Promise.reject(user);
        })
        .then((data) => res.json(data))
        .catch((err) => res.status(400).json(err));
};
module.exports = {
  signinAuthentication,
  createSession
};

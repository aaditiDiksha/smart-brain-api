
const { createSession } = require("./signin");

const handleRegister = (req,  db, bcrypt) => {
  const { email, name, password } = req.body;
  if (!email || !name || !password) {
    return Promise.reject('incorrect form submission');
  }
  const hash = bcrypt.hashSync(password);
   return db.transaction(trx => {
     return trx.insert({ hash, email})
      .into('login')
      .returning('email')
      .then(loginEmail => {
        return trx('users')
          .insert({ 
            email: loginEmail[0],
            name: name,
            joined: new Date()
          })
          .returning('*')
          .then(user => 
            Promise.resolve(user[0]))
      })
      .then(trx.commit)
      .catch(trx.rollback)
    })
    .catch(err =>{
      Promise.reject(' user already exists')
    }
    )
}

const generateAuthToken = (req,res,db,bcrypt) => {
  handleRegister(req,db,bcrypt)
  .then(user => {
    return user.email && user.id
      ? createSession(user)
      : Promise.reject("Unable to register!!!");
  })
  .then(data =>res.json(data))
  .catch(err => {
    console.log(err);
    return res.status(400).json(err);
  } )
}

module.exports = {
  generateAuthToken
};



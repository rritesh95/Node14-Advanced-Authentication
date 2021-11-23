const path = require('path');

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session'); //express session library to maintain sessions
const MongoDBStore = require('connect-mongodb-session')(session);
const csrf = require('csurf'); //package to implement CSRF tokens
const flash = require('connect-flash'); //package to implement flash messages

const errorController = require('./controllers/error');
// const mongoConnect = require('./util/database').mongoConnect;
const User = require('./models/user');

const MONGODB_URI = 'mongodb://MongoDB_User:MongoDBUser%40210791@node-complete-shard-00-00.0vl9o.mongodb.net:27017,node-complete-shard-00-01.0vl9o.mongodb.net:27017,node-complete-shard-00-02.0vl9o.mongodb.net:27017/shop?ssl=true&replicaSet=atlas-13wbgl-shard-0&authSource=admin&retryWrites=true&w=majority';
const app = express();

const store = new MongoDBStore({
  uri: MONGODB_URI,
  collection: 'sessions'
})
const csrfProtection = csrf(); //initialize our "csurf" plugin
//in "csrf()" you can pass object which it use for configuration default is "session",
//it depends on what mechanisam we are using for sign in

app.set('view engine', 'ejs');
app.set('views', 'views');

const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const authRoutes = require('./routes/auth');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: "my secret", //in real-world it should be a large string
  resave: false, //it specifies that don't save session on each request untill some information
  //we need to save in session is modified (helps in performance optimization)
  saveUninitialized: false, //ensure no session save happens for requests it is not intended to
  store: store //store to which session should be stored
  //must implement store for storing session instead of relying on memory which can create
  //performance problem if user requests increases also it's less secure
}));

app.use(csrfProtection); //have to do here, after user authentication mechanism is initialized
//here in our case it's session

app.use(flash()); //needs to initialize after session configuration is done.

app.use((req,res,next) => {
  if(!req.session.user){
    return next();
  }

  User.findById(req.session.user._id)
    .then(user => {
      req.user = user;
      next();
    })
    .catch(err => console.log(err));
});

app.use((req,res,next) => {
  res.locals.isAuthenticated = req.session.isLoggedIn;
  res.locals.csrfToken = req.csrfToken();
  next();
})

app.use('/admin', adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

app.use(errorController.get404);

// mongoConnect(() => { //while using mongodb alone without mongoose
//   app.listen(3000);
// });

mongoose.connect(
  MONGODB_URI
)
.then(() => {
  console.log('Connected!');
  //removed below code when implementing authentication
  // User.findOne() //it will send the first user it finds as no condition specified
  //   .then(user => {
  //     if(!user){
  //       const user = new User({
  //         name: "testUser",
  //         email: "testemail@test.com",
  //         cart: { items: [] }
  //       });

  //       user.save(); //it will create user in db
  //     }
  //   });
  app.listen(3000);
})
.catch(err => console.log(err));
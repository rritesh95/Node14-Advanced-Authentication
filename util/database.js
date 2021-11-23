//////////////////////FIle Not required when working with Mongoose///////////////////

const mongodb = require('mongodb');
const MongoClient = mongodb.MongoClient;

let _db; //_ at start is a notation which says it will be used for internal usage only

const mongoConnect = (callback) => {
  MongoClient.connect(
    //'mongodb+srv://MongoDB_User:MongoDBUser%40210791@node-complete.0vl9o.mongodb.net/myFirstDatabase?retryWrites=true&w=majority'
    'mongodb://MongoDB_User:MongoDBUser%40210791@node-complete-shard-00-00.0vl9o.mongodb.net:27017,node-complete-shard-00-01.0vl9o.mongodb.net:27017,node-complete-shard-00-02.0vl9o.mongodb.net:27017/shop?ssl=true&replicaSet=atlas-13wbgl-shard-0&authSource=admin&retryWrites=true&w=majority'
    //commented first URL as it was giving error and found solution that we should use
    //URL for "node 2.2.12 and Later" the it wil work
    //also in URL we give database name also "myFirstDatabase" in our case here which we replacing by "shop"
  )
    .then(client => {
      console.log("Connected!");
      _db = client.db(); //can explicitly pass db name here if not passed it will take default one
      //given in URL while connecting above.
      callback();
    })
    .catch(err => {
      console.log(err);
      throw err;
    })
};

const getDb = () => {
  if(_db){
    return _db;
  }
  throw "No database found!";
}

exports.mongoConnect = mongoConnect;
exports.getDb = getDb;
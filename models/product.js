const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const productSchema = new Schema({
  title:{
    type: String,
    required: true
  },
  price:{
    type: Number,
    required: true
  },
  description:{
    type: String,
    required: true
  },
  imageUrl:{
    type: String,
    required: true
  },
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
});

module.exports = mongoose.model('Product', productSchema);
//first argument 'Product' will be used for creating collections
//all character will be converted to small case and also pluralised when
//creating colections when we make 1st "save" on this model


// const mongodb = require('mongodb');
// const getDb = require('../util/database').getDb;

// class Product {
//   constructor(title,price,description,imageUrl,id,userId){
//     this.title = title;
//     this.price = price;
//     this.description = description;
//     this.imageUrl = imageUrl;
//     this._id = id ? new mongodb.ObjectId(id) : null;
//     this.userId = userId;
//   }

//   save(){
//     const db = getDb();
//     let dbOperation;
//     if(this._id){
//       dbOperation = db.collection('products')
//         .updateOne({ _id : this._id }, {$set : this});
//     }
//     else{
//       dbOperation = db.collection('products').insertOne(this);
//     }
//     return dbOperation
//       .then(result => {
//         console.log(result);
//       })
//       .catch(err => {
//         console.log(err);
//       })
//   }

//   static fetchAll(){
//     const db = getDb();
//     return db.collection('products')
//       .find() //returns cursor which we should use to iterate over data
//       .toArray() //we are using it as we are sure that data is not large otherwise we have to 
//       //go with cursor only and implement pagination like thing.
//       .then(products => {
//         return products;
//       })
//       .catch(err => {
//         console.log(err);
//       })
//   }

//   static findById(prodId){
//     const db = getDb();
//     return db.collection('products')
//       .find({ _id : new mongodb.ObjectId(prodId)}) //mongoDb stores id as "_id" also it has special
//       //type "ObjectId('...')" which we have to keep in mind
//       .next() //method that will return last value executed by cursor
//       .then(product => {
//         console.log(product);
//         return product;
//       })
//       .catch(err => {
//         console.log(err);
//       })
//   }

//   static deleteById(prodId){
//     const db = getDb();
//     return db.collection('products')
//       .deleteOne({ _id : new mongodb.ObjectId(prodId)})
//       .then(result => {
//         console.log("deleted");
//       })
//       .catch(err => {
//         console.log(err);
//       })
//   }
// }

// module.exports = Product;

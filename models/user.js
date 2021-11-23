const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const userSchema = new Schema({
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  resetToken: String,
  resetTokenExpiration: Date,
  cart: {
    items: [{
      productId: { 
        type: Schema.Types.ObjectId,
        ref: 'Product', //'Product' is a name of model and "ref" is used to define relation
        required: true
      },
      quantity: {
        type: Number,
        required: true
      }
    }]
  }
});

//adding method to schema
//To Do:: add product to Cart
userSchema.methods.addToCart = function(product){ 
  const productCartIndex = this.cart.items.findIndex(prd => { //this here refers to model instance
    return prd.productId.toString() === product._id.toString();
    //OR return prd.productId == product._id; //as for javascript this ids works as a string
  });
  let newQuantity = 1;
  const updatedCartItems = [...this.cart.items];
  
  if(productCartIndex >= 0){
    newQuantity = updatedCartItems[productCartIndex].quantity + 1;
    updatedCartItems[productCartIndex].quantity = newQuantity;
  }
  else{
    updatedCartItems.push({
      productId: product._id, 
      quantity: newQuantity 
    })
  }

  const updatedCart = { items: updatedCartItems };
  this.cart = updatedCart;
  return this.save();
}

//To Do:: to remove item from cart
userSchema.methods.deleteCartItem = function(prodId){
  const updatedCartItems = this.cart.items.filter(item => {
    return item.productId.toString() !== prodId.toString();
  });

  this.cart.items = updatedCartItems;
  return this.save();
}

//To Do:: Clear the cart of user
userSchema.methods.clearCart = function(){
  this.cart = {
    items: []
  };
  return this.save();
}

module.exports = mongoose.model('User', userSchema);


// const mongodb = require('mongodb');
// const getDb = require('../util/database').getDb;

// const ObjectId = mongodb.ObjectId;

// class User {
//   constructor(username, email, cart, id){
//     this.username = username;
//     this.email = email;
//     this.cart = cart;
//     this._id = id;
//   }

//   save(){
//     const db = getDb();
//     return db.collection('users').insertOne(this);
//   }

//   addToCart(product){
//     const productCartIndex = this.cart.items.findIndex(prd => {
//       return prd.productId.toString() === product._id.toString();
//       //OR return prd.productId == product._id; //as for javascript this ids works as a string
//     });
//     let newQuantity = 1;
//     const updatedCartItems = [...this.cart.items];
    
//     if(productCartIndex >= 0){
//       newQuantity = updatedCartItems[productCartIndex].quantity + 1;
//       updatedCartItems[productCartIndex].quantity = newQuantity;
//     }
//     else{
//       updatedCartItems.push({
//         productId: new ObjectId(product._id), 
//         quantity: newQuantity 
//       })
//     }

//     const updatedCart = { items: updatedCartItems };
//     const db = getDb();
//     return db.collection('users')
//       .updateOne(
//         { _id: new ObjectId(this._id)},
//         { $set: {cart : updatedCart }}
//       );
//   }

//   getCart(){
//     const db = getDb();
//     const productIds = this.cart.items.map(item => {
//       return item.productId;
//     });

//     return db.collection('products')
//       .find({ _id: {$in : productIds} })
//       .toArray()
//       .then(products => {
//         return products.map(p => {
//           return {
//             ...p,
//             quantity: this.cart.items.find(item => {
//               return item.productId.toString() === p._id.toString();
//             }).quantity
//           };
//         })
//       })
//       .catch(err => console.log(err));
//   }

//   deleteCartItem(prodId){
//     const updatedCartItems = this.cart.items.filter(item => {
//       return item.productId.toString() !== prodId.toString();
//     });

//     const db = getDb();
//     return db.collection('users')
//       .updateOne(
//         { _id: new ObjectId(this._id)},
//         { $set: {"cart.items" : updatedCartItems }}
//       );
//   }

//   addOrder(){
//     const db = getDb();
//     return this.getCart()
//       .then(products => {
//         const order = {
//           items : products,
//           user: {
//             _id: new ObjectId(this._id),
//             name: this.username
//           }
//         };

//         return db.collection('orders')
//         .insertOne(order)
//         .then(result => {
//           this.cart = { items: [] };
//           return db.collection('users')
//             .updateOne(
//               { _id: new ObjectId(this._id) },
//               { $set: { cart: { items: [] } } }  
//             );
//         })
//       })
//       .catch(err => console.log(err));
//   }

//   getOrders(){
//     const db = getDb();
//     return db.collection('orders')
//       .find({ "user._id": new ObjectId(this._id) })
//       // .find({ user: { _id: new ObjectId(this._id) } })
//       .toArray()
//       .then(orders => {
//         console.log(orders);
//         return orders;
//       })
//       .catch(err => console.log(err));
//   }

//   static findById(userId){
//     const db = getDb();
//     return db.collection('users').findOne({ _id : new ObjectId(userId)});
//     //alternate way
//     // return db.collection('users')
//     //   .find({_id : new ObjectId(userId)})
//     //   .next()
//   }
// }

// module.exports = User;

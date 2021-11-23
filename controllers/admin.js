const Product = require('../models/product');

exports.getAddProduct = (req, res, next) => {
  res.render('admin/edit-product', {
    pageTitle: 'Add Product',
    path: '/admin/add-product',
    editing: false,
    isAuthenticated: req.session.isLoggedIn
  });
};

exports.postAddProduct = (req, res, next) => {
  const title = req.body.title;
  const imageUrl = req.body.imageUrl;
  const price = req.body.price;
  const description = req.body.description;
  
  //const product = new Product(title,price,description,imageUrl,null, req.user._id);
  //above code was used when working with mongoDb alone
  //below code is used when working with mongoDb + mongoose
  const product = new Product({
    title: title,
    imageUrl: imageUrl,
    description: description,
    price: price,
    // userId: req.user._id //can also write "req.user", mongoose will take _id by itself
    userId: req.user
  });

  product.save() //it will save details to database and "save" is a method given by mongoose
    .then(result => {
      // console.log(result);
      res.redirect('/admin/products');
    })
    .catch(err => {
      console.log(err);
    });
};

exports.getEditProduct = (req, res, next) => {
  const editMode = req.query.edit;
  if (!editMode) {
    return res.redirect('/');
  }
  const prodId = req.params.productId;
  Product.findById(prodId) //"findById" is a method given by mongoose
    .then(product => {
      if (!product) {
        return res.redirect('/');
      }
      res.render('admin/edit-product', {
        pageTitle: 'Edit Product',
        path: '/admin/edit-product',
        editing: editMode,
        product: product,
        isAuthenticated: req.session.isLoggedIn
      });
    })
    .catch(err => console.log(err));
};

exports.postEditProduct = (req, res, next) => {
  const prodId = req.body.productId;
  const updatedTitle = req.body.title;
  const updatedPrice = req.body.price;
  const updatedImageUrl = req.body.imageUrl;
  const updatedDesc = req.body.description;

  // const product = new Product(updatedTitle,updatedPrice,updatedDesc,updatedImageUrl,prodId);
  Product.findById(prodId)
    .then(product => { //product we get here is a mongoose object on which we can run it's functions
      if(product.userId.toString() !== req.user._id.toString()){
        return res.redirect('/');
      }

      product.title = updatedTitle;
      product.imageUrl = updatedImageUrl;
      product.description = updatedDesc;
      product.price = updatedPrice;

      return product.save() //"save" is method given by mongoose to run on models
      //and here "product" is model returned by mongoose in "Product.findById(prodId)"
        .then(result => {
          console.log('UPDATED PRODUCT!');
          res.redirect('/admin/products');
        })
    })
    .catch(err => console.log(err));
};

exports.getProducts = (req, res, next) => {
  // Product.fetchAll() //used while working with mongoDb alone
  Product.find({ userId: req.user._id })  //this gives list and not cursor like in mongoDb alone
    //"find" is a method give by mongoose to query data from collection
    
    //.select("title price -_id") //only bring specified fields from db and "-" is to specifically 
    //remove particular field, we are removing "_id" as even if not mentioned in list it
    //will come from database
    
    //.populate('userId', "name") //it is used to retrieve reference collection data and also
    //filter them 'userId' is the key which defines relation here
    
    .then(products => {
      res.render('admin/products', {
        prods: products,
        pageTitle: 'Admin Products',
        path: '/admin/products',
        isAuthenticated: req.session.isLoggedIn
      });
    })
    .catch(err => console.log(err));
};

exports.postDeleteProduct = (req, res, next) => {
  const prodId = req.body.productId;

  // Product.findByIdAndRemove(prodId)
  Product.deleteOne({_id: prodId, userId: req.user._id})
    .then(result => {
      console.log('DESTROYED PRODUCT');
      res.redirect('/admin/products');
    })
    .catch(err => console.log(err));
  //above code is for mongoDb + mongoose

  //below code is the case when we used mongoDb alone
  // Product.deleteById(prodId)
  //   .then(() => {
  //     console.log('DESTROYED PRODUCT');
  //     res.redirect('/admin/products');
  //   })
  //   .catch(err => console.log(err));
};

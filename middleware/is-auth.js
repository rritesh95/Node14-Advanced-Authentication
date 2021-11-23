module.exports = (req,res,next) => {
    if(!req.session.isLoggedIn){
        return res.redirect('/login');
    }
    //we can put above code in all controlers where we want to protect routes but
    //that will be too much, instead of that we createred middleware which we will
    //chain in every routes we want to protect, will call "next()" only when
    //session is created otherwise redirect to "/login" route
    next();
}
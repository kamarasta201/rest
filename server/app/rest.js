(function(){if (Meteor.isClient) {
  Router.route('/', function () {

  });

  Accounts.ui.config({
    passwordSignupFields: "USERNAME_ONLY"
  });
}

Post = new Mongo.Collection('posts');

if (Meteor.isServer) {

  // Global API configuration
  Restivus.configure({
    useAuth: true,
    prettyJson: true
  });

  Restivus.addCollection(Post);
}

})();

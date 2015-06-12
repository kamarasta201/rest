(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var check = Package.check.check;
var Match = Package.check.Match;
var _ = Package.underscore._;
var Router = Package['iron:router'].Router;
var RouteController = Package['iron:router'].RouteController;
var Iron = Package['iron:core'].Iron;

/* Package-scope variables */
var Restivus, __coffeescriptShare;

(function () {

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                               //
// packages/nimble:restivus/lib/restivus.coffee.js                                                               //
//                                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                 //
__coffeescriptShare = typeof __coffeescriptShare === 'object' ? __coffeescriptShare : {}; var share = __coffeescriptShare;
var          
  __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
  __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

this.Restivus = (function() {
  function Restivus() {
    this.configure = __bind(this.configure, this);
    this.routes = [];
    this.config = {
      paths: [],
      useAuth: false,
      apiPath: 'api/',
      version: 1,
      prettyJson: false,
      auth: {
        token: 'services.resume.loginTokens.token',
        user: function() {
          return {
            userId: this.request.headers['x-user-id'],
            token: this.request.headers['x-auth-token']
          };
        }
      },
      onLoggedIn: function() {
        return {};
      },
      onLoggedOut: function() {
        return {};
      },
      useClientRouter: true,
      defaultHeaders: {
        'Content-Type': 'application/json'
      },
      enableCors: true
    };
    this.configured = false;
  }


  /**
    Configure the ReST API
  
    Must be called exactly once, from anywhere on the server.
   */

  Restivus.prototype.configure = function(config) {
    if (this.configured) {
      throw new Error('Restivus.configure() can only be called once');
    }
    this.configured = true;
    _.extend(this.config, config);
    if (this.config.enableCors) {
      _.extend(this.config.defaultHeaders, {
        'Access-Control-Allow-Origin': '*'
      });
    }
    if (this.config.apiPath[0] === '/') {
      this.config.apiPath = this.config.apiPath.slice(1);
    }
    if (_.last(this.config.apiPath) !== '/') {
      this.config.apiPath = this.config.apiPath + '/';
    }
    if (!this.config.useClientRouter && Meteor.isClient) {
      Router.options.autoStart = false;
    }
    _.each(this.routes, function(route) {
      return route.addToApi();
    });
    if (this.config.useAuth) {
      this._initAuth();
      console.log("Restivus configured at " + this.config.apiPath + " with authentication");
    } else {
      console.log("Restivus configured at " + this.config.apiPath + " without authentication");
    }
  };


  /**
    Add endpoints for the given HTTP methods at the given path
   */

  Restivus.prototype.addRoute = function(path, options, methods) {
    var route;
    route = new Route(this, path, options, methods);
    this.routes.push(route);
    if (this.configured) {
      route.addToApi();
    }
  };


  /**
    Generate routes for the Meteor Collection with the given name
   */

  Restivus.prototype.addCollection = function(collection, options) {
    var collectionEndpoints, collectionRouteEndpoints, endpointsAwaitingConfiguration, entityRouteEndpoints, excludedEndpoints, methods, methodsOnCollection, path, routeOptions;
    if (options == null) {
      options = {};
    }
    methods = ['get', 'post', 'put', 'delete', 'getAll', 'deleteAll'];
    methodsOnCollection = ['post', 'getAll', 'deleteAll'];
    if (collection === Meteor.users) {
      collectionEndpoints = this._userCollectionEndpoints;
    } else {
      collectionEndpoints = this._collectionEndpoints;
    }
    endpointsAwaitingConfiguration = options.endpoints || {};
    routeOptions = options.routeOptions || {};
    excludedEndpoints = options.excludedEndpoints || [];
    path = options.path || collection._name;
    collectionRouteEndpoints = {};
    entityRouteEndpoints = {};
    if (_.isEmpty(endpointsAwaitingConfiguration) && _.isEmpty(excludedEndpoints)) {
      _.each(methods, function(method) {
        if (__indexOf.call(methodsOnCollection, method) >= 0) {
          _.extend(collectionRouteEndpoints, collectionEndpoints[method].call(this, collection));
        } else {
          _.extend(entityRouteEndpoints, collectionEndpoints[method].call(this, collection));
        }
      }, this);
    } else {
      _.each(methods, function(method) {
        var configuredEndpoint, endpointOptions;
        if (__indexOf.call(excludedEndpoints, method) < 0 && endpointsAwaitingConfiguration[method] !== false) {
          endpointOptions = endpointsAwaitingConfiguration[method];
          configuredEndpoint = {};
          _.each(collectionEndpoints[method].call(this, collection), function(action, methodType) {
            return configuredEndpoint[methodType] = _.chain(action).clone().extend(endpointOptions).value();
          });
          if (__indexOf.call(methodsOnCollection, method) >= 0) {
            _.extend(collectionRouteEndpoints, configuredEndpoint);
          } else {
            _.extend(entityRouteEndpoints, configuredEndpoint);
          }
        }
      }, this);
    }
    this.addRoute(path, routeOptions, collectionRouteEndpoints);
    this.addRoute("" + path + "/:id", routeOptions, entityRouteEndpoints);
  };


  /**
    A set of endpoints that can be applied to a Collection Route
   */

  Restivus.prototype._collectionEndpoints = {
    get: function(collection) {
      return {
        get: {
          action: function() {
            var entity;
            entity = collection.findOne(this.urlParams.id);
            if (entity) {
              return {
                status: "success",
                data: entity
              };
            } else {
              return {
                statusCode: 404,
                body: {
                  status: "fail",
                  message: "Item not found"
                }
              };
            }
          }
        }
      };
    },
    put: function(collection) {
      return {
        put: {
          action: function() {
            var entity, entityIsUpdated;
            entityIsUpdated = collection.update(this.urlParams.id, this.bodyParams);
            if (entityIsUpdated) {
              entity = collection.findOne(this.urlParams.id);
              return {
                status: "success",
                data: entity
              };
            } else {
              return {
                statusCode: 404,
                body: {
                  status: "fail",
                  message: "Item not found"
                }
              };
            }
          }
        }
      };
    },
    "delete": function(collection) {
      return {
        "delete": {
          action: function() {
            if (collection.remove(this.urlParams.id)) {
              return {
                status: "success",
                data: {
                  message: "Item removed"
                }
              };
            } else {
              return {
                statusCode: 404,
                body: {
                  status: "fail",
                  message: "Item not found"
                }
              };
            }
          }
        }
      };
    },
    post: function(collection) {
      return {
        post: {
          action: function() {
            var entity, entityId;
            entityId = collection.insert(this.bodyParams);
            entity = collection.findOne(entityId);
            if (entity) {
              return {
                status: "success",
                data: entity
              };
            } else {
              ({
                statusCode: 400
              });
              return {
                status: "fail",
                message: "No item added"
              };
            }
          }
        }
      };
    },
    getAll: function(collection) {
      return {
        get: {
          action: function() {
            var entities;
            entities = collection.find().fetch();
            if (entities) {
              return {
                status: "success",
                data: entities
              };
            } else {
              return {
                statusCode: 404,
                body: {
                  status: "fail",
                  message: "Unable to retrieve items from collection"
                }
              };
            }
          }
        }
      };
    },
    deleteAll: function(collection) {
      return {
        "delete": {
          action: function() {
            var itemsRemoved;
            itemsRemoved = collection.remove({});
            if (itemsRemoved) {
              return {
                status: "success",
                data: {
                  message: "Removed " + itemsRemoved + " items"
                }
              };
            } else {
              return {
                statusCode: 404,
                body: {
                  status: "fail",
                  message: "No items found"
                }
              };
            }
          }
        }
      };
    }
  };


  /**
    A set of endpoints that can be applied to a Meteor.users Collection Route
   */

  Restivus.prototype._userCollectionEndpoints = {
    get: function(collection) {
      return {
        get: {
          action: function() {
            var entity;
            entity = collection.findOne(this.urlParams.id, {
              fields: {
                profile: 1
              }
            });
            if (entity) {
              return {
                status: "success",
                data: entity
              };
            } else {
              return {
                statusCode: 404,
                body: {
                  status: "fail",
                  message: "User not found"
                }
              };
            }
          }
        }
      };
    },
    put: function(collection) {
      return {
        put: {
          action: function() {
            var entity, entityIsUpdated;
            entityIsUpdated = collection.update(this.urlParams.id, {
              $set: {
                profile: this.bodyParams
              }
            });
            if (entityIsUpdated) {
              entity = collection.findOne(this.urlParams.id, {
                fields: {
                  profile: 1
                }
              });
              return {
                status: "success",
                data: entity
              };
            } else {
              return {
                statusCode: 404,
                body: {
                  status: "fail",
                  message: "User not found"
                }
              };
            }
          }
        }
      };
    },
    "delete": function(collection) {
      return {
        "delete": {
          action: function() {
            if (collection.remove(this.urlParams.id)) {
              return {
                status: "success",
                data: {
                  message: "User removed"
                }
              };
            } else {
              return {
                statusCode: 404,
                body: {
                  status: "fail",
                  message: "User not found"
                }
              };
            }
          }
        }
      };
    },
    post: function(collection) {
      return {
        post: {
          action: function() {
            var entity, entityId;
            entityId = Accounts.createUser(this.bodyParams);
            entity = collection.findOne(entityId, {
              fields: {
                profile: 1
              }
            });
            if (entity) {
              return {
                status: "success",
                data: entity
              };
            } else {
              ({
                statusCode: 400
              });
              return {
                status: "fail",
                message: "No user added"
              };
            }
          }
        }
      };
    },
    getAll: function(collection) {
      return {
        get: {
          action: function() {
            var entities;
            entities = collection.find({}, {
              fields: {
                profile: 1
              }
            }).fetch();
            if (entities) {
              return {
                status: "success",
                data: entities
              };
            } else {
              return {
                statusCode: 404,
                body: {
                  status: "fail",
                  message: "Unable to retrieve users"
                }
              };
            }
          }
        }
      };
    },
    deleteAll: function(collection) {
      return {
        "delete": {
          action: function() {
            var usersRemoved;
            usersRemoved = collection.remove({});
            if (usersRemoved) {
              return {
                status: "success",
                data: {
                  message: "Removed " + usersRemoved + " users"
                }
              };
            } else {
              return {
                statusCode: 404,
                body: {
                  status: "fail",
                  message: "No users found"
                }
              };
            }
          }
        }
      };
    }
  };


  /*
    Add /login and /logout endpoints to the API
   */

  Restivus.prototype._initAuth = function() {
    var self;
    self = this;

    /*
      Add a login endpoint to the API
    
      After the user is logged in, the onLoggedIn hook is called (see Restfully.configure() for adding hook).
     */
    this.addRoute('login', {
      authRequired: false
    }, {
      post: function() {
        var auth, e, user;
        user = {};
        if (this.bodyParams.user.indexOf('@') === -1) {
          user.username = this.bodyParams.user;
        } else {
          user.email = this.bodyParams.user;
        }
        try {
          auth = Auth.loginWithPassword(user, this.bodyParams.password);
        } catch (_error) {
          e = _error;
          return {
            statusCode: e.error,
            body: {
              status: "error",
              message: e.reason
            }
          };
        }
        if (auth.userId && auth.authToken) {
          this.user = Meteor.users.findOne({
            '_id': auth.userId,
            'services.resume.loginTokens.token': auth.authToken
          });
          this.userId = this.user._id;
        }
        self.config.onLoggedIn.call(this);
        return {
          status: "success",
          data: auth
        };
      }
    });

    /*
      Add a logout endpoint to the API
    
      After the user is logged out, the onLoggedOut hook is called (see Restfully.configure() for adding hook).
     */
    return this.addRoute('logout', {
      authRequired: true
    }, {
      get: function() {
        var authToken;
        authToken = this.request.headers['x-auth-token'];
        Meteor.users.update(this.user._id, {
          $pull: {
            'services.resume.loginTokens': {
              token: authToken
            }
          }
        });
        self.config.onLoggedOut.call(this);
        return {
          status: "success",
          data: {
            message: 'You\'ve been logged out!'
          }
        };
      }
    });
  };

  return Restivus;

})();

Restivus = new this.Restivus;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                               //
// packages/nimble:restivus/lib/route.coffee.js                                                                  //
//                                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                 //
__coffeescriptShare = typeof __coffeescriptShare === 'object' ? __coffeescriptShare : {}; var share = __coffeescriptShare;
this.Route = (function() {
  function Route(api, path, options, endpoints) {
    this.api = api;
    this.path = path;
    this.options = options;
    this.endpoints = endpoints;
    if (!this.endpoints) {
      this.endpoints = this.options;
      this.options = {};
    }
  }

  Route.prototype.addToApi = function() {
    var fullPath, self;
    self = this;
    if (_.contains(this.api.config.paths, this.path)) {
      throw new Error("Cannot add a route at an existing path: " + this.path);
    }
    this._resolveEndpoints();
    this._configureEndpoints();
    this.api.config.paths.push(this.path);
    fullPath = this.api.config.apiPath + this.path;
    return Router.route(fullPath, {
      where: 'server',
      action: function() {
        var method, responseData;
        this.urlParams = this.params;
        this.queryParams = this.params.query;
        this.bodyParams = this.request.body;
        this.done = (function(_this) {
          return function() {
            return _this._responseInitiated = true;
          };
        })(this);
        responseData = null;
        method = this.request.method;
        if (self.endpoints[method.toLowerCase()]) {
          _.extend(this, self.endpoints[method.toLowerCase()]);
          responseData = self._callEndpoint(this, self.endpoints[method.toLowerCase()]);
        } else {
          responseData = {
            statusCode: 404,
            body: {
              status: "error",
              message: 'API endpoint not found'
            }
          };
        }
        if (responseData === null || responseData === void 0) {
          throw new Error("Cannot return null or undefined from an endpoint: " + method + " " + fullPath);
        }
        if (this.response.headersSent && !this._responseInitiated) {
          throw new Error("Must call this.done() after handling endpoint response manually: " + method + " " + fullPath);
        }
        if (this._responseInitiated) {
          this.response.end();
          return;
        }
        if (responseData.body && (responseData.statusCode || responseData.headers)) {
          return self._respond(this, responseData.body, responseData.statusCode, responseData.headers);
        } else {
          return self._respond(this, responseData);
        }
      }
    });
  };


  /*
    Convert all endpoints on the given route into our expected endpoint object if it is a bare function
  
    @param {Route} route The route the endpoints belong to
   */

  Route.prototype._resolveEndpoints = function() {
    _.each(this.endpoints, function(endpoint, method, endpoints) {
      if (_.isFunction(endpoint)) {
        return endpoints[method] = {
          action: endpoint
        };
      }
    });
  };


  /*
    Configure the authentication and role requirement on an endpoint
  
    Once it's globally configured in the API, authentication can be required on an entire route or individual
    endpoints. If required on an entire route, that serves as the default. If required in any individual endpoints, that
    will override the default.
  
    After the endpoint is configured, all authentication and role requirements of an endpoint can be accessed at
    <code>endpoint.authRequired</code> and <code>endpoint.roleRequired</code>, respectively.
  
    @param {Route} route The route the endpoints belong to
    @param {Endpoint} endpoint The endpoint to configure
   */

  Route.prototype._configureEndpoints = function() {
    _.each(this.endpoints, function(endpoint) {
      var _ref, _ref1;
      if (!((_ref = this.options) != null ? _ref.roleRequired : void 0)) {
        this.options.roleRequired = [];
      }
      if (!endpoint.roleRequired) {
        endpoint.roleRequired = [];
      }
      endpoint.roleRequired = _.union(endpoint.roleRequired, this.options.roleRequired);
      if (_.isEmpty(endpoint.roleRequired)) {
        endpoint.roleRequired = false;
      }
      if (!this.api.config.useAuth) {
        endpoint.authRequired = false;
      } else if (endpoint.authRequired === void 0) {
        if (((_ref1 = this.options) != null ? _ref1.authRequired : void 0) || endpoint.roleRequired) {
          endpoint.authRequired = true;
        } else {
          endpoint.authRequired = false;
        }
      }
    }, this);
  };


  /*
    Authenticate an endpoint if required, and return the result of calling it
  
    @returns The endpoint response or a 401 if authentication fails
   */

  Route.prototype._callEndpoint = function(endpointContext, endpoint) {
    if (this._authAccepted(endpointContext, endpoint)) {
      if (this._roleAccepted(endpointContext, endpoint)) {
        return endpoint.action.call(endpointContext);
      } else {
        return {
          statusCode: 401,
          body: {
            status: "error",
            message: "You do not have permission to do this."
          }
        };
      }
    } else {
      return {
        statusCode: 401,
        body: {
          status: "error",
          message: "You must be logged in to do this."
        }
      };
    }
  };


  /*
    Authenticate the given endpoint if required
  
    Once it's globally configured in the API, authentication can be required on an entire route or individual
    endpoints. If required on an entire endpoint, that serves as the default. If required in any individual endpoints, that
    will override the default.
  
    @returns False if authentication fails, and true otherwise
   */

  Route.prototype._authAccepted = function(endpointContext, endpoint) {
    if (endpoint.authRequired) {
      return this._authenticate(endpointContext);
    } else {
      return true;
    }
  };


  /*
    Verify the request is being made by an actively logged in user
  
    If verified, attach the authenticated user to the context.
  
    @returns {Boolean} True if the authentication was successful
   */

  Route.prototype._authenticate = function(endpointContext) {
    var auth, userSelector;
    auth = this.api.config.auth.user.call(endpointContext);
    if (!(auth != null ? auth.user : void 0) && (auth != null ? auth.userId : void 0) && (auth != null ? auth.token : void 0)) {
      userSelector = {};
      userSelector._id = auth.userId;
      userSelector[this.api.config.auth.token] = auth.token;
      auth.user = Meteor.users.findOne(userSelector);
    }
    if (auth != null ? auth.user : void 0) {
      endpointContext.user = auth.user;
      endpointContext.userId = auth.user._id;
      return true;
    } else {
      return false;
    }
  };


  /*
    Authenticate the user role if required
  
    Must be called after _authAccepted().
  
    @returns True if the authenticated user belongs to <i>any</i> of the acceptable roles on the endpoint
   */

  Route.prototype._roleAccepted = function(endpointContext, endpoint) {
    if (endpoint.roleRequired) {
      if (_.isEmpty(_.intersection(endpoint.roleRequired, endpointContext.user.roles))) {
        return false;
      }
    }
    return true;
  };


  /*
    Respond to an HTTP request
   */

  Route.prototype._respond = function(endpointContext, body, statusCode, headers) {
    var defaultHeaders;
    if (statusCode == null) {
      statusCode = 200;
    }
    if (headers == null) {
      headers = {};
    }
    defaultHeaders = this._lowerCaseKeys(this.api.config.defaultHeaders);
    headers = this._lowerCaseKeys(headers);
    headers = _.extend(defaultHeaders, headers);
    if (headers['content-type'].match(/json|javascript/) !== null) {
      if (this.api.config.prettyJson) {
        body = JSON.stringify(body, void 0, 2);
      } else {
        body = JSON.stringify(body);
      }
    }
    endpointContext.response.writeHead(statusCode, headers);
    endpointContext.response.write(body);
    return endpointContext.response.end();
  };


  /*
    Return the object with all of the keys converted to lowercase
   */

  Route.prototype._lowerCaseKeys = function(object) {
    return _.chain(object).pairs().map(function(attr) {
      return [attr[0].toLowerCase(), attr[1]];
    }).object().value();
  };

  return Route;

})();
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                               //
// packages/nimble:restivus/lib/auth.coffee.js                                                                   //
//                                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                 //
__coffeescriptShare = typeof __coffeescriptShare === 'object' ? __coffeescriptShare : {}; var share = __coffeescriptShare;
var getUserQuerySelector, userValidator;

this.Auth || (this.Auth = {});


/*
  A valid user will have exactly one of the following identification fields: id, username, or email
 */

userValidator = Match.Where(function(user) {
  check(user, {
    id: Match.Optional(String),
    username: Match.Optional(String),
    email: Match.Optional(String)
  });
  if (_.keys(user).length === !1) {
    throw new Match.Error('User must have exactly one identifier field');
  }
  return true;
});


/*
  Return a MongoDB query selector for finding the given user
 */

getUserQuerySelector = function(user) {
  if (user.id) {
    return {
      '_id': user.id
    };
  } else if (user.username) {
    return {
      'username': user.username
    };
  } else if (user.email) {
    return {
      'emails.address': user.email
    };
  }
  throw new Error('Cannot create selector from invalid user');
};


/*
  Log a user in with their password
 */

this.Auth.loginWithPassword = function(user, password) {
  var authToken, authenticatingUser, authenticatingUserSelector, passwordVerification, _ref;
  if (!user || !password) {
    return void 0;
  }
  check(user, userValidator);
  check(password, String);
  authenticatingUserSelector = getUserQuerySelector(user);
  authenticatingUser = Meteor.users.findOne(authenticatingUserSelector);
  if (!authenticatingUser) {
    throw new Meteor.Error(403, 'User not found');
  }
  if (!((_ref = authenticatingUser.services) != null ? _ref.password : void 0)) {
    throw new Meteor.Error(403, 'User has no password set');
  }
  passwordVerification = Accounts._checkPassword(authenticatingUser, password);
  if (passwordVerification.error) {
    throw new Meteor.Error(403, 'Incorrect password');
  }
  authToken = Accounts._generateStampedLoginToken();
  Meteor.users.update(authenticatingUser._id, {
    $push: {
      'services.resume.loginTokens': authToken
    }
  });
  return {
    authToken: authToken.token,
    userId: authenticatingUser._id
  };
};
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package['nimble:restivus'] = {
  Restivus: Restivus
};

})();

//# sourceMappingURL=nimble_restivus.js.map

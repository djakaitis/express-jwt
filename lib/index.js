const promisify = require("util").promisify;
const jwt = require("jsonwebtoken");
const UnauthorizedError = require("./errors/UnauthorizedError");
const unless = require("express-unless");
const set = require("lodash.set");

const verifyJwtAsync = promisify(jwt.verify);

const DEFAULT_REVOKED_FUNCTION = function(_, __, cb) {
  return cb(null, false);
};

function isFunction(object) {
  return Object.prototype.toString.call(object) === "[object Function]";
}

function wrapStaticSecretInCallback(secret) {
  return function(_, __, cb) {
    return cb(null, secret);
  };
}

module.exports = function(options) {
  if (!options || !options.secret) throw new Error("secret should be set");

  let secretCallback = options.secret;

  if (!isFunction(secretCallback)) {
    secretCallback = wrapStaticSecretInCallback(secretCallback);
  }

  const isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION;
  const isRevokedAsync = promisify(isRevokedCallback);

  const _requestProperty =
    options.userProperty || options.requestProperty || "user";

  const _resultProperty = options.resultProperty;

  const credentialsRequired =
    typeof options.credentialsRequired === "undefined"
      ? true
      : options.credentialsRequired;

  var middleware = async function(req, res, next) {
    var token;

    if (
      req.method === "OPTIONS" &&
      req.headers.hasOwnProperty("access-control-request-headers")
    ) {
      var hasAuthInAccessControl = !!~req.headers[
        "access-control-request-headers"
      ]
        .split(",")
        .map(function(header) {
          return header.trim();
        })
        .indexOf("authorization");

      if (hasAuthInAccessControl) {
        return next();
      }
    }

    if (options.getToken && typeof options.getToken === "function") {
      try {
        token = options.getToken(req);
      } catch (e) {
        return next(e);
      }
    } else if (req.headers && req.headers.authorization) {
      var parts = req.headers.authorization.split(" ");
      if (parts.length == 2) {
        var scheme = parts[0];
        var credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        } else {
          if (credentialsRequired) {
            return next(
              new UnauthorizedError("credentials_bad_scheme", {
                message: "Format is Authorization: Bearer [token]"
              })
            );
          } else {
            return next();
          }
        }
      } else {
        return next(
          new UnauthorizedError("credentials_bad_format", {
            message: "Format is Authorization: Bearer [token]"
          })
        );
      }
    }

    if (!token) {
      if (credentialsRequired) {
        return next(
          new UnauthorizedError("credentials_required", {
            message: "No authorization token was found"
          })
        );
      } else {
        return next();
      }
    }

    let dtoken;

    try {
      dtoken = jwt.decode(token, { complete: true }) || {};
    } catch (err) {
      return next(new UnauthorizedError("invalid_token", err));
    }

    //replace waterfall
    try {
      let secret = await getSecret(secretCallback);
      let decoded = await verifyTokenAsync(secret);
      await checkRevoked(req, decoded, isRevokedCallback);

      if (_resultProperty) {
        set(res, _resultProperty, result);
      } else {
        set(req, _requestProperty, result);
      }
      next();
    } catch (error) {
      return next(error);
    }

    async function getSecret() {
      var arity = secretCallback.length;
      if (arity == 4) {
        secretCallback(req, dtoken.header, dtoken.payload);
      } else {
        // arity == 3
        secretCallback(req, dtoken.payload);
      }
    }

    async function verifyTokenAsync(secret) {
      try {
        let decodedToken = await verifyJwtAsync(token, secret, options);
        return decodedToken;
      } catch (error) {
        throw new UnauthorizedError("invalid_token", error);
      }
    }

    async function checkRevoked(req, decoded) {
      try {
        let isRevoked = await isRevokedAsync(req, dtoken.payload);
        if (isRevoked) {
          throw new UnauthorizedError("revoked_token", {
            message: "The token has been revoked."
          });
        }
        return decoded;
      } catch (error) {
        throw new UnauthorizedError("invalid_token", error);
      }
    }
  };

  middleware.unless = unless;
  middleware.UnauthorizedError = UnauthorizedError;

  return middleware;
};

module.exports.UnauthorizedError = UnauthorizedError;

import NavigatorManagerV1 from "@ApiDomain/NavigatorManagerV1";
import UtilsManager, { RouterParamsUrl } from "@ApiUtils/UtilsManager";
import { ValidationToken } from "@ApiUtils/UtilsManager";
import LogJob from "@Jobs/LogJob";
import { NextFunction, Request, Response } from "express";

const InfoLogger = require("../api/utils/logger").InfoLogger;
const createError = require("http-errors");
const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const timeout = require("connect-timeout");
const cron = require("cron");
const app = express();
const constants = require("@Helpers/constants");

const jwt = require('jsonwebtoken');
const rutasProtegidas = express.Router();

// CORS Access
const cors = require("cors");
const allowedOrigins = ["http://10.0.56.8:8000", "https://app.swaggerhub.com", "http://localhost:8000", "https://www-prep-originh.carolinaherrera.com",
"http://www-prep-originh.carolinaherrera.com", "www-prep-originh.carolinaherrera.com",
"https://local-www-prep-originh.carolinaherrera.com", "http://local-www-prep-originh.carolinaherrera.com", "local-www-prep-originh.carolinaherrera.com",
"https://www-preph.carolinaherrera.com", "https://www.carolinaherrera.com", "http://www-preph.carolinaherrera.com", "www-preph.carolinaherrera.com", 
"http://local-www-prep-originh.carolinaherrera.com:3000", "https://local-www-prep-originh.carolinaherrera.com:3000", "http://www-preph.jeanpaulgaultier.com", 
"https://www-preph.jeanpaulgaultier.com", "http://212.129.31.72", "https://212.129.31.72", "https://wwwh.jeanpaulgaultier.com",
"http://13.36.231.44", "https://13.36.231.44", "http://15.188.21.139", "https://15.188.21.139",
"http://13.36.149.169", "https://13.36.149.169", "http://13.36.57.152", "https://13.36.57.152", "http://13.37.43.46", "https://13.37.43.46", "https://www-stag.carolinaherrera.com"];

app.use(cors({
  origin: function(origin, callback){
    if (!origin) return callback(undefined, true);
    if (allowedOrigins.indexOf(origin) === -1){
      const msg = "The CORS policy for this site does not " +
                "allow access from the specified Origin.";
      return callback(new Error(msg), false);
    }
    return callback(undefined, true);
  },
  allowedHeaders: ["Content-Type", "token", "land", "brand"],
  exposedHeaders: ["token"]
}));

const os = require("os");
const hostname = os.hostname();
const utilsManager = new UtilsManager;
utilsManager.setConstantsEndpoint(hostname);

let timeOutvalue = process.env.TIMEOUT || "60s";
if (hostname.includes("ch-") || hostname.includes("stag")){
  timeOutvalue = "300s";
}
app.use(timeout(timeOutvalue));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(haltOnTimedout);
app.use(express.static(path.join(__dirname, "public")));
app.use(helmet());

// Patch proxy issue
app.use(function (req, res, next) {
  if (req.url.includes("//")) {
    req.url = req.url.replace("//", "/");
  }
  next();
});

function signToken(paramsSign: any) {
  return jwt.sign(paramsSign.payload, paramsSign.llave, {
    algorithm: "HS256", // default
    expiresIn: 30
  });
}

app.use("/:v2?/register", async (req: Request, res: Response) => {
  const { user, pass } = req.body;
  if(user === "asfo" && pass === "holamundo") {
    const payload = {
      user
    };
    
    const token = signToken({payload, llave: constants.llave, algorithm: 'HS256', expiresIn: 30});
    console.log("Token creado - ", new Date().toLocaleString());

    return res.status(200).send({
      message: 'Authentication OK',
      token: token
    });    
  } else {
    return res.status(401).send({ error: "User or password wrong"})
  }
});

rutasProtegidas.use((req: Request | any, res: Response, next: NextFunction) => {
  // const token = req.headers['access-token'] || req.headers['authorization'];
  const token = req.headers['authorization'];
  const { user } = req.body;

  if(!token) {
    return res.status(401).send({ error: "You have not provided a token, if you have not one, go to /register in order to get it"});
  }

  if(!token.includes("Bearer")) {
    return res.status(401).send({ error: "You are not using json web token authorization, please use this one for every request !!!"});
  }

  const tokenBearer = token.replace("Bearer", "").trim();

  if (tokenBearer) {
    // jwt.verify(tokenBearer, constants.llave, (err, decoded) => {      
    //   if (err) {
    //     // return res.send({ message: 'Token expired or invalid. Go to /register to get a new token'  });
    //     return res.send({ error: { name: err.name, message: err.message }});
    //   } else {
    //     req.decoded = decoded;    
    //     next();
    //   }
    // });

    jwt.verify(tokenBearer, constants.llave, (err, decoded) => {      
      if (err) {
        // return res.send({ message: 'Token expired or invalid. Go to /register to get a new token'  });

        // refresh token
        if(err.name === 'TokenExpiredError' && err.message === 'jwt expired') {
          signToken({payload: {user}, llave: constants.llave, algorithm: 'HS256', expiresIn: "15m"});
          console.log("Token renovado - ", new Date().toLocaleString());
          req.decoded = decoded;    
          return next();
        }
        return res.send({ error: { name: err.name, message: err.message }});
      }
    });
  } else {
    return res.send({ 
        mensaje: 'Token missed !!! Go to /register to get a new token' 
    });
  }
});

app.use(rutasProtegidas);

// NEW ROUTER NAVIGATORMANAGERV1
const navigatorManagerV1 = new NavigatorManagerV1();
app.use("/:v2?/products", ValidationToken, RouterParamsUrl, navigatorManagerV1.productManager.routerProduct);
app.use("/:v2?/users/:userId/addresses", ValidationToken, RouterParamsUrl, navigatorManagerV1.addressesManager.routerAddresses);
app.use("/:v2?/game", ValidationToken, RouterParamsUrl, navigatorManagerV1.gameManager.routerGame);
app.use("/:v2?/miscs", ValidationToken, RouterParamsUrl, navigatorManagerV1.miscManager.routerMisc);
app.use("/:v2?/token", RouterParamsUrl, navigatorManagerV1.tokenManager.routerToken);
app.use("/:v2?/users/:userId/wishlist", ValidationToken, RouterParamsUrl, navigatorManagerV1.wishlistManager.routerWishlist);
app.use("/:v2?/users/:userId/orders", ValidationToken, RouterParamsUrl, navigatorManagerV1.ordersManager.routerOrders);
app.use("/:v2?/users/:userId/cards", ValidationToken, RouterParamsUrl, navigatorManagerV1.cardManager.routerCard);
app.use("/:v2?/users/:userId/notifications", ValidationToken, RouterParamsUrl, navigatorManagerV1.userNotificationsManager.routerNotifications);
app.use("/:v2?/catalogs", ValidationToken, RouterParamsUrl, navigatorManagerV1.catalogManager.routerCatalog);
app.use("/:v2?/users/:userId/carts/:cartId/paypal", ValidationToken, RouterParamsUrl, navigatorManagerV1.paypalManager.routerPayPal);
app.use("/:v2?/users/:userId/carts", ValidationToken, RouterParamsUrl, navigatorManagerV1.cartsManager.routerCarts);
app.use("/:v2?/users/:userId/bundletemplates", ValidationToken, RouterParamsUrl, navigatorManagerV1.bundleManager.routerBundle);
app.use("/:v2?/bundletemplate", ValidationToken, RouterParamsUrl, navigatorManagerV1.bundleProductManager.routerBundleProduct)
app.use("/:v2?/stores", ValidationToken, RouterParamsUrl, navigatorManagerV1.storesManager.routerStores);
app.use("/:v2?/subscription", ValidationToken, RouterParamsUrl, navigatorManagerV1.subcriptionManager.routerSubcription);
app.use("/:v2?/promotions", ValidationToken, RouterParamsUrl, navigatorManagerV1.promotionsManager.routerPromotions);
app.use("/:v2?/logs", navigatorManagerV1.logsManager.routerLogs);
app.use("/:v2?/users", ValidationToken, RouterParamsUrl, navigatorManagerV1.userGigyaUuidManager.routerGygia);
app.use("/:v2?/z_services", RouterParamsUrl, navigatorManagerV1.zServicesManager.routerZServices);
app.use("/:v2?/export", ValidationToken, RouterParamsUrl, navigatorManagerV1.exportManager.routerExport);
app.use("/:v2?/cms", ValidationToken, RouterParamsUrl, navigatorManagerV1.cmsManager.routerCms);
app.use("/:v2?/notifications", ValidationToken, RouterParamsUrl, navigatorManagerV1.notificationsManager.routerNotifications);
app.use("/:v2?/notifications/email", ValidationToken, RouterParamsUrl, navigatorManagerV1.mailingManager.routerMailing);
app.use("/:v2?/puigproperties", ValidationToken, RouterParamsUrl, navigatorManagerV1.puigProperties.routerPuigProperties);
app.use("/:v2?/validate", ValidationToken, RouterParamsUrl, navigatorManagerV1.validations.routerValidate);
app.use("/:v2?/installments",ValidationToken, RouterParamsUrl, navigatorManagerV1.installmentsManager.routerInstallments);

app.use(haltOnTimedout);

app.set("cronStatus", true);
const logJob = new LogJob(navigatorManagerV1.utilsManager);
const job = cron.job("15 03 * * *", () => {
  if (app.get("cronStatus") == true) {
    logJob.clearDisabledLogs();
  }
});

job.start();

// catch 404 and forward to error handler
app.use(function (req: Request, res: Response, next: NextFunction) {
  next(createError(404));
});

// error handler
app.use(function (err: any, req: Request, res: Response, next: NextFunction) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  InfoLogger.error(err.message);
  res.locals.error = req.app.get("env") === "dev" ? err : {};
  // render the error page
  res.status(err.status || 500).json({ error: err || "Internal Server Error"});
});

function haltOnTimedout(req, res, next) {
  if (!req.timedout) next();
}

module.exports = app;
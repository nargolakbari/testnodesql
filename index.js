// inspired from:
// https://medium.com/@nitesh_17214/how-to-create-oidc-client-in-nodejs-b8ea779e0c64
// https://stackabuse.com/adding-authentication-to-express-with-passport/
//
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const passport = require("passport");
const http = require("http"); // used by: createServer
const path = require("path");
const dotenv = require("dotenv");
const fs = require("fs");
var showconsentflag = false; //showmyconsent is not called
var jsonflag = false; //there is no json file
//read config from a local file called ".env"
const ENV_FILE = path.join(__dirname, ".env");
dotenv.config({ path: ENV_FILE });

// securestorage for transactions like double opt-in etc that cannot be handled by POST or session
// first in local filesystem, TODO implement in blob storage(S3) or database for better scalability
const securestorage = "securestorage"; // directory - needs to be created
if (!fs.existsSync(`${securestorage}`)) {
  fs.mkdirSync(`${securestorage}`);
}
if (!fs.existsSync(`${securestorage}/open`)) {
  fs.mkdirSync(`${securestorage}/open`);
}
if (!fs.existsSync(`${securestorage}/done`)) {
  fs.mkdirSync(`${securestorage}/done`);
}
// -- done with secure securestorage prep

// https://nodemailer.com/smtp/
// check-out https://www.npmjs.com/package/nodemailer-smime -- 4years old -- MIT license -- Nodemailer plugin to sign mail using S/MIME
// based on https://www.npmjs.com/package/node-forge (17Mio downloads/week ! ) > https://github.com/digitalbazaar/forge
var nodemailer = require("nodemailer");

const consentfileName = "confirmconsent.html";
const consentfileData = fs.readFileSync(consentfileName, "utf8");
// secure: process.env.smtpsecure || process.env.SMTPSECURE || false, // upgrade later with STARTTLS
const transporter = nodemailer.createTransport({
  host: process.env.smtphost || process.env.SMTPHOST || "smtp.gmail.com",
  port: process.env.smtpport || process.env.SMTPPORT || 587,
  secure: (boolean =
    process.env.SMTPSECURE == null ? false : process.env.SMTPSECURE === "true"),
  auth: {
    user: process.env.smtpuser || process.env.SMTPUSER || "changeme",
    pass: process.env.smtppass || process.env.SMTPPASS || "changeme",
  },
});
// -- done with mailer preperation

// npm install node-fetch@2.6 (was before: npm install node-fetch@2.0 but this has critical vulerabilities)
//
// As of version 3.0, node-fetch is an ESM-only module - you are not able to import it with require().
// If you don't use ESM yourself, it's advised to stay on version 2.0 instead of the latest one, in which case you can use the standard
// require() syntax.import fetch from 'node-fetch';
// Note: The API between node-fetch 3.0 and 2.0 is the same, just the import differs. > now: import fetch from 'node-fetch';
const fetch = require("node-fetch");

const { Issuer, Strategy } = require("openid-client");
const { XMLParser } = require("fast-xml-parser");
// const { stringify } = require("querystring"); // ??? no idea where this comes from !
// const { XMLParser, XMLBuilder, XMLValidator} = require('fast-xml-parser');
// const parser = XMLParser;

const shuiheader = `<!DOCTYPE html>
<html lang="en">

<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta charset="utf-8">
  <title>Siemens Healthineers Consent Management Demonstrator</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- import shui -->
  <script type="text/javascript" crossorigin="anonymous" charset="utf-8" src="https://sorry.citizens4digital.com/shui1211/shui.min.js"></script>
  <link rel="stylesheet" crossorigin="anonymous" type="text/css" href="https://sorry.citizens4digital.com/shui1211/shui-styles.css">
  <script type="text/javascript" crossorigin="anonymous" charset="utf-8" src="https://sorry.citizens4digital.com/abc/scripts/helpers.js"></script>
</head>

<body id="mainBody">
<sh-page id="shuipage">
<!-- access bar -->
<sh-access-bar slot="access" label="Consent Management Demo">
    <sh-tabs slot="tabs">
      <sh-tab-item icon="compass-direction-w" name="demo" label="Demo" active onclick="toggleTheme()"></sh-tab-item>
    </sh-tabs>
    <sh-user-identifier id="userid" slot="user" unauthenticated name="Sign In / Register" onclick="location.href='/login?dis=no'")></sh-user-identifier>
</sh-access-bar>

<!-- browser page -->
<sh-card label="" state="card-1" page="browser">`;

const shuifooter = `<sh-divider spacing="xl"></sh-divider>
<sh-text>Siemens Healthcare GmbH ©2023 <A HREF="https://www.siemens-healthineers.com/corporate/siemens-website-privacy-policy">Web Consent Portal Privacy Policy</A></sh-text></sh-card>
</sh-page>
</body>
</html>`;

var body;
var consenttempname = [];
var consenttempdate = [];
var consenttempversion = [];
var consenttemptype = [];
var email = "";
var listofdomain = [];
var domainnamelist = [];
var signerproperties = [];
var modulename = [];
var domaintemparray = []; //this is a 2D matrix
var globaltemplate="";
var globaltemplateversion="";
var globaldomain="";
var username = "";
var fieldlist=[];// keeps the name of consent field names
var fieldlistvalues=[];
var modulename = [];
var moduleversion = [];
var domainsignerids = [];
var signeridtypenames = [];
var signeridtypvalues = [];

const app = express();

app.use(cookieParser());
app.use(
  express.urlencoded({
    extended: true,
  })
);

app.use(express.json({ limit: "15mb" }));
app.use(
  session({ secret: "cmsecret", resave: false, saveUninitialized: true })
);
app.use(helmet());
app.use(passport.initialize());
app.use(passport.session());

// https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize
// serializeUser determines which data of the user object should be stored in the session.
// The result of the serializeUser method is attached to the session as req.session.passport.user = {}.
// Here for instance, it would be (as we provide the user id as the key) req.session.passport.user = {id: 'xyz'}

passport.serializeUser(function (user, done) {
  console.log("-----------------------------");
  console.log("serialize user");
  console.log(user);
  console.log("-----------------------------");
  done(null, user);
});
passport.deserializeUser(function (user, done) {
  console.log("-----------------------------");
  console.log("deserialize user");
  console.log(user);
  console.log("-----------------------------");
  done(null, user);
});

Issuer.discover(process.env.OIDCSRVR).then(function (oidcIssuer) {
  var client = new oidcIssuer.Client({
    client_id: process.env.CLIENTID,
    client_secret: process.env.CLIENTSECRET,
    redirect_uris: [process.env.CLIENTRURI], // *** change here to localhost:3000 for local testing
    response_types: ["code"],
  });

  passport.use(
    "oidc",
    new Strategy(
      { client, passReqToCallback: true },
      (req, tokenSet, userinfo, done) => {
        console.log("tokenSet", tokenSet);
        console.log("userinfo", userinfo);
        req.session.tokenSet = tokenSet;
        req.session.userinfo = userinfo;
        return done(null, tokenSet.claims());
      }
    )
  );
});

app.use(function (req, res, next) {
  res.setHeader(
    "Content-Security-Policy",
    "script-src 'self' localhost:* https://sorry.citizens4digital.com/"
  );
  return next();
});

app.use("/static", express.static(path.join(__dirname, "public")));
// app.use(express.static('public'))
// app.use(express.static('static'))
// express.mime.type['js'] = 'video/ogg'; // klappt nicht
// express.mime.type['css'] = 'video/ogg';

app.get(
  "/login",
  function (req, res, next) {
    console.log("-----------------------------");
    console.log("/Start login handler");
    next();
  },
  passport.authenticate("oidc", { scope: "openid" })
);

app.get("/login/callback", (req, res, next) => {
  passport.authenticate("oidc", {
    successRedirect: "/showmyconsents",
    failureRedirect: "/",
  })(req, res, next);
});

///getconsetsofemail

// var finalbody = `<sh-text size='header-1'> please select Permission Form </sh-text>`;
app.get("/mac", (req, res) => {
  res.send(`${shuiheader}<P>
   <UL>
   <LI><a href='/login'>Log In with OpenID connect Provider</a> (will soon move into upper right corner: Sign in/Register)</LI>
   </UL>
   <sh-text size='header-1'>  select Permission Form to add a Consent </sh-text>
   <UL>
   <LI><a href='/macPF/MAC02/Individual_PF_EN01'>Individual_PF_EN</a> - simple form - consent for MAC team</LI>
   <LI><a href='/macPF/MAC02/Individual_PF_EN01'>Individual_PF_DE</a> - adding soon</LI>
   <LI><a href='/macPF/MAC02/Individual_PF_EN01'>CPF_Grant_of_Rights_EN</a> - adding soon</LI>
   <LI><a href='/macPF/MAC02/Individual_PF_EN01'>CPF_Grant_of_Rights_DE</a> - adding soon</LI>
   <LI><a href='/macPF/MAC02/Individual_PF_EN01'>CPF_Data_Privacy_Consent_EN_to_be_adapted_for_every_customer</a> - adding soon</LI>
   <LI><a href='/macPF/MAC02/Individual_PF_EN01'>CPF_Data_Privacy_Consent_DE_to_be_adapted_for_every_customer</a> - adding soon</LI>
   </UL>

   <sh-text size='header-1'>  use link below to search consents </sh-text>

   <UL>
   <LI><a href='/macsearch/MAC02'>search in MAC domain</a> - simple form for search Permission Forms </LI>
   </UL>
   </P>${shuifooter}`);
});



function test002(req, res) {
  res.send(`${shuiheader}<P>
   Hello from function test002
   </P>${shuifooter}`);
}
app.get("/test002", (req, res) => test002(req, res));

function test003() {
  return `<P>Hello from function test003</P>`;
}
app.get("/test003", (req, res) => {
  const message = test003();
  res.send(`${shuiheader}${message}${shuifooter}`);
});




//____________________________________________________
//____________________________________________________

///_______________list domain / name of service : listDomains ________________
app.get("/showmyconsents", (req, res) => {
  domainnamelist = [];
  showconsentflag = false; //defult value tell us we have jsonfile and showmyconsent doesn't call createsignerdomainlist(req,res)
  console.log("/user - req.session = ", req.session);
  signerproperties = []; //be sure this array is empty
  username = JSON.stringify(req.session.passport.user.preferred_username);
  //  username ="berta@kabeq.com";

  //let sumlist=[];
  var s = username;
  if (s.length > 2) {
    s = s.substring(0, s.length - 1); // remove double quotes
    s = s.substring(1);
  }

  username = s;
  email = username; // the value of email

  //******************
  let fileExists = fs.existsSync("signeremaildomains.json");
  console.log("signeremaildomains.json exists:", fileExists);

  if (!fileExists) {
    //if there is no signeremaildomains.json
    fs.open("signeremaildomains.json", "w", function (err, file) {
      if (err) throw err;
      showconsentflag = true;
      console.log("a blank json file was created!"); //it creates a blank file
      createsignerdomainlist(req, res); //writing process starts
    });
  } else {
    // we have json file and start to  gathering information and get all consents
    starttogetconsent(req, res);
  }
});

//_________________________________________________________
app.get("/updatejsonfile", (req, res) => {
  showconsentflag = false;
  createsignerdomainlist(req, res);
});
//_________________________________________________________

function createsignerdomainlist(req, res) {
  //
  //this function create a jsonfile which includes domains and signeridtype: email properties
  function listalldomain() {
    const customPromise = new Promise((resolve, reject) => {
      // var gicsreturn = 'error';
      var gicscall = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cm2="http://cm2.ttp.ganimed.icmvc.emau.org/">
          <soapenv:Header/>
          <soapenv:Body>
              <cm2:listDomains/>
          </soapenv:Body>
          </soapenv:Envelope>`;

      console.log("call:", gicscall); // Print the call for debug

      fetch(process.env.GICSSRVR, {
        method: "post",
        body: gicscall,
        headers: { "content-type": "text/xml;charset=UTF-8" },
      })
        .then((res) => {
          return res.text();
        })
        .then((text) => {
          const parser = new XMLParser();
          const gicsreturn = parser.parse(text);

          console.log("test string :" + JSON.stringify(gicsreturn));
          const payload =
            gicsreturn["soap:Envelope"]["soap:Body"]["ns2:listDomainsResponse"]
              .return;
          console.log("type of signer or singer: " + typeof payload.domains);
          var domainnamelist = [];
          var hi = typeof payload.domains;
          //  let multidomain = Array.isArray(payload.domains);

          if (Array.isArray(payload.domains)) {
            payload.domains.forEach(
              (domain) => {
                domainnamelist.push(domain.name);
                console.log("domain name  " + domain.name);                
              }
            );

          } else {
            // there is one domain
            domainnamelist.push(payload.domains.name);
          }
          resolve(domainnamelist);
        }); // end of no-error block

      // else {
      //    reject(new Error('Call to server somehow failed ' + response.statusCode))
      // }

      // }) // end of request.post()
    });

    return customPromise;
  }

  function getsignertype(domainname) {
    // this is a general function to get each domain signertypes properties but right now we just select email
    const customPromise = new Promise((resolve, reject) => {
      // var gicsreturn = 'error';
      var gicscall = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cm2="http://cm2.ttp.ganimed.icmvc.emau.org/">
        <soapenv:Header/>
        <soapenv:Body>
        <cm2:listSignerIdTypes>
            <domainName>${domainname}</domainName>
        </cm2:listSignerIdTypes>
        </soapenv:Body>
        </soapenv:Envelope>`;

      console.log("call:", gicscall); // Print the call for debug
      fetch(process.env.GICSSRVR, {
        method: "post",
        body: gicscall,
        headers: { "content-type": "text/xml;charset=UTF-8" },
      })
        .then((res) => {
          return res.text();
        })
        .then((text) => {
          const parser = new XMLParser();
          const gicsreturn = parser.parse(text); // ["soap:Envelope"]["soap:Body"]; // remove Envelope and Body

          console.log("test string :" + JSON.stringify(gicsreturn));
          const payload =
            gicsreturn["soap:Envelope"]["soap:Body"][
              "ns2:listSignerIdTypesResponse"
            ].return;
          console.log("type of singer :" + typeof payload.sinerIdTypes);
          var domainsignerids = [];

          var hi = typeof payload.sinerIdTypes;
          // let multisignertype = Array.isArray(payload.sinerIdTypes);

          if (Array.isArray(payload.sinerIdTypes)) {
            payload.sinerIdTypes.forEach(
              (sinerIdType) => {
                if (sinerIdType.name === "email" || sinerIdType.name === "Email") {
                  // currently we need just email as signerIDtype
                  domainsignerids.push(value5.name); // type of signerid here is email/Email
                  domainsignerids.push(value5.fhirID);
                  domainsignerids.push(value5.createTimestamp);
                }               
              }
            );

          } else {
            // there is one signeridtype
            if (
              payload.sinerIdTypes.name === "email" ||
              payload.sinerIdTypes.name === "Email"
            ) {
              domainsignerids.push(payload.sinerIdTypes.name); //type of signer here is email/Email
              domainsignerids.push(payload.sinerIdTypes.fhirID);
              domainsignerids.push(payload.sinerIdTypes.createTimestamp);
            }
          }
          resolve(domainsignerids);
        }); // end of fetch-then-then

      // else {
      //     reject(new Error('Call to server somehow failed ' + response.statusCode))
      //  }
      // }) // end of request.post
    });

    return customPromise;
  }
  const uselist = async () => {
    // this function collect all properties of signerID Type :email for each domain in a 2D matrix

    var mylist = listofdomain;
    var i = 0;
    domainnamelist = [];
    for (const item of mylist) {
      const propertylist = await getsignertype(item); //
      var info = propertylist.length;

      // signerproperties[i]=propertylist;// a row includes : type (email) , fhirID , creationtime
      if (info !== 0) {
        signerproperties[i] = propertylist;
        domainnamelist.push(item); //domain name
        i++;
      }
      console.log("list of email type properties: " + propertylist);
    }
  };

  const createjson = async () => {
    //this function write a json file include name of domain and properties of signerIDtype(email)

    var numdomain = domainnamelist.length;
    domainindex = 0;
    var myjs = "";
    if (numdomain > 1) {
      myjs += `{
          "domainsigner": {"return":{
              "domains": [
            `;
      for (const item of domainnamelist) {
        myjs += `{"name": "${item}",
            "signeridtype": 
                {
                    "name": "email",
                    "fhirID": "${signerproperties[domainindex][1]}",
					"createTimestamp": "${signerproperties[domainindex][2]}"
                }          
        }`;

        if (domainindex !== numdomain - 1) {
          myjs += `,`;
        }
        domainindex++;
      }
      myjs += `]}}}`;
    }
    // else : there is one doamin that has email as signeridType
    else {
      myjs = `{
        "domainsigner": {"return":{
            "domains": 
            {
                "name": "${domainnamelist[0]}",
                "signeridtype": 
                    {
                        "name": "email",
                        "fhirID": "${signerproperties[0][1]}",
                        "createTimestamp": "${signerproperties[0][2]}"
                    }          
            } 
    }}}`;
    }

    console.log("json file content: " + myjs);
    jsondata = myjs; //data transfer to gelobal variable
  };

  //________________________________________________________________________

  listalldomain() // get list of all domains
    .then((data) => {
      listofdomain = data;
      console.log("this is a list of domains: " + listofdomain);
    })
    .then((newData) => {
      console.log("calling function to get signeridType : email  properties ");
      return uselist(); //calling function to get signeridType : email  properties
    })

    .then(() => {
      console.log(
        "this is a list of domains which have email signertype: " +
          domainnamelist
      );
    })
    .then(() => {
      return createjson();
    })
    .then(() => {
      let fileExists = fs.existsSync("signeremaildomains.json");
      console.log("signeremaildomains.json exists:", fileExists);
      //if there is no signeremaildomains.json , it creates a blank file
      if (!fileExists) {
        fs.open("signeremaildomains.json", "w", function (err, file) {
          if (err) throw err;
          console.log("a blank json file was created!");
        });
      }
      var result = "";
      // should we use writeFileSync here ?
      fs.writeFile("./signeremaildomains.json", jsondata, (err) => {
        if (err) {
          throw err;
        } else {
          console.log("Data written successfully to json file");
          //  if this function called from url : showmyconsents
          if (showconsentflag) {
            starttogetconsent(req, res);
          } // if yes start to collect info and make response
          else {
            //this function called from url updatejsonfile and
            console.log("****jsonfile was updated*****");
            result = "Data written successfully to json file";
            var finishjob = `<sh-text size='body-1' color="primary">${result}</sh-text>`;
            res.send(`${shuiheader}${finishjob}${shuifooter}`); // we want to keep going  in the chain
          }
        }
      });
    });
}

function starttogetconsent(req, res) {
  var i = 0;
  domainnamelist = [];
  //console.log("/user - req.session = ", req.session);
  signerproperties = []; //be sure this array is empty
  const readjson = require("./signeremaildomains");
  const payload = readjson["domainsigner"].return;
  //let multidomain = Array.isArray(payload.domains);
  if (!Array.isArray(payload.domains)) {
    console.log("there is one domain with signertype email");
    console.log(payload.domains.name);
    domainnamelist.push(payload.domains.name); // extract name of domain //  domainnamelist is a global list
    domainsignerids = [];
    domainsignerids.push(payload.domains.signeridtype.name); // extract properties of signeriftype: email
    domainsignerids.push(payload.domains.signeridtype.fhirID);
    domainsignerids.push(payload.domains.signeridtype.createTimestamp);

    signerproperties[i] = domainsignerids; //signerproperties is global array
    console.log("fhirID for check: " + domainsignerids[1]);
  } 
  else {
    console.log("there are more than one domains with signertype email");
    var domainnum = payload.domains.length;

    payload.domains.forEach((element) => {
      // var formElement = `<label for="${element.label}">${element.label}:</label><input type="text" id="${element.label}" name="${element.label}" ${setRequired}><br><br>`;
      console.log(element.name);
      domainnamelist.push(element.name); // extract name of domain //  domainnamelist is a global list
      domainsignerids = [];
      domainsignerids.push(element.signeridtype.name); // extract properties of signeriftype: email
      domainsignerids.push(element.signeridtype.fhirID);
      domainsignerids.push(element.signeridtype.createTimestamp);

      signerproperties[i] = domainsignerids; //signerproperties is global array
      console.log("fhirID for check:" + domainsignerids[1]);
      i++;
    });
  }
  // ________start of getAllConsentsForSignerIds/ name of service :getAllConsentsForSignerIds ________________________

  function getconsentofsigner(
    dname,
    signerfhirid,
    sigertime,
    signervalue,
    signertyp
  ) {
    // special type  is email/Email

    const customPromise = new Promise((resolve, reject) => {
      var gicscall = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
  xmlns:cm2="http://cm2.ttp.ganimed.icmvc.emau.org/">
  <soapenv:Header/>
      <soapenv:Body>
          <cm2:getAllConsentsForSignerIds>
              <domainName>${dname}</domainName>
              <signerIds>
                  <fhirID>${signerfhirid}</fhirID>
                  <creationDate>${sigertime}</creationDate>
                  <id>${signervalue}</id>
                  <idType>${signertyp}</idType>
                  <orderNumber>1</orderNumber>
              </signerIds>
          </cm2:getAllConsentsForSignerIds>
      </soapenv:Body>
  </soapenv:Envelope>`;

      // const moptions = {
      // method: 'POST',
      // json: false,
      // uri: process.env.GICSSRVR,
      // body: gicscall,
      // headers: {
      //  'Authorization': 'Bearer ' + ' token',
      //     'content-type': 'text/xml;charset=UTF-8'
      // }
      // };
      //_________variables ___________________________________
      // var modulepart="";
      // var moduleindex; //this list keep module's index  and use for policy list & check lists arrays
      // var domainname = "";
      consenttempdate = [];
      consenttemptype = [];
      consenttempname = [];
      consenttempversion = [];

      console.log("call:", gicscall); // Print the call for debug
      // caution - from here we have an async call which waits in server response
      // request.post(moptions, (error, response, body ) => {
      //    if (!error && response.statusCode < 300) {
      //    gicsreturn2 = body;
      //    gicsreturn = body;
      //    console.log('body:', gicsreturn ); // Print the response for debug
      // res.json(response.statusCode, body);
      body = "";
      // const parser = new XMLParser();
      // gicsreturn = parser.parse(gicsreturn);
      fetch(process.env.GICSSRVR, {
        method: "post",
        body: gicscall,
        headers: { "content-type": "text/xml;charset=UTF-8" },
      })
        .then((res) => {
          return res.text();
        })
        .then((text) => {
          const parser = new XMLParser();
          const gicsreturn = parser.parse(text); // ["soap:Envelope"]["soap:Body"]; // remove Envelope and Body

          console.log("test string :" + JSON.stringify(gicsreturn));
          const payload =
            gicsreturn["soap:Envelope"]["soap:Body"][
              "ns2:getAllConsentsForSignerIdsResponse"
            ].return;
          if (payload === "") {
            console.log(
              `there is no consent for ${signervalue} in domain:${dname} `
            );
            resolve(true);
          } else {
            // we have a real payload

            console.log("this is payload :" + payload);
            // let multiconsent = Array.isArray(payload.consents);
            if (Array.isArray(payload.consents)) {
              console.log("there is more than one consent for this person  :");
              for (const key in payload.consents) {
                if (payload.consents.hasOwnProperty(key)) {
                  const value = payload.consents[key];
                  consenttempdate.push(value.consentDates.legalConsentDate);
                  console.log(
                    "consenttempdate is  :" +
                      value.consentDates.legalConsentDate
                  );

                  consenttemptype.push(value.templateType);
                  console.log("consenttemptype :" + value.templateType);
                  consenttempname.push(value.key.consentTemplateKey.name);
                  console.log(
                    "consenttempname :" + value.key.consentTemplateKey.name
                  );
                  consenttempversion.push(value.key.consentTemplateKey.version);
                  console.log(
                    "version :" + value.key.consentTemplateKey.version
                  );
                }
              }
            } else {
              console.log("there is one consent for this person :");
              const value = payload.consents;
              consenttempdate.push(value.consentDates.legalConsentDate);
              console.log(
                "consenttempdate is  :" + value.consentDates.legalConsentDate
              );

              consenttemptype.push(value.templateType);
              console.log("consenttemptype :" + value.templateType);
              consenttempname.push(value.key.consentTemplateKey.name);
              console.log(
                "consenttempname :" + value.key.consentTemplateKey.name
              );
              consenttempversion.push(value.key.consentTemplateKey.version);
              console.log("version :" + value.key.consentTemplateKey.version);
            }
          }
          resolve(true);
        }); // end of fetch-then-then
      // else
      // {
      //    reject(new Error('Call to server somehow failed ' + response.statusCode))
      // }
      // })
    });
    return customPromise;
  }
  // ________enf  of getAllConsentsForSignerIds________________________

  //___________extract all info about module and policies/ name of service : getConsentTemplate_____________________________
  function getallinfo(dname, temp, tversion) {
    const customPromise2 = new Promise((resolve, reject) => {
      var gicscall = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
xmlns:cm2="http://cm2.ttp.ganimed.icmvc.emau.org/">
<soapenv:Header/>
<soapenv:Body>
  <cm2:getConsentTemplate>
    <consentTemplateKey>
      <domainName>${dname}</domainName>
      <name>${temp}</name>
      <version>${tversion}</version>
    </consentTemplateKey>  
  </cm2:getConsentTemplate>
</soapenv:Body>
</soapenv:Envelope>`;

      // const options = {
      // method: 'POST',
      // json: false,
      // uri: process.env.GICSSRVR,
      // body: gicscall,
      // headers: {
      //  'Authorization': 'Bearer ' + ' token',
      // 'content-type': 'text/xml;charset=UTF-8'
      // }
      // };
      //_________variables ___________________________________
      // var modulepart="";
      var moduleindex; //this list keeps module's index  and use for policy list & check lists arrays
      fieldlist = [];
      modulename = [];
      var moduleversion = [];
      var modulemandatory = [];
      var modulelabel = [];
      var moduletext = [];
      var moduletitle = [];

      // var templatelabel=""; // VScode says ... unused
      // var tempolatetext="";
      // var templateheader="";
      // var templatefooter="";
      // var templatetitle="";
      let modulepolicies = [];

      console.log("call:", gicscall); // Print the call for debug
      // caution - from here we have an async call which waits in server response
      // request.post(options, (error, response, body ) => {
      // if (!error && response.statusCode < 300) {
      //   gicsreturn2 = body;
      //   gicsreturn = body;
      // console.log('body:', gicsreturn ); // Print the response for debug
      // res.json(response.statusCode, body);

      fetch(process.env.GICSSRVR, {
        method: "post",
        body: gicscall,
        headers: { "content-type": "text/xml;charset=UTF-8" },
      })
        .then((res) => {
          return res.text();
        })
        .then((text) => {
          const parser = new XMLParser();
          const gicsreturn = parser.parse(text); // ["soap:Envelope"]["soap:Body"]; // remove Envelope and Body
          // const gicsreturn = parser.parse (gicsreturn);

          console.log("test string :" + JSON.stringify(gicsreturn));
          // Error: cannot redeclare block-scoped variable 'payload'.ts(2451)
          // const payload = gicsreturn["soap:Envelope"]["soap:Body"]["ns2:getConsentTemplateResponse"].return;
          // try to fix:
          const payload =
            gicsreturn["soap:Envelope"]["soap:Body"][
              "ns2:getConsentTemplateResponse"
            ].return;
          body = "";

          console.log("template Label:" + payload.label);
          if (typeof  payload.label !== "undefined") {
            templatelabel = payload.label;
          }

          console.log(" template Title:" + payload.title);
          if (typeof payload.title !== "undefined") {
            templatetitle = payload.title;
          }
          console.log("Footer:" + payload.header);
          if (typeof payload.header !== "undefined") {
            templateheader = payload.header;
          }

          if (typeof payload.text !== "undefined") {
            tempolatetext = payload.text;
          }

          if (typeof payload.footer !== "undefined") {
            templatefooter = payload.footer;
          }
          console.log("Footer:" + payload.footer);

          console.log("created on    :" + payload.creationDate);
          console.log("lastupdated on :" + payload.updateDate);
          console.log("domain name: " + payload.key.domainName);
          // var domainame= payload.key.domainName;
          // var templatename=payload.key.name;
          var templateversion = payload.key.version;
          var mysrtversion = String(templateversion);
          var myintversion = Number(templateversion);
          if (myintversion % 1 == 0) {
            //check for natural number (int) because  version 1.0 will be converted to 1 and we don't want it
            mysrtversion += ".0";
          } // prepare version for saving in list
          templateversion = mysrtversion;
          console.log("key.name:       " + payload.key.name);
          console.log("key.version:    " + mysrtversion);

          console.log("== loop  modules ==");
          let multimodules = Array.isArray(payload.assignedModules);
          if (!multimodules) {
            //there is one module

            console.log(" orderNumber: " + payload.assignedModules.orderNumber);
            moduleindex = Number(payload.assignedModules.orderNumber);
            //  this index is used for save /access to policies and checkboxes

            /// checkboxs are not displayed  in final result , just for collecting info which can be useful for future

            console.log(
              "modulemandatory: " + payload.assignedModules.mandatory
            );
            modulemandatory.push(payload.assignedModules.mandatory);

            console.log(
              "modulemandatory: " + payload.assignedModules.module.key.name
            );
            modulename.push(payload.assignedModules.module.key.name);

            mysrtversion = String(payload.assignedModules.module.key.version);
            myintversion = Number(payload.assignedModules.module.key.version);
            if (myintversion % 1 == 0) {
              //check for natural number (int) because  version 1.0 will be converted to 1 and we don't want it
              mysrtversion += ".0";
            } // prepare version for saving in list
            console.log("moduleversion: " + mysrtversion);
            moduleversion.push(mysrtversion);

            console.log(
              "module label: " + payload.assignedModules.module.label
            );
            modulelabel.push(payload.assignedModules.module.label);

            console.log(" module text: " + payload.assignedModules.module.text);
            moduletext.push(payload.assignedModules.module.text);

            console.log(
              "module title: " + payload.assignedModules.module.title
            );
            moduletitle.push(payload.assignedModules.module.title);

            let multipolicies = Array.isArray(
              payload.assignedModules.module.assignedPolicies
            );
            modulepolicies[moduleindex] = [];
            if (!multipolicies) {
              //there is one policy
              console.log("************");
              console.log(
                "label of Policies: " +
                  payload.assignedModules.module.assignedPolicies.policy.label
              );
              modulepolicies[moduleindex].push(
                payload.assignedModules.module.assignedPolicies.policy.comment
              );
            } 
            else {// module has multiple policies
              payload.assignedModules.module.assignedPolicies.forEach(
                (assignedPolicy) => {                  
                  modulepolicies[moduleindex].push(assignedPolicy.policy.comment);                
                }
              );
            }
          } 
          else {
            // there are more than one modules
            for (const key in payload.assignedModules) {
              if (payload.assignedModules.hasOwnProperty(key)) {
                const value = payload.assignedModules[key];
                console.log("is is value");
                console.log(value);
                console.log("is is value", typeof value);

                console.log(" orderNumber: " + value.orderNumber);
                moduleindex = Number(value.orderNumber); // make it a 2D array , each row is beloged to one madule

                console.log(" value. mandatory: " + value.mandatory);
                modulemandatory.push(value.mandatory);

                var mukeyobjkey = value.module.key;
                console.log("key.moduleName: " + mukeyobjkey.name);
                modulename.push(mukeyobjkey.name);
                mysrtversion = String(mukeyobjkey.version);
                myintversion = Number(mukeyobjkey.version);
                if (myintversion % 1 == 0) {
                  //check for natural number (int) because after extract version 1.0 convert to 1
                  mysrtversion += ".0";
                }
                // prepare version for saving in list
                console.log("key.moduleversion: " + mysrtversion);
                moduleversion.push(mysrtversion);

                var modulevalus = value.module; //properties of module
                console.log(" label: " + modulevalus.label);
                modulelabel.push(modulevalus.label);

                console.log(" text: " + modulevalus.text);
                moduletext.push(modulevalus.text);

                console.log(" title: " + modulevalus.title);
                moduletitle.push(modulevalus.title);
                let multipolicies = Array.isArray(
                  payload.assignedModules.module.assignedPolicies);
                modulepolicies[moduleindex] = [];
                if (!multipolicies) {
                  //there is one policy              
                  console.log(
                    "label of Policies: " +
                      payload.assignedModules.module.assignedPolicies.policy.label
                  );
                  modulepolicies[moduleindex].push(
                    payload.assignedModules.module.assignedPolicies.policy.comment
                  );
                } 
                else {// module has multiple policies
                  payload.assignedModules.module.assignedPolicies.forEach(
                    (assignedPolicy) => {                  
                      modulepolicies[moduleindex].push(assignedPolicy.policy.comment);                
                    }
                  );
                }
              }
            }
          }

          //  _____________start to build the response body ___________________________

          // turn <div> into <b> if in title

          var payloadtitle = payload.title; // turn const into var to allow modifications
          //payloadtitle = payloadtitle.replace(/div>/gi, ""); // turn <div> into <b>
          payloadtitle = payloadtitle.replace(/(<([^>]+)>)/gi, '');
          body += `<sh-accordion arrow-invert flat label="${payloadtitle}">
  <sh-text size='body-1' color="primary">${payload.header}</sh-text>`;

          //__________module part_____________________________________________________________

          console.log(" part modulename.length body: ", modulename.length);
          for (var i = 0; i < modulename.length; i++) {
            //add madule names  and versions
            var mtitle = moduletitle[i];          
            if (typeof moduletitle[i] !== "undefined") {
              mtitle=mtitle.replace( /(<([^>]+)>)/gi, '');// remove html tag from title 
            }
            else {
              mtitle="";
            }           
            var mid = `<sh-text size='body-1' color="primary">Module title: ${mtitle}</sh-text>`;
            body += mid;
            console.log(" part of body: ", mid);

          
            var mtext = moduletext[i];
            if (typeof moduletext[i] !== "undefined") {
              mtext=mtext.replace( /(<([^>]+)>)/ig, '');// remove html tag from text 
            }
            else {
              mtext="";
            }

            var mid = `<sh-text size='body-1' color="primary"> ${mtext}</sh-text>`;

            body += mid;

            var mid = `<sh-text size='body-1' color="primary">list of module policies:</sh-text>`;

            body += mid;
            console.log(" part of body: ", mid);
            var mid = `<ol>`; //make a list
            body += mid;
            console.log(" part of body: ", mid);
            for (var j = 0; j < modulepolicies[i].length; j++) {
              body += `<li>${modulepolicies[i][j]}</li>`;
            }
            body += `</ol>`;
            body += `<sh-text size='body-1' color="primary">${payload.footer}</sh-text>
  <sh-text size='body-1' color="primary">Domain: ${dname} -- Template: ${temp} -- Version: ${tversion}</sh-text>`;
            body += `</sh-accordion> <hr>`; // draw a line
            console.log(" part of body: ", mid);
            resolve(body);
          }
        }); // end of server-call no-error

      // else { // "fetch" error handling is now inside of block - no longer in "else" here
      //  reject(new Error(' call to server somehow failed!'))
      // }
      // }) // end of request.post()
    });
    return customPromise2;
  }

  //__________________________ calling function PART __________________________________________________________

  //__________________________________get templates for specific email value in a our domain list__________________________
  const collectdt = async () => {
    var indexi = 0;
    var indexarray = 0;
    domaintemparray = [];
    var mylist = domainnamelist;
    for (const item of mylist) {
      //getconsentofsigner(dname,signerfhirid,sigertime,signervalue,signertyp) // email : is the value of email from textbox
      const answerreceived = await getconsentofsigner(
        item,
        signerproperties[indexi][1],
        signerproperties[indexi][2],
        email,
        signerproperties[indexi][0]
      );
      if (answerreceived) {
        // request was sent
        tempnames = consenttempname;
        if (typeof tempnames === "undefined") {
          //there is no consent of this person in that domain so go on
          var info = 0;
          indexi++;
        } else {
          // theres is a consent in that domain for that person so get information
          var info = tempnames.length;
          // the number of template for current domain

          for (var k = 0; k < info; k++) {
            var temporarylist = [];
            temporarylist.push(item); //name of domain
            temporarylist.push(consenttempname[k]);
            temporarylist.push(consenttemptype[k]);

            var mysrtversion = String(consenttempversion[k]);
            var myintversion = Number(consenttempversion[k]);
            if (myintversion % 1 == 0) {
              //check for natural number (int) because  version 1.0 will be converted to 1 and we don't want it
              mysrtversion += ".0";
            } // prepare version for saving in list
            temporarylist.push(mysrtversion);

            temporarylist.push(consenttempdate[k]);
            domaintemparray[indexarray] = temporarylist;
            indexarray++;
          }

          indexi++;
        }
      }
    }
  };
  // show all info
  const showinfo = async () => {
    var myindex = 0;
    allinfo = "";
    //permit=false;
    var mylist = domaintemparray;
    var alltuple = mylist.length;
    for (const item of mylist) {
      // tempbody: gratually collects information of template and it may for one person there are several consents of different (domain/template)
      const tempbody = await getallinfo(
        domaintemparray[myindex][0],
        domaintemparray[myindex][1],
        domaintemparray[myindex][3]
      );
      if (typeof tempbody !== "undefined" && tempbody !== "") {
        var s = domaintemparray[myindex][4];
        s = s.substring(0, s.length - 10);
        var dt = s.replace("T", " "); // create right format for date
        allinfo += `<sh-text size='body-1' color="primary">Date and Time of consent: ${dt}</sh-text>`;

        allinfo += tempbody;
        myindex++;
      }
    }
    if (myindex === alltuple) {
      var finalbody = `<sh-text size='header-1'> list of your consents </sh-text>`;
      var mid = "";
      finalbody += mid;
      finalbody += `<hr>`;
      finalbody += allinfo;
      res.send(`${shuiheader}${finalbody}${shuifooter}`);
    }
  };

  collectdt()
    .then(() => {
      return showinfo(); ///getallinfo(dname,temp,tversion)
      // console.log("this is body2: "+ body2);
    })
    .then(() => {
      console.log(" end of search for email: " + email);
    });
}
//_________________________________________________________
//_________________________________________________________

const httpServer = http.createServer(app);
httpServer.listen(process.env.port || process.env.PORT || 3000, function () {
  // console.log(`\n${ httpServer.name } listening to ${ httpServer.url }`);
  console.log(`Http Server Running on port ${process.env.PORT}`);
});
/////_____________________________________________________________

app.get( '/macPF/:domain/:template', (req, res) => {
var gicsreturn = 'error';
globaldomain=req.params.domain;
globaltemplate=req.params.template;
//var gicsreturn = 'error';
var gicscall = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cm2="http://cm2.ttp.ganimed.icmvc.emau.org/">
<soapenv:Header/>
<soapenv:Body>
   <cm2:listSignerIdTypes>
      <domainName>${globaldomain}</domainName>
   </cm2:listSignerIdTypes>
</soapenv:Body>
</soapenv:Envelope>`;

fetch( process.env.GICSSRVR, { 
  method: "post",
  body: gicscall,
  headers: { 'content-type': 'text/xml;charset=UTF-8' }
})
.then(res => { return res.text() } )
.then ( text => { 
    const parser = new XMLParser();
    const gicsreturn = parser.parse (text); // ["soap:Envelope"]["soap:Body"]; // remove Envelope and Body

    // const parser = new XMLParser();
    // gicsreturn = parser.parse(gicsreturn);

    console.log ( "test string :" + JSON.stringify(gicsreturn) ); 
    const payload =gicsreturn["soap:Envelope"]["soap:Body"]["ns2:listSignerIdTypesResponse"].return ;
    console.log ( "type of singer :" + typeof payload.sinerIdTypes ) ;
    signeridtypenames=[];
    

    if( Array.isArray(payload.sinerIdTypes)===true){//this checks that there are more than one signerID
        for (const key in payload.sinerIdTypes) {
            
                const value5 = payload.sinerIdTypes[key];
                    if (typeof value5 == 'object' ){
                    //
                    signeridtypenames.push(value5.name);}
            
        }
    }
  
           
        
     
     else{// there is one signerID
      signeridtypenames.push(payload.sinerIdTypes.name);
        }
     // end of call server
     
  

      
   // else {
   //   console.log('Call to server somehow failed ' + response.statusCode );
  //  }
    for(var y=0; y<signeridtypenames.length;y++){
        console.log("this is signerID: ", signeridtypenames[y]);

    }


  });



 //____________________________________________________extracting of signerIDs is finished ___________________________
  
  var gicscall = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
  xmlns:cm2="http://cm2.ttp.ganimed.icmvc.emau.org/">
  <soapenv:Header/>
   <soapenv:Body>
      <cm2:getCurrentConsentTemplate>
         <consentTemplateName>${req.params.template}</consentTemplateName>
         <domainName>${req.params.domain}</domainName>
      </cm2:getCurrentConsentTemplate>
   </soapenv:Body>
</soapenv:Envelope>`;

//_________variables ___________________________________
var modulepart="";
var moduleindex;//this list keep module's index  and use for policy list & check lists arrays
 fieldlist=[];
 modulename = [];
 var body ="";

var modulemandatory = [];
var modulelabel = [];
var moduletext = [];
var moduletitle = [];


var templateheader="";
var templatefooter="";
var templatetitle="";
let modulepolicies = [];
let modulecheckboxs= [];


var modulepart="";

 const substrde="Hiermit willige ich in die Erhebung und Verarbeitung meiner personenbezogenen Daten im oben genannten Rahmen und zu den oben genannten Zwecken ein.";
 const substren="I hereby consent to the collection and processing of my personal data as described herein.";

fetch( process.env.GICSSRVR, { 
  method: "post",
  body: gicscall,
  headers: { 'content-type': 'text/xml;charset=UTF-8' }
})
.then(res => { return res.text() } )
.then ( text => { 
    const parser = new XMLParser();
    const gicsreturn = parser.parse (text); // ["soap:Envelope"]["soap:Body"]; // remove Envelope and Body

  
      console.log ( "test string :" + JSON.stringify(gicsreturn) ); 
      const payload = gicsreturn["soap:Envelope"]["soap:Body"]["ns2:getCurrentConsentTemplateResponse"].return;

      console.log ( " template Title:" + payload.title ); 
      if(payload.title!=='undefined'){templatetitle=payload.title}
      //console.log ( "******" +  typeof(payload.header)  ); 
      
      console.log ( "template Header:" + payload.header ); 
     
      if(payload.header!=='undefined'){
        var checkde=false;//these flags use for special condition in consent form EN/DE  
        var checken=false;
        const str = payload.header;
       //if one of these sentences is included in header we remove that from header and convert it to checkbox
        if (str.includes(substrde)){  
                var checkde=true;
                
                const newstr = str.replace("Hiermit willige ich in die Erhebung und Verarbeitung meiner personenbezogenen Daten im oben genannten Rahmen und zu den oben genannten Zwecken ein.", "");
                templateheader=newstr;
           }
        else if(str.includes(substren)){
          var checken=true;
          const newstr = str.replace("I hereby consent to the collection and processing of my personal data as described herein.", "");
          templateheader=newstr;
        }
        else{templateheader=payload.header;}
        
        
        //console.log(p.replace('The quick brown fox jumps over', ''));

       // 
      }

      console.log ( "template Label:"  + payload.label );
      if( payload.label !=='undefined'){templatelabel= payload.label } 
      console.log ( "Text:"  + payload.text ); 
      if(payload.text !=='undefined'){tempolatetext=payload.text }

      if( payload.footer !=='undefined'){templatefooter= payload.footer } 
      console.log ( "Footer:" + payload.footer ); 

      console.log ( "created on    :" + payload.creationDate ); 
      console.log ( "lastupdated on :" + payload.updateDate ); 
      console.log ( "domain name: " + payload.key.domainName ); 
      var domainame= payload.key.domainName;
      var templatename=payload.key.name;
      var templateversion=payload.key.version;
      mysrtversion =String(templateversion);        
      myintversion=Number(templateversion);
      if (myintversion % 1 == 0){ //check for natural number (int) because  version 1.0 will be converted to 1 and we don't want it
          mysrtversion+=".0"} // prepare version for saving in list 
     globaltemplateversion=mysrtversion;
      console.log ( "key.name:       " + payload.key.name ); 
      console.log ( "key.version:    " + mysrtversion );


     console.log ( "== loop  modules ==");
     let result =  Array.isArray(payload.assignedModules);
        if (!Array.isArray(payload.assignedModules)){//there is one module
            
          
          moduleindex =0;       
          //  this index is used for save /access to policies and checkboxes

         
         modulemandatory.push(payload.assignedModules.mandatory);

       
          modulename.push(payload.assignedModules.module.key.name);

          var mysrtversion =String(payload.assignedModules.module.key.version);        
          var myintversion=Number(payload.assignedModules.module.key.version);
          if (myintversion % 1 == 0){ //check for natural number (int) because  version 1.0 will be converted to 1 and we don't want it
              mysrtversion+=".0"} // prepare version for saving in list 
          console.log( 'moduleversion: ' +mysrtversion );  
          moduleversion.push(mysrtversion);
  
          console.log( 'module label: ' + payload.assignedModules.module.label);
          modulelabel.push( payload.assignedModules.module.label);

          console.log( ' module text: ' + payload.assignedModules.module.text);
          moduletext.push(payload.assignedModules.module.text);

          console.log( 'module title: ' + payload.assignedModules.module.title);
          moduletitle.push(payload.assignedModules.module.title);

          let result2 =  Array.isArray(payload.assignedModules.module.assignedPolicies);
          modulepolicies[moduleindex]=[];
          if  (result2===false){//there is one policy
              console.log( '************');
              console.log ( "label of Policies: " +  payload.assignedModules.module.assignedPolicies.policy.label );
              modulepolicies[moduleindex].push(payload.assignedModules.module.assignedPolicies.policy.comment);
             

          }
          else{//there are more than one policy
            for (let i = 0; i < payload.assignedModules.module.assignedPolicies.length; i++) {
              console.log("this is a object of policy"+ payload.assignedModules.module.assignedPolicies[i]);
              for (const key in payload.assignedModules.module.assignedPolicies[i]){
                if (payload.assignedModules.module.assignedPolicies[i].hasOwnProperty(key)){
                  const value4 = payload.assignedModules.module.assignedPolicies[i][key];
                  if (typeof value4 == 'object' ){
                    console.log( ' *********** ');
                    console.log( ' policy object: ', value4);
                    console.log( ' policy label: ', value4.label);
                    modulepolicies[moduleindex].push(value4.comment)
                }

                }

              }
            }
        
          }
          
        }
        else{// there are more than one modules
          modulename=[];
          moduleversion=[];
          modulelabel=[];
          moduletitle=[];

            for (const key in payload.assignedModules) {
                if (payload.assignedModules.hasOwnProperty(key)) {
                    const value = payload.assignedModules[key];
                    console.log("is is value");
                    console.log(value);
                    console.log("is is value", typeof value);

                    console.log( ' orderNumber: ' + value. orderNumber);
                    moduleindex=Number(value. orderNumber);// make it a 2D array , each row is beloged to one madule
                    modulecheckboxs[moduleindex]=[];                  
                    console.log( ' value. mandatory: ' +  value. mandatory);
                    modulemandatory.push(value. mandatory);


                    var mukeyobjkey=value.module.key;
                    console.log( 'key.moduleName: ' + mukeyobjkey.name);
                    modulename.push(mukeyobjkey.name);
                    var mysrtversion =String(mukeyobjkey.version)        
                    var myintversion=Number(mukeyobjkey.version)
                        if (myintversion % 1 == 0){ //check for natural number (int) because after extract version 1.0 convert to 1
                            mysrtversion+=".0"}
                            // prepare version for saving in list      
                    console.log( 'key.moduleversion: ' + mysrtversion);
                    moduleversion.push(mysrtversion);

                    var modulevalus=value.module;//properties of module
                    console.log( ' label: ' + modulevalus.label);
                    modulelabel.push(modulevalus.label);

                    console.log( ' text: ' + modulevalus.text);
                    moduletext.push(modulevalus.text);


                    console.log( ' title: ' + modulevalus.title);
                    moduletitle.push(modulevalus.title);
                    modulepolicies[moduleindex]=[];
                    if(typeof value.module.assignedPolicies.policy === 'undefined'){//nested object = arrays of objects 
                       
                      console.log("the number of policies: " + value.module.assignedPolicies.length);
                      for (let i = 0; i < value.module.assignedPolicies.length; i++) {
                        console.log("this is a object of policy"+ value.module.assignedPolicies[i]);
                        for (const key in value.module.assignedPolicies[i]){
                          if (value.module.assignedPolicies[i].hasOwnProperty(key)){
                            const value4 = value.module.assignedPolicies[i][key];
                            if (typeof value4 == 'object' ){
                              console.log( ' *********** ');
                              console.log( ' policy object :  ', value4);
                              console.log( ' policy label ', value4.label);
                              
                              modulepolicies[moduleindex].push(value4.comment);
                          }                  
          
                          }
          
                        }
                      }
                  
                    }
                    else{//if module have one policy
                      for (const key in value.module.assignedPolicies){
                        if (value.module.assignedPolicies.hasOwnProperty(key)){                        
                            var value3=value.module.assignedPolicies[key];
                            if (typeof value3 == 'object' ){
                                console.log( ' *********** ');
                                console.log( ' policy label: ', value3.label);
                                modulepolicies[moduleindex].push(value3.comment);}
                            }
                        }
                    }
                }
            }
        }
                
 
  //  _____________start to build your request body with filled consent form ___________________________


      var body = `<sh-text size='header-1'>Welcome to addconsent</sh-text>
      <sh-text size='body-1' color="primary"></sh-text>
      <form  
      action="/maccolleague" method="post">`;


      body+=`<br>`;
      ///<label for="templatetitle">template title: </label>///<label for="templateheader">template header: </label>
    
      var s=templatetitle;
      body+=`<label for="templatetitle">${templatetitle}</label><br>`;


      var setRequired =" ";
      fieldlist=[];
      formElement="";
      if (payload.freeTextDefs!=='undefined'){//body +=modulepart;
          payload.freeTextDefs.forEach (element => {
              console.log ( "Element Label:"  + element.name );
              fieldlist[element.pos] =element.name //preserve the orders of fields 
              });
             // fieldposition.push(element.pos);
            }
  
        for(var k=0 ;k<fieldlist.length; k++){
          if (fieldlist[k].includes("birth")){
            body += `<label for="${fieldlist[k]}">${fieldlist[k]}:</label>
            <input type="text" id="${fieldlist[k]}" placeholder="yyyy-mm-dd" value=""
            min="1997-01-01" max="2030-12-31" name="${fieldlist[k]}"></input><br><br>`
            //var formElement = `<label for="${fieldlist[k]}">${fieldlist[k]}:</label><input type="date" id="${fieldlist[k]}" name="${fieldlist[k]}" ${setRequired}><br><br>`;
                 // body +=formElement;

          }//type="date" id="birthday" name="birthday"
          else{var formElement = `<label for="${fieldlist[k]}">${fieldlist[k]}:</label><input type="text" id="${fieldlist[k]}" name="${fieldlist[k]}" ${setRequired}><br><br>`;
          body +=formElement;
          console.log ( "form element:"  + formElement);}

           }
      var s=templateheader;
      body+=`<label for="templateheader">${templateheader}</label><br><br>`;
    //  console.log ( "checkde*:"  + checkde);
    //  console.log ( "substrde*:"  + substrde);
     

      console.log( ' part modulename.length body: ', modulename.length);
      for(var i=0;i<modulename.length;i++){//add madule names  and versions 
        
       // var mid=`<label for="Module name">Module name: </label><label for="Module name">${modulename[i]}</label><br><br>`;
      ///  console.log( ' part of body: ', mid);
     
       var mtext = moduletext[i];
       if (typeof moduletext[i] !== "undefined") {
         mtext=mtext.replace( /(<([^>]+)>)/ig, '');// remove html tag from text 
       }
       else {
         mtext="";
       }

      // var mid=`<label for="Module test">Module text:</label><label for="Moduletext">${mtext}</label><br>`;
    // body+=mid;
   
      //var mid=`<label for"modulepolicies">module policies:</label>`;
      body+= `<label><input type="checkbox" name="csharp" value="ACCEPTED" required> <strong>Hereby I consent to the my personal data might be used for the following purposes</strong></label>`
      // 
    

       console.log( ' part of body: ', mid);
      var mid=`<ol>`; //make a list
      body+=mid;
      console.log( ' part of body: ', mid);   
      for(var j=0; j<modulepolicies[i].length; j++){
          body+=`<li>${modulepolicies[i][j]}</li>`;

      }
      body+=`</ol>`; 
       

     
        console.log( ' part of body: ', mid);
 
         
        // this script allows for just one checked item in a group of module 
       
        
    }
  
  //  body+=` <hr>`; 
    //_________________end of module and it's policies ____________________________________    
    var s=templatefooter;
    body+=`<label for="templatefooter">${templatefooter}</label><br><br>`;
    
   /* body+=`<sh-text size='header-1'>this part is completed by MAC Colleagues </sh-text>
  <sh-text size='body-1' color="primary"></sh-text>`;// draw a line
    for(var k=signeridtypenames.length-1; k>=0; k--){
      var signerelement =  `<label for="${signeridtypenames[k]}">${signeridtypenames[k]}:</label><input type="text" id="${signeridtypenames[k]}" name="${signeridtypenames[k]}" ${setRequired}><br><br>`;
      body += signerelement;
      
    }*/
   
     body+=` <hr>`;// draw a line

      const enfofboy= `<input id = "Submit" type="submit" value="Submit">
    </form>`;
       body +=enfofboy
       console.log ( "sow me body:"  + body);
      
    
    
    console.log('******************* ' +`${shuiheader}${body}${shuifooter}` );
    res.send(`${shuiheader}${body}${shuifooter}`)
  })
    //var body = htmldocopen + '</head><body><H1>hello from /zeinab</H1><div><pre>' + gicsreturn + '</pre></div></body></html>';

 
  console.log('THIS MESSAGE will NOT wait for request to return !!! be aware ! ');
}); 
///+++++++++++++++++++++++++++++++++++++++++++++++++++++
app.post("/maccolleague",(req,res) => {
  fieldlistvalues=[];
  for(var h=0; h<fieldlist.length;h++)
{

    var fieldnam= String(fieldlist[h]);
    fieldlistvalues.push(req.body[fieldnam])
    

}
 setRequired="";
  var body = `<sh-text size='header-1'>this part is completed by MAC Colleagues </sh-text>
  <sh-text size='body-1' color="primary"></sh-text>
  <form  
  action="/searchconsent" method="post">`;
  body+=` <hr>`;// draw a line
  var Inspector =  `<label for="Inspector">Inspector:</label><input type="text" id="Inspector" name="Inspector" ${setRequired}><br><br>`;
  body += Inspector;
  for(var k=signeridtypenames.length-1; k>=0; k--){
      var signerelement =  `<label for="${signeridtypenames[k]}">${signeridtypenames[k]}:</label><input type="text" id="${signeridtypenames[k]}" name="${signeridtypenames[k]}" ${setRequired}><br><br>`;
      body += signerelement;
      
    }
    console.log ( "signer element&&&&:"  + body);
    body += `<input id = "Submit" type="submit" value="Submit">
      </form>`;
        
         console.log ( "sow me body:"  + body);

      console.log('******************* ' +`${shuiheader}${body}${shuifooter}` );
      res.send(`${shuiheader}${body}${shuifooter}`)

})
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//searchconsent
app.post("/searchconsent",(req,res) => {
    
    var now = new Date().toISOString();//myintversion
   
  ///___________________________
 // console.log("bodddydddyyyyyyyyyyyy: " + req.body); 
  var mid="";
  var addgicscall = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
    xmlns:cm2="http://cm2.ttp.ganimed.icmvc.emau.org/">
    <soapenv:Header/>
    <soapenv:Body>
       <cm2:addConsent>
         <consent>
           <moduleStates>`
 for(var i=0; i<modulename.length; i++){ 
     mid+=`<entry>
    <key>
      <domainName>${globaldomain}</domainName>
      <name>${modulename[i]}</name>
      <version>${moduleversion[i]}</version>
    </key>
    <value>
      <consentState>ACCEPTED</consentState>
    </value>
 </entry>`
 } 
 addgicscall+= mid;
 addgicscall+=`</moduleStates>
 <patientSignatureIsFromGuardian>false</patientSignatureIsFromGuardian>
 <physicianId>N/A</physicianId>
 <physicianSigningPlace>N/A</physicianSigningPlace>
 <physicianSigningDate>2022-01-01T00:20:00.000</physicianSigningDate>
 <key>
   <consentDate>${now}</consentDate>
   <consentTemplateKey>
     <domainName>${globaldomain}</domainName>
     <name>${globaltemplate}</name>
     <version>${globaltemplateversion}</version>
   </consentTemplateKey>` ;


 mid=""; 
 varsinglent=signeridtypenames.length
for(var h=0; h<signeridtypenames.length;h++){
    var index=Number(varsinglent)-h;
    var signertype= signeridtypenames[h];
     mid+=  `<signerIds>
    <id>${req.body[signertype]}</id>
    <idType>${signertype}</idType>
    <orderNumber>${index}</orderNumber>
  </signerIds>`;


} 
addgicscall+= mid;
addgicscall+=`</key>
<comment></comment>
<patientSigningPlace>via API</patientSigningPlace>
<patientSigningDate>${now}</patientSigningDate>` ;
var mid="";
/*for(var h=0; h<fieldlist.length;h++)
{

    var fieldnam= String(fieldlist[h]);
    mid+= `<freeTextVals>
    <freeTextDefName>${fieldlist[h]}</freeTextDefName>
    <value>${req.body[fieldnam]}</value>
  </freeTextVals>`;


}*/
for(var h=0; h<fieldlist.length;h++)
{

    var fieldnam= String(fieldlist[h]);
    mid+= `<freeTextVals>
    <freeTextDefName>${fieldlist[h]}</freeTextDefName>
    <value>${fieldlistvalues[h]}</value>
  </freeTextVals>`;


}
addgicscall+= mid;
mid=`<patientSignatureBase64>erwtte65hdfhfh</patientSignatureBase64>
<physicianSignatureBase64>ete56e77fghk</physicianSignatureBase64>`;
addgicscall+= mid;
addgicscall+=`</consent>
</cm2:addConsent>
</soapenv:Body>
</soapenv:Envelope>` ; 
successflag=false; // flag  to  check if  add consent  is successful?
console.log('show me my call: ', addgicscall );
  ///_______________
  fetch( process.env.GICSSRVR, { 
    method: "post",
    body: addgicscall,
    headers: { 'content-type': 'text/xml;charset=UTF-8' }
  })
  .then(res => { return res.text() } )
  .then ( text => { 
    const parser = new XMLParser();
  const data = parser.parse (text)["soap:Envelope"]["soap:Body"]; // remove Envelope and Body
  if ( typeof data["soap:Fault"]  !== 'undefined' ) { // handle error first ... 
    template = `<sh-text size='header-1'>Sorry - we got an error from the server</sh-text>
    <sh-text size='body-1' color="primary">error details: ${data}</sh-text>`;
    console.log( 'returned Error: ', data );
  } else {
    // console.log( 'we got from server... ', data );
    const payload = data["ns2:addConsentResponse"].return;
    const resultstr = JSON.stringify(payload); // just put everything in a string
    console.log( 'returned expect data - OK: ', resultstr );
    template = `<sh-text size='header-1'>Thank You</sh-text>
    <sh-text size='body-1' color="primary">Your data had been received and saved</sh-text>`;
    successflag=true;
  } 

 //qc=
 var qscall = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cm2="http://cm2.ttp.ganimed.icmvc.emau.org/">
 <soapenv:Header/>
 <soapenv:Body>
   <cm2:setQCForConsent>
     <consentKey>
       <consentDate>${now}</consentDate>
       <consentTemplateKey>
       <domainName>${globaldomain}</domainName>
       <name>${globaltemplate}</name>
       <version>${globaltemplateversion}</version>
       </consentTemplateKey>`;
       mid=""; 
       varsinglent=signeridtypenames.length
      for(var h=0; h<signeridtypenames.length;h++){
          var index=Number(varsinglent)-h;
          var signertype= signeridtypenames[h];
           mid+=  `<signerIds>
          <id>${req.body[signertype]}</id>
          <idType>${signertype}</idType>
          <orderNumber>${index}</orderNumber>
        </signerIds>`;

      } 
      qscall+=mid;
      qscall+=`</consentKey>
     <qc>
       <comment>case is valid</comment>
       <inspector>${req.body.Inspector}</inspector>
       <type>checked_no_faults</type>
     </qc>
   </cm2:setQCForConsent>
 </soapenv:Body>
</soapenv:Envelope>`;

console.log('show quality state call: '+qscall );

fetch( process.env.GICSSRVR, { 
 method: "post",
 body: qscall,
 headers: { 'content-type': 'text/xml;charset=UTF-8' }
})
.then(res => { return res.text() } )
.then ( text => { 
 const parser = new XMLParser();
const data = parser.parse (text)["soap:Envelope"]["soap:Body"]; // remove Envelope and Body
if ( typeof data["soap:Fault"]  !== 'undefined' ) { // handle error first ... 
 
 console.log( 'returned Error: ', data );
} else {
 // console.log( 'we got from server... ', data );
 const payload = data["ns2:setQCForConsentResponse"].return;
 const resultstr = JSON.stringify(payload); // just put everything in a string
 console.log( 'returned expect data - OK: ', resultstr );
 
} 
})

      
  res.send(`${shuiheader}${template}
    ${shuifooter}`)
  })
  console.log('THIS MESSAGE will NOT wait for request to return !!! be aware ! ');
})
app.get( '/macsearch/:domain', (req, res) => {
  var gicsreturn = 'error';
globaldomain=req.params.domain;
//globaltemplate=req.params.template;
//var gicsreturn = 'error';
var gicscall = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cm2="http://cm2.ttp.ganimed.icmvc.emau.org/">
<soapenv:Header/>
<soapenv:Body>
   <cm2:listSignerIdTypes>
      <domainName>${globaldomain}</domainName>
   </cm2:listSignerIdTypes>
</soapenv:Body>
</soapenv:Envelope>`;

fetch( process.env.GICSSRVR, { 
  method: "post",
  body: gicscall,
  headers: { 'content-type': 'text/xml;charset=UTF-8' }
})
.then(res => { return res.text() } )
.then ( text => { 
    const parser = new XMLParser();
    const gicsreturn = parser.parse (text); 

    console.log ( "test string :" + JSON.stringify(gicsreturn) ); 
    const payload =gicsreturn["soap:Envelope"]["soap:Body"]["ns2:listSignerIdTypesResponse"].return ;
    console.log ( "type of singer :" + typeof payload.sinerIdTypes ) ;
    signeridtypenames=[];
    

    if( Array.isArray(payload.sinerIdTypes)===true){//this checks that there are more than one signerID
        for (const key in payload.sinerIdTypes) {
            
                const value5 = payload.sinerIdTypes[key];
                    if (typeof value5 == 'object' ){
                    //
                    signeridtypenames.push(value5.name);}           
        }
    }
  
     else{// there is one signerID
      signeridtypenames.push(payload.sinerIdTypes.name);
        }
    
    for(var y=0; y<signeridtypenames.length;y++)
    {
        console.log("this is signerID: ", signeridtypenames[y]);

    }

   
    var mid=""
    var body = `<sh-text size='header-1'>you can  search the cases </sh-text><form  
      action="/searchresult/${globaldomain}" method="post">
      <label for="signertype">Choose a field for search  then enter  it's value :</label>
      <select name="selectedsignertype" id="selectedsignertype">`;

      signeridtypenames.forEach(element =>  
          mid+=`<option value="${element}">${element}</option>`        
        );

      body+=mid;
      body+=`</select>  <input type="text" id="signervalue" name="signervalue" "  "<br><br>`;
      body += `<input id = "Submit" type="submit" value="Submit">
      </form>`;
      console.log('showw search : ' +body);
      
      res.send(`${shuiheader}${body}
          ${shuifooter}`)

  
  });
  //$("#box1 option:selected").text();  req.body.signertype;
  console.log('THIS MESSAGE will NOT wait for request to return !!! be aware ! ');
})

app.post( '/searchresult/:domain', (req, res) => {
  var singertype=req.body.selectedsignertype
  var signervalue =req.body.signervalue
  //console.log('showwww ! '+ optionshowme);

  globaldomain=req.params.domain;

  
  domainnamelist = [];
  //console.log("/user - req.session = ", req.session);
  signerproperties = []; //be sure this array is empty
  const readjson = require("./macdomain");
  const payload = readjson["domainsigner"].return;
  var index=0;
    console.log("there is one doman for MAC team");
  
    domainnamelist.push(globaldomain);
    payload.signeridtypes.forEach((element) => {
      
      domainsignerids = [];
      if(element.name===singertype){
        domainsignerids.push(element.name); // extract properties of signeriftype: email
        domainsignerids.push(element.fhirID);
        domainsignerids.push(element.createTimestamp);
        signerproperties[index] = domainsignerids; //signerproperties is global array
      }
    });

      
      //console.log("fhirID for check:" + domainsignerids[1]);
      
 
  
  // ________start of getAllConsentsForSignerIds/ name of service :getAllConsentsForSignerIds ________________________

  function getconsentofsigner(
    dname,
    signerfhirid,
    sigertime,
    signervalue,
    signertyp
  ) {
    // special type  is email/Email

    const customPromise = new Promise((resolve, reject) => {
      var gicscall = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
  xmlns:cm2="http://cm2.ttp.ganimed.icmvc.emau.org/">
  <soapenv:Header/>
      <soapenv:Body>
          <cm2:getAllConsentsForSignerIds>
              <domainName>${dname}</domainName>
              <signerIds>
                  <fhirID>${signerfhirid}</fhirID>
                  <creationDate>${sigertime}</creationDate>
                  <id>${signervalue}</id>
                  <idType>${signertyp}</idType>
                  <orderNumber>1</orderNumber>
              </signerIds>
          </cm2:getAllConsentsForSignerIds>
      </soapenv:Body>
  </soapenv:Envelope>`;

      // const moptions = {
      // method: 'POST',
      // json: false,
      // uri: process.env.GICSSRVR,
      // body: gicscall,
      // headers: {
      //  'Authorization': 'Bearer ' + ' token',
      //     'content-type': 'text/xml;charset=UTF-8'
      // }
      // };
      //_________variables ___________________________________
      // var modulepart="";
      // var moduleindex; //this list keep module's index  and use for policy list & check lists arrays
      // var domainname = "";
      consenttempdate = [];
      consenttemptype = [];
      consenttempname = [];
      consenttempversion = [];

      console.log("call:", gicscall); // Print the call for debug
      // caution - from here we have an async call which waits in server response
      // request.post(moptions, (error, response, body ) => {
      //    if (!error && response.statusCode < 300) {
      //    gicsreturn2 = body;
      //    gicsreturn = body;
      //    console.log('body:', gicsreturn ); // Print the response for debug
      // res.json(response.statusCode, body);
      body = "";
      // const parser = new XMLParser();
      // gicsreturn = parser.parse(gicsreturn);
      fetch(process.env.GICSSRVR, {
        method: "post",
        body: gicscall,
        headers: { "content-type": "text/xml;charset=UTF-8" },
      })
        .then((res) => {
          return res.text();
        })
        .then((text) => {
          const parser = new XMLParser();
          const gicsreturn = parser.parse(text); // ["soap:Envelope"]["soap:Body"]; // remove Envelope and Body

          console.log("test string :" + JSON.stringify(gicsreturn));
          const payload =
            gicsreturn["soap:Envelope"]["soap:Body"][
              "ns2:getAllConsentsForSignerIdsResponse"
            ].return;
          if (payload === "") {
            console.log(
              `there is no consent for ${signervalue} in domain:${dname} `
            );
            resolve(true);
          } else {
            // we have a real payload

            console.log("this is payload :" + payload);
            // let multiconsent = Array.isArray(payload.consents);
            if (Array.isArray(payload.consents)) {
              console.log("there is more than one consent for this person  :");
              for (const key in payload.consents) {
                if (payload.consents.hasOwnProperty(key)) {
                  const value = payload.consents[key];
                  consenttempdate.push(value.consentDates.legalConsentDate);
                  console.log(
                    "consenttempdate is  :" +
                      value.consentDates.legalConsentDate
                  );

                  consenttemptype.push(value.templateType);
                  console.log("consenttemptype :" + value.templateType);
                  consenttempname.push(value.key.consentTemplateKey.name);
                  console.log(
                    "consenttempname :" + value.key.consentTemplateKey.name
                  );
                  consenttempversion.push(value.key.consentTemplateKey.version);
                  console.log(
                    "version :" + value.key.consentTemplateKey.version
                  );
                }
              }
            } else {
               signeridtypenames = [];
               signeridtypvalues = [];
              console.log("there is one consent for this person :");
              const value = payload.consents;
              consenttempdate.push(value.consentDates.legalConsentDate);
              console.log(
                "consenttempdate is  :" + value.consentDates.legalConsentDate
              );
              payload.consents.key.signerIds.forEach(
                (signerid) => {
                  // console.log ( "assignedPolicies: " + assignedPolicy.policy.comment );
                  //listofpolicies += `<LI>${assignedPolicy.policy.label} ${assignedPolicy.policy.comment}</LI>`;
                   signeridtypenames.push(signerid.idType)
                   signeridtypvalues.push(signerid.id)
                }
              );
              consenttemptype.push(value.templateType);
              console.log("consenttemptype :" + value.templateType);
              consenttempname.push(value.key.consentTemplateKey.name);
              console.log(
                "consenttempname :" + value.key.consentTemplateKey.name
              );
              consenttempversion.push(value.key.consentTemplateKey.version);
              console.log("version :" + value.key.consentTemplateKey.version);

            }
          }
          resolve(true);
        }); // end of fetch-then-then
      // else
      // {
      //    reject(new Error('Call to server somehow failed ' + response.statusCode))
      // }
      // })
    });
    return customPromise;
  }
  // ________enf  of getAllConsentsForSignerIds________________________

  //___________extract all info about module and policies/ name of service : getConsentTemplate_____________________________
  function getallinfo(dname, temp, tversion) {
    const customPromise2 = new Promise((resolve, reject) => {
      var gicscall = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
xmlns:cm2="http://cm2.ttp.ganimed.icmvc.emau.org/">
<soapenv:Header/>
<soapenv:Body>
  <cm2:getConsentTemplate>
    <consentTemplateKey>
      <domainName>${dname}</domainName>
      <name>${temp}</name>
      <version>${tversion}</version>
    </consentTemplateKey>  
  </cm2:getConsentTemplate>
</soapenv:Body>
</soapenv:Envelope>`;

      // const options = {
      // method: 'POST',
      // json: false,
      // uri: process.env.GICSSRVR,
      // body: gicscall,
      // headers: {
      //  'Authorization': 'Bearer ' + ' token',
      // 'content-type': 'text/xml;charset=UTF-8'
      // }
      // };
      //_________variables ___________________________________
      // var modulepart="";
      var moduleindex; //this list keeps module's index  and use for policy list & check lists arrays
      fieldlist = [];
      modulename = [];
      var moduleversion = [];
      var modulemandatory = [];
      var modulelabel = [];
      var moduletext = [];
      var moduletitle = [];

      // var templatelabel=""; // VScode says ... unused
      // var tempolatetext="";
      // var templateheader="";
      // var templatefooter="";
      // var templatetitle="";
      let modulepolicies = [];

      console.log("call:", gicscall); // Print the call for debug
      // caution - from here we have an async call which waits in server response
      // request.post(options, (error, response, body ) => {
      // if (!error && response.statusCode < 300) {
      //   gicsreturn2 = body;
      //   gicsreturn = body;
      // console.log('body:', gicsreturn ); // Print the response for debug
      // res.json(response.statusCode, body);

      fetch(process.env.GICSSRVR, {
        method: "post",
        body: gicscall,
        headers: { "content-type": "text/xml;charset=UTF-8" },
      })
        .then((res) => {
          return res.text();
        })
        .then((text) => {
          const parser = new XMLParser();
          const gicsreturn = parser.parse(text); // ["soap:Envelope"]["soap:Body"]; // remove Envelope and Body
          // const gicsreturn = parser.parse (gicsreturn);

          console.log("test string :" + JSON.stringify(gicsreturn));
          // Error: cannot redeclare block-scoped variable 'payload'.ts(2451)
          // const payload = gicsreturn["soap:Envelope"]["soap:Body"]["ns2:getConsentTemplateResponse"].return;
          // try to fix:
          const payload =
            gicsreturn["soap:Envelope"]["soap:Body"][
              "ns2:getConsentTemplateResponse"
            ].return;
          body = "";

          console.log("template Label:" + payload.label);
          if (typeof  payload.label !== "undefined") {
            templatelabel = payload.label;
          }

          console.log(" template Title:" + payload.title);
          if (typeof payload.title !== "undefined") {
            templatetitle = payload.title;
          }
          console.log("Footer:" + payload.header);
          if (typeof payload.header !== "undefined") {
            templateheader = payload.header;
          }

          if (typeof payload.text !== "undefined") {
            tempolatetext = payload.text;
          }

          if (typeof payload.footer !== "undefined") {
            templatefooter = payload.footer;
          }
          console.log("Footer:" + payload.footer);

          console.log("created on    :" + payload.creationDate);
          console.log("lastupdated on :" + payload.updateDate);
          console.log("domain name: " + payload.key.domainName);
          // var domainame= payload.key.domainName;
          // var templatename=payload.key.name;
          var templateversion = payload.key.version;
          var mysrtversion = String(templateversion);
          var myintversion = Number(templateversion);
          if (myintversion % 1 == 0) {
            //check for natural number (int) because  version 1.0 will be converted to 1 and we don't want it
            mysrtversion += ".0";
          } // prepare version for saving in list
          templateversion = mysrtversion;
          console.log("key.name:       " + payload.key.name);
          console.log("key.version:    " + mysrtversion);

          console.log("== loop  modules ==");
          let multimodules = Array.isArray(payload.assignedModules);
          if (!multimodules) {
            //there is one module

            console.log(" orderNumber: " + payload.assignedModules.orderNumber);
            moduleindex = Number(payload.assignedModules.orderNumber);
            //  this index is used for save /access to policies and checkboxes

            /// checkboxs are not displayed  in final result , just for collecting info which can be useful for future

            console.log(
              "modulemandatory: " + payload.assignedModules.mandatory
            );
            modulemandatory.push(payload.assignedModules.mandatory);

            console.log(
              "modulemandatory: " + payload.assignedModules.module.key.name
            );
            modulename.push(payload.assignedModules.module.key.name);

            mysrtversion = String(payload.assignedModules.module.key.version);
            myintversion = Number(payload.assignedModules.module.key.version);
            if (myintversion % 1 == 0) {
              //check for natural number (int) because  version 1.0 will be converted to 1 and we don't want it
              mysrtversion += ".0";
            } // prepare version for saving in list
            console.log("moduleversion: " + mysrtversion);
            moduleversion.push(mysrtversion);

            console.log(
              "module label: " + payload.assignedModules.module.label
            );
            modulelabel.push(payload.assignedModules.module.label);

            console.log(" module text: " + payload.assignedModules.module.text);
            moduletext.push(payload.assignedModules.module.text);

            console.log(
              "module title: " + payload.assignedModules.module.title
            );
            moduletitle.push(payload.assignedModules.module.title);

            let multipolicies = Array.isArray(
              payload.assignedModules.module.assignedPolicies
            );
            modulepolicies[moduleindex] = [];
            if (!multipolicies) {
              //there is one policy
              console.log("************");
              console.log(
                "label of Policies: " +
                  payload.assignedModules.module.assignedPolicies.policy.label
              );
              modulepolicies[moduleindex].push(
                payload.assignedModules.module.assignedPolicies.policy.comment
              );
            } 
            else {// module has multiple policies
              payload.assignedModules.module.assignedPolicies.forEach(
                (assignedPolicy) => {                  
                  modulepolicies[moduleindex].push(assignedPolicy.policy.comment);                
                }
              );
            }
          } 
          else {
            // there are more than one modules
            for (const key in payload.assignedModules) {
              if (payload.assignedModules.hasOwnProperty(key)) {
                const value = payload.assignedModules[key];
                console.log("is is value");
                console.log(value);
                console.log("is is value", typeof value);

                console.log(" orderNumber: " + value.orderNumber);
                moduleindex = Number(value.orderNumber); // make it a 2D array , each row is beloged to one madule

                console.log(" value. mandatory: " + value.mandatory);
                modulemandatory.push(value.mandatory);

                var mukeyobjkey = value.module.key;
                console.log("key.moduleName: " + mukeyobjkey.name);
                modulename.push(mukeyobjkey.name);
                mysrtversion = String(mukeyobjkey.version);
                myintversion = Number(mukeyobjkey.version);
                if (myintversion % 1 == 0) {
                  //check for natural number (int) because after extract version 1.0 convert to 1
                  mysrtversion += ".0";
                }
                // prepare version for saving in list
                console.log("key.moduleversion: " + mysrtversion);
                moduleversion.push(mysrtversion);

                var modulevalus = value.module; //properties of module
                console.log(" label: " + modulevalus.label);
                modulelabel.push(modulevalus.label);

                console.log(" text: " + modulevalus.text);
                moduletext.push(modulevalus.text);

                console.log(" title: " + modulevalus.title);
                moduletitle.push(modulevalus.title);
                let multipolicies = Array.isArray(
                  payload.assignedModules.module.assignedPolicies);
                modulepolicies[moduleindex] = [];
                if (!multipolicies) {
                  //there is one policy              
                  console.log(
                    "label of Policies: " +
                      payload.assignedModules.module.assignedPolicies.policy.label
                  );
                  modulepolicies[moduleindex].push(
                    payload.assignedModules.module.assignedPolicies.policy.comment
                  );
                } 
                else {// module has multiple policies
                  payload.assignedModules.module.assignedPolicies.forEach(
                    (assignedPolicy) => {                  
                      modulepolicies[moduleindex].push(assignedPolicy.policy.comment);                
                    }
                  );
                }
              }
            }
          }

          //  _____________start to build the response body ___________________________

          // turn <div> into <b> if in title

          var payloadtitle = payload.title; // turn const into var to allow modifications
          //payloadtitle = payloadtitle.replace(/div>/gi, ""); // turn <div> into <b>
          payloadtitle = payloadtitle.replace(/(<([^>]+)>)/gi, '');
          body += `<sh-accordion arrow-invert flat label="${payloadtitle}">
  <sh-text size='body-1' color="primary">${payload.header}</sh-text>`;

          //__________module part_____________________________________________________________

          console.log(" part modulename.length body: ", modulename.length);
          for (var i = 0; i < modulename.length; i++) {
            //add madule names  and versions
            var mtitle = moduletitle[i];          
            if (typeof moduletitle[i] !== "undefined") {
              mtitle=mtitle.replace( /(<([^>]+)>)/gi, '');// remove html tag from title 
            }
            else {
              mtitle="";
            }           
            var mid = `<sh-text size='body-1' color="primary">Module title: ${mtitle}</sh-text>`;
            body += mid;
            console.log(" part of body: ", mid);

          
            var mtext = moduletext[i];
            if (typeof moduletext[i] !== "undefined") {
              mtext=mtext.replace( /(<([^>]+)>)/ig, '');// remove html tag from text 
            }
            else {
              mtext="";
            }

            var mid = `<sh-text size='body-1' color="primary"> ${mtext}</sh-text>`;

            body += mid;

            var mid = `<sh-text size='body-1' color="primary">list of module policies:</sh-text>`;

            body += mid;
            console.log(" part of body: ", mid);
            var mid = `<ol>`; //make a list
            body += mid;
            console.log(" part of body: ", mid);
            for (var j = 0; j < modulepolicies[i].length; j++) {
              body += `<li>${modulepolicies[i][j]}</li>`;
            }
            body += `</ol>`;
            body += `<sh-text size='body-1' color="primary">${payload.footer}</sh-text>
  <sh-text size='body-1' color="primary">Domain: ${dname} -- Template: ${temp} -- Version: ${tversion}</sh-text>`;
            body += `</sh-accordion> <hr>`; // draw a line
            console.log(" part of body: ", mid);
            resolve(body);
          }
        }); // end of server-call no-error

      // else { // "fetch" error handling is now inside of block - no longer in "else" here
      //  reject(new Error(' call to server somehow failed!'))
      // }
      // }) // end of request.post()
    });
    return customPromise2;
  }

  //__________________________ calling function PART __________________________________________________________

  //__________________________________get templates for specific email value in a our domain list__________________________
  const collectdt = async () => {
    var indexi = 0;
    var indexarray = 0;
    domaintemparray = [];
    var mylist = domainnamelist;
    for (const item of mylist) {
      //getconsentofsigner(dname,signerfhirid,sigertime,signervalue,signertyp) // email : is the value of email from textbox
      const answerreceived = await getconsentofsigner(
        item,
        signerproperties[indexi][1],
        signerproperties[indexi][2],
        signervalue,
        signerproperties[indexi][0]
      );
      if (answerreceived) {
        // request was sent
        tempnames = consenttempname;
        if (typeof tempnames === "undefined") {
          //there is no consent of this person in that domain so go on
          var info = 0;
          indexi++;
        } else {
          // theres is a consent in that domain for that person so get information
          var info = tempnames.length;
          // the number of template for current domain

          for (var k = 0; k < info; k++) {
            var temporarylist = [];
            temporarylist.push(item); //name of domain
            temporarylist.push(consenttempname[k]);
            temporarylist.push(consenttemptype[k]);

            var mysrtversion = String(consenttempversion[k]);
            var myintversion = Number(consenttempversion[k]);
            if (myintversion % 1 == 0) {
              //check for natural number (int) because  version 1.0 will be converted to 1 and we don't want it
              mysrtversion += ".0";
            } // prepare version for saving in list
            temporarylist.push(mysrtversion);

            temporarylist.push(consenttempdate[k]);
            domaintemparray[indexarray] = temporarylist;
            indexarray++;
          }

          indexi++;
        }
      }
    }
  };
  // show all info
  const showinfo = async () => {
    var myindex = 0;
    allinfo = "";
    //permit=false;
    var mylist = domaintemparray;
    var alltuple = mylist.length;
    for (const item of mylist) {
      // tempbody: gratually collects information of template and it may for one person there are several consents of different (domain/template)
      const tempbody = await getallinfo(
        domaintemparray[myindex][0],
        domaintemparray[myindex][1],
        domaintemparray[myindex][3]
      );
      if (typeof tempbody !== "undefined" && tempbody !== "") {
        var s = domaintemparray[myindex][4];
        s = s.substring(0, s.length - 10);
        var dt = s.replace("T", " "); // create right format for date
        allinfo += `<sh-text size='body-1' color="primary">Date and Time of consent: ${dt}</sh-text>`;
        for(var i=0; i<signeridtypenames.length;i++){
          allinfo += `<sh-text size='body-1' color="primary"> ${signeridtypenames[i]}: ${signeridtypvalues[i]}</sh-text>`;


        }

        allinfo += tempbody;
        myindex++;
      }
    }
    if (myindex === alltuple) {
      var finalbody = `<sh-text size='header-1'> list of your consents </sh-text>`;
      var mid = "";
      finalbody += mid;
      finalbody += `<hr>`;
      finalbody += allinfo;
      res.send(`${shuiheader}${finalbody}${shuifooter}`);
    }
  };

  collectdt()
    .then(() => {
      return showinfo(); ///getallinfo(dname,temp,tversion)
      // console.log("this is body2: "+ body2);
    })
    .then(() => {
      console.log(" end of search for email: " + email);
    });




 // res.send(`${shuiheader}${optionshowme}
  //${shuifooter}`)
})
//$("#ddlViewBy:selected").text()
  
  
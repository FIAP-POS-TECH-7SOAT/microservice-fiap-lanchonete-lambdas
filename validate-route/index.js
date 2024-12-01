const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");

const COGNITO_JWKS_URL =
  "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TmRZTwsOD/.well-known/jwks.json";

let publicKeys = null;

// Função para buscar e cachear as chaves públicas
const getPublicKeys = async () => {
  console.log('Pegando publicKeys');
  if (!publicKeys) {
    const response = await fetch(COGNITO_JWKS_URL);
    const { keys } = await response.json();
    publicKeys = keys.reduce((acc, key) => {
      acc[key.kid] = jwkToPem(key); // Converter JWKS para PEM
      return acc;
    }, {});
  }
  return publicKeys;
};

// Função para validar o token JWT
const validateToken = async (token) => {
  console.log('validateToken');
  const keys = await getPublicKeys();
  console.log('Devolveu getPublicKeys', keys);

  const decodedHeader = jwt.decode(token, { complete: true });
  console.log('decodedHeader', decodedHeader);
  

  if (!decodedHeader || !keys[decodedHeader.header.kid]) {
    console.log('Token inválido ou chave não encontrada.');
    throw new Error("Token inválido ou chave não encontrada.");
  }

  const pem = keys[decodedHeader.header.kid]; // Chave PEM correspondente ao token
  return jwt.verify(token, pem, { algorithms: ["RS256"] });
};

module.exports.handler = async (event) => {
  console.log('event', event);

  const authorizationHeader = event.headers.Authorization || event.headers.authorization;
  let decodedToken;
  let userGroup;
  const context={
    client: {},
    establishment: {},
    booleanKey: true,
    arrayKey: ["value1", "value2"],
    mapKey: { "value1": "value2" }
  };

  console.log('Tem Authorization?', !!authorizationHeader);

  if (authorizationHeader) {
    const token = authorizationHeader.replace('Bearer ', '').trim();
    try {
      decodedToken = await validateToken(token);

      console.log("Token válido:", decodedToken);

      userGroup = decodedToken["cognito:groups"] ? decodedToken["cognito:groups"][0] : null;
      const {username} =decodedToken
      if(userGroup === "establishments"){
        context.establishment ={
          name:username,
          cpf:username,
          email: `${username}@mail.com`
        }
      }else{
        context.client ={
          name:username,
          cpf:username,
          email: `${username}@mail.com`
        }
      }
      console.log('userGroup', userGroup);

      // return {
      //   isAuthorized: true,
      //   context: {
      //     stringKey: "value",
      //     numberKey: 1,
      //     booleanKey: true,
      //     arrayKey: ["value1", "value2"],
      //     mapKey: { "value1": "value2" }
      //   }
      // };

    } catch (error) {
      console.log('error', error);

      return {
        isAuthorized: false,
        context
      };
    }
  }

  if (event.rawPath.startsWith("/service-productions") && authorizationHeader) {
    if (userGroup !== "establishments") {
      return {
        isAuthorized: false,
        context
      };
    }
  } else if (event.rawPath.startsWith("/service-productions") && !authorizationHeader) {
    return {
      isAuthorized: false,
      context
    };
  }
  console.log('Devia autorizar', context);
  return {
    isAuthorized: true,
    context
  };
};

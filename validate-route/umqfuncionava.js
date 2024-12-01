const jwt = require("jsonwebtoken");
const jose = require('jose')

const jwkToPem = require("jwk-to-pem"); // Para converter JWKS para PEM

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
  console.log('Devolveu getPublicKeys',keys);
  
  
  const decodedHeader = jwt.decode(token, { complete: true });
  console.log('decodedHeader',decodedHeader);
  
  
  if (!decodedHeader || !keys[decodedHeader.header.kid]) {
    console.log('Token inválido ou chave não encontrada.');
    
    throw new Error("Token inválido ou chave não encontrada.");
  }

  const pem = keys[decodedHeader.header.kid]; // Chave PEM correspondente ao token
  return jwt.verify(token, pem, { algorithms: ["RS256"] });
};


module.exports.handler = async (event) => {
  console.log('event',event);
  
  const authorizationHeader = event.headers.Authorization || event.headers.authorization;
  let decodedToken;
  let userGroup;
 
  console.log('Tem Authorization?', !!authorizationHeader);
  
  if (authorizationHeader) {
    
    const token = authorizationHeader.replace('Bearer ', '').trim();
    try {
        decodedToken = await validateToken(token);

        console.log("Token válido:", decodedToken);

        userGroup = decodedToken["cognito:groups"] ? decodedToken["cognito:groups"][0] : null;
        
        console.log('userGroup',userGroup);


        return {
          statusCode: 200,
          body: JSON.stringify({ message: "Token válido.", decodedToken }),
        };
      } catch (error) {
        console.log('error',error);
        
        return {
          statusCode: 403,
          body: JSON.stringify({ message: "Token inválido.", error: error.message }),
        };
      }
  }

  if (event.rawPath.startsWith("/service-productions") && authorizationHeader) {

    if(userGroup !== "establishments"){
        return {
            statusCode: 403,
            body: JSON.stringify({ message: "Acesso negado para esse recurso." }),
        }
      }
    }else if(event.rawPath.startsWith("/service-productions") && !authorizationHeader){
      return {
        statusCode: 403,
        body: JSON.stringify({ message: "Acesso negado para esse recurso." }),
      }
    }



    return {
        statusCode: 200,
        body: JSON.stringify({
            message: "Requisição validada com sucesso.",
            
        }),
    };

  
};

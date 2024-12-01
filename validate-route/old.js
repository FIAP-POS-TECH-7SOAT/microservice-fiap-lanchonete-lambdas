    
    const jwt = require("jsonwebtoken");

    const COGNITO_JWKS_URL = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TmRZTwsOD/.well-known/jwks.json";
    let publicKeys = null;

    // Função para buscar e cachear as chaves públicas
    const getPublicKeys = async () => {
        if (!publicKeys) {
            
            const response = await fetch(COGNITO_JWKS_URL);
            
            
            const toJson = await response.json()
            
            publicKeys = toJson.keys.reduce((acc, key) => {
                acc[key.kid] = key;
                return acc;
            }, {});
            
        }
        return publicKeys;
    };

    // Função para validar o token JWT
    const validateToken = async (token) => {
        const keys = await getPublicKeys();
        const decodedHeader = jwt.decode(token, { complete: true });
        // console.log('decodedHeader',decodedHeader);
        

        if (!decodedHeader || !keys[decodedHeader.header.kid]) {
            throw new Error("Token inválido ou chave não encontrada.");
        }

        const publicKey = keys[decodedHeader.header.kid];
        const keyObject = `-----BEGIN PUBLIC KEY-----\n${Buffer.from(publicKey.n, "base64").toString("utf8")}\n-----END PUBLIC KEY-----`;

        return jwt.verify(token, keyObject, { algorithms: ["RS256"] });
    };

    // Handler da Lambda
    handler = async (event) => {
        // console.log('event',event);
        const authorizationHeader = event.headers.Authorization || event.headers.authorization;

        // console.log('authorizationHeader',authorizationHeader);
        // console.log('event.path.',event.path);


        let decodedToken;
        let userGroup;
        const updatedHeaders = {
            ...event.headers,
        };
        // se tiver jwt vamos decodificar
        if(authorizationHeader){
            const token = authorizationHeader.split(" ")[1]; // Exemplo: "Bearer <token>"
            try {
                // console.log('token',token);
                
                decodedToken = await validateToken(token);
                userGroup = decodedToken["cognito:groups"] ? decodedToken["cognito:groups"][0] : null;
                updatedHeaders["x-user-token"] = token;
                updatedHeaders["x-user-group"] = userGroup;
            } catch (error) {
                return {
                    statusCode: 403,
                    body: JSON.stringify({ message: "Token inválido.", error: error.message }),
                };
            }
        }
        
        // se tiver jwt vamos decodificar e for a rota de "service-productions" entao verificar se o grupo ta certo
        if (event.path.startsWith("/service-productions") && authorizationHeader) {

            if(userGroup !== "establishments"){
                return {
                    statusCode: 403,
                    body: JSON.stringify({ message: "Acesso negado para esse recurso." }),
                }
            }
        }else{
            return {
                statusCode: 403,
                body: JSON.stringify({ message: "Acesso negado para esse recurso." }),
            }
        }

       
        // Encaminha o evento para os microserviços com os novos headers
        const updatedEvent = {
            ...event,
            headers: updatedHeaders,
        };
        console.log({
            message: "Requisição validada com sucesso.",
            event: updatedEvent,
        });
        
        return {
            statusCode: 200,
            body: JSON.stringify({
                message: "Requisição validada com sucesso.",
                event: updatedEvent,
            }),
        };
    };


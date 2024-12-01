

import { createHmac } from 'crypto';
import { CognitoIdentityProviderClient, AdminInitiateAuthCommand, AdminRespondToAuthChallengeCommand } from '@aws-sdk/client-cognito-identity-provider';

const REGION =process.env.REGION
const CLIENT_ID =process.env.CLIENT_ID
const CLIENT_SECRET =process.env.CLIENT_SECRET
const USER_POOL_ID =process.env.USER_POOL_ID

// Função para gerar o SECRET_HASH
const generateSecretHash = (username) => {
  return createHmac('sha256', CLIENT_SECRET)
    .update(`${username}${CLIENT_ID}`)
    .digest('base64');
};

// Função para autenticar um usuário e lidar com o reset de senha obrigatório
const authenticateUser = async (cpf) => {
  const cognitoIdentityProviderClient = new CognitoIdentityProviderClient({
    region: REGION,
  });

  try {
    const initiateAuthCommand = new AdminInitiateAuthCommand({
      UserPoolId: USER_POOL_ID,
      ClientId: CLIENT_ID,
      AuthFlow: 'ADMIN_NO_SRP_AUTH',
      AuthParameters: {
        USERNAME: cpf,
        PASSWORD: cpf,
        SECRET_HASH: generateSecretHash(cpf),
      },
    });

    const authResponse = await cognitoIdentityProviderClient.send(initiateAuthCommand);
    console.log('authResponse', authResponse);
    // Verifica se há um desafio para mudar a senha
    if (authResponse.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
 

      const respondToAuthChallengeCommand = new AdminRespondToAuthChallengeCommand({
        UserPoolId: USER_POOL_ID,
        ClientId: CLIENT_ID,
        ChallengeName: 'NEW_PASSWORD_REQUIRED',
        Session: authResponse.Session,
        ChallengeResponses: {
          USERNAME: cpf,
          NEW_PASSWORD: cpf,
          SECRET_HASH: generateSecretHash(cpf),
        },
      });

      const challengeResponse = await cognitoIdentityProviderClient.send(respondToAuthChallengeCommand);
      console.log('Senha alterada e usuário autenticado com sucesso:', challengeResponse);
      return challengeResponse.AuthenticationResult;
    }

    console.log('Usuário autenticado com sucesso:', authResponse);
    return authResponse.AuthenticationResult;

  } catch (error) {
    console.error('Erro ao autenticar o usuário:', error);
    throw error;
  }
};

// Função handler para AWS Lambda
export const handler = async (event) => {
  const { cpf } = JSON.parse(event.body);

  if (!cpf) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "cpf é obrigatorio." }),
    };
  }

  try {
    const authResult = await authenticateUser(cpf);
    return {
      statusCode: 200,
      body: JSON.stringify(authResult),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message }),
    };
  }
};

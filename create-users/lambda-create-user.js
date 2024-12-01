import  { CognitoIdentityProviderClient, AdminCreateUserCommand, AdminAddUserToGroupCommand } from '@aws-sdk/client-cognito-identity-provider';


const REGION = process.env.REGION
const USER_POOL_ID = process.env.USER_POOL_ID


const createUser = async ({email, cpf, name,group_name}) => {
  try {

     const cognitoIdentityProviderClient= new CognitoIdentityProviderClient({
      region: REGION,
    })
    const temporaryPassword = {}
    if(group_name==='clients'){
      temporaryPassword.TemporaryPassword=cpf;
    }

    const command = new AdminCreateUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: cpf,
      ...temporaryPassword,
      UserAttributes: [
        {
          Name: 'email',
          Value: email,
        },
        {
          Name: 'name',
          Value: name,
        },
     
      ],
    });

    const addUserToGroupCommand = new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: cpf,
      GroupName: group_name,
    });

    const response = await cognitoIdentityProviderClient.send(command);
    
    console.log('User created successfully:', response);

    const addUserToGroupResponse = await cognitoIdentityProviderClient.send(addUserToGroupCommand);
    console.log('User added to group successfully:', addUserToGroupResponse);
  } catch (error) {
    console.error('Error creating user:', error);
    throw new Error(error)
  }
};

export const handler = async (event) => {
    const { email, cpf, name,group_name} = JSON.parse(event.body)

    // Check for null or undefined values
    if (!email || !cpf || !name) {
        return {
            statusCode: 400,
            body: JSON.stringify({ error: "Email, CPF and name are required." }),
        };
    }

    try {
        const response = await createUser({email, cpf, name,group_name});

        // Return the success response in AWS Lambda format
        return {
            statusCode: 200,
            body: JSON.stringify(response),
        };
    } catch(err) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: err.message }),
        };
    }
};

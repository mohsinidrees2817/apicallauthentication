import streamlit as st
import boto3
import jwt
from chatapplication import user_details_page

# USER_POOL_ID = "eu-north-1_q6jhOXKyD"
# CLIENT_ID = "52lc3klggv1uclbsonfpdbieiu"
# REGION = "eu-north-1"
# OPENAI_API_KEY = "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"

USER_POOL_ID = st.secrets["USER_POOL_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
REGION = st.secrets["REGION"]

def authenticate(username, password):
    try:
        client = boto3.client('cognito-idp', region_name=REGION)
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )
        return response
    except Exception as e:
        st.error(f"Authentication error: {e}")
        return None

def decode_id_token(id_token):
    # global decoded_token 
    decoded_token = jwt.decode(id_token, algorithms=["HS256"], options={"verify_signature": False})
    # st.write(decoded_token)
    return decoded_token


def getuser(idtoken, access_token):
    try:
        clientidp = boto3.client('cognito-idp', region_name=REGION)

        client = boto3.client('cognito-identity', region_name=REGION)
        userid = clientidp.get_user(
                 AccessToken=access_token
        )   
        st.write("usernameid: ", userid)
        response = client.get_id(
            AccountId='184281502346',
            # IdentityPoolId='eu-north-1:d09c65cc-3afe-4022-b611-25686de4164c',
            IdentityPoolId='eu-north-1:e5fb9369-2969-4e71-b54f-f85875d5302c',	
            Logins={
                f'cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}': idtoken
            }
        )
        # st.write("response for finding userid: ", response)
        identityId = response['IdentityId']
        logins = {
            f'cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}': idtoken
        }
        responsee = client.get_credentials_for_identity(
                IdentityId=identityId,
                Logins=logins
            )
        # return responsee
        st.write("credentials: ",responsee)
        accesskeyID = responsee['Credentials']['AccessKeyId']
        secretkey = responsee['Credentials']['SecretKey']
        sessiontoken = responsee['Credentials']['SessionToken']
        st.write("Access key:", accesskeyID)
        st.write("Secret key:", secretkey)
        # st.write("Session token:", sessiontoken)
        iam_client = boto3.client('iam',
        aws_access_key_id=accesskeyID,
        aws_secret_access_key=secretkey,
        aws_session_token=sessiontoken)

        sts_client = boto3.client('sts',
        aws_access_key_id=accesskeyID,
        aws_secret_access_key=secretkey,
        aws_session_token=sessiontoken)
        responseforUserid = sts_client.get_caller_identity()
        usergroup = iam_client.list_groups_for_user(UserName="mohsinabbasi902@gmail.com")
        st.write("user groups: ", usergroup['Groups'][0])

        # response = iam_client.get_user()
        st.write("caller identity: ", responseforUserid )
        userid = responseforUserid["UserId"]
        arn  = responseforUserid["Arn"]
        usergroup = usergroup['Groups'][0]
        chat_with_Q(accesskeyID, secretkey, sessiontoken ,userid, arn,usergroup)


    except Exception as e:
        st.error("Failed to get credentials: " + str(e))

    


def chat_with_Q(accesskeyID, secretkey, sessiontoken, userid, arn ,userGroups):
    try:
        client = boto3.client('qbusiness', region_name='us-west-2',
                aws_access_key_id=accesskeyID,
                aws_secret_access_key=secretkey,
                aws_session_token=sessiontoken)
        response = client.chat_sync(
                applicationId='1c33d7de-d3ed-4c5b-a332-4d5526b36593',
                userGroups=[
                    'qbussines',
                ],
                userId=userid,
                userMessage='what is rebhub?'
        )
        st.write("chat response", response)
    except Exception as e:
        st.error("Failed to chat with api: " + str(e))


def get_open_id_token(identity_id, user_id_token):
    client = boto3.client('cognito-identity', region_name=REGION)
    
    logins = {
        f'cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}': user_id_token
    }
    
    try:
        response = client.get_open_id_token(
            IdentityId=identity_id,
            Logins=logins
        )
        # return response
        st.write(response)

    except Exception as e:
        st.error("Failed to get credentials: " + str(e))


# def goupsinfo(identity_id):
#     client = boto3.client('cognito-identity', region_name=REGION)
#     try:
#         response = client.get_credentials_for_identity(IdentityId=identity_id)
#         credentials = response['Credentials']
        
#         # Display the credentials
#         st.write("Credentials for user", "mohsin")
#         st.write("Access key:", credentials['AccessKeyId'])
#         st.write("Secret key:", credentials['SecretKey'])
#         st.write("Session token:", credentials['SessionToken'])   
#     except Exception as e:
#         st.error("Failed to get credentials: " + str(e))



# if passwordchange forced
def respond_to_auth_challenge(username, new_password, session):
    try:
        client = boto3.client('cognito-idp', region_name=REGION)
        response = client.respond_to_auth_challenge(
            ChallengeName='NEW_PASSWORD_REQUIRED',
            ClientId=CLIENT_ID,
            ChallengeResponses={
                'USERNAME': username,
                'NEW_PASSWORD': new_password
            },
            Session=session
        )
        return response
    except Exception as e:
        st.error(f"Error updating password: {e}")
        return None





def login():
    global user_data
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        auth_response = authenticate(username, password)
        if auth_response:
            user_data = auth_response
            if 'ChallengeName' in auth_response and auth_response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
                st.warning("New password is required. Please reset your password.")
                update_password(username, password, auth_response['Session'])
            else:
                st.success("Authentication successful!")
                st.session_state['auth_response'] = auth_response
                id_token = auth_response['AuthenticationResult']['IdToken']
                access_token = auth_response['AuthenticationResult']['AccessToken']
                getuser(id_token, access_token)
                
                # st.write(response['UserAttributes'][0]['Value'])
                
                # decoded_token = decode_id_token(id_token)
                # st.write(decoded_token['sub'])
                # st.session_state['decoded_token'] = response
                # identity_id =response['UserAttributes'][0]['Value']
                # goupsinfo(response)
                # get_open_id_token(response, id_token)
                # st.write(token)
                # if response:
                #     st.session_state.runpage = user_details_page
                #     st.session_state.runpage()
                #     st.experimental_rerun()

def update_password(username,password, session):
    st.header("Updating password")
    new_password = password
    update_response = respond_to_auth_challenge(username, new_password, session)
    if update_response:
        st.success("Password updated successfully!")
    else:
        st.error("Error updating password. Please try again.")




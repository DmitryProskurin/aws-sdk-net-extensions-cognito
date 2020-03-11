![.NET on AWS Banner](./logo.png ".NET on AWS")

## Amazon Cognito Authentication Extension Library

**This software is in development and we do not recommend using this software in production environment.**

The [Amazon Cognito](https://aws.amazon.com/cognito/) Extension Library simplifies the authentication process of [Amazon Cognito User Pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html) for .NET developers.

It allows you to use various authentication methods for Amazon Cognito User Pools with only a few short method calls, along with making the process intuitive.

[Learn more about Amazon Cognito User Pools.](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-getting-started.html)

This library targets the .NET Standard 2.0 and introduces the following dependencies:

* [AWSSDK.CognitoIdentity](https://www.nuget.org/packages/AWSSDK.CognitoIdentity/)
* [AWSSDK.CognitoIdentityProvider](https://www.nuget.org/packages/AWSSDK.CognitoIdentityProvider/)


# Getting Started

To set up an AWS account and install the AWS SDK for .NET to take advantage of this library, see [Getting Started with the AWS SDK for .NET.](https://docs.aws.amazon.com/sdk-for-net/v3/developer-guide/net-dg-setup.html).

While this library is in development, you will need to build it manually.

Create a new project in Visual Studio and add the Amazon Cognito Authentication Extension Library as a reference to the project.

Using the library to make calls to the Amazon Cognito Identity Provider API from the AWS SDK for .NET is as simple as creating the necessary **CognitoAuthentication** objects and calling the appropriate **AmazonCognitoIdentityProviderClient** methods. The principal Amazon Cognito authentication objects are:

- **CognitoUserPool** objects store information about a user pool, including the poolID, clientID, and other pool attributes.
- **CognitoUser** objects contain a user’s username, the pool they are associated with, session information, and other user properties.
- **CognitoDevice** objects include device information, such as the device key.

## Authenticating with Secure Remote Protocol (SRP)

Instead of implementing hundreds of lines of cryptographic methods yourself, you now only need to create the necessary **AmazonCognitoIdentityProviderClient**, **CognitoUserPool**, **CognitoUser**, and **InitiateSrpAuthRequest** objects and then call **StartWithSrpAuthAsync**:


```csharp
using Amazon.Runtime;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;

public async void AuthenticateWithSrpAsync()
{
    var provider = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(), FallbackRegionFactory.GetRegionEndpoint());
    var userPool = new CognitoUserPool("poolID", "clientID", provider);
    var user = new CognitoUser("username", "clientID", userPool, provider);

    var password = "userPassword";

    AuthFlowResponse authResponse = await user.StartWithSrpAuthAsync(new InitiateSrpAuthRequest()
    {
        Password = password
    }).ConfigureAwait(false);
}
```

The **AuthenticationResult** property of the **AuthFlowResponse** object contains the user’s session tokens if the user was successfully authenticated. If more challenge responses are required, this field is null and the **ChallengeName** property describes the next challenge, such as multi-factor authentication. You would then call the appropriate method to continue the authentication flow. 

## Authenticating with Multiple Forms of Authentication

Continuing the authentication flow with challenges, such as with **NewPasswordRequired** and **Multi-Factor Authentication (MFA)**, is simpler as well. 

The following code shows one way of checking the challenge type and get the appropriate responses for MFA and NewPasswordRequired challenges during the authentication flow based on the **AuthFlowResponse** retrieved earlier:

```csharp
while (authResponse.AuthenticationResult == null)
{
    if (authResponse.ChallengeName == ChallengeNameType.NEW_PASSWORD_REQUIRED)
    {
        Console.WriteLine("Enter your desired new password:");
        string newPassword = Console.ReadLine();

        authResponse = 
            await user.RespondToNewPasswordRequiredAsync(new RespondToNewPasswordRequiredRequest()
            {
                SessionID = authResponse.SessionID,
                NewPassword = newPassword
            }).ConfigureAwait(false);
    }
    else if (authResponse.ChallengeName == ChallengeNameType.SMS_MFA)
    {
        Console.WriteLine("Enter the MFA Code sent to your device:");
        string mfaCode = Console.ReadLine();

        authResponse = await user.RespondToSmsMfaAuthAsync(new RespondToSmsMfaRequest()
        {
                SessionID = authResponse.SessionID,
                MfaCode = mfaCode
        }).ConfigureAwait(false);
        }
        else
        {
            Console.WriteLine("Unrecognized authentication challenge.");
            break;
        }
}
```
[Learn more about Amazon Cognito User Pool Authentication Flow.](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html)

## Refresh Token Authentication

Refresh token authentication required device remembering in Cognito User pool. After user pass all form of authentication, last
respond will contains **NewDeviceMetadataType** in **AuthenticationResult**. That data used to confirm device in Cognito User Pool. **StartWithRefreshTokenAuthAsync** not working without remembered device in Cognito User Pool.

```csharp
class CognitonAuthentication
{
    private readonly AmazonCognitoIdentityProviderClient _provider;
    private readonly CognitoUserPool _userPool;
    
    public CognitonAuthentication()
    {
        _provider = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(),
            FallbackRegionFactory.GetRegionEndpoint());
        _userPool = new CognitoUserPool("poolID", "clientID", _provider);
    }

    public async Task<CognitoUser> SignInWithPasswordAsync(string email, string password)
    {
        var user = _userPool.GetUser(email);

        var authFlowResponse = await user.StartWithSrpAuthAsync(new InitiateSrpAuthRequest
        {
            Password = password
        }).ConfigureAwait(false);

        //if user don't has another forms of auth, then authFlowResponse.ChallengeName will be null
        //and you can confirm device in Cognito like this
        var deviceMetadata = authFlowResponse.AuthenticationResult.NewDeviceMetadata;
        await user.ConfirmDeviceAsync(deviceMetadata, "device friendly name").ConfigureAwait(false);

        //now user has valid device object, remembered in Cognito.
        saveDeviceInfoForUser(user);
        saveSessionTokensForUser(user);
        return user;
    }

    /// <summary>
    /// Refresh session for user. User must has remembered device and session object
    /// </summary>
    public async Task RefreshSessionForUserAsync(CognitoUser user)
    {
        await user.StartWithRefreshTokenAuthAsync(
                new InitiateRefreshTokenAuthRequest {
                    AuthFlowType = AuthFlowType.REFRESH_TOKEN
                })
            .ConfigureAwait(false);
        saveSessionTokensForUser(user);
    }

    private void saveDeviceInfoForUser(CognitoUser user)
    {
        //save device values(between app sessions) for use in refresh token auth flow after token expired
        saveDeviceKeyForUser(user,user.Device.DeviceKey);
        saveDeviceGroupKeyForUser(user, user.Device.GroupDeviceKey);
        saveDeviceSecretForUser(user, user.Device.DeviceSecret);
    }
    
    private void saveSessionTokensForUser(CognitoUser user)
    {
        //save that token values(between app sessions) for use when user launch app again
        saveAccessTokenForUser(user, user.SessionTokens.AccessToken);
        saveIdTokenForUser(user, user.SessionTokens.IdToken);
        saveRefreshTokenForUser(user, user.SessionTokens.RefreshToken);
        saveIssuedTimeForuser(user, user.SessionTokens.IssuedTime);
        saveExpirationTimeForUser(user, user.SessionTokens.ExpirationTime);
    }
}
```

Later, after token is expired(check **CognitoUser.SessionTokens.ExpirationTime**) or user don't launch app for long time, you should restore device and session info in **CognitoUser** object and call **RefreshSessionForUserAsync**.
For example:

```csharp
class CognitonAuthentication
{
    public CognitonAuthentication()
    {
        _provider = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(),
            FallbackRegionFactory.GetRegionEndpoint());
        _userPool = new CognitoUserPool("poolID", "clientID", _provider);
    }
    
    //CognitoUser from that method can be used in RefreshSessionForUserAsync for refresh session
    public CognitoUser RestoreUser(string email) {
        var user = _userPool.GetUser(email);
        //restore deviceinfo, otherwise RefreshSessionForUserAsync can't work
        user = restoreDevice(user);
        //refresh token is required for refresh session
        user = restoreSessionTokens(user);
        return user;
    }

    private CognitoUser restoreDevice(CognitoUser user)
    {
        var device = new CognitoDevice(
            restoreDeviceKeyForUser(user), new Dictionary<string, string>(),
            DateTime.Now, DateTime.Now,
            DateTime.Now, user) {
            GroupDeviceKey = restoreDeviceGroupKeyForUser(user),
            DeviceSecret = restoreDeviceSecretForUser(user)
        };
        user.Device = device;
        return user;
    }

    private CognitoUser restoreSessionTokens(CognitoUser user)
    {
        var userSession = new CognitoUserSession(
            restoreIdTokenForUser(user),
            restoreSessionTokenForUser(user),
            restoreRefreshTokenForUser(user),
            restoreIssuedTimeForUser(user),
            restoreExpirationTimeForUser(user));
        user.SessionTokens = userSession;
        return user;
    }
}
```

Note: modification for device remembering based on AWS sdk for Android. Also, it contains fix for negative salts. **Random** fill array of bytes(on client) and use it for device credentials. Probably, AWS side convert client's byte
array to BigInteger and fails in check for negative value. I make simple(but not best) solution - look at [CognitoDeviceHelper](https://github.com/DmitryProskurin/aws-sdk-net-extensions-cognito/blob/CognitoUserImprovements/src/Amazon.Extensions.CognitoAuthentication/Util/CognitoDeviceHelper.cs) **GenerateDeviceSaltAndVerifier** method,
Salt negate. If you wan't improve this solution, that byte array as Salt fails on AWS: 
```
new byte[16]{ 0xff, 0x7e, 0x46, 0xac, 0x16, 0x9b, 0x00, 0x91, 0xe1, 0x88, 0xa2, 0x9c, 0x17, 0x80,0x57, 0xab }
```
## Authenticating with Multiple Forms of Authentication

Once a user is authenticated using the Amazon Cognito Authentication Extension Library, you can them allow them to access the specific AWS resources. 

This requires you to create an identity pool through the **Amazon Cognito Federated Identities** console.

You can also specify different roles for both unauthenticated and authenticated users to be able to access different resources. 
These roles can be changed in the IAM console where you can add or remove permissions in the “Action” field of the role’s attached policy. 

Then, using the appropriate identity pool, user pool, and Amazon Cognito user information, calls can be made to different AWS resources. The following shows a user authenticated with SRP accessing the developer’s different S3 buckets permitted by the associated identity pool’s role:

```csharp
using Amazon;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;

public async void GetS3BucketsAsync()
{
    var provider = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(),
                                                            FallbackRegionFactory.GetRegionEndpoint());
    var userPool = new CognitoUserPool("poolID", "clientID", provider);
    var user = new CognitoUser("username", "clientID", userPool, provider);

    var password = "userPassword";

    await user.StartWithSrpAuthAsync(new InitiateSrpAuthRequest()
    {
        Password = password
    }).ConfigureAwait(false);

    var credentials = 
        user.GetCognitoAWSCredentials("identityPoolID", RegionEndpoint.<YourIdentityPoolRegion>);

    using (var client = new AmazonS3Client(credentials))
    {
        ListBucketsResponse response = 
            await client.ListBucketsAsync(new ListBucketsRequest()).ConfigureAwait(false);

        foreach (S3Bucket bucket in response.Buckets)
        {
            Console.WriteLine(bucket.BucketName);
        }
    }
}
```

## Other Forms of Authentication

In addition to SRP, NewPasswordRequired, and MFA, the Amazon Cognito Authentication Extension Library offers an easier authentication flow for:

- **Custom** – Begins with a call to StartWithCustomAuthAsync(InitiateCustomAuthRequest customRequest)
- **RefreshToken** – Begins with a call to StartWithRefreshTokenAuthAsync(InitiateRefreshTokenAuthRequest refreshTokenRequest)
- **RefreshTokenSRP** – Begins with a call to StartWithRefreshTokenAuthAsync(InitiateRefreshTokenAuthRequest refreshTokenRequest)
- **AdminNoSRP** – Begins with a call to StartWithAdminNoSrpAuth(InitiateAdminNoSrpAuthRequest adminAuthRequest)

# Getting Help

We use the [GitHub issues](https://github.com/aws/aws-sdk-net-extensions-cognito/issues) for tracking bugs and feature requests and have limited bandwidth to address them.

If you think you may have found a bug, please open an [issue](https://github.com/aws/aws-sdk-net-extensions-cognito/issues/new)

# Contributing

We welcome community contributions and pull requests. See
[CONTRIBUTING](./CONTRIBUTING.md) for information on how to set up a development
environment and submit code.

# Additional Resources

[AWS .NET GitHub Home Page](https://github.com/aws/dotnet)  
GitHub home for .NET development on AWS. You'll find libraries, tools, and resources to help you build .NET applications and services on AWS.

[AWS Developer Center - Explore .NET on AWS](https://aws.amazon.com/developer/language/net/)  
Find all the .NET code samples, step-by-step guides, videos, blog content, tools, and information about live events that you need in one place. 

[AWS Developer Blog - .NET](https://aws.amazon.com/blogs/developer/category/programing-language/dot-net/)  
Come see what .NET developers at AWS are up to!  Learn about new .NET software announcements, guides, and how-to's.

[@awsfornet](https://twitter.com/awsfornet)  
Follow us on twitter!

# License

Libraries in this repository are licensed under the Apache 2.0 License. 

See [LICENSE](./LICENSE) and [NOTICE](./NOTICE) for more information.

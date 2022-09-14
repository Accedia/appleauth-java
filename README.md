# What is AppleAuth?
AppleAuth is a very simple library for Java, based on Google Api Client, that encapsulates logic for communicating with [Apple's REST API for Sign in with Apple](https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api).
The main goal is to make the implementation of [Sign in with Apple](https://developer.apple.com/sign-in-with-apple/) easier for any web application.

# Prerequisites
## Configure Sign in with Apple from the Developer Portal
In order to use Sign in with Apple you must enroll in the [Apple Developer Program](https://developer.apple.com/programs/enroll/).
After you have enrolled in the program go to [Developer Account Help](https://help.apple.com/developer-account/) and navigate to Configure app capabilities > Sign in with Apple.
There you can find the information for configuring Sign in with Apple for your app.

## Display the "Sign in with Apple" button
Next, you have to configure your web page for Sign in with Apple. Follow the guidelines from the official [documentation](https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/configuring_your_webpage_for_sign_in_with_apple). You can also refer to this [link](https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/displaying_sign_in_with_apple_buttons) to see how to setup the styles of the buttons.

# Example
## Using `AppleAuthProvider.java` `AppleClientPrivateKeyFactory.java`
First order of business should be creating an instance of `ECPrivateKey` representing the client's(your) private key.<br/>
`AppleClientPrivateKeyFactory` can help you create a `ECPrivateKey` if you have your private key as string or stream (from a p8 for example).

Creating a new instance of `AppleAuthProvider`, should be trivial at this point. The only two parameters that are not 
self explanatory are the `SecretGenerator` and the collection of scopes.<br/>
`SecretGenerator` is responsible for creating the auth's client_secret. A new instance of the class should cover most of the use cases.
`scopes` is a collection that determines what information will re required from apple and what information will be populated in the returned id_token.

Note: `AppleAuthProvider` is thread safe and is intended to be long lived. For best performance, we recommend you create a single instance of it, unless you need a second with different parameters.

Once you have your `AppleAuthProvider` instance you can:  
- Call `getLoginLink` to get an apple oAuth2 login link. You can use the state parameter to carry over information to the redirect url.
- Use `makeNewAuthorisationTokenRequest` to make a initial authorisation request to apple and retrieve user data based on the auth code from the redirect.
- Use `makeNewRefreshTokenRequest` to verify that the user is still using 'Sign in with Apple' to sign in your system.
## Handling initial response from Apple
After the user clicks on the "Sign in with Apple" button on your page they will be redirected to https://appleid.apple.com/. 
After they provide their credentials Apple will make a POST request to the url that you have specified as Redirect URL. 
It will contain a `code` field. Its contents is what should be handed down to `makeNewAuthorisationTokenRequest` in order retrieve the authorization token (it will also contain the state used to create the redirect url).
Keep in mind that tokens returned from Apple are short-lived, so you should create a session or a user in your system 
using the returned `AppleAuthorizationToken` object. After that you can verify if the user is 
still logged in using "Sign in with Apple" by retrieving a refresh token using the `makeNewRefreshTokenRequest` method.

```java
        public class AppleIdTokenManager {
        
            private final static String CLIENT_ID = "Your client id";
            private static final String KEY_ID = "Your Key id";
            private static final String TEAM_ID = "Your team id";
            private static final String REDIRECT_URL = "Your redirect url";
        
            public static void main(String[] args) throws IOException, InvalidKeySpecException {
                // Generating your private key.
                // This could be just a string containing the key.
                InputStream pkStream = AppleIdTokenManager.class
                        .getClassLoader().getResourceAsStream("your_pk_file.p8");
                AppleClientPrivateKeyFactory appleClientPrivateKeyFactory = new AppleClientPrivateKeyFactory();
                ECPrivateKey privateKey = appleClientPrivateKeyFactory.getEcPrivateKey(pkStream);
                
                // Creating provider instance.
                SecretGenerator secretGenerator = new SecretGenerator();
                AppleAuthProvider appleAuthProvider = new AppleAuthProvider(
                        CLIENT_ID,
                        KEY_ID,
                        TEAM_ID,
                        secretGenerator,
                        privateKey,
                        Arrays.asList(AppleUserScope.EMAIL, AppleUserScope.NAME),
                        REDIRECT_URL
                );
                
                // We are ready to start using the provider.

                // Generate a url and navigate the user to it.
                String loginLink = appleAuthProvider.getLoginLink("Some form of state");
                
                // Once the user is redirected back to our domain get the "code" in the request.
                String authCode = "the code in the callback request";
                // Now we can authenticate the user.
                AppleAuthorizationToken initialToken = appleAuthProvider.makeNewAuthorisationTokenRequest(authCode);
                // After the authentication we should check (not more than once every 24h) if the user 
                // is still logged in using "Sign in with Apple" by retrieving a refresh token.
                AppleAuthorizationToken refreshToken = appleAuthProvider.makeNewRefreshTokenRequest(initialToken
                        .getRefreshToken());
        
            }
        }
```

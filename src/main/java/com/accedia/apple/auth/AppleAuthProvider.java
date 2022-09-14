package com.accedia.apple.auth;

import com.accedia.apple.auth.user.AppleAuthorizationToken;
import com.accedia.apple.auth.user.UserData;
import com.accedia.apple.auth.user.UserDataDeserializer;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.google.api.client.auth.oauth2.*;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.common.collect.ImmutableList;

import javax.annotation.Nullable;
import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static java.util.stream.Collectors.toList;

public class AppleAuthProvider {

    private final static String DEFAULT_APPLE_AUTH_TOKEN_URL = "https://appleid.apple.com/auth/token";
    private final static String DEFAULT_APPLE_AUTH_AUTHORIZE_URL = "https://appleid.apple.com/auth/authorize";
    private final static long DEFAULT_SECRET_LIFE_IN_SEC = 20 * 60;
    private final static long DEFAULT_MAX_TIMEOUT_IN_SEC = 20;

    private final String clientId;
    private final Supplier<ClientParametersAuthentication> appleClientParameters;
    private final SecretGenerator secretGenerator;
    private final ECPrivateKey ecPrivateKey;
    private final Supplier<Instant> nowSupplier;
    private final String keyId;
    private final String teamId;
    private final long secretLifeInSec;
    private final GenericUrl appleAuthTokenUrl;
    private final String appleAuthAuthorizationUrl;
    private final UserDataDeserializer userDataDeserializer;
    private final List<String> appleUserScopes;
    private final String redirectUrl;
    private final HttpTransport httpTransport;
    private final JsonFactory jsonFactory;
    private final JWTVerifier jwtVerifier;


    /**
     * A constructor with minimum configuration. Uses default Apple URLs, http transport, json factory and timings.
     *
     * @param clientId        A10-character key identifier obtained from your developer account.
     *                        (aka "Service ID" that is configured for “Sign In with Apple")
     * @param keyId           A 10-character key identifier obtained from your developer account.
     *                        Configured for "Sign In with Apple".
     * @param teamId          A 10-character key identifier obtained from your developer account.
     * @param secretGenerator A provider for the client secret as specified in apple auth id.
     * @param privateKey      The private key as supplied by Apple.
     * @param redirectUrl     URL to which the user will be redirected after successful verification.
     *                        You need to configure a verified domain and map the redirect URL to it.
     *                        Can’t be an IP address or localhost. Can be left null if url generation won't
     *                        be used.
     * @param scopes          The apple required scopes. Values given here will determine the content of the
     *                        User Data returned in the tokens. Can be left null if url generation won't
     *                        be used.
     */
    public AppleAuthProvider(String clientId, String keyId, String teamId, SecretGenerator secretGenerator,
                             ECPrivateKey privateKey, @Nullable Collection<AppleUserScope> scopes,
                             @Nullable String redirectUrl) {
        this(clientId,
                keyId,
                teamId,
                DEFAULT_APPLE_AUTH_TOKEN_URL,
                DEFAULT_APPLE_AUTH_AUTHORIZE_URL,
                new UserDataDeserializer(),
                new NetHttpTransport(),
                new GsonFactory(),
                DEFAULT_MAX_TIMEOUT_IN_SEC,
                secretGenerator,
                privateKey,
                Instant::now,
                DEFAULT_SECRET_LIFE_IN_SEC,
                new AppleKeyProvider(),
                scopes,
                redirectUrl
        );
    }

    /**
     * Constructor using no default values.
     *
     * @param clientId                  A10-character key identifier obtained from your developer account.
     *                                  (aka "Service ID" that is configured for “Sign In with Apple")
     * @param keyId                     A 10-character key identifier obtained from your developer account.
     *                                  Configured for "Sign In with Apple".
     * @param teamId                    A 10-character key identifier obtained from your developer account.
     * @param redirectUrl               URL to which the user will be redirected after successful verification.
     *                                  You need to configure a verified domain and map the redirect URL to it.
     *                                  Can’t be an IP address or localhost.
     * @param scopes                    The apple required scopes. Values given here will determine the content of the
     *                                  User Data returned
     *                                  in the tokens.
     * @param ecPrivateKey              The private key supplied by apple.
     * @param secretGenerator           A provider for the client secret as specified in apple auth id.
     * @param secretLifeInSec           The lifespan of the client secret in seconds.
     * @param appleAuthTokenUrl         The apple oauth2 url for issuing Authentication and Verification tokens.
     * @param appleAuthAuthorizationUrl The apple url for beginning the Auth login.
     * @param userDataDeserializer      A deserializer used to extract user data from the raw apple token response.
     * @param httpTransport             The transport that will be used to make the token authenticate nad validate
     *                                  requests.
     * @param jsonFactory               The factory used to create the parser and generator for the tokens.
     * @param appleKeyProvider          A provider that will be used to validate the token responses.
     * @param maxTimeoutInSec           The Maximum allowed time for a http request before a timeout occurs.
     * @param nowSupplier               Should return the current instance.
     */
    public AppleAuthProvider(String clientId,
                             String keyId,
                             String teamId,
                             String appleAuthTokenUrl,
                             String appleAuthAuthorizationUrl,
                             UserDataDeserializer userDataDeserializer,
                             HttpTransport httpTransport,
                             JsonFactory jsonFactory,
                             long maxTimeoutInSec,
                             SecretGenerator secretGenerator,
                             ECPrivateKey ecPrivateKey,
                             Supplier<Instant> nowSupplier,
                             long secretLifeInSec,
                             RSAKeyProvider appleKeyProvider,
                             @Nullable Collection<AppleUserScope> scopes,
                             @Nullable String redirectUrl
    ) {
        this.clientId = clientId;
        this.secretGenerator = secretGenerator;
        this.ecPrivateKey = ecPrivateKey;
        this.nowSupplier = nowSupplier;
        this.keyId = keyId;
        this.teamId = teamId;
        this.secretLifeInSec = secretLifeInSec;
        this.userDataDeserializer = userDataDeserializer;
        this.appleUserScopes = scopes != null ? ImmutableList.copyOf(
                scopes.stream().map(AppleUserScope::getLiteral).collect(toList())
        ) : null;
        this.appleAuthTokenUrl = new GenericUrl(appleAuthTokenUrl);
        this.jsonFactory = jsonFactory;
        this.appleAuthAuthorizationUrl = appleAuthAuthorizationUrl;
        appleClientParameters = Suppliers.memoizeWithExpiration(this::generateClientAuthParameterSet,
                this.secretLifeInSec - maxTimeoutInSec,
                TimeUnit.SECONDS
        );
        this.redirectUrl = redirectUrl;
        this.httpTransport = httpTransport;

        Algorithm validationAlg = Algorithm.RSA256(appleKeyProvider);
        this.jwtVerifier = JWT.require(validationAlg)
                .build();

    }

    private ClientParametersAuthentication generateClientAuthParameterSet() {
        String newSecret = secretGenerator.generateSecret(ecPrivateKey, keyId, teamId, clientId,
                nowSupplier.get(), secretLifeInSec);
        return new ClientParametersAuthentication(clientId, newSecret);
    }

    /**
     * Generates a login link that will take the user Apple's authentication portal.
     * @param state A string that will be passed back when the user eventually makes their way to the redirect url.
     *              This will be automatically escaped.
     * @return A URL ready for embedding.
     */
    public String getLoginLink(String state) {
        return new AuthorizationCodeRequestUrl(appleAuthAuthorizationUrl, clientId)
                .setRedirectUri(this.redirectUrl)
                .setResponseTypes(Arrays.asList("code", "id_token"))
                .setScopes(appleUserScopes)
                .setState(state)
                .set("response_mode", "form_post")  //Could be parameterized based on scope.
                .build();
    }

    /**
     * Makes an authorisation request. Retrieves a User's date from Apple. Use this object to create users or sessions.
     * @param authCode Received from Apple after successfully redirecting the user.
     * @throws IOException
     */
    public AppleAuthorizationToken makeNewAuthorisationTokenRequest(String authCode) throws IOException {
        AuthorizationCodeTokenRequest authoriseTokenRequest
                = new AuthorizationCodeTokenRequest(httpTransport, jsonFactory, appleAuthTokenUrl, authCode);

        return executeTokenRequest(authoriseTokenRequest);
    }

    /**
     * Verifies if a token is valid.
     * Use this method to check daily if the user is still signed in on your app using Apple ID.
     * @param refreshToken
     * @return
     * @throws IOException
     */
    public AppleAuthorizationToken makeNewRefreshTokenRequest(String refreshToken) throws IOException {
        RefreshTokenRequest refreshTokenRequest
                = new RefreshTokenRequest(httpTransport, jsonFactory, appleAuthTokenUrl, refreshToken);

        return executeTokenRequest(refreshTokenRequest);
    }

    private AppleAuthorizationToken executeTokenRequest(TokenRequest tokenRequest) throws IOException {

        tokenRequest.setClientAuthentication(appleClientParameters.get());
        TokenResponse tokenResponse = tokenRequest.execute();
        Optional<String> idToken = Optional.ofNullable(tokenResponse.get("id_token")).map(Object::toString);
        idToken.ifPresent(this::validateToken);
        UserData userData = idToken.map(userDataDeserializer::getUserDataFromIdToken).orElse(null);
        return new AppleAuthorizationToken(
                tokenResponse.getAccessToken(),
                tokenResponse.getExpiresInSeconds(),
                idToken.orElse(null),
                tokenResponse.getRefreshToken(),
                userData);
    }

    private void validateToken(String token) {
        jwtVerifier.verify(token);
    }

}

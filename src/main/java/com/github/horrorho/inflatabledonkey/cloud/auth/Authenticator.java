/* 
 * The MIT License
 *
 * Copyright 2015 Ahseya.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.github.horrorho.inflatabledonkey.cloud.auth;

import com.dd.plist.NSDictionary;
import com.dd.plist.NSNumber;
import com.dd.plist.NSString;
import com.fasterxml.jackson.databind.JsonNode;
import com.github.horrorho.inflatabledonkey.requests.AuthenticationRequestFactory;
import com.github.horrorho.inflatabledonkey.responsehandler.PropertyListResponseHandler;
import com.github.horrorho.inflatabledonkey.responsehandler.JsonResponseHandler;
import com.github.horrorho.inflatabledonkey.util.PListsLegacy;
import com.github.horrorho.inflatabledonkey.util.CookieUtils;
import java.util.List;
import java.util.Scanner;
import java.io.IOException;
import net.jcip.annotations.Immutable;
import org.apache.http.cookie.Cookie;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpUriRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * Auth factory.
 *
 * @author Ahseya
 */
@Immutable
public final class Authenticator {

    private static final Logger logger = LoggerFactory.getLogger(Authenticator.class);

    public static Auth authenticate(HttpClient httpClient, CookieStore donkeyCookieStore, String id, String password) throws IOException {
        logger.trace("<< authenticate() < id: {} password: {}", id, password);

        AuthenticationRequestFactory authenticationRequestFactory = AuthenticationRequestFactory.instance();
        PropertyListResponseHandler<NSDictionary> nsDictionaryResponseHandler
                = PropertyListResponseHandler.dictionary();

        if( CookieUtils.cookiesExist() ) {
            // Load donkeyCookieStore so the request will pass it.
            CookieUtils.loadCookies(donkeyCookieStore);
        } else {
            // If it doesn't let's check if we need Two-Factor Authentication at all..
            try {
                HttpUriRequest request2fa = authenticationRequestFactory.twoFactorRequest(id, password);
    
                JsonResponseHandler<JsonNode> jsonResponseHandler = new JsonResponseHandler<>(JsonNode.class);
                JsonNode loginResp = httpClient.execute(request2fa, jsonResponseHandler);
                boolean requires2fa = false;
                try {
                    requires2fa = loginResp.get("hsaChallengeRequired").asBoolean();
                } catch(java.lang.NullPointerException npe) {}

                if(requires2fa) { // We need to send verification code and validate it since 2-Factor is required
                    /* This works, but for some reason SMS authorization code doesn't work when appended to password.
                    try { // Send a 2FA Code to iPhone
                        HttpUriRequest request2favalid = authenticationRequestFactory.twoFactorCodeRequest();
                        JsonNode codeResp = httpClient.execute(request2favalid, jsonResponseHandler);
                    } catch (HttpResponseException ex) {
                        System.out.println("Failed to send 2-Factor Code.");
                        throw ex;
                    }
                    */
                    // Prompt user for 2FA Code. Its the one that pops up on your phone via Wi-Fi
                    Scanner input = new Scanner(System.in);
                    System.out.print("Enter your two factor validation code:");
                    String tfa_code = input.nextLine();
                    //TODO: Should do some validation of tfa_code, but this works for now.
                    /* This will successfully verify the 2FA SMS code, but don't get an mme Token from this.
                    try { // Try to verify the 2FA Code.
                        HttpUriRequest request2favalid = authenticationRequestFactory.twoFactorValidationRequest(tfa_code);
                        JsonNode validationResp = httpClient.execute(request2favalid, jsonResponseHandler);
                        // From here, we need to save/serialize the auth cookies in httpClient so all further requests don't need to re-2fa-auth.
                        List<Cookie> cookies = donkeyCookieStore.getCookies();
                        if( !cookies.isEmpty() ) { // Serialize the cookies to json jobject.
                            CookieUtils.saveCookies(cookies);
                        }
                    } catch (HttpResponseException ex) {
                        System.out.println("2FA Code Validation Failed.");
                        throw ex;
                    }
                    */

                    // For now append 6 digit code to pass
                    // I'm still working on how to get mme from SMS authorization and cookies above.
                    password += tfa_code;  // This will authenticate and allow us to get an mme-token. 
                }
            } catch (HttpResponseException ex) {
                throw ex;
            } catch (java.net.URISyntaxException sex) {
                System.exit(-1);
            }
        }

        try {
            HttpUriRequest request = authenticationRequestFactory.apply(id, password);
            NSDictionary authentication = httpClient.execute(request, nsDictionaryResponseHandler);
            logger.debug("-- authenticate() - authentication: {}", authentication.toASCIIPropertyList());

            NSDictionary appleAccountInfo = PListsLegacy.getAs(authentication, "appleAccountInfo", NSDictionary.class);
            String dsPrsID = PListsLegacy.getAs(appleAccountInfo, "dsPrsID", NSNumber.class).toString();

            NSDictionary tokens = PListsLegacy.getAs(authentication, "tokens", NSDictionary.class);
            String mmeAuthToken = PListsLegacy.getAs(tokens, "mmeAuthToken", NSString.class).getContent();

            logger.debug("-- authenticate() -  dsPrsID: {}", dsPrsID);
            logger.debug("-- authenticate() -  mmeAuthToken: {}", mmeAuthToken);

            Auth auth = new Auth(dsPrsID, mmeAuthToken);

            logger.trace(">> authenticate() > auth: {}", auth);
            return auth;

        } catch (HttpResponseException ex) {
            logger.warn("--authenticate() - HttpResponseException: {}", ex.getMessage());
            int statusCode = ex.getStatusCode();

            if (statusCode == 401) {
                throw new HttpResponseException(statusCode, "Bad appleId/ password or not an iCloud account?");
            }

            if (statusCode == 409) {
                throw new HttpResponseException(statusCode, "Two-step enabled or partial iCloud account activation?");
            }

            throw ex;
        }
    }
}

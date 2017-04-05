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
package com.github.horrorho.inflatabledonkey.requests;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.Objects;
import java.util.function.BiFunction;
import java.net.URISyntaxException;
import net.jcip.annotations.Immutable;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import java.io.UnsupportedEncodingException;
import org.json.JSONObject;

/**
 * Authentication NSDictionary HttpUriRequest factory.
 *
 * @author Ahseya
 */
@Immutable
public final class AuthenticationRequestFactory implements BiFunction<String, String, HttpUriRequest> {

    public static final AuthenticationRequestFactory instance() {
        return INSTANCE;
    }

    private static final AuthenticationRequestFactory INSTANCE = new AuthenticationRequestFactory(
            "https://setup.icloud.com/setup/ws/1",
            "https://setup.icloud.com/setup/authenticate/$APPLE_ID$",
            CoreHeaders.headers());

    private final String clientId;
    private final String clientBuildNumber;
    private final String ws_url;
    private final String login_url;
    private final String tfa_code_url;
    private final String validation_url;
    private final String url;
    private final Map<Headers, Header> headers;

    AuthenticationRequestFactory(String ws_url, String url, Map<Headers, Header> headers) {
        this.ws_url = Objects.requireNonNull(ws_url);
        this.login_url = this.ws_url + "/login";
        this.tfa_code_url = this.ws_url + "/sendVerificationCode";
        this.validation_url = this.ws_url + "/validateVerificationCode";
        this.url = Objects.requireNonNull(url);
        this.headers = new HashMap<>(headers);
        this.clientId = UUID.randomUUID().toString();
        //this.clientBuildNumber = "14E45";
        this.clientBuildNumber = "13A404";
    }

    public HttpUriRequest twoFactorCodeRequest() 
        throws UnsupportedEncodingException, URISyntaxException
    {
        // Generate URL with request parameters.
        URIBuilder uri = new URIBuilder(tfa_code_url);
        uri.setParameter("clientBuildNumber", clientBuildNumber)
            .setParameter("clientId", clientId);

        System.out.println("(((((((((--)))))))))" + uri.toString());

        HttpPost request = new HttpPost(uri.toString());

        // Generate JSON Auth Request.
        JSONObject jsonObj = new JSONObject();
        jsonObj.put("phoneNumber", "********14");
        jsonObj.put("deviceId", "1");
        jsonObj.put("areaCode", "");
        jsonObj.put("deviceType", "SMS");
        StringEntity entity = new StringEntity(jsonObj.toString(), "UTF-8");
        entity.setContentType("application/json");

        System.out.println("Requesting Code...");
        System.out.println(jsonObj.toString());
        // Set POST Request Body to JSON Auth
        request.setEntity(entity);

        // Set required authentication headers
        request.setHeader(headers.get(Headers.ORIGIN));
        request.setHeader(headers.get(Headers.USERAGENT));
        request.setHeader(headers.get(Headers.XMMECLIENTINFO));

        return request;
    }

    public HttpUriRequest twoFactorValidationRequest(String code) 
        throws UnsupportedEncodingException, URISyntaxException
    {
        // Generate URL with request parameters.
        URIBuilder uri = new URIBuilder(validation_url);
        uri.setParameter("clientBuildNumber", clientBuildNumber)
            .setParameter("clientId", clientId);

        System.out.println("+++++++++++++" + uri.toString());

        HttpPost request = new HttpPost(uri.toString());

        // Generate JSON Auth Request.
        JSONObject jsonObj = new JSONObject();
        jsonObj.put("verificationCode", code);
        jsonObj.put("phoneNumber", "********14");
        jsonObj.put("deviceId", "1");
        jsonObj.put("trustBrowser", true);
        jsonObj.put("areaCode", "");
        jsonObj.put("deviceType", "SMS");
        StringEntity entity = new StringEntity(jsonObj.toString(), "UTF-8");
        entity.setContentType("application/json");

        System.out.println("Sending...");
        System.out.println(jsonObj.toString());
        // Set POST Request Body to JSON Auth
        request.setEntity(entity);

        // Set required authentication headers
        request.setHeader(headers.get(Headers.ORIGIN));
        request.setHeader(headers.get(Headers.USERAGENT));
        request.setHeader(headers.get(Headers.XMMECLIENTINFO));

        return request;
    }

    public HttpUriRequest twoFactorRequest(String id, String password) 
        throws UnsupportedEncodingException, URISyntaxException
    {
        // Generate URL with request parameters.
        URIBuilder uri = new URIBuilder(login_url);
        uri.setParameter("clientBuildNumber", clientBuildNumber)
            .setParameter("clientId", clientId);

        System.out.println("-------------" + uri.toString());

        HttpPost request = new HttpPost(uri.toString());

        // Generate JSON Auth Request.
        JSONObject jsonObj = new JSONObject();
        jsonObj.put("apple_id", id);
        jsonObj.put("password", password);
        jsonObj.put("extended_login", false);
        StringEntity entity = new StringEntity(jsonObj.toString(), "UTF-8");
        entity.setContentType("application/json");

        // Set POST Request Body to JSON Auth
        request.setEntity(entity);

        // Set required authentication headers
        request.setHeader(headers.get(Headers.ORIGIN));
        request.setHeader(headers.get(Headers.USERAGENT));
        request.setHeader(headers.get(Headers.XMMECLIENTINFO));

        return request;
    }

    @Override
    public HttpUriRequest apply(String id, String password) {
        String authorization = AccessTokens.BASIC.token(id, password);

        HttpGet request = new HttpGet(url);
        request.setHeader(headers.get(Headers.USERAGENT));
        request.setHeader(headers.get(Headers.XMMECLIENTINFO));
        request.setHeader(HttpHeaders.AUTHORIZATION, authorization);
        //request.setHeader("X-iCloud-HSA-Login", "");

        return request;
    }
}

package com.github.horrorho.inflatabledonkey.requests;

import static com.github.horrorho.inflatabledonkey.requests.Headers.*;
import java.util.HashMap;
import java.util.Map;
import net.jcip.annotations.Immutable;
import org.apache.http.Header;

/*
 * The MIT License
 *
 * Copyright 2016 Ahseya.
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
/**
 * CoreHeaders.
 *
 * @author Ahseya
 */
@Immutable
public final class CoreHeaders {

    private static final Map<Headers, Header> HEADERS = Headers.headers(
            USERAGENT.mapEntry(
                    "CloudKit/479 (13A404)"),
            XMMECLIENTINFO.mapEntry(
                    "<iPhone5,3> <iPhone OS;9.0.1;13A404> <com.apple.cloudkit.CloudKitDaemon/479 (com.apple.cloudd/479)>"),
            XCLOUDKITPROTOCOLVERSION.mapEntry(
                    "client=1;comments=1;device=1;presence=1;records=1;sharing=1;subscriptions=1;users=1;mescal=1;"),
            XAPPLEMMCSPROTOVERSION.mapEntry(
                    "4.0"),
            XCLOUDKITENVIRONMENT.mapEntry(
                    "production"),
            XCLOUDKITPARTITION.mapEntry(
                    "production"),
            ORIGIN.mapEntry(
                    "https://www.icloud.com")
    );

    public static Map<Headers, Header> headers() {
        return new HashMap<>(HEADERS);
    }
}

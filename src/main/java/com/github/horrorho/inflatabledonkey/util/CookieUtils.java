/*
 * The MIT License
 *
 * Copyright 2017 Trevor.
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
package com.github.horrorho.inflatabledonkey.util;

import java.util.Date;
import java.util.List;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.cookie.Cookie;
import org.apache.http.client.CookieStore;

/**
 * CookieUtils.
 *
 * @author Trevor
 */
public final class CookieUtils {

    private static final String cookiefile = "AUTHCOOKIEJAR.json";

    private static String readFileToString(String filePath) throws IOException {
        StringBuffer fileData = new StringBuffer();
        BufferedReader reader = new BufferedReader(new FileReader(filePath));
        char[] buf = new char[1024];
        int numRead=0;
        while((numRead=reader.read(buf)) != -1){
            String readData = String.valueOf(buf, 0, numRead);
            fileData.append(readData);
        }
        reader.close();
        return fileData.toString();
    }

    public static String expiryDateToString(Date date, String format) {
        String dateStr = null;
        DateFormat df = new SimpleDateFormat(format);
        try {
            dateStr = df.format(date);
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return dateStr;
    }

    public static Date expiryStringToDate(String dateStr, String format) {
        Date date = null;
        DateFormat df = new SimpleDateFormat(format);
        try {
            date = df.parse(dateStr);
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return date;
    }

    public static boolean cookiesExist() {
        File f = new File(cookiefile);
        return (f.exists() && !f.isDirectory());
    }

    public static void loadCookies(CookieStore cookieStore) 
        throws IOException, JSONException 
    {
        JSONObject cookiejar = new JSONObject(readFileToString(cookiefile));
        // Now recreate each cookie.
        JSONArray cookies = cookiejar.getJSONArray("cookies");
        for(Object cobj : cookies) {
			JSONObject c = (JSONObject)cobj;
			BasicClientCookie cookie = new BasicClientCookie(
				c.getString("name"), c.getString("value"));
			cookie.setDomain(c.getString("domain"));
			cookie.setPath(c.getString("path"));
            cookie.setExpiryDate(CookieUtils.expiryStringToDate(c.getString("expirydate"), "yyyy-MM-dd HH:mm:ss"));

            cookieStore.addCookie(cookie);
		}
    }

    public static void saveCookies(List<Cookie> cookies) {
        JSONObject cookiejar = new JSONObject();
        JSONArray cookieArr = new JSONArray();
        for (Cookie c : cookies) {
            JSONObject cj = new JSONObject();
            //if (!c.isPersistent()) {
            //    continue;
            //}
            cj.put("domain", c.getDomain());
            cj.put("path", c.getPath());
            cj.put("name", c.getName());
            cj.put("value", c.getValue());
            cj.put("expirydate", CookieUtils.expiryDateToString(c.getExpiryDate(), "yyyy-MM-dd HH:mm:ss"));

            if (c.getPorts() != null) {
                JSONArray cookieports = new JSONArray();
                for (int port : c.getPorts()) {
                    cookieports.put(port);
                }
                cj.put("ports", cookieports);
            }
            cookieArr.put(cj);
        }
        cookiejar.put("cookies", cookieArr);
        try (FileWriter file = new FileWriter(cookiefile)) {
            file.write(cookiejar.toString());
            file.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

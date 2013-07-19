/*
 * Copyright 2007 Yusuke Yamamoto
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package twitter4j.media;

import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.auth.OAuthAuthorization;
import twitter4j.conf.Configuration;
import twitter4j.internal.http.HttpParameter;

import twitter4j.internal.org.json.JSONObject;

import java.util.Map;
import java.util.HashMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * @author Rémy Rakic - remy.rakic at gmail.com
 * @author Takao Nakaguchi - takao.nakaguchi at gmail.com
 * @author withgod - noname at withgod.jp
 * @since Twitter4J 2.1.8
 */
class YFrogUpload extends AbstractImageUploadImpl {

    public YFrogUpload(Configuration conf, OAuthAuthorization oauth) {
        super(conf,  oauth);
    }

    public YFrogUpload(Configuration conf, String apiKey, OAuthAuthorization oauth) {
        super(conf, apiKey, oauth);
    }

    @Override
    protected String postUpload() throws TwitterException {
        int statusCode = httpResponse.getStatusCode();
        if (statusCode != 200) {
            throw new TwitterException("YFrog image upload returned invalid status code", httpResponse);
        }

        String response = httpResponse.asString();

        if (response.contains("<rsp stat=\"fail\">")) {
            String error = response.substring(response.indexOf("msg") + 5, response.lastIndexOf("\""));
            throw new TwitterException("YFrog image upload failed with this error message: " + error, httpResponse);
        }
        if (response.contains("<rsp stat=\"ok\">")) {
            return response.substring(response.indexOf("<mediaurl>") + "<mediaurl>".length(), response.indexOf("</mediaurl>"));
        }

        try {
          JSONObject json = new JSONObject(response);
          if (!json.isNull("rsp")){
            JSONObject rsp = json.getJSONObject("rsp");
            if (!rsp.isNull("mediaurl")){
              return rsp.getString("mediaurl");
            }

          }
        } catch (Exception e) {
          e.printStackTrace();
        }

        throw new TwitterException("Unknown YFrog response", httpResponse);
    }

    private static final Pattern pattern = Pattern.compile("([a-z_]+)=\"([^\"]+)\"");

    @Override
    protected void preUpload() throws TwitterException {
       uploadUrl = "https://yfrog.com/api/xauth_upload";

       String verifyCredentialsAuthorizationHeader = generateVerifyCredentialsAuthorizationHeader(TWITTER_VERIFY_CREDENTIALS_JSON_V1_1);
       Map<String,String> map = new HashMap<String,String>();

       Matcher matcher = pattern.matcher(verifyCredentialsAuthorizationHeader);
       while(matcher.find()){
         String key = matcher.group(1);
         String value = matcher.group(2);
         map.put(key,value);
       }

       StringBuilder builder = new StringBuilder();

       builder.append("OAuth realm=\"http://api.twitter.com/\",");

       builder.append("oauth_consumer_key=\"");
       builder.append(map.get("oauth_consumer_key"));
       builder.append("\",");
       builder.append("oauth_nonce=\"");
       builder.append(map.get("oauth_nonce"));
       builder.append("\",");
       builder.append("oauth_signature=\"");
       builder.append(map.get("oauth_signature"));
       builder.append("\",");
       builder.append("oauth_signature_method=\"HMAC-SHA1\",");
       builder.append("oauth_timestamp=\"");
       builder.append(map.get("oauth_timestamp"));
       builder.append("\",");
       builder.append("oauth_token=\"");
       builder.append(map.get("oauth_token"));
       builder.append("\",");
       builder.append("oauth_version=\"1.0\"");

       String auth = builder.toString();

       headers.put("X-Auth-Service-Provider", TWITTER_VERIFY_CREDENTIALS_JSON_V1_1);
       headers.put("X-Verify-Credentials-Authorization", auth);


        HttpParameter[] params = {new HttpParameter("key", apiKey) ,  this.image};
        if (message != null) {
            params = appendHttpParameters(new HttpParameter[]{
                    this.message}, params);
        }

        this.postParameter = params;


    }
}

(ns oauth-client.handler
  (:require [compojure.core :refer [defroutes GET]]
            [clojure.string :as str]
            [ring.middleware.defaults :refer [wrap-defaults site-defaults]]
            [ring.middleware.oauth2 :refer [wrap-oauth2]]
            [clj-http.client :as client]
            [ring.util.codec :as codec]
            [ring.util.request :as req]
            [ring.util.response :as resp]
            [buddy.core.keys :as keys]
            [buddy.sign.jwt :as jwt]
            [environ.core :refer [env]])
  (:import [java.time Instant]))


;; attack vectors: https://tools.ietf.org/html/draft-ietf-oauth-v2-threatmodel-06#section-4
;; - 3rd party can authenticate against existing user's google profile (of course)
;; - 3rd party gets code for existing user
;;   - convinces user to click disguised link to initiate auth process and obtain code
;;   - submit code to callback via a popup
;;     - requires 2 clicks minus (if prompt=none) (if auth-client doesn't verify callback state)
;; - 3rd party gets JWT
;;   - tricks a user into authenticating on malicious site, e.g. via embedded iframe
;; - 3rd party gets private key
;; - code or jwt are intercepted from non-SSL traffic
;;
;; invalid attack vectors
;; - 3rd party gets a user's id
;; - 3rd party gets a code for a non-registered user
;; - 3rd party gets oauth-token for registered user (user email, avatar, name, id is leaked, but can't request a jwt token)
;;
;; additional steps
;; - use SSL
;; - prevent oauth form from running in an iframe (Google already does this?)
;; - ensure final redirect (currently hardcoded) has to be on the same domain
;; - ensure auth-server redirect_uri callback is whitelisted (Google does this)
;; - ensure state for auth callback

;; NEXT STEPS
;; - CSRF token for redirect-uri [see oauth2 ring middleware: https://github.com/weavejester/ring-oauth2/blob/master/src/ring/middleware/oauth2.clj]
;;  - guarantees request originated from auth login page
;;  - how to implement statelessly?
;; - success-uri configurable at request-time
;; - reimplement using just ring [useage of compojure functionality it limited enough to justify just going w/ ring]


(def private-key (keys/private-key (env :private-key)
                                   (env :private-key-passphrase)))

(def config
  {:authorize-uri    "https://accounts.google.com/o/oauth2/v2/auth"
   :access-token-uri "https://www.googleapis.com/oauth2/v4/token"
   :user-info-uri    "https://www.googleapis.com/userinfo/v2/me" 
   :client-id        (env :client-id)
   :client-secret    (env :client-secret)
   :scopes           ["openid"] ;; profile, email
   :redirect-uri     "/auth/google/callback"
   :success-uri      "/auth/success"
   :error-uri        "/auth/error"})

(defn redirect-uri
  [request]
  (-> (req/request-url request)
      (java.net.URI/create)
      (.resolve (:redirect-uri config))
      str))

(defn authorize-uri
  [request]
  (str (:authorize-uri config)
       (if (.contains ^String (:authorize-uri config) "?") "&" "?")
       (codec/form-encode {:response_type "code"
                           :client_id     (:client-id config)
                           :redirect_uri  (redirect-uri request)
                           :scope         (str/join " " (:scopes config))})))

(defn request-access-token
  [request]
  (-> (client/post (:access-token-uri config)
                   {:accept :json,
                    :as :json,
                    :form-params {:code (get-in request [:query-params "code"]) 
                                  :grant_type "authorization_code"
                                  :redirect_uri (redirect-uri request)
                                  :client_id (:client-id config)
                                  :client_secret (:client-secret config)}})
      :body
      :access_token))

(defn request-user-info 
  [access-token]
  (-> (client/get (:user-info-uri config)
                  {:oauth-token access-token,
                   :as :json})
      :body))

(defn verify-user
  [id]
  "Verify user with id exists in the system and optionally retrieve user info"
  (Thread/sleep 500)
  (if (not= id "113766572582938032472")
    (throw (Exception. "400"))))

(defn sign-jwt
  [id]
  (jwt/sign {:id id
             :exp (+ (.getEpochSecond (Instant/now)) (* 60 60 6))} ;; 6 hours
            private-key
            {:alg :rs256}))

;; To Unsign
;; (jwt/unsign token public-key {:alg :rs256})

(defroutes app-routes
  (GET "/auth"
       []
       (resp/content-type (resp/resource-response "/auth/index.html" {:root "public"}) "text/html"))

  (GET "/auth/error"
       []
       (resp/content-type (resp/resource-response "/auth/error/index.html" {:root "public"}) "text/html"))

  (GET "/auth/success"
       []
       (resp/content-type (resp/resource-response "/auth/success/index.html" {:root "public"}) "text/html"))

  (GET "/auth/google"
       request
       (resp/redirect (authorize-uri request)))

  (GET "/auth/google/callback"
       request
       (try (let [access-token (request-access-token request)
                  {:keys [id]} (request-user-info access-token)]
              (verify-user id)
              (resp/redirect (str (:success-uri config)
                                  "?"
                                  (codec/form-encode {:token (sign-jwt id)}))))
            (catch Exception _ (resp/redirect (:error-uri config))))))

(def app
  (-> app-routes
      (wrap-defaults site-defaults)))

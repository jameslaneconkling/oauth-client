(defproject oauth-client "0.1.0-SNAPSHOT"
  :description "OAuth Authorization Code Grant reference implementation"
  :url "https://github.com/jameslaneconkling/oauth-client"
  :min-lein-version "2.0.0"
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [compojure "1.5.1"]
                 [ring/ring-defaults "0.2.1"]
                 [ring-oauth2 "0.1.4"]
                 [environ "1.1.0"]
                 [clj-http "3.8.0"]
                 [buddy/buddy-core "1.4.0"]
                 [buddy/buddy-sign "2.2.0"]]
  :plugins [[lein-ring "0.9.7"]
            [lein-environ "0.4.0"]]
  :ring {:handler oauth-client.handler/app}
  :profiles
  {:dev {:dependencies [[javax.servlet/servlet-api "2.5"]
                        [ring/ring-mock "0.3.0"]]}})

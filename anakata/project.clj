(defproject anakata "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [metosin/compojure-api "1.0.2"]
                 [clojurewerkz/elastisch "2.2.1"]]
  :ring {:handler anakata.core/ithazards}
  :profiles {:dev {
                   :plugins [[lein-ring "0.9.7"]]
                   :dependencies [[javax.servlet/servlet-api "2.5"]]
                   :ring {:port 3001}}})

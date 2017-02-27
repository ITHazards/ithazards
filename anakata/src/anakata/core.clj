(ns anakata.core
  (:require [compojure.api.sweet :refer :all]
            [ring.util.http-response :refer :all]
            [schema.core :as s]
            [ring.swagger.schema :as rs]
            [clojurewerkz.elastisch.rest          :as esr]
            [clojurewerkz.elastisch.rest.document :as esd]
            [clojurewerkz.elastisch.rest.response :as esrsp]))


(s/defschema Vulnerability
  {:cve-id s/Str
   :published s/Str
   :last-modified s/Str
   :summary s/Str
   :affected-software [s/Str]})

(defonce vulnerabilities (atom []))

(defn add! [new-vulnerability]
  (swap! vulnerabilities conj new-vulnerability))

(defn get-vulnerabilities []
  (let [conn (esr/connect "http://127.0.0.1:9200")
        res (esd/search conn "vulnerabilities" "vulnerability")
        hits (esrsp/hits-from res)]
    (loop [results hits]
      (let [hit (first results)]
        (if hit
          (do
            (add! (get hit :_source))
            (recur (rest results))))))
    (-> vulnerabilities deref)))

(def ithazards
  (api
   {:swagger
    {:ui "/"
     :spec "/swagger.json"
     :data {:info {:title "IT Hazards"}
            :tags [{:name "api"}]}}}
   (context "/vulnerabilities" []
            :tags ["vulnerabilities"]
            (GET "/" []
                 :return [Vulnerability]
                 :summary "Gets vulnerabilities"
                 (ok (get-vulnerabilities))))))

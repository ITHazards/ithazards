(ns anakata.core
  (:require [compojure.api.sweet :refer :all]
            [ring.util.http-response :refer :all]
            [schema.core :as s]
            [ring.swagger.schema :as rs]
            [clojurewerkz.elastisch.rest          :as esr]
            [clojurewerkz.elastisch.rest.document :as esd]
            [clojurewerkz.elastisch.rest.response :as esrsp]))

(def es-url
  (let [env-es-url (System/getenv "ES_URL")]
    (if (nil? env-es-url)
      "http://localhost:9200"
      env-es-url)))

(s/defschema Vulnerability
  {:cve-id s/Str
   :published s/Str
   :last-modified s/Str
   :summary s/Str
   :affected-software [s/Str]})

(defn ensure-vulnerability [vulnerability]
  (if (not (contains? vulnerability :affected-software))
    (assoc vulnerability :affected-software [])
    vulnerability))

(defn read-vulnerabilities [hits]
  (let [hit (first hits)]
    (if hit
      (do
        (conj
          (read-vulnerabilities (rest hits))
          (ensure-vulnerability (get hit :_source))))
      [])))

(defn get-response [index type from size]
  (esrsp/hits-from (esd/search (esr/connect es-url)
                               index
                               type
                               :from from
                               :size size)))

(defn get-vulnerabilities [from size]
  (let [hits (get-response "vulnerabilities"
                           "vulnerability"
                           from
                           size)]
      (read-vulnerabilities hits)))

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
        :header-params [{from :- s/Int 0} {size :- s/Int 10}]
        :summary "Gets vulnerabilities"
        (ok (get-vulnerabilities from size))))))

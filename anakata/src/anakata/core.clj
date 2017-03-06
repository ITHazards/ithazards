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

(defn get-vulnerabilities [from size]
  (let [conn (esr/connect "http://127.0.0.1:9200")
        res (esd/search conn "vulnerabilities" "vulnerability"
                        :from from
                        :size size)
        hits (esrsp/hits-from res)]
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

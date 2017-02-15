(ns anakata.core
  (:require [compojure.api.sweet :refer :all]
            [ring.util.http-response :refer :all]
            [schema.core :as s]
            [ring.swagger.schema :as rs]))

(s/defschema Vulnerability
  {:cve-id s/Str})

(s/defschema NewVulnerability (dissoc Vulnerability :cve-id))

(def ithazards
  (api
   {:swagger
    {:ui "/"
     :spec "/swagger.json"
     :data {:info {:title "IT Hazards"}
            :tags [{:name "api"}]}}}
   (context "/api" []
            :tags ["api"]
            (POST "/vulnerabilities" []
                 :body [vulnerability (describe NewVulnerability "CVE-0-0")]
                 (ok)))))

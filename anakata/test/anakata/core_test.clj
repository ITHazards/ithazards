(ns anakata.core-test
  (:use midje.sweet)
  (:require [clojure.test :refer :all]
            [anakata.core :refer :all]))

(def incomplete-vuln-data
  {:cve-id "CVE-0000-0000"
   :published "2001-09-10 10:00:00"
   :last-modified "2001-09-10 10:00:00"
   :summary "Brief summary of incomplete vulnerability"})
(def complete-vuln-data
  {:cve-id "CVE-0001-0001"
   :published "2001-09-10 10:00:00"
   :last-modified "2001-09-10 10:00:00"
   :summary "Brief summary of complete vulnerability"
   :affected-software ["Some software"]})

(facts "about `ensure-vulnerability`"
       (fact "it returns vulnerability with affected-software"
             (let [incomplete-vuln (ensure-vulnerability incomplete-vuln-data)]
                  (contains? incomplete-vuln :affected-software) => true
                  (get incomplete-vuln :cve-id) => "CVE-0000-0000"
                  (get incomplete-vuln :affected-software) => []
                  )
             (let [complete-vuln (ensure-vulnerability complete-vuln-data)]
                  (contains? complete-vuln :affected-software) => true
                  (get complete-vuln :cve-id) => "CVE-0001-0001"
                  (get complete-vuln :affected-software) => ["Some software"])))

(def vulnerabilities-data
  [{:_source incomplete-vuln-data} {:_source complete-vuln-data}])

(facts "about `read-vulnerabilities`"
       (fact "it returns a list of vulnerabilities"
             (let [vulnerabilities (read-vulnerabilities vulnerabilities-data)]
                  (clojure.core/count vulnerabilities) => (clojure.core/count vulnerabilities-data)
                  (get (first vulnerabilities) :cve-id) => (get complete-vuln-data :cve-id)
                  (get (second vulnerabilities) :cve-id) => (get incomplete-vuln-data :cve-id))))

(def vulnerabilities-data-1
  [{:_source incomplete-vuln-data}])

(def vulnerabilities-data-2
  [{:_source complete-vuln-data}])

(facts "about `get-vulnerabilities`"
       (fact "it returns a list of vulnerabilities"
             (prerequisites (get-response "vulnerabilities"
                                          "vulnerability"
                                          0
                                          10) => vulnerabilities-data)
             (let [vulnerabilities (get-vulnerabilities 0 10)]
               (clojure.core/count vulnerabilities) => (clojure.core/count vulnerabilities-data)
               (get (first vulnerabilities) :cve-id) => (get complete-vuln-data :cve-id)
               (get (second vulnerabilities) :cve-id) => (get incomplete-vuln-data :cve-id)))
       (fact "it returns a paged list of vulnerabilities"
             (prerequisites (get-response "vulnerabilities"
                                          "vulnerability"
                                          0
                                          1) => vulnerabilities-data-1
                            (get-response "vulnerabilities"
                                          "vulnerability"
                                          1
                                          1) => vulnerabilities-data-2)
             (let [vulnerabilities (get-vulnerabilities 0 1)
                   vulnerabilities2 (get-vulnerabilities 1 1)]
               (clojure.core/count vulnerabilities) => (clojure.core/count vulnerabilities-data-1)
               (clojure.core/count vulnerabilities2) => (clojure.core/count vulnerabilities-data-2)
               (get (first vulnerabilities) :cve-id) => (get incomplete-vuln-data :cve-id)
               (get (first vulnerabilities2) :cve-id) => (get complete-vuln-data :cve-id)
               ))
       )

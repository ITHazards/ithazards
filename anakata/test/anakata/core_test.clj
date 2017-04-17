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
             (contains? (ensure-vulnerability incomplete-vuln-data) :affected-software) => true
             (contains? (ensure-vulnerability complete-vuln-data) :affected-software) => true)
       (fact "it returns untouched vulnerability when affected-software is present"
             (get (ensure-vulnerability incomplete-vuln-data) :affected-software) => []
             (get (ensure-vulnerability complete-vuln-data) :affected-software) => ["Some software"]))

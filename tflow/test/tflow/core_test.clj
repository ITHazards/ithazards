(ns tflow.core-test
  (:use midje.sweet)
  (:require [clojure.test :refer :all]
            [tflow.core :refer :all]
            [clojure.string :as str]
            [clojure.data.xml :as xml]
            [clojure.zip :as zip]
            [clojurewerkz.elastisch.rest  :as esr]
            [clojurewerkz.elastisch.rest.index :as esi]
            [clojurewerkz.elastisch.rest.document :as esd]
            [clojure.java.io :as io]))

(def modified-xml-file "test/tflow/fixtures/modified.xml")
(def modified-xml (str/join "" (str/split-lines (slurp (io/input-stream modified-xml-file)))))
(def expected-modified-zipper (zip/xml-zip (xml/parse (io/input-stream modified-xml-file))))
(def modified-url "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz")

(def vulns-2002-xml-file "test/tflow/fixtures/vulns-2002.xml")
(def vulns-2002-xml (str/join "" (str/split-lines (slurp (io/input-stream vulns-2002-xml-file)))))
(def expected-vulns-2002-zipper (zip/xml-zip (xml/parse (io/input-stream vulns-2002-xml-file))))
(def vulns-2002-url "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-vulns-2002.xml.gz")

(facts "about `get-zipper`"
       (prerequisites (gunzip-text-lines vulns-2002-url) => vulns-2002-xml
                      (gunzip-text-lines modified-url) => modified-xml)
       (fact "it returns a zipper with parsed XML content"
             (get-zipper vulns-2002-url) => expected-vulns-2002-zipper
             (get-zipper modified-url) => expected-modified-zipper))

(facts "about `init-search`"
       (prerequisites (esr/connect "http://localhost:9200") => []
                      (init-indices []) => [])
       (fact "it returns a connection to search engine"
             (init-search "http://localhost:9200") => []))

(def conn [])
(def expected_conn ["vulnerabilities"])

(facts "about `init-indices`"
       (fact "it returns the connection with the index created"
             (prerequisites (esi/exists? conn "vulnerabilities") => false
                            (esi/exists? expected_conn "vulnerabilities") => true
                            (esi/create conn "vulnerabilities" :mappings es-vulnerability-map :settings es-vulnerability-settings) => (def conn expected_conn)
                            (esi/create expected_conn "vulnerabilities" :mappings es-vulnerability-map :settings es-vulnerability-settings) => nil)
             (init-indices conn)
             conn => expected_conn
             (init-indices expected_conn)
             conn => expected_conn)
       )

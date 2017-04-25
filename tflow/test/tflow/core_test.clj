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
             conn => expected_conn))

(def indexer [])
(def modified-nvd expected-modified-zipper)
(def expected-modified-info [
                             {
                              :cve-id "CVE-2012-6697"
                              :last-modified "2017-04-13T10:59:00.637-04:00"
                              :published "2017-04-13T10:59:00.480-04:00"
                              :summary "InspIRCd before 2.0.7 allows remote attackers to cause a denial of service (infinite loop)."}
                             {
                              :cve-id "CVE-2012-1301"
                              :last-modified "2017-04-13T13:59:00.187-04:00"
                              :published "2017-04-13T13:59:00.170-04:00"
                              :summary "The FeedProxy.aspx script in Umbraco 4.7.0 allows remote attackers to proxy requests on their behalf via the \"url\" parameter."}
                             {
                              :cve-id "CVE-2010-1821"
                              :last-modified "2017-04-13T12:59:00.737-04:00"
                              :published "2017-04-13T12:59:00.723-04:00"
                              :summary "Apple Mac OS X 10.6 through 10.6.3 and Mac OS X Server 10.6 through 10.6.3 allows local users to obtain system privileges."}
                             {
                              :cve-id "CVE-2010-1816"
                              :last-modified "2017-04-13T12:59:00.567-04:00"
                              :published "2017-04-13T12:59:00.533-04:00"
                              :summary "Buffer overflow in ImageIO in Apple Mac OS X 10.6 through 10.6.3 and Mac OS X Server 10.6 through 10.6.3 allows remote attackers to execute arbitrary code or cause a denial of service (crash) via a crafted image."}
                             {
                              :affected-software ["cpe:/o:dataprobe:ibootbar_firmware:2007-09-20"]
                              :cve-id "CVE-2007-6760"
                              :last-modified "2017-04-13T15:38:09.210-04:00"
                              :published "2017-04-07T17:59:00.193-04:00"
                              :summary "Dataprobe iBootBar (with 2007-09-20 and possibly later beta firmware) allows remote attackers to bypass authentication, and conduct power-cycle attacks on connected devices, via a DCCOOKIE cookie."}
                             {
                              :affected-software ["cpe:/o:dataprobe:ibootbar_firmware:2007-09-20"]
                              :cve-id "CVE-2007-6759"
                              :last-modified "2017-04-13T15:37:40.617-04:00"
                              :published "2017-04-07T17:59:00.163-04:00"
                              :summary "Dataprobe iBootBar (with 2007-09-20 and possibly later released firmware) allows remote attackers to bypass authentication, and conduct power-cycle attacks on connected devices, via a DCRABBIT cookie."}])

(facts "about `walk-entries`"
       (fact "it indexes all entries"
             (walk-entries (zip/down modified-nvd) ..indexer..) => expected-modified-info
             (provided (esd/put ..indexer.. anything anything anything anything) => nil)))

(facts "about `scrape-file`"
       (fact "it processes a whole NVD file"
             (scrape-file modified-xml-file "http://localhost:9200") => nil
             (provided
              (get-zipper modified-xml-file) => ..zipper..
              (init-search "http://localhost:9200") => ..indexer..
              (zip/node ..zipper..) => {:attrs {:pub_date "2010-09-09T09:09:09.000+02:00"}}
              (zip/down ..zipper..) => ..entries..
              (walk-entries ..entries.. ..indexer..) => [0 1 2 3 4 5])))

(facts "about `process args`"
       (fact "it sets default values"
             (process-args []) => anything
             es-url => "http://localhost:9200"
             source-url => "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz")
       (fact "it sets `-i` option as es-url"
             (process-args ["-i" "http://search:9200"]) => anything
             es-url => "http://search:9200"
             source-url => "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz")
       (fact "it sets first argument as source url"
             (process-args ["https://mysource.com"]) => anything
             es-url => "http://localhost:9200"
             source-url => "https://mysource.com")
       (fact "it sets `-i` option as es-url and first argument as source-url"
             (process-args ["-i" "http://search:9200" "https://mysource.com"]) => anything
             es-url => "http://search:9200"
             source-url => "https://mysource.com"))

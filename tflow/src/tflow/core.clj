(ns tflow.core
  (:require [clojure.java.io :as io]
            [clojure.zip :as zip]
            [clojure.data.xml :as xml]
            [clojure.string :as str]
            [clojure.tools.cli :as cli]
            [clojurewerkz.elastisch.rest  :as esr]
            [clojurewerkz.elastisch.rest.index :as esi]
            [clojurewerkz.elastisch.rest.document :as esd])
  (:import java.util.zip.GZIPInputStream)
  (:gen-class))

(def source-url "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz")
(def es-url "http://localhost:9200")
(def es nil)
(def es-vulnerability-map {
    "vulnerability" {
      :properties {
        :cve-id {:type "string" :store true}
        :published-datetime {:type "date" :store true}
        :last-modified-datetime {:type "date" :store true}
        :summary {
          :type "string"
          :store true
          :analyzer "snowball"
          :term_vector "with_positions_offsets"}}}})
(def es-vulnerability-settings {
    "number_of_shards" 5
    "number_of_replicas" 0})

(defn gunzip-text-lines
  "Returns the contents of input as a sequence of lines (strings).
  input: something which can be opened by io/input-stream.
      The bytes supplied by the resulting stream must be gzip compressed.
  opts: as understood by clojure.core/slurp pass :encoding \"XYZ\" to
      set the encoding of the decompressed bytes. UTF-8 is assumed if
      encoding is not specified.

  This function was copied from https://gist.github.com/bpsm/1858654 and
  must be credited to Ben Smith-Mannschott"
  [input & opts]
  (with-open [input (-> input io/input-stream GZIPInputStream.)]
    (str/split-lines (apply slurp input opts))))

(defn get-zipper
  "Returns a zipper with the XML in the url."
  [url]
  (zip/xml-zip (xml/parse-str (str/join "" (gunzip-text-lines url)))))

(defn walk-software-list
  "Processes a vulnerable software list returning a list of CPEs."
  [software-list]
  (if software-list
    (vec (flatten (conj
      [(first (get (zip/node software-list) :content))]
      (walk-software-list (zip/right software-list)))))
    []))

(defn walk-entry-content
  "Processes an entry contents getting the CVE id, published and last modified
  dates, summary and the list of CPEs affected.

  The following fields are not being collected:
  * CVSS
  * CWE
  * References
  * Vulnerable configuration
  * Security Protection
  * Others"
  [content]
  (if content
    (conj
      (let [
        tag (get (zip/node content) :tag)
        value (get (zip/node content) :content)]
        (case tag
          :cve-id {:cve-id (first value)}
          :published-datetime {:published (first value)}
          :last-modified-datetime {:last-modified (first value)}
          :summary {:summary (first value)}
          :vulnerable-software-list {
            :affected-software (walk-software-list (zip/down content))}
          {}))
      (walk-entry-content (zip/right content)))
    {}))

(defn walk-entries
  [entry]
  (if entry
    (let [content (walk-entry-content (zip/down entry))]
      (esd/put
        es
        "vulnerabilities"
        "vulnerability"
        (get content :cve-id)
        content)
      (conj (walk-entries (zip/right entry)) content))
    []))

(def cli-options
  [
   ["-i" "--indexer URL" "Elasticsearch URL"
    :default es-url]
   ["-h" "--help"]])

(defn usage [options-summary]
  (->> [
    "tflow is a vulnerability parser."
    ""
    "Usage: tflow [url_to_parse]"
    ""
    "Options:"
    options-summary]
    (str/join \newline)))

(defn exit [status msg]
  (println msg)
  (System/exit status))

(defn error-msg [errors]
  (str "The following errors occurred while parsing your command:\n\n"
  (str/join \newline errors)))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (let [
    {:keys [options arguments errors summary]} (cli/parse-opts args cli-options)]
    (cond
      (:help options) (exit 0 (usage summary))
      (:indexer options) (def es-url (get options :indexer))
      (>= (count arguments) 1) (def source-url (first arguments))
      errors (exit 1 (error-msg errors))))
  (let [
    nvd (get-zipper source-url)]
    (println (apply str ["Parsing " source-url " on " es-url]))
    (def es (esr/connect es-url))
    (if (not (esi/exists? es "vulnerabilities"))
      (do
        (esi/create
          es
          "vulnerabilities"
          :mappings es-vulnerability-map
          :settings es-vulnerability-settings)
        ))
    (def published (get (get (zip/node nvd) :attrs) :pub_date))
    (def entries (walk-entries (zip/down nvd)))
    (println (apply str [
      "Parsing finished, "
      (count entries)
      " entries parsed"]))))

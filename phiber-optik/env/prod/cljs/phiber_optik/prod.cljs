(ns phiber-optik.prod
  (:require [phiber-optik.core :as core]))

;;ignore println statements in prod
(set! *print-fn* (fn [& _]))

(core/init!)

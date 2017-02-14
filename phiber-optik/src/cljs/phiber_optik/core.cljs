(ns phiber-optik.core
    (:require [reagent.core :as reagent :refer [atom]]
              [reagent.session :as session]
              [secretary.core :as secretary :include-macros true]
              [accountant.core :as accountant]))
;; -------------------------
;; Components

(defn input-search []
  [:div.input-search
   [:input {:type "text", :size 40}]
   [:input {:type "submit" :value "Search"}]])

;; -------------------------
;; Views

(defn home-page []
  [:div [:h2 "It Hazards"]
   [:image {:src "/public/images/logo.png"}]
   [:div [:a {:href "/about"} "go to about page"]]
    [input-search]])

(defn about-page []
  [:div [:h2 "About It Hazards"]
   [:div [:a {:href "/"} "go to the home page"]]])

(defn current-page []
  [:div [(session/get :current-page)]])

;; -------------------------
;; Routes

(secretary/defroute "/" []
  (session/put! :current-page #'home-page))

(secretary/defroute "/about" []
  (session/put! :current-page #'about-page))

;; -------------------------
;; Initialize app

(defn mount-root []
  (reagent/render [current-page] (.getElementById js/document "app")))

(defn init! []
  (accountant/configure-navigation!
    {:nav-handler
     (fn [path]
       (secretary/dispatch! path))
     :path-exists?
     (fn [path]
       (secretary/locate-route path))})
  (accountant/dispatch-current!)
  (mount-root))

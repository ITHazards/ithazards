(ns phiber-optik.core
    (:require [reagent.core :as reagent :refer [atom]]
              [reagent.session :as session]
              [ajax.core :refer [GET]]
              [secretary.core :as secretary :include-macros true]
              [accountant.core :as accountant])
    (:require-macros [adzerk.env :as env]))

(env/def
  ANAKATA_URL "http://localhost:3001")

(def vulnerabilities (atom []))

(defn swap-vulnerabilities [response]
  (swap! vulnerabilities concat (for [vulnerability response]
                                  (into {}
                                        (for [[k v] vulnerability]
                                          [(keyword k) v])))))

(defn update-vulnerabilities []
  (GET (str ANAKATA_URL "/vulnerabilities") {:response-format :json
                                             :handler swap-vulnerabilities}))

;; -------------------------
;; Components

(defn input-search []
  [:div.input-search
   [:input {:type "text", :size 20}]
   [:input {:type "submit" :value "Find vulnerabilities"}]])

(defn vulnerability-ul [vulnerability]
  [:ul {:class "vulnerability"}
   [:li
    [:ul {:class "vulnerability-title"}
     [:li {:class "id"} (get vulnerability :cve-id)]
     [:li {:class "dates"}
      [:ul {:class "vulnerability-dates"}
       [:li {:class "published"} (str "Published: " (get vulnerability :published))]
       [:li {:class "last-modified"} (str "Last modified: " (get vulnerability :last-modified))]
       ]
      ]
     ]
    ]
   [:li {:class "summary"} (get vulnerability :summary)]
   ]
  )

(defn get-vulnerabilities-list [vulnerabilities]
  (for [vulnerability vulnerabilities]
    ^{:key vulnerability}
    [:li (vulnerability-ul vulnerability)]
    )
  )

;; -------------------------
;; Views

(defn home-page []
  (update-vulnerabilities)
    (fn []
      (let [items @vulnerabilities]
        [:div
         [:header
          [:div
            [:h1 {:class "main-title"} "IT Hazards"]
            [input-search]]
          ]
         [:div {:class "content"}
          [:ul {:class "vulnerability-list"}
           (get-vulnerabilities-list items)
           ]]
         [:footer
          [:ul
           [:li [:a {:href "/about"} "About IT Hazards"]]
           ]
          ]
         ]
        )
      )
  )

(defn about-page []
  [:header
   [:div
    [:h1 {:class "main-title"} "IT Hazards"]
    [input-search]]
   [:div {:class "about"}
     "IT Hazards pretends to be a tool for software development and security engineers."
    ]
   [:footer
    [:ul
     [:li [:a {:href "/"} "Back to home"]]]]])

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

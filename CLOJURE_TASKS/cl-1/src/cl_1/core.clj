(ns cl-1.core
  (:gen-class))

(defn gen-strings [alphabet n]
  (reduce
    (fn [acc _]
      (reduce
        concat
        (map
          (fn [s]
            (map
              (fn [c]
                (str s c))
              (filter
                (fn [c]
                  (or (empty? s)
                      (not= (last s) (first c))))
                alphabet)))
          acc)))
    [""]
    (range n)))

(defn -main []
  (println (gen-strings ["a" "b" "c"] 3)))
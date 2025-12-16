(ns cl-3.core
  (:gen-class))

(defn pfilter
  ([pred coll] (pfilter pred coll 64 4))
  ([pred coll block-size max-parallel]
   (let [blocks (partition-all block-size coll)]
     (letfn [(go [futs remaining-blocks]
               (lazy-seq
                 (when (or (seq futs) (seq remaining-blocks))
                   (let [current-fut (first futs)
                         rest-futs (rest futs)
                         new-fut (when (seq remaining-blocks)
                                   (future (doall (filter pred (first remaining-blocks)))))
                         next-futs (cond-> rest-futs
                                     new-fut (conj new-fut))]
                     (concat @current-fut
                             (go next-futs (if new-fut (rest remaining-blocks) remaining-blocks)))))))]
       (let [initial-futs (map #(future (doall (filter pred %)))
                               (take max-parallel blocks))
             remaining-blocks (drop max-parallel blocks)]
         (go initial-futs remaining-blocks))))))


(defn heavy-even? [x]
  (Thread/sleep 1)   ;; имитация долгого вычисления
  (even? x))

(defn -main
  [& args]
  (println "Parallel lazy filter demo")

  (println
    "Infinite result:"
    (take 10
          (pfilter #(zero? (mod % 7)) (range))))

  (println "\n--- Performance test ---")

  (let [data (range 5000)]

    (println "\nSequential filter:")
    (time
      (doall
        (filter heavy-even? data)))

    (println "\nParallel pfilter:")
    (time
      (doall
        (pfilter heavy-even? data))))
        (shutdown-agents))
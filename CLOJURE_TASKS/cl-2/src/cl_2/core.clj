(ns cl-2.core
  (:gen-class))

(def primes
  (letfn [(sieve [nums]
            (lazy-seq
              (let [p (first nums)]
                (cons p
                      (sieve
                        (filter #(not (zero? (mod % p)))
                                (rest nums)))))))]
    (sieve (iterate inc 2))))

(defn -main
  []
  (println (take 10 primes)))

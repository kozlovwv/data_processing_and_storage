(ns cl-2.core-test
  (:require [clojure.test :refer :all]
            [cl-2.core :refer :all]))

(deftest primes-test
  (testing "First 10 primes"
    (is (= [2 3 5 7 11 13 17 19 23 29]
           (take 10 primes))))

  (testing "Primes under 30"
    (is (= [2 3 5 7 11 13 17 19 23 29]
           (take-while #(< % 30) primes))))

  (testing "100th prime"
    (is (= 541
           (nth primes 99)))))
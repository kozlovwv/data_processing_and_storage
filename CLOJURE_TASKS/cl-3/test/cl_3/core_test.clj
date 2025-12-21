(ns cl-3.core-test
  (:require [clojure.test :refer :all]
            [cl-3.core :refer :all]))

(deftest pfilter-basic-test
  (testing "pfilter works like filter on finite collections"
    (is (= (pfilter even? (range 10))
           (filter even? (range 10))))))

(deftest pfilter-empty-test
  (testing "pfilter on empty collection"
    (is (= (pfilter even? [])
           '()))))

(deftest pfilter-infinite-test
  (testing "pfilter works with infinite sequences"
    (is (= (take 5 (pfilter #(zero? (mod % 7)) (range)))
           '(0 7 14 21 28)))))

(deftest pfilter-laziness-test
  (testing "pfilter is lazy"
    (let [result (pfilter even? (range))]
      (is (= (take 3 result) '(0 2 4))))))

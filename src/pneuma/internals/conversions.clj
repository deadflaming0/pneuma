(ns pneuma.internals.conversions
  (:require [clojure.math :as math]))

(defn integer->big-endian-byte-array
  [n x]
  (let [bs (->> n
                (iterate #(bit-shift-right % 8))
                (take-while pos?)
                (map #(bit-and % 0xff))
                reverse)]
    (vec (concat (repeat (- x (count bs)) 0) bs))))

(defn numeral-string->integer
  [X radix]
  (reduce #(+ %2 (* %1 radix)) 0 X))

(defn integer->numeral-string
  [x m radix]
  (loop [i 0
         x' x
         X '()]
    (if (= i m)
      X
      (recur (inc i)
             (long (math/floor (/ x' radix)))
             (conj X (mod x' radix))))))

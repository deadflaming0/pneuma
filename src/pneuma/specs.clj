(ns pneuma.specs
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]))

(defn- fixed-byte-array-spec
  [sizes]
  (s/with-gen
    (s/and #(instance? (Class/forName "[B") %)
           #(contains? sizes (count %)))
    #(gen/fmap byte-array
               (gen/bind
                (gen/elements sizes)
                (fn [size] (gen/vector (gen/choose -128 127) size))))))

(s/def ::key (fixed-byte-array-spec #{16 24 32}))

(defn- flexible-byte-array-spec
  []
  (s/with-gen
    (s/nilable #(instance? (Class/forName "[B") %))
    #(gen/one-of
      [(gen/return nil)
       (gen/fmap byte-array
                 (gen/bind
                  (gen/choose 1 8)
                  (fn [size] (gen/vector (gen/choose -128 127) size))))])))

(s/def ::ff1.tweak (flexible-byte-array-spec))

(s/def ::ff3-1.tweak (fixed-byte-array-spec #{8}))

(s/def ::radix (s/with-gen (s/and int? #(<= 2 %) #(>= 36 %)) #(gen/choose 2 36)))

(defn- random-string
  [radix]
  (let [min-length 5
        max-length 20
        length (+ min-length (rand-int (inc (- max-length min-length))))
        result (apply str (repeatedly length #(Character/forDigit (rand-int radix) radix)))]
    result))

(defn plaintext-spec
  ([]
   (plaintext-spec 10))
  ([radix]
   (s/with-gen
     (s/and string? #(not= % ""))
     #(gen/fmap (fn [_] (random-string radix))
                (gen/return nil)))))

(s/def ::plaintext (plaintext-spec))

(s/def ::ciphertext (s/and string? #(not= % "")))

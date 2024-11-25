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

(def key-sizes #{16 24 32})

(s/def ::key (fixed-byte-array-spec key-sizes))

(def max-ff1-tweak-size 16)

(defn- flexible-byte-array-spec
  []
  (s/with-gen
    (s/or :nil nil?
          :byte-array #(and (instance? (Class/forName "[B") %)
                            (<= (alength %) max-ff1-tweak-size)))
    #(gen/one-of
      [(gen/return nil)
       (gen/fmap byte-array
                 (gen/bind
                  (gen/choose 1 max-ff1-tweak-size)
                  (fn [size] (gen/vector (gen/choose -128 127) size))))])))

(s/def ::ff1.tweak (flexible-byte-array-spec))

(def ff3-1-tweak-sizes #{8})

(s/def ::ff3-1.tweak (fixed-byte-array-spec ff3-1-tweak-sizes))

(s/def ::radix (s/with-gen (s/int-in 2 37) #(gen/choose 2 36)))

(defn- pseudorandom-string
  [radix]
  (let [min-length 5
        max-length 20
        length (+ min-length (rand-int (inc (- max-length min-length))))]
    (apply str (repeatedly length #(Character/forDigit (rand-int radix) radix)))))

(defn plaintext-spec
  ([]
   (plaintext-spec 10))
  ([radix]
   (s/with-gen
     (s/and string? #(not= % ""))
     #(gen/fmap (fn [_] (pseudorandom-string radix))
                (gen/return nil)))))

(s/def ::plaintext (plaintext-spec))

(s/def ::ciphertext (s/and string? #(not= % "")))

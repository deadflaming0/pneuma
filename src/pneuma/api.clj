(ns pneuma.api
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.test.alpha :as stest]
            [pneuma.internals.ff1 :as ff1]
            [pneuma.internals.ff3-1 :as ff3-1]
            [pneuma.specs :as specs]))

(defn- ->X
  [input radix]
  (map #(Character/digit % radix) input))

(defn- ->Y
  [output radix]
  (apply str (map #(.toString (BigInteger. (str %)) radix) output)))

(defn ff1-encrypt
  [key tweak radix plaintext]
  (let [X (->X plaintext radix)
        ciphertext (ff1/ff1-encrypt key tweak radix X)]
    (->Y ciphertext radix)))

(s/fdef ff1-encrypt
  :args (s/cat :key ::specs/key
               :tweak ::specs/ff1.tweak
               :radix ::specs/radix
               :plaintext ::specs/plaintext)
  :ret ::specs/ciphertext)

(defn ff1-decrypt
  [key tweak radix ciphertext]
  (let [X (->X ciphertext radix)
        plaintext (ff1/ff1-decrypt key tweak radix X)]
    (->Y plaintext radix)))

(s/fdef ff1-decrypt
  :args (s/cat :key ::specs/key
               :tweak ::specs/ff1.tweak
               :radix ::specs/radix
               :ciphertext ::specs/ciphertext)
  :ret ::specs/plaintext)

(defn ff3-1-encrypt
  [key tweak radix plaintext]
  (let [X (->X plaintext radix)
        ciphertext (ff3-1/ff3-1-encrypt key tweak radix X)]
    (->Y ciphertext radix)))

(s/fdef ff3-1-encrypt
  :args (s/cat :key ::specs/key
               :tweak ::specs/ff3-1.tweak
               :radix ::specs/radix
               :plaintext ::specs/plaintext)
  :ret ::specs/ciphertext)

(defn ff3-1-decrypt
  [key tweak radix ciphertext]
  (let [X (->X ciphertext radix)
        plaintext (ff3-1/ff3-1-decrypt key tweak radix X)]
    (->Y plaintext radix)))

(s/fdef ff3-1-decrypt
  :args (s/cat :key ::specs/key
               :tweak ::specs/ff3-1.tweak
               :radix ::specs/radix
               :ciphertext ::specs/ciphertext)
  :ret ::specs/plaintext)

(stest/instrument `ff1-encrypt)
(stest/instrument `ff1-decrypt)
(stest/instrument `ff3-1-encrypt)
(stest/instrument `ff3-1-decrypt)

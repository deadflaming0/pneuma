(ns pneuma.api
  (:import [java.security SecureRandom])
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

(defn- random-bytes
  [n]
  (let [seed (byte-array n)]
    (.nextBytes (SecureRandom.) seed)
    seed))

(def new-key random-bytes)

(s/fdef new-key
  :args (s/cat :n specs/key-sizes)
  :ret ::specs/key)

(def new-ff1-tweak random-bytes)

(s/fdef new-ff1-tweak
  :args (s/cat :n (s/int-in 1 (inc specs/max-ff1-tweak-size)))
  :ret ::specs/ff1.tweak)

(defn new-ff3-1-tweak
  []
  (random-bytes 8))

(s/fdef new-ff3-1-tweak
  :ret ::specs/ff3-1.tweak)

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

(stest/instrument `new-key)
(stest/instrument `new-ff1-tweak)
(stest/instrument `new-ff3-1-tweak)
(stest/instrument `ff1-encrypt)
(stest/instrument `ff1-decrypt)
(stest/instrument `ff3-1-encrypt)
(stest/instrument `ff3-1-decrypt)

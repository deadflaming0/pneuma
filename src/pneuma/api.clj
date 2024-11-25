(ns pneuma.api
  "Provides a cryptographic API for key management and encryption/decryption operations using FF1 and FF3-1 algorithms."
  (:import [java.security SecureRandom])
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.test.alpha :as stest]
            [pneuma.internals.ff1 :as ff1]
            [pneuma.internals.ff3-1 :as ff3-1]
            [pneuma.specs :as specs]))

(defn- random-bytes
  [n]
  (let [seed (byte-array n)]
    (.nextBytes (SecureRandom.) seed)
    seed))

(def new-key
  "Generates a cryptographically secure random byte array to serve as a key of a valid AES size."
  random-bytes)

(s/fdef new-key
  :args (s/cat :n specs/key-sizes)
  :ret ::specs/key)

(def new-ff1-tweak
  "Generates a cryptographically secure random byte array to serve as a tweak for the FF1 algorithm."
  random-bytes)

(s/fdef new-ff1-tweak
  :args (s/cat :n (s/int-in 1 (inc specs/max-ff1-tweak-size)))
  :ret ::specs/ff1.tweak)

(defn new-ff3-1-tweak
  "Generates a cryptographically secure random byte array to serve as a tweak for the FF3-1 algorithm."
  []
  (random-bytes 8))

(s/fdef new-ff3-1-tweak
  :ret ::specs/ff3-1.tweak)

(defn- ->X
  [input radix]
  (map #(Character/digit % radix) input))

(defn- ->Y
  [output radix]
  (apply str (map #(.toString (BigInteger. (str %)) radix) output)))

(defn ff1-encrypt
  "Encrypts a plaintext using the FF1 format-preserving encryption (FPE) algorithm.
  Requires a key, a tweak, a numeric radix, and the plaintext to encrypt.
  Returns a ciphertext in the same format as the plaintext."
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
  "Decrypts a ciphertext using the FF1 format-preserving encryption (FPE) algorithm.
  Requires the same key, tweak, and numeric radix used during encryption.
  Produces the original plaintext as output."
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
  "Encrypts a plaintext using the FF3-1 format-preserving encryption (FPE) algorithm.
  Requires a key, a tweak, a numeric radix, and the plaintext to encrypt.
  Returns a ciphertext in the same format as the plaintext."
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
  "Decrypts a ciphertext using the FF3-1 format-preserving encryption (FPE) algorithm.
  Requires the same key, tweak, and numeric radix used during encryption.
  Produces the original plaintext as output."
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

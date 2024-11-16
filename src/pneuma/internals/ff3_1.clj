(ns pneuma.internals.ff3-1
  (:refer-clojure :exclude [key])
  (:require [clojure.math :as math]
            [clojure.string :as string]
            [pneuma.internals.conversions :as conversions])
  (:import (javax.crypto Cipher)
           (javax.crypto.spec SecretKeySpec)))

(defn- P
  [W i radix substring]
  (concat
   (map #(bit-xor (bit-and %1 0xff) %2)
        (seq W)
        (conversions/integer->big-endian-byte-array i 4))
   (conversions/integer->big-endian-byte-array
    (conversions/numeral-string->integer (reverse substring) radix)
    12)))

(defn- S
  [key P]
  (let [cipher (Cipher/getInstance "AES/ECB/NoPadding")
        _ (.init cipher Cipher/ENCRYPT_MODE (SecretKeySpec. (byte-array (reverse key)) "AES"))]
    (apply str
           (map #(format "%02x" (bit-and % 0xff))
                (reverse (vec (.doFinal cipher (byte-array (reverse P)))))))))

(defn- byte-array->binary-vector
  [ba]
  (vec
   (mapcat (fn [b]
             (let [binary-string (Integer/toBinaryString (bit-and 0xff b))]
               (apply vector
                      (map #(Character/getNumericValue %)
                           (str (string/join (repeat (- 8 (count binary-string)) "0")) binary-string)))))
           ba)))

(defn- binary-vector->byte-array
  [bs]
  (byte-array
   (map #(-> (apply str %)
             (Integer/parseInt 2)
             (bit-and 0xff)
             unchecked-byte)
        (partition 8 (apply str bs)))))

(defn- prepare-tweak
  [tweak]
  (let [as-binary-vector (byte-array->binary-vector tweak)
        tweak' (concat
                (subvec as-binary-vector 0 28)
                [0 0 0 0]
                (subvec as-binary-vector 32 56)
                (subvec as-binary-vector 28 32)
                [0 0 0 0])]
    (binary-vector->byte-array tweak')))

(defn ff3-1-encrypt
  [key tweak radix X]
  (let [n (count X)
        u (int (math/ceil (/ n 2)))
        v (- n u)
        [A B] (split-at u X)
        [Tl Tr] (split-at 4 (prepare-tweak tweak))]
    (loop [i 0
           A' A
           B' B]
      (let [[m W] (if (even? i) [u Tr] [v Tl])
            P' (P W i radix B')
            S' (S key P')
            y (BigInteger. S' 16)
            c (long (mod (+ (conversions/numeral-string->integer (reverse A') radix) y)
                         (long (math/pow radix m))))
            C (reverse (conversions/integer->numeral-string c m radix))]
        (if (= i 7)
          (concat B' C)
          (recur (inc i)
                 B'
                 C))))))

(defn ff3-1-decrypt
  [key tweak radix X]
  (let [n (count X)
        u (int (math/ceil (/ n 2)))
        v (- n u)
        [A B] (split-at u X)
        [Tl Tr] (split-at 4 (prepare-tweak tweak))]
    (loop [i 7
           A' A
           B' B]
      (let [[m W] (if (even? i) [u Tr] [v Tl])
            P' (P W i radix A')
            S' (S key P')
            y (BigInteger. S' 16)
            c (long (mod (- (conversions/numeral-string->integer (reverse B') radix) y)
                         (long (math/pow radix m))))
            C (reverse (conversions/integer->numeral-string c m radix))]
        (if (= i 0)
          (concat C A')
          (recur (dec i)
                 C
                 A'))))))

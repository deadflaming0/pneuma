(ns pneuma.internals.ff1
  (:refer-clojure :exclude [key])
  (:require [clojure.math :as math]
            [pneuma.internals.conversions :as conversions])
  (:import (javax.crypto Cipher)
           (javax.crypto.spec IvParameterSpec SecretKeySpec)))

(defn- setup
  [tweak radix X]
  (let [n (count X)
        u (int (math/floor (/ n 2)))
        v (- n u)
        [A B] (split-at u X)
        b (int (math/ceil (/ (math/ceil (* v (/ (math/log radix) (math/log 2)))) 8)))
        d (int (+ (* 4 (math/ceil (/ b 4))) 4))
        P (flatten
           [1
            2
            1
            (let [radix-bytes (byte-array 3)]
              (aset-byte radix-bytes 2 (unchecked-byte radix))
              (aset-byte radix-bytes 1 (unchecked-byte (bit-shift-right radix 8)))
              (aset-byte radix-bytes 0 (unchecked-byte (bit-shift-right radix 16)))
              (vec radix-bytes))
            10
            (mod u 256)
            (let [n-bytes (byte-array 4)]
              (aset-byte n-bytes 3 (unchecked-byte n))
              (aset-byte n-bytes 2 (unchecked-byte (bit-shift-right n 8)))
              (aset-byte n-bytes 1 (unchecked-byte (bit-shift-right n 16)))
              (aset-byte n-bytes 0 (unchecked-byte (bit-shift-right n 24)))
              (vec n-bytes))
            (let [t (count tweak)
                  t-bytes (byte-array 4)]
              (aset-byte t-bytes 3 (unchecked-byte t))
              (aset-byte t-bytes 2 (unchecked-byte (bit-shift-right t 8)))
              (aset-byte t-bytes 1 (unchecked-byte (bit-shift-right t 16)))
              (aset-byte t-bytes 0 (unchecked-byte (bit-shift-right t 24)))
              (vec t-bytes))])]
    {:u u
     :v v
     :A A
     :B B
     :b b
     :d d
     :P P}))

(defn- Q
  [tweak b i radix substring]
  (flatten
   (concat
    tweak ;; tweak is optional
    [(let [zero-bytes-count (mod (- (- (count tweak)) b 1) 16)
           zero-bytes (byte-array zero-bytes-count)]
       (vec zero-bytes))]
    [i]
    [(conversions/integer->big-endian-byte-array (conversions/numeral-string->integer substring radix) b)])))

(defn- PRF
  [key P Q]
  (let [cipher (Cipher/getInstance "AES/CBC/NoPadding")
        iv (IvParameterSpec. (byte-array 16))
        _ (.init cipher Cipher/ENCRYPT_MODE (SecretKeySpec. key "AES") iv)
        P||Q (byte-array (concat P Q))
        encrypted (.doFinal cipher P||Q)]
    (map #(bit-and % 0xff) (take-last 16 encrypted))))

(defn- S
  [d R key]
  (let [cipher (Cipher/getInstance "AES/ECB/NoPadding")
        _ (.init cipher Cipher/ENCRYPT_MODE (SecretKeySpec. key "AES"))
        expanded (map (fn [i]
                        (let [ba (byte-array 16)
                              _ (java.util.Arrays/fill ba (byte i))
                              R||i (map #(bit-and (bit-xor %1 %2) 0xff) R ba)]
                          (vec (.doFinal cipher (byte-array R||i)))))
                      (range 1 (int (math/ceil (/ d 16)))))]
    (apply str (map #(format "%02x" (bit-and % 0xff))
                    (take d (concat R expanded))))))

(defn ff1-encrypt
  [key tweak radix X]
  (let [{:keys [u v A B b d P]} (setup tweak radix X)]
    (loop [i 0
           A' A
           B' B]
      (let [Q' (Q tweak b i radix B')
            R' (PRF key P Q')
            S' (S d R' key)
            y (BigInteger. S' 16)
            m (if (even? i) u v)
            c (long (mod (+ (conversions/numeral-string->integer A' radix) y)
                         (long (math/pow radix m))))
            C (conversions/integer->numeral-string c m radix)]
        (if (= i 9)
          (concat B' C)
          (recur (inc i)
                 B'
                 C))))))

(defn ff1-decrypt
  [key tweak radix X]
  (let [{:keys [u v A B b d P]} (setup tweak radix X)]
    (loop [i 9
           A' A
           B' B]
      (let [Q' (Q tweak b i radix A')
            R' (PRF key P Q')
            S' (S d R' key)
            y (BigInteger. S' 16)
            m (if (even? i) u v)
            c (long (mod (- (conversions/numeral-string->integer B' radix) y)
                         (long (math/pow radix m))))
            C (conversions/integer->numeral-string c m radix)]
        (if (= i 0)
          (concat C A')
          (recur (dec i)
                 C
                 A'))))))

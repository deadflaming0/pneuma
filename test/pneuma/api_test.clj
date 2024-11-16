(ns pneuma.api-test
  {:clj-kondo/config '{:linters {:unresolved-symbol {:level :off}}}}
  (:refer-clojure :exclude [key])
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.test :refer [are deftest]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.properties :as prop]
            [pneuma.api :refer [ff1-encrypt ff1-decrypt
                                ff3-1-encrypt ff3-1-decrypt]]
            [pneuma.specs :as specs]))

;; sample-based testing

;; source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf

(deftest ff1-aes128
  (let [key (byte-array [0x2b 0x7e 0x15 0x16 0x28 0xae 0xd2 0xa6 0xab 0xf7 0x15 0x88 0x09 0xcf 0x4f 0x3c])]
    (are [tweak radix plaintext]
         (= (ff1-decrypt key tweak radix (ff1-encrypt key tweak radix plaintext))
            plaintext)
      nil 10 "0123456789"
      (byte-array [0x39 0x38 0x37 0x36 0x35 0x34 0x33 0x32 0x31 0x30]) 10 "0123456789"
      (byte-array [0x37 0x37 0x37 0x37 0x70 0x71 0x72 0x73 0x37 0x37 0x37]) 36 "0123456789abcdefghi")))

(deftest ff1-aes192
  (let [key (byte-array [0x2b 0x7e 0x15 0x16 0x28 0xae 0xd2 0xa6 0xab 0xf7 0x15 0x88 0x09 0xcf 0x4f 0x3c 0xef 0x43 0x59 0xd8 0xd5 0x80 0xaa 0x4f])]
    (are [tweak radix plaintext]
         (= (ff1-decrypt key tweak radix (ff1-encrypt key tweak radix plaintext))
            plaintext)
      nil 10 "0123456789"
      (byte-array [0x39 0x38 0x37 0x36 0x35 0x34 0x33 0x32 0x31 0x30]) 10 "0123456789"
      (byte-array [0x37 0x37 0x37 0x37 0x70 0x71 0x72 0x73 0x37 0x37 0x37]) 36 "0123456789abcdefghi")))

(deftest ff1-aes256
  (let [key (byte-array [0x2b 0x7e 0x15 0x16 0x28 0xae 0xd2 0xa6 0xab 0xf7 0x15 0x88 0x09 0xcf 0x4f 0x3c 0xef 0x43 0x59 0xd8 0xd5 0x80 0xaa 0x4f 0x7f 0x03 0x6d 0x6f 0x04 0xfc 0x6a 0x94])]
    (are [tweak radix plaintext]
         (= (ff1-decrypt key tweak radix (ff1-encrypt key tweak radix plaintext))
            plaintext)
      nil 10 "0123456789"
      (byte-array [0x39 0x38 0x37 0x36 0x35 0x34 0x33 0x32 0x31 0x30]) 10 "0123456789"
      (byte-array [0x37 0x37 0x37 0x37 0x70 0x71 0x72 0x73 0x37 0x37 0x37]) 36 "0123456789abcdefghi")))

;; source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF3samples.pdf

(deftest ff3-1-aes128
  (let [key (byte-array [0xef 0x43 0x59 0xd8 0xd5 0x80 0xaa 0x4f 0x7f 0x03 0x6d 0x6f 0x04 0xfc 0x6a 0x94])]
    (are [tweak radix plaintext]
         (= (ff3-1-decrypt key tweak radix (ff3-1-encrypt key tweak radix plaintext))
            plaintext)
      (byte-array [0xd8 0xe7 0x92 0x0a 0xfa 0x33 0x0a 0x73]) 10 "890121234567890000"
      (byte-array [0x9a 0x76 0x8a 0x92 0xf6 0x0e 0x12 0xd8]) 10 "890121234567890000"
      (byte-array [0xd8 0xe7 0x92 0x0a 0xfa 0x33 0x0a 0x73]) 10 "89012123456789000000789000000"
      (byte-array [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]) 10 "89012123456789000000789000000"
      (byte-array [0x9a 0x76 0x8a 0x92 0xf6 0x0e 0x12 0xd8]) 26 "0123456789abcdefghi")))

(deftest ff3-1-aes192
  (let [key (byte-array [0xef 0x43 0x59 0xd8 0xd5 0x80 0xaa 0x4f 0x7f 0x03 0x6d 0x6f 0x04 0xfc 0x6a 0x94 0x2b 0x7e 0x15 0x16 0x28 0xae 0xd2 0xa6])]
    (are [tweak radix plaintext]
         (= (ff3-1-decrypt key tweak radix (ff3-1-encrypt key tweak radix plaintext))
            plaintext)
      (byte-array [0xd8 0xe7 0x92 0x0a 0xfa 0x33 0x0a 0x73]) 10 "890121234567890000"
      (byte-array [0x9a 0x76 0x8a 0x92 0xf6 0x0e 0x12 0xd8]) 10 "890121234567890000"
      (byte-array [0xd8 0xe7 0x92 0x0a 0xfa 0x33 0x0a 0x73]) 10 "89012123456789000000789000000"
      (byte-array [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]) 10 "89012123456789000000789000000"
      (byte-array [0x9a 0x76 0x8a 0x92 0xf6 0x0e 0x12 0xd8]) 26 "0123456789abcdefghi")))

(deftest ff3-1-aes256
  (let [key (byte-array [0xef 0x43 0x59 0xd8 0xd5 0x80 0xaa 0x4f 0x7f 0x03 0x6d 0x6f 0x04 0xfc 0x6a 0x94 0x2b 0x7e 0x15 0x16 0x28 0xae 0xd2 0xa6 0xab 0xf7 0x15 0x88 0x09 0xcf 0x4f 0x3c])]
    (are [tweak radix plaintext]
         (= (ff3-1-decrypt key tweak radix (ff3-1-encrypt key tweak radix plaintext))
            plaintext)
      (byte-array [0xd8 0xe7 0x92 0x0a 0xfa 0x33 0x0a 0x73]) 10 "890121234567890000"
      (byte-array [0x9a 0x76 0x8a 0x92 0xf6 0x0e 0x12 0xd8]) 10 "890121234567890000"
      (byte-array [0xd8 0xe7 0x92 0x0a 0xfa 0x33 0x0a 0x73]) 10 "89012123456789000000789000000"
      (byte-array [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]) 10 "89012123456789000000789000000"
      (byte-array [0x9a 0x76 0x8a 0x92 0xf6 0x0e 0x12 0xd8]) 26 "0123456789abcdefghi")))

;; generative testing

(defspec ff1-spec 10000
  (prop/for-all
   [key (s/gen ::specs/key)
    tweak (s/gen ::specs/ff1.tweak)
    radix (s/gen ::specs/radix)]
   (let [plaintext-1 (gen/generate (s/gen (specs/plaintext-spec radix)))
         ciphertext (ff1-encrypt key tweak radix plaintext-1)
         plaintext-2 (ff1-decrypt key tweak radix ciphertext)]
     (= plaintext-1 plaintext-2))))

(defspec ff3-1-spec 10000
  (prop/for-all
   [key (s/gen ::specs/key)
    tweak (s/gen ::specs/ff3-1.tweak)
    radix (s/gen ::specs/radix)]
   (let [plaintext-1 (gen/generate (s/gen (specs/plaintext-spec radix)))
         ciphertext (ff3-1-encrypt key tweak radix plaintext-1)
         plaintext-2 (ff3-1-decrypt key tweak radix ciphertext)]
     (= plaintext-1 plaintext-2))))
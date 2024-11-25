# pneuma

A Clojure implementation of Draft NIST Special Publication 800-38G Revision 1 (Methods for Format-Preserving Encryption), featuring FF1 and FF3-1.

## Using FF1

```clj
(require '[pneuma.api :as api])

(def k (api/new-key 16))
(def tweak (api/new-ff1-tweak 16)) ;; or `nil`, but not recommended
(def radix 10) ;; must be between 2 and 36 (inclusive)
(def plaintext "1234567890")

(= (api/ff1-decrypt k tweak radix (api/ff1-encrypt k tweak radix plaintext))
   plaintext) ;; => true
```

## Using FF3-1

```clj
(require '[pneuma.api :as api])

(def k (api/new-key 16))
(def tweak (api/new-ff3-1-tweak))
(def radix 10) ;; must be between 2 and 36 (inclusive)
(def plaintext "1234567890")

(= (api/ff3-1-decrypt k tweak radix (api/ff3-1-encrypt k tweak radix plaintext))
   plaintext) ;; => true
```
